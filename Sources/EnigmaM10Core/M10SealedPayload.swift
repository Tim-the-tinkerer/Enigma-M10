import Foundation

/// Inner plaintext placed in front of the packed payload on v6 / `M10PW03`.
/// Exact original/stored sizes and CRC-32 are not in the public header.
public enum M10SealedPayload {
    public static let headerLength = 4 + 8 + 8 + 1
    private static let innerFlagZlib: UInt8 = 1 << 0

    public struct Inner: Sendable {
        public var crc: UInt32
        public var originalBytes: Int
        public var storedBytes: Int
        public var zlib: Bool
        public var packed: Data
        public var packedSymbols: String

        var info: DensePack.Info {
            DensePack.Info(
                originalBytes: originalBytes,
                storedBytes: storedBytes,
                codec: zlib ? .zlib : .none
            )
        }
    }

    public static func headerSymbolCount(suite: M10CipherSuite) -> Int {
        switch suite {
        case .base256: return headerLength
        case .alpha36, .ascii: return headerLength * 2
        case .base512: return Base512Symbols.symbolCount(for: headerLength)
        }
    }

    public static func packedUnitCount(storedBytes: Int, suite: M10CipherSuite) -> Int {
        guard storedBytes > 0 else { return 0 }
        switch suite {
        case .base256:
            return storedBytes
        case .alpha36:
            return ((storedBytes + DensePack.blockBytes - 1) / DensePack.blockBytes)
                * Alpha36Symbols.denseBlockSymbols
        case .ascii:
            return ((storedBytes + DensePack.blockBytes - 1) / DensePack.blockBytes)
                * Ascii94Symbols.denseBlockSymbols
        case .base512:
            return Base512Symbols.symbolCount(for: storedBytes)
        }
    }

    public static func int(from value: UInt64, limit: Int) throws -> Int {
        guard value <= UInt64(limit), value <= UInt64(Int.max) else {
            throw M10Error.payloadTooLarge
        }
        return Int(value)
    }

    public static func header(crc: UInt32, info: DensePack.Info) -> Data {
        var body = Data()
        var crcBE = crc.bigEndian
        body.append(Data(bytes: &crcBE, count: 4))
        appendU64(&body, UInt64(info.originalBytes))
        appendU64(&body, UInt64(info.storedBytes))
        body.append(info.codec == .zlib ? innerFlagZlib : 0)
        return body
    }

    public static func wrapBytes(crc: UInt32, info: DensePack.Info, packed: Data) throws -> Data {
        var body = header(crc: crc, info: info)
        body.append(packed)
        return try M10Padding.padData(body, originalBytes: info.originalBytes)
    }

    public static func wrapSymbols(
        crc: UInt32,
        info: DensePack.Info,
        packed: String,
        suite: M10CipherSuite
    ) throws -> String {
        let prefix = PairCodec.encode(header(crc: crc, info: info), suite: suite)
        var body = prefix
        body.append(packed)
        let extra = M10Padding.padCount(
            cipherBytes: body.count,
            boundary: M10Padding.boundary(
                originalBytes: info.originalBytes, unpaddedCount: body.count
            )
        )
        if extra > 0 {
            body.append(try M10Padding.randomSymbols(count: extra, suite: suite))
        }
        return body
    }

    public static func wrapFile(
        packedURL: URL,
        crc: UInt32,
        info: DensePack.Info,
        suite: M10CipherSuite,
        to destURL: URL
    ) throws {
        let handle = try FileIO.createEmptyFile(at: destURL)
        defer { try? handle.close() }
        if suite == .base256 {
            handle.write(header(crc: crc, info: info))
            try FileIO.copyContents(from: packedURL, to: handle)
            let unpadded = headerLength + info.storedBytes
            let extra = M10Padding.padCount(
                cipherBytes: unpadded,
                boundary: M10Padding.boundary(
                    originalBytes: info.originalBytes, unpaddedCount: unpadded
                )
            )
            if extra > 0 {
                handle.write(try M10MessageKey.randomBytes(extra))
            }
            return
        }
        handle.write(Data(PairCodec.encode(header(crc: crc, info: info), suite: suite).utf8))
        try FileIO.copyContents(from: packedURL, to: handle)
        let packedBytes = try FileIO.byteCount(at: packedURL)
        let symbolBytes = suite == .base512 ? Base512Symbols.utf8BytesPerSymbol : 1
        let packedUnits = packedBytes / max(symbolBytes, 1)
        let unpadded = headerSymbolCount(suite: suite) + packedUnits
        let extra = M10Padding.padCount(
            cipherBytes: unpadded,
            boundary: M10Padding.boundary(
                originalBytes: info.originalBytes, unpaddedCount: unpadded
            )
        )
        if extra > 0 {
            handle.write(Data(try M10Padding.randomSymbols(count: extra, suite: suite).utf8))
        }
    }

    public static func unwrapBytes(_ decoded: Data) throws -> Inner {
        let parsed = try parseHeader(decoded)
        let start = headerLength
        guard start + parsed.storedBytes <= decoded.count else { throw M10Error.corruptPayload }
        let packed = Data(decoded[start..<(start + parsed.storedBytes)])
        return Inner(
            crc: parsed.crc,
            originalBytes: parsed.originalBytes,
            storedBytes: parsed.storedBytes,
            zlib: parsed.zlib,
            packed: packed,
            packedSymbols: Base256Symbols.latin1String(packed)
        )
    }

    public static func unwrapSymbols(_ decoded: String, suite: M10CipherSuite) throws -> Inner {
        let prefixCount = headerSymbolCount(suite: suite)
        guard decoded.count >= prefixCount else { throw M10Error.corruptPayload }
        let prefix = String(decoded.prefix(prefixCount))
        guard let headerData = PairCodec.decode(prefix, suite: suite, storedLength: headerLength),
              headerData.count == headerLength else {
            throw M10Error.corruptPayload
        }
        let parsed = try parseHeader(headerData)
        let packedCount = packedUnitCount(storedBytes: parsed.storedBytes, suite: suite)
        guard prefixCount + packedCount <= decoded.count else { throw M10Error.corruptPayload }
        let start = decoded.index(decoded.startIndex, offsetBy: prefixCount)
        let end = decoded.index(start, offsetBy: packedCount)
        let packedSymbols = String(decoded[start..<end])
        let packed = suite == .base256
            ? (Base256Symbols.latin1Data(packedSymbols) ?? Data())
            : Data(packedSymbols.utf8)
        return Inner(
            crc: parsed.crc,
            originalBytes: parsed.originalBytes,
            storedBytes: parsed.storedBytes,
            zlib: parsed.zlib,
            packed: packed,
            packedSymbols: packedSymbols
        )
    }

    public static func unwrapFile(
        at decodedURL: URL,
        suite: M10CipherSuite,
        packedURL: URL
    ) throws -> Inner {
        let size = try FileIO.byteCount(at: decodedURL)
        let symbolBytes = suite == .base512 ? Base512Symbols.utf8BytesPerSymbol : 1
        let headerChars = headerSymbolCount(suite: suite)
        let headerBytes = suite == .base256 ? headerLength : headerChars * symbolBytes
        guard size >= headerBytes else { throw M10Error.corruptPayload }
        let input = try FileHandle(forReadingFrom: decodedURL)
        defer { try? input.close() }
        let headerChunk = try input.read(upToCount: headerBytes) ?? Data()
        guard headerChunk.count == headerBytes else { throw M10Error.corruptPayload }
        let headerData: Data
        if suite == .base256 {
            headerData = headerChunk
        } else {
            guard let decoded = PairCodec.decode(
                String(decoding: headerChunk, as: UTF8.self),
                suite: suite,
                storedLength: headerLength
            ), decoded.count == headerLength else {
                throw M10Error.corruptPayload
            }
            headerData = decoded
        }
        let parsed = try parseHeader(headerData)
        let packedCount = packedUnitCount(storedBytes: parsed.storedBytes, suite: suite)
        let packedBytes = suite == .base256 ? packedCount : packedCount * symbolBytes
        guard headerBytes + packedBytes <= size else { throw M10Error.corruptPayload }
        let dest = try FileIO.createEmptyFile(at: packedURL)
        defer { try? dest.close() }
        var remaining = packedBytes
        while remaining > 0 {
            let chunk = try input.read(upToCount: min(FileIO.chunkBytes, remaining)) ?? Data()
            if chunk.isEmpty { throw M10Error.corruptPayload }
            dest.write(chunk)
            remaining -= chunk.count
        }
        return Inner(
            crc: parsed.crc,
            originalBytes: parsed.originalBytes,
            storedBytes: parsed.storedBytes,
            zlib: parsed.zlib,
            packed: Data(),
            packedSymbols: ""
        )
    }

    private static func parseHeader(_ data: Data) throws -> (
        crc: UInt32, originalBytes: Int, storedBytes: Int, zlib: Bool
    ) {
        guard data.count >= headerLength else { throw M10Error.corruptPayload }
        var cursor = 0
        let crc = readU32(data, &cursor)
        let originalBytes = try int(from: readU64(data, &cursor), limit: M10Format.maxStreamPayloadBytes)
        let storedBytes = try int(from: readU64(data, &cursor), limit: M10Format.maxStreamPayloadBytes)
        let flags = data[cursor]
        guard flags & ~innerFlagZlib == 0 else { throw M10Error.invalidFormat }
        return (crc, originalBytes, storedBytes, flags & innerFlagZlib != 0)
    }

    private static func appendU64(_ data: inout Data, _ value: UInt64) {
        var be = value.bigEndian
        data.append(Data(bytes: &be, count: 8))
    }

    private static func readU32(_ data: Data, _ cursor: inout Int) -> UInt32 {
        var value: UInt32 = 0
        for _ in 0..<4 {
            value = (value << 8) | UInt32(data[cursor])
            cursor += 1
        }
        return value
    }

    private static func readU64(_ data: Data, _ cursor: inout Int) -> UInt64 {
        var value: UInt64 = 0
        for _ in 0..<8 {
            value = (value << 8) | UInt64(data[cursor])
            cursor += 1
        }
        return value
    }
}

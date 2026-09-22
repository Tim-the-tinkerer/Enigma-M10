import Foundation

/// Dense base-36 / base-94 packing from EnigmaVault (17-byte blocks).
public enum DensePack {
    public static let blockBytes = 17

    public struct Info: Equatable, Sendable {
        public var originalBytes: Int
        public var storedBytes: Int
        public var codec: PayloadCodec

        public init(originalBytes: Int, storedBytes: Int, codec: PayloadCodec) {
            self.originalBytes = originalBytes
            self.storedBytes = storedBytes
            self.codec = codec
        }
    }

    public static func pack(_ data: Data, suite: M10CipherSuite, allowCompression: Bool = true) -> (symbols: String, info: Info) {
        let (wire, codec) = compressWire(data, allowCompression: allowCompression)
        let info = Info(originalBytes: data.count, storedBytes: wire.count, codec: codec)
        switch suite {
        case .alpha36:
            return (dense36Encode(wire), info)
        case .ascii:
            return (dense94Encode(wire), info)
        case .base256:
            return (Base256Symbols.latin1String(wire), info)
        case .base512:
            return (Base512Symbols.encode(wire), info)
        }
    }

    public static func unpack(_ symbols: String, info: Info, suite: M10CipherSuite) throws -> Data {
        let wire: Data?
        switch suite {
        case .alpha36:
            wire = dense36Decode(symbols, storedLength: info.storedBytes)
        case .ascii:
            wire = dense94Decode(symbols, storedLength: info.storedBytes)
        case .base256:
            if let bytes = Base256Symbols.latin1Data(symbols), bytes.count == info.storedBytes {
                wire = bytes
            } else {
                wire = nil
            }
        case .base512:
            wire = Base512Symbols.decode(symbols, storedLength: info.storedBytes)
        }
        guard let wire else { throw M10Error.corruptPayload }
        return try decompressWire(wire, info: info)
    }

    /// Pack a file to a UTF-8 symbol file without holding the full payload in RAM.
    public static func packFile(
        at url: URL,
        to symbolsURL: URL,
        suite: M10CipherSuite,
        allowCompression: Bool = true
    ) throws -> (info: Info, crc32: UInt32) {
        let originalBytes = try FileIO.byteCount(at: url)
        let crc = try CRC32.hashFile(at: url)
        if originalBytes == 0 {
            let handle = try FileIO.createEmptyFile(at: symbolsURL)
            try? handle.close()
            return (Info(originalBytes: 0, storedBytes: 0, codec: .none), crc)
        }

        var wireURL = url
        var wireIsTemp = false
        var codec: PayloadCodec = .none

        if allowCompression {
            let compressedURL = FileIO.temporaryURL("m10_zlib")
            do {
                try StreamZlib.compress(from: url, to: compressedURL)
                let compressedSize = try FileIO.byteCount(at: compressedURL)
                if compressedSize > 0, compressedSize < originalBytes {
                    wireURL = compressedURL
                    wireIsTemp = true
                    codec = .zlib
                } else {
                    try? FileManager.default.removeItem(at: compressedURL)
                }
            } catch {
                try? FileManager.default.removeItem(at: compressedURL)
                throw error
            }
        }
        defer {
            if wireIsTemp { try? FileManager.default.removeItem(at: wireURL) }
        }

        let storedBytes = try FileIO.byteCount(at: wireURL)
        try encodeFile(at: wireURL, to: symbolsURL, suite: suite)
        return (Info(originalBytes: originalBytes, storedBytes: storedBytes, codec: codec), crc)
    }

    public static func unpackFile(
        symbolsURL: URL,
        info: Info,
        suite: M10CipherSuite,
        to destination: URL
    ) throws {
        switch info.codec {
        case .none:
            try decodeFile(at: symbolsURL, storedLength: info.storedBytes, suite: suite, to: destination)
        case .zlib:
            let wireURL = FileIO.temporaryURL("m10_wire")
            defer { try? FileManager.default.removeItem(at: wireURL) }
            try decodeFile(at: symbolsURL, storedLength: info.storedBytes, suite: suite, to: wireURL)
            try StreamZlib.decompress(from: wireURL, to: destination, expectedSize: info.originalBytes)
        }
    }

    public static func encodeFile(at url: URL, to output: URL, suite: M10CipherSuite) throws {
        if suite == .base256 {
            if FileManager.default.fileExists(atPath: output.path) {
                try FileManager.default.removeItem(at: output)
            }
            try FileManager.default.copyItem(at: url, to: output)
            return
        }
        if suite == .base512 {
            try encodeFile512(at: url, to: output)
            return
        }
        let storedBytes = try FileIO.byteCount(at: url)
        let input = try FileHandle(forReadingFrom: url)
        defer { try? input.close() }
        let dest = try FileIO.createEmptyFile(at: output)
        defer { try? dest.close() }
        let symbolCount = suite == .alpha36
            ? Alpha36Symbols.denseBlockSymbols
            : Ascii94Symbols.denseBlockSymbols
        let radix = suite.alphabetSize
        let indexToChar: (Int) -> Character = suite == .alpha36
            ? Alpha36Symbols.indexToChar
            : Ascii94Symbols.indexToChar

        var remainder = Data()
        var writeBuf = Data()
        writeBuf.reserveCapacity(65_536)
        func flushSymbols(_ digits: [UInt8]) {
            for digit in digits {
                let ch = indexToChar(Int(digit))
                if let ascii = ch.asciiValue {
                    writeBuf.append(ascii)
                }
            }
            if writeBuf.count >= 65_536 {
                dest.write(writeBuf)
                writeBuf.removeAll(keepingCapacity: true)
            }
        }

        if storedBytes == 0 { return }

        while true {
            let chunk = try input.read(upToCount: FileIO.chunkBytes) ?? Data()
            if chunk.isEmpty { break }
            remainder.append(chunk)
            let fullBlocks = remainder.count / blockBytes
            let processBytes = fullBlocks * blockBytes
            if processBytes > 0 {
                for offset in stride(from: 0, to: processBytes, by: blockBytes) {
                    let block = [UInt8](remainder[offset..<(offset + blockBytes)])
                    flushSymbols(encodeBlock(block, radix: radix, symbolCount: symbolCount))
                }
                remainder = remainder.subdata(in: processBytes..<remainder.count)
            }
        }
        if !remainder.isEmpty {
            flushSymbols(encodeBlock([UInt8](remainder), radix: radix, symbolCount: symbolCount))
        }
        if !writeBuf.isEmpty { dest.write(writeBuf) }
    }

    public static func decodeFile(
        at url: URL,
        storedLength: Int,
        suite: M10CipherSuite,
        to destination: URL
    ) throws {
        guard storedLength >= 0, storedLength <= M10Format.maxStreamPayloadBytes else {
            throw M10Error.corruptPayload
        }
        let dest = try FileIO.createEmptyFile(at: destination)
        defer { try? dest.close() }
        if storedLength == 0 { return }
        if suite == .base256 {
            let input = try FileHandle(forReadingFrom: url)
            defer { try? input.close() }
            var remaining = storedLength
            while remaining > 0 {
                let chunk = try input.read(upToCount: min(FileIO.chunkBytes, remaining)) ?? Data()
                if chunk.isEmpty { throw M10Error.corruptPayload }
                dest.write(chunk)
                remaining -= chunk.count
            }
            return
        }
        if suite == .base512 {
            try decodeFile512(at: url, storedLength: storedLength, to: dest)
            return
        }

        let symbolCount = suite == .alpha36
            ? Alpha36Symbols.denseBlockSymbols
            : Ascii94Symbols.denseBlockSymbols
        let radix = suite.alphabetSize
        let indexOf: (Character) -> Int? = suite == .alpha36
            ? Alpha36Symbols.charToIndex
            : Ascii94Symbols.charToIndex
        let isValid: (Character) -> Bool = suite == .alpha36
            ? Alpha36Symbols.isValidSymbol
            : Ascii94Symbols.isValidSymbol

        let blocks = try blockCount(storedLength: storedLength)
        let expectedSymbols = try multiplied(blocks, symbolCount)
        let input = try FileHandle(forReadingFrom: url)
        defer { try? input.close() }

        var pending = Data()
        var written = 0
        var symbolsRead = 0
        while written < storedLength {
            if pending.count < symbolCount {
                let chunk = try input.read(upToCount: FileIO.chunkBytes) ?? Data()
                if chunk.isEmpty { break }
                pending.append(chunk)
            }
            var symbols: [Character] = []
            symbols.reserveCapacity(symbolCount)
            var consumed = 0
            for byte in pending {
                consumed += 1
                let character = Character(UnicodeScalar(byte))
                guard isValid(character) else { continue }
                symbols.append(character)
                if symbols.count == symbolCount { break }
            }
            pending = consumed < pending.count ? pending.subdata(in: consumed..<pending.count) : Data()
            guard symbols.count == symbolCount,
                  let buf = decodeBlock(symbols, indexOf: indexOf, radix: radix, symbolCount: symbolCount) else {
                throw M10Error.corruptPayload
            }
            let take = min(blockBytes, storedLength - written)
            dest.write(Data(buf[(blockBytes - take)..<blockBytes]))
            written += take
            symbolsRead += symbolCount
        }
        guard written == storedLength, symbolsRead == expectedSymbols else {
            throw M10Error.corruptPayload
        }
    }

    private static func encodeFile512(at url: URL, to output: URL) throws {
        let data = try Data(contentsOf: url, options: [.mappedIfSafe])
        let dest = try FileIO.createEmptyFile(at: output)
        defer { try? dest.close() }
        dest.write(Data(Base512Symbols.encode(data).utf8))
    }

    private static func decodeFile512(at url: URL, storedLength: Int, to dest: FileHandle) throws {
        let text = String(decoding: try Data(contentsOf: url, options: [.mappedIfSafe]), as: UTF8.self)
        guard let wire = Base512Symbols.decode(text, storedLength: storedLength) else {
            throw M10Error.corruptPayload
        }
        dest.write(wire)
    }

    // MARK: - Compression

    private static func compressWire(_ data: Data, allowCompression: Bool) -> (Data, PayloadCodec) {
        guard allowCompression, !data.isEmpty else { return (data, .none) }
        if let deflated = ZlibCodec.compress(data), deflated.count < data.count {
            return (deflated, .zlib)
        }
        return (data, .none)
    }

    private static func decompressWire(_ wire: Data, info: Info) throws -> Data {
        switch info.codec {
        case .none:
            return wire
        case .zlib:
            guard let original = ZlibCodec.decompress(wire, expectedSize: info.originalBytes) else {
                throw M10Error.corruptPayload
            }
            return original
        }
    }

    // MARK: - Dense-36 (17 bytes <-> 27 symbols)

    public static func dense36Encode(_ data: Data) -> String {
        let bytes = [UInt8](data)
        var chars: [Character] = []
        chars.reserveCapacity((bytes.count / blockBytes + 1) * Alpha36Symbols.denseBlockSymbols)
        var index = 0
        while index < bytes.count {
            let end = min(index + blockBytes, bytes.count)
            let digits = encodeBlock(Array(bytes[index..<end]), radix: 36, symbolCount: Alpha36Symbols.denseBlockSymbols)
            for digit in digits { chars.append(Alpha36Symbols.indexToChar(Int(digit))) }
            index = end
        }
        return String(chars)
    }

    public static func dense36Decode(_ symbols: String, storedLength: Int) -> Data? {
        let chars = Array(Alpha36Symbols.filteredSymbols(symbols))
        return decodeSymbols(
            chars,
            storedLength: storedLength,
            symbolCount: Alpha36Symbols.denseBlockSymbols,
            indexOf: Alpha36Symbols.charToIndex,
            radix: 36
        )
    }

    // MARK: - Dense-94 (17 bytes <-> 21 symbols)

    public static func dense94Encode(_ data: Data) -> String {
        let bytes = [UInt8](data)
        var chars: [Character] = []
        chars.reserveCapacity((bytes.count / blockBytes + 1) * Ascii94Symbols.denseBlockSymbols)
        var index = 0
        while index < bytes.count {
            let end = min(index + blockBytes, bytes.count)
            let digits = encodeBlock(Array(bytes[index..<end]), radix: 94, symbolCount: Ascii94Symbols.denseBlockSymbols)
            for digit in digits { chars.append(Ascii94Symbols.indexToChar(Int(digit))) }
            index = end
        }
        return String(chars)
    }

    public static func dense94Decode(_ symbols: String, storedLength: Int) -> Data? {
        let chars = Array(Ascii94Symbols.filteredSymbols(symbols))
        return decodeSymbols(
            chars,
            storedLength: storedLength,
            symbolCount: Ascii94Symbols.denseBlockSymbols,
            indexOf: Ascii94Symbols.charToIndex,
            radix: 94
        )
    }

    private static func encodeBlock(_ block: [UInt8], radix: Int, symbolCount: Int) -> [UInt8] {
        var buf = [UInt8](repeating: 0, count: blockBytes)
        let start = blockBytes - block.count
        for i in 0..<block.count { buf[start + i] = block[i] }

        var digits = [UInt8](repeating: 0, count: symbolCount)
        for d in stride(from: symbolCount - 1, through: 0, by: -1) {
            var rem = 0
            for i in 0..<blockBytes {
                let cur = rem * 256 + Int(buf[i])
                buf[i] = UInt8(cur / radix)
                rem = cur % radix
            }
            digits[d] = UInt8(rem)
        }
        return digits
    }

    private static func decodeSymbols(
        _ chars: [Character],
        storedLength: Int,
        symbolCount: Int,
        indexOf: (Character) -> Int?,
        radix: Int
    ) -> Data? {
        guard storedLength >= 0, storedLength <= M10Format.maxStreamPayloadBytes else { return nil }
        if storedLength == 0 { return chars.isEmpty ? Data() : nil }
        guard let blocks = try? blockCount(storedLength: storedLength),
              let expected = try? multiplied(blocks, symbolCount),
              chars.count == expected else {
            return nil
        }

        var output = Data(capacity: storedLength)
        for block in 0..<blocks {
            let start = block * symbolCount
            let slice = Array(chars[start..<(start + symbolCount)])
            guard let buf = decodeBlock(slice, indexOf: indexOf, radix: radix, symbolCount: symbolCount) else {
                return nil
            }
            let take = min(blockBytes, storedLength - output.count)
            output.append(contentsOf: buf[(blockBytes - take)..<blockBytes])
        }
        return output
    }

    static func blockCount(storedLength: Int) throws -> Int {
        guard storedLength >= 0, storedLength <= M10Format.maxStreamPayloadBytes else {
            throw M10Error.corruptPayload
        }
        if storedLength == 0 { return 0 }
        return (storedLength - 1) / blockBytes + 1
    }

    static func multiplied(_ a: Int, _ b: Int) throws -> Int {
        let (value, overflow) = a.multipliedReportingOverflow(by: b)
        guard !overflow, value >= 0 else { throw M10Error.corruptPayload }
        return value
    }

    private static func decodeBlock(
        _ symbols: [Character],
        indexOf: (Character) -> Int?,
        radix: Int,
        symbolCount: Int
    ) -> [UInt8]? {
        guard symbols.count == symbolCount else { return nil }
        var buf = [UInt8](repeating: 0, count: blockBytes)
        for ch in symbols {
            guard let value = indexOf(ch) else { return nil }
            var carry = value
            for i in stride(from: blockBytes - 1, through: 0, by: -1) {
                let cur = Int(buf[i]) * radix + carry
                buf[i] = UInt8(cur & 0xFF)
                carry = cur >> 8
            }
            if carry != 0 { return nil }
        }
        return buf
    }
}

public enum PayloadCodec: String, Codable, Equatable, Sendable {
    case none
    case zlib

    public var isCompressed: Bool { self != .none }

    public static func resolve(codecField: String?) throws -> PayloadCodec {
        if let codecField {
            guard let parsed = PayloadCodec(rawValue: codecField) else {
                throw M10Error.invalidFormat
            }
            return parsed
        }
        return .none
    }

    public var jsonField: String? {
        switch self {
        case .none: return nil
        case .zlib: return "zlib"
        }
    }
}

import Foundation
import CryptoKit

/// Opaque password-mode container. External-key archives stay JSON `ENIGMAM10`.
///
/// ```
/// M10PW03 | flags | argon2 | nonce | name | tag | ciphertext
/// ```
/// Ciphertext is Enigma(inner ‖ pad). `M10PW01` / `M10PW02` still decrypt.
public enum M10PasswordBinary {
    public static let magicV1 = Data("M10PW01".utf8)
    public static let magicV2 = Data("M10PW02".utf8)
    public static let magicV3 = Data("M10PW03".utf8)
    public static let magic = magicV3
    static let tagLength = 32
    static let nonceLength = 16

    private static let flagNameEncrypted: UInt8 = 1 << 0
    private static let flagZlib: UInt8 = 1 << 1
    private static let flagFolder: UInt8 = 1 << 2
    private static let flagPadShift: UInt8 = 5
    private static let pw03KnownFlags: UInt8 = flagNameEncrypted | flagFolder | (0b11 << 3)

    public struct Parsed: Sendable {
        public var archive: M10Format.Archive
        public var ciphertext: Data
        public var binaryOffset: UInt64
        public var header: Data
        public var tag: Data
    }

    public static func matches(_ data: Data) -> Bool {
        data.starts(with: magicV1) || data.starts(with: magicV2) || data.starts(with: magicV3)
    }

    public static func matches(at url: URL) -> Bool {
        guard let handle = try? FileHandle(forReadingFrom: url) else { return false }
        defer { try? handle.close() }
        let head = (try? handle.read(upToCount: magicV3.count)) ?? Data()
        return matches(head)
    }

    public static func encode(
        kind: M10Format.Kind,
        suite: M10CipherSuite,
        kdf: M10KDFParams,
        nonce: Data,
        originalBytes: Int,
        storedBytes: Int,
        zlib: Bool,
        crc32: UInt32,
        nameEncrypted: Bool,
        nameBytes: Data,
        ciphertext: Data,
        authKey: SymmetricKey,
        formatVersion: Int = M10Format.currentVersion,
        padBoundary: Int = 0
    ) throws -> Data {
        let header = try makeHeader(
            kind: kind,
            suite: suite,
            kdf: kdf,
            nonce: nonce,
            originalBytes: originalBytes,
            storedBytes: storedBytes,
            zlib: zlib,
            crc32: crc32,
            nameEncrypted: nameEncrypted,
            nameBytes: nameBytes,
            formatVersion: formatVersion,
            padBoundary: padBoundary
        )
        let tag = hmac(authKey: authKey, header: header, ciphertext: ciphertext)
        var out = header
        out.append(tag)
        out.append(ciphertext)
        return out
    }

    static func encodePrefix(
        kind: M10Format.Kind,
        suite: M10CipherSuite,
        kdf: M10KDFParams,
        nonce: Data,
        originalBytes: Int,
        storedBytes: Int,
        zlib: Bool,
        crc32: UInt32,
        nameEncrypted: Bool,
        nameBytes: Data,
        ciphertextURL: URL,
        authKey: SymmetricKey,
        formatVersion: Int = M10Format.currentVersion,
        padBoundary: Int = 0
    ) throws -> Data {
        let header = try makeHeader(
            kind: kind,
            suite: suite,
            kdf: kdf,
            nonce: nonce,
            originalBytes: originalBytes,
            storedBytes: storedBytes,
            zlib: zlib,
            crc32: crc32,
            nameEncrypted: nameEncrypted,
            nameBytes: nameBytes,
            formatVersion: formatVersion,
            padBoundary: padBoundary
        )
        var mac = HMAC<SHA256>(key: authKey)
        mac.update(data: Data("M10PW-aad-1".utf8))
        mac.update(data: header)
        mac.update(data: Data([0]))
        let input = try FileHandle(forReadingFrom: ciphertextURL)
        defer { try? input.close() }
        while true {
            let chunk = try input.read(upToCount: FileIO.chunkBytes) ?? Data()
            if chunk.isEmpty { break }
            mac.update(data: chunk)
        }
        var out = header
        out.append(Data(mac.finalize()))
        return out
    }

    public static func parse(_ data: Data) throws -> Parsed {
        let prefix = try parseThroughTag(data)
        let ciphertext = Data(data[Int(prefix.binaryOffset)...])
        var archive = prefix.archive
        archive.payloadLength = ciphertext.count
        return Parsed(
            archive: archive,
            ciphertext: ciphertext,
            binaryOffset: prefix.binaryOffset,
            header: prefix.header,
            tag: prefix.tag
        )
    }

    /// `archiveSize` is the full file length when `data` is only a prefix (readPrefix).
    static func parseThroughTag(
        _ data: Data,
        archiveSize: Int? = nil
    ) throws -> (archive: M10Format.Archive, header: Data, tag: Data, binaryOffset: UInt64) {
        guard data.count <= M10Format.maxStreamArchiveBytes else { throw M10Error.archiveTooLarge }
        if let archiveSize {
            guard archiveSize >= data.count, archiveSize <= M10Format.maxStreamArchiveBytes else {
                throw M10Error.invalidFormat
            }
        }
        var cursor = 0
        func need(_ n: Int) throws {
            guard cursor + n <= data.count else { throw M10Error.invalidFormat }
        }
        try need(magicV3.count)
        let magicSlice = data[cursor..<(cursor + magicV3.count)]
        let formatVersion: Int
        if magicSlice.elementsEqual(magicV3) {
            formatVersion = M10Format.sealedPaddingVersion
        } else if magicSlice.elementsEqual(magicV2) {
            formatVersion = M10Format.independentMachinesVersion
        } else if magicSlice.elementsEqual(magicV1) {
            formatVersion = M10Format.createdAtMacVersion
        } else {
            throw M10Error.invalidFormat
        }
        cursor += magicV3.count
        try need(1)
        let flags = data[cursor]
        cursor += 1
        if formatVersion >= M10Format.sealedPaddingVersion {
            guard flags & ~pw03KnownFlags == 0 else { throw M10Error.invalidFormat }
        }
        let suite = try suiteFromCode((flags >> 3) & 0b11)
        try need(4 + 4 + 1 + 1 + 1)
        let memoryKiB = readU32(data, &cursor)
        let iterations = readU32(data, &cursor)
        let parallelism = UInt32(data[cursor]); cursor += 1
        let hashLength = Int(data[cursor]); cursor += 1
        let saltLen = Int(data[cursor]); cursor += 1
        guard saltLen >= 8, saltLen <= 64 else { throw M10Error.kdfInvalid }
        try need(saltLen)
        let salt = data[cursor..<(cursor + saltLen)]
        cursor += saltLen
        try need(nonceLength)
        let nonce = data[cursor..<(cursor + nonceLength)]
        cursor += nonceLength

        var originalBytes = 0
        var storedBytes = 0
        var crc32: UInt32 = 0
        if formatVersion < M10Format.sealedPaddingVersion {
            try need(8 + 8 + 4)
            let originalRaw = readU64(data, &cursor)
            let storedRaw = readU64(data, &cursor)
            originalBytes = try M10SealedPayload.int(
                from: originalRaw, limit: M10Format.maxStreamPayloadBytes
            )
            storedBytes = try M10SealedPayload.int(
                from: storedRaw, limit: M10Format.maxStreamPayloadBytes
            )
            crc32 = readU32(data, &cursor)
        }

        try need(2)
        let nameLen = Int(readU16(data, &cursor))
        if formatVersion >= M10Format.sealedPaddingVersion {
            guard nameLen == M10Padding.expectedNameWireBytes(suite: suite) else {
                throw M10Error.invalidFormat
            }
        }
        try need(nameLen)
        let nameBytes = Data(data[cursor..<(cursor + nameLen)])
        cursor += nameLen
        let header = Data(data[0..<cursor])
        try need(tagLength)
        let tag = Data(data[cursor..<(cursor + tagLength)])
        cursor += tagLength
        let binaryOffset = UInt64(cursor)
        let ciphertextCount: Int
        if let archiveSize {
            guard archiveSize >= cursor else { throw M10Error.invalidFormat }
            ciphertextCount = archiveSize - cursor
        } else {
            ciphertextCount = data.count - cursor
        }
        guard ciphertextCount >= 0 else { throw M10Error.invalidFormat }

        let kdf = try M10KDFParams(
            alg: "argon2id",
            salt: M10MessageKey.hex(Data(salt)),
            memoryKiB: memoryKiB,
            iterations: iterations,
            parallelism: parallelism,
            hashLength: hashLength
        ).validated()
        var padBytes: Int? = nil
        var codec: String? = nil
        if formatVersion >= M10Format.sealedPaddingVersion {
            guard ciphertextCount > 0, ciphertextCount % M10Padding.smallBoundary == 0 else {
                throw M10Error.invalidFormat
            }
        } else {
            codec = flags & flagZlib != 0 ? "zlib" : nil
            if formatVersion >= M10Format.independentMachinesVersion {
                let padding = try M10Padding.fromFlag((flags >> flagPadShift) & 0b11)
                if padding != .none {
                    guard ciphertextCount >= storedBytes, ciphertextCount % padding.rawValue == 0 else {
                        throw M10Error.invalidFormat
                    }
                    let extra = ciphertextCount - storedBytes
                    guard extra > 0, extra <= padding.rawValue else { throw M10Error.invalidFormat }
                    padBytes = extra
                }
            }
        }
        let nameEncrypted = flags & flagNameEncrypted != 0
        let encryptedFilename: String?
        let originalFilename: String?
        if nameEncrypted {
            encryptedFilename = encodedFilename(nameBytes, suite: suite)
            originalFilename = nil
        } else if formatVersion >= M10Format.sealedPaddingVersion {
            encryptedFilename = nil
            originalFilename = encodedFilename(nameBytes, suite: suite)
        } else {
            guard let name = String(data: nameBytes, encoding: .utf8) else {
                throw M10Error.corruptFilename
            }
            encryptedFilename = nil
            originalFilename = name
        }
        let archive = M10Format.Archive(
            version: formatVersion,
            kind: flags & flagFolder != 0 ? .folder : .file,
            cipherSuite: suite,
            originalFilename: originalFilename,
            encryptedFilename: encryptedFilename,
            ciphertext: nil,
            createdAt: M10MessageKey.canonicalCreatedAt(),
            payloadOriginalBytes: originalBytes,
            payloadStoredBytes: storedBytes,
            payloadCodec: codec,
            crc32: crc32,
            payloadOffset: 0,
            payloadLength: ciphertextCount,
            messageNonce: M10MessageKey.hex(Data(nonce)),
            authTag: M10MessageKey.hex(tag),
            keyMode: M10KeyMode.password.rawValue,
            kdf: kdf,
            payloadPadBytes: padBytes
        )
        return (archive, header, tag, binaryOffset)
    }

    static func verify(_ parsed: Parsed, authKey: SymmetricKey) throws {
        let expected = hmac(authKey: authKey, header: parsed.header, ciphertext: parsed.ciphertext)
        guard M10Secure.equal(expected, parsed.tag) else { throw M10Error.wrongPassword }
    }

    static func verifyFile(
        at url: URL,
        parsedHeader: (archive: M10Format.Archive, header: Data, tag: Data, binaryOffset: UInt64),
        authKey: SymmetricKey
    ) throws {
        var hmac = HMAC<SHA256>(key: authKey)
        hmac.update(data: Data("M10PW-aad-1".utf8))
        hmac.update(data: parsedHeader.header)
        hmac.update(data: Data([0]))
        let input = try FileHandle(forReadingFrom: url)
        defer { try? input.close() }
        try input.seek(toOffset: parsedHeader.binaryOffset)
        while true {
            let chunk = try input.read(upToCount: FileIO.chunkBytes) ?? Data()
            if chunk.isEmpty { break }
            hmac.update(data: chunk)
        }
        guard M10Secure.equal(Data(hmac.finalize()), parsedHeader.tag) else { throw M10Error.wrongPassword }
    }

    /// Reads through the auth tag; ciphertext stays on disk.
    public static func readPrefix(at url: URL) throws -> (archive: M10Format.Archive, header: Data, tag: Data, binaryOffset: UInt64) {
        let size = try FileIO.byteCount(at: url)
        guard size <= M10Format.maxStreamArchiveBytes else { throw M10Error.archiveTooLarge }
        let handle = try FileHandle(forReadingFrom: url)
        defer { try? handle.close() }
        let cap = min(size, 1_048_576)
        let prefix = try handle.read(upToCount: cap) ?? Data()
        return try parseThroughTag(prefix, archiveSize: size)
    }

    static func encodedFilename(_ raw: Data, suite: M10CipherSuite) -> String {
        switch suite {
        case .base256:
            return Base256Symbols.encodeFilenameCiphertext(raw)
        case .alpha36, .ascii:
            return String(decoding: raw, as: UTF8.self)
        }
    }

    static func filenameBytes(field: String, suite: M10CipherSuite, original: String?) -> (Data, Bool) {
        if let original {
            return (Data(original.utf8), false)
        }
        switch suite {
        case .base256:
            return (Base256Symbols.decodeFilenameCiphertext(field) ?? Data(), true)
        case .alpha36, .ascii:
            return (Data(field.utf8), true)
        }
    }

    static func opaqueBasename(nonce: Data) -> String {
        let hex = M10MessageKey.hex(nonce).prefix(M10Format.maxDiskBasenameLetters)
        return "\(hex).\(M10Format.fileExtension)"
    }

    private static func makeHeader(
        kind: M10Format.Kind,
        suite: M10CipherSuite,
        kdf: M10KDFParams,
        nonce: Data,
        originalBytes: Int,
        storedBytes: Int,
        zlib: Bool,
        crc32: UInt32,
        nameEncrypted: Bool,
        nameBytes: Data,
        formatVersion: Int,
        padBoundary: Int
    ) throws -> Data {
        let kdf = try kdf.validated()
        guard let salt = kdf.saltData, nonce.count == nonceLength else { throw M10Error.kdfInvalid }
        guard nameBytes.count <= Int(UInt16.max) else { throw M10Error.invalidFormat }

        var header = Data()
        header.append(magic(for: formatVersion))
        var flags: UInt8 = suiteCode(suite) << 3
        if nameEncrypted { flags |= flagNameEncrypted }
        if kind == .folder { flags |= flagFolder }
        if formatVersion < M10Format.sealedPaddingVersion {
            if zlib { flags |= flagZlib }
            if formatVersion >= M10Format.independentMachinesVersion {
                flags |= padFlag(padBoundary) << flagPadShift
            }
        }
        header.append(flags)
        appendU32(&header, kdf.memoryKiB)
        appendU32(&header, kdf.iterations)
        header.append(UInt8(kdf.parallelism))
        header.append(UInt8(kdf.hashLength))
        header.append(UInt8(salt.count))
        header.append(salt)
        header.append(nonce)
        if formatVersion < M10Format.sealedPaddingVersion {
            appendU64(&header, UInt64(originalBytes))
            appendU64(&header, UInt64(storedBytes))
            appendU32(&header, crc32)
        }
        appendU16(&header, UInt16(nameBytes.count))
        header.append(nameBytes)
        return header
    }

    private static func hmac(authKey: SymmetricKey, header: Data, ciphertext: Data) -> Data {
        var hmac = HMAC<SHA256>(key: authKey)
        hmac.update(data: Data("M10PW-aad-1".utf8))
        hmac.update(data: header)
        hmac.update(data: Data([0]))
        hmac.update(data: ciphertext)
        return Data(hmac.finalize())
    }

    private static func magic(for formatVersion: Int) -> Data {
        if formatVersion >= M10Format.sealedPaddingVersion { return magicV3 }
        if formatVersion >= M10Format.independentMachinesVersion { return magicV2 }
        return magicV1
    }

    private static func padFlag(_ boundary: Int) -> UInt8 {
        M10Padding(rawValue: boundary)?.flagCode ?? 0
    }

    private static func suiteCode(_ suite: M10CipherSuite) -> UInt8 {
        switch suite {
        case .alpha36: return 0
        case .ascii: return 1
        case .base256: return 2
        }
    }

    private static func suiteFromCode(_ code: UInt8) throws -> M10CipherSuite {
        switch code {
        case 0: return .alpha36
        case 1: return .ascii
        case 2: return .base256
        default: throw M10Error.invalidFormat
        }
    }

    private static func appendU16(_ data: inout Data, _ value: UInt16) {
        var be = value.bigEndian
        data.append(Data(bytes: &be, count: 2))
    }

    private static func appendU32(_ data: inout Data, _ value: UInt32) {
        var be = value.bigEndian
        data.append(Data(bytes: &be, count: 4))
    }

    private static func appendU64(_ data: inout Data, _ value: UInt64) {
        var be = value.bigEndian
        data.append(Data(bytes: &be, count: 8))
    }

    private static func readU16(_ data: Data, _ cursor: inout Int) -> UInt16 {
        let hi = UInt16(data[cursor])
        let lo = UInt16(data[cursor + 1])
        cursor += 2
        return (hi << 8) | lo
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

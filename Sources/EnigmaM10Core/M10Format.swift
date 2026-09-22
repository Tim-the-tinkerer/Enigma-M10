import Foundation

/// `.enigmam10` archive for Enigma – M 10.
///
/// Password and External Key modes do not embed machine settings. Internal Key
/// mode stores its catalog codebook in the archive.
///
/// External-key / internal-key JSON:
/// ```
/// ENIGMAM10 v7
/// { compact JSON; Internal Key includes a codebook object }
/// ```
/// Password mode writes opaque `M10PW04` binary (`M10PW01`–`M10PW03` still decrypt).
/// v1: legacy import. v2: required nonce/HMAC, parked-notch stepping.
/// v3: carry-only stepping, unbiased positions, encrypt-then-MAC.
/// v4: v3 HMAC also binds createdAt.
/// v5: leftover decrypt (`M10PW02` public sizes + optional pad flags).
/// v6: automatic 4 KiB/64 KiB padding; original/stored/CRC live inside the ciphertext.
/// v7: Base-512 uses ~20 notches/rotor (~1/26 turnover). v6 Base-512 keeps 1–2 notches.
public enum M10Format {
    public static let fileExtension = "enigmam10"
    public static let codebookExtension = "m10key"
    public static let magic = "ENIGMAM10"
    public static let legacyVersion = 1
    public static let authenticatedVersion = 2
    public static let carrySteppingVersion = 3
    public static let createdAtMacVersion = 4
    public static let independentMachinesVersion = 5
    public static let sealedPaddingVersion = 6
    public static let scaledNotchesVersion = 7
    public static let currentVersion = 7
    public static let maxPayloadBytes = 256 * 1024 * 1024
    public static let maxArchiveBytes = 512 * 1024 * 1024
    /// Files at or above this size use the disk pipeline and hybrid binary payload.
    public static let streamThresholdBytes = 1_048_576
    public static let maxStreamPayloadBytes = 2 * 1024 * 1024 * 1024
    public static let maxStreamArchiveBytes = 16 * 1024 * 1024 * 1024
    /// APFS name limit is 255 UTF-8 bytes, including `.enigmam10`.
    public static let maxDiskNameBytes = 255
    public static let maxDiskBasenameLetters = maxDiskNameBytes - 1 - fileExtension.count

    public enum Kind: String, Codable, Sendable {
        case file
        case folder
    }

    public struct Archive: Codable, Equatable, Sendable {
        public var version: Int
        public var kind: Kind
        public var cipherSuite: M10CipherSuite
        public var originalFilename: String?
        public var encryptedFilename: String?
        public var ciphertext: String?
        public var createdAt: Date
        public var payloadOriginalBytes: Int
        public var payloadStoredBytes: Int
        public var payloadCodec: String?
        public var crc32: UInt32
        /// Offset into the binary region after the JSON newline (hybrid layout).
        public var payloadOffset: Int? = nil
        /// Length of the binary ciphertext region (hybrid layout).
        public var payloadLength: Int? = nil
        /// Random per-archive nonce. Not a codebook field; used to derive start positions.
        public var messageNonce: String? = nil
        /// HMAC-SHA256 of interpretation fields + filename + payload. Required on v2+.
        public var authTag: String? = nil
        /// `password`, `external`, or `internal`. Omitted on pre-password archives (treated as external).
        public var keyMode: String? = nil
        /// Argon2id parameters + salt. Present only for password mode. No rotors.
        public var kdf: M10KDFParams? = nil
        /// Catalog codebook stored in the archive. Only for `keyMode == internal`.
        public var codebook: M10Configuration? = nil
        /// Random bytes after the real ciphertext (v5+). HMAC covers the pad.
        public var payloadPadBytes: Int? = nil

        public var requiresAuthentication: Bool {
            version >= M10Format.authenticatedVersion
        }

        public var isHybrid: Bool {
            payloadLength != nil
        }

        public init(
            version: Int,
            kind: Kind,
            cipherSuite: M10CipherSuite,
            originalFilename: String? = nil,
            encryptedFilename: String? = nil,
            ciphertext: String? = nil,
            createdAt: Date,
            payloadOriginalBytes: Int,
            payloadStoredBytes: Int,
            payloadCodec: String? = nil,
            crc32: UInt32,
            payloadOffset: Int? = nil,
            payloadLength: Int? = nil,
            messageNonce: String? = nil,
            authTag: String? = nil,
            keyMode: String? = nil,
            kdf: M10KDFParams? = nil,
            codebook: M10Configuration? = nil,
            payloadPadBytes: Int? = nil
        ) {
            self.version = version
            self.kind = kind
            self.cipherSuite = cipherSuite
            self.originalFilename = originalFilename
            self.encryptedFilename = encryptedFilename
            self.ciphertext = ciphertext
            self.createdAt = createdAt
            self.payloadOriginalBytes = payloadOriginalBytes
            self.payloadStoredBytes = payloadStoredBytes
            self.payloadCodec = payloadCodec
            self.crc32 = crc32
            self.payloadOffset = payloadOffset
            self.payloadLength = payloadLength
            self.messageNonce = messageNonce
            self.authTag = authTag
            self.keyMode = keyMode
            self.kdf = kdf
            self.codebook = codebook
            self.payloadPadBytes = payloadPadBytes
        }

        enum CodingKeys: String, CodingKey {
            case version
            case kind
            case cipherSuite
            case originalFilename
            case encryptedFilename
            case ciphertext
            case createdAt
            case payloadOriginalBytes
            case payloadStoredBytes
            case payloadCodec
            case crc32
            case payloadOffset
            case payloadLength
            case messageNonce
            case authTag
            case keyMode
            case kdf
            case codebook
            case payloadPadBytes
        }
    }

    public struct Header: Sendable {
        public var archive: Archive
        public var binaryOffset: UInt64
    }

    public struct EncryptResult: Sendable {
        public var data: Data
        public var suggestedFilename: String
        public var writtenFile: URL? = nil
    }

    public static func isArchive(at url: URL) -> Bool {
        guard let handle = try? FileHandle(forReadingFrom: url) else { return false }
        defer { try? handle.close() }
        let head = (try? handle.read(upToCount: 16)) ?? Data()
        if M10PasswordBinary.matches(head) { return true }
        guard let text = String(data: head, encoding: .utf8) else { return false }
        return text.hasPrefix("\(magic) v")
    }

    public static func isCodebook(at url: URL) -> Bool {
        url.pathExtension.lowercased() == codebookExtension
    }

    public static func encodeArchive(_ archive: Archive) throws -> Data {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        encoder.dateEncodingStrategy = .iso8601
        let json = try encoder.encode(archive)
        guard let body = String(data: json, encoding: .utf8) else {
            throw M10Error.invalidFormat
        }
        guard !jsonObjectContainsMachineSettings(body) else {
            throw M10Error.invalidFormat
        }
        let text = "\(magic) v\(archive.version)\n\(body)"
        guard let data = text.data(using: .utf8) else { throw M10Error.invalidFormat }
        return data
    }

    public static func decodeArchive(_ data: Data) throws -> Archive {
        try parseLayout(data).archive
    }

    public static func parseLayout(_ data: Data) throws -> Header {
        if M10PasswordBinary.matches(data) {
            let parsed = try M10PasswordBinary.parse(data)
            return Header(archive: parsed.archive, binaryOffset: parsed.binaryOffset)
        }
        guard data.count <= maxStreamArchiveBytes else { throw M10Error.archiveTooLarge }
        var start = 0
        if data.starts(with: [0xEF, 0xBB, 0xBF]) { start = 3 }
        guard start < data.count else { throw M10Error.invalidFormat }
        guard let firstNewline = data[start...].firstIndex(of: UInt8(ascii: "\n")) else {
            throw M10Error.invalidFormat
        }
        let headerLine = String(decoding: data[start..<firstNewline], as: UTF8.self)
            .trimmingCharacters(in: .whitespacesAndNewlines)
        let version = try parseHeaderLine(headerLine)

        let jsonStart = data.index(after: firstNewline)
        guard jsonStart < data.endIndex else { throw M10Error.invalidFormat }
        let jsonEnd: Data.Index
        let binaryOffset: UInt64
        if let secondNewline = data[jsonStart...].firstIndex(of: UInt8(ascii: "\n")) {
            jsonEnd = secondNewline
            binaryOffset = UInt64(data.distance(from: data.startIndex, to: secondNewline) + 1)
        } else {
            jsonEnd = data.endIndex
            binaryOffset = UInt64(data.count)
        }
        let json = Data(data[jsonStart..<jsonEnd])
        let archive = try decodeJSON(json, headerVersion: version)
        let binaryBytes = data.count - Int(binaryOffset)
        try validateSealedCiphertext(archive, binaryBytes: archive.isHybrid ? binaryBytes : nil)
        return Header(archive: archive, binaryOffset: binaryOffset)
    }

    public static func readHeader(at url: URL) throws -> Header {
        if M10PasswordBinary.matches(at: url) {
            let prefix = try M10PasswordBinary.readPrefix(at: url)
            return Header(archive: prefix.archive, binaryOffset: prefix.binaryOffset)
        }
        let size = try FileIO.byteCount(at: url)
        guard size <= maxStreamArchiveBytes else { throw M10Error.archiveTooLarge }
        let handle = try FileHandle(forReadingFrom: url)
        defer { try? handle.close() }
        guard let headerLine = try readLine(from: handle) else { throw M10Error.invalidFormat }
        let version = try parseHeaderLine(headerLine)
        guard let jsonLine = try readLine(from: handle) else { throw M10Error.invalidFormat }
        guard let json = jsonLine.data(using: .utf8) else { throw M10Error.invalidFormat }
        let archive = try decodeJSON(json, headerVersion: version)
        let binaryOffset = handle.offsetInFile
        let binaryBytes = size - Int(binaryOffset)
        try validateSealedCiphertext(archive, binaryBytes: archive.isHybrid ? binaryBytes : nil)
        return Header(archive: archive, binaryOffset: binaryOffset)
    }

    public static func encodeHybridHeader(_ archive: Archive) throws -> Data {
        var copy = archive
        copy.ciphertext = nil
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        encoder.dateEncodingStrategy = .iso8601
        let json = try encoder.encode(copy)
        guard let body = String(data: json, encoding: .utf8) else {
            throw M10Error.invalidFormat
        }
        guard !jsonObjectContainsMachineSettings(body) else {
            throw M10Error.invalidFormat
        }
        let text = "\(magic) v\(copy.version)\n\(body)\n"
        guard let data = text.data(using: .utf8) else { throw M10Error.invalidFormat }
        return data
    }

    static func validateSealedCiphertext(_ archive: Archive, binaryBytes: Int?) throws {
        guard archive.version >= sealedPaddingVersion else { return }
        if archive.isHybrid {
            let length = archive.payloadLength ?? 0
            guard length > 0, length % M10Padding.smallBoundary == 0 else {
                throw M10Error.invalidFormat
            }
            if let binaryBytes {
                guard binaryBytes == length else { throw M10Error.invalidFormat }
            }
        } else {
            let count = archive.ciphertext?.count ?? 0
            guard count > 0, count % M10Padding.smallBoundary == 0 else {
                throw M10Error.invalidFormat
            }
        }
    }

    private static func parseHeaderLine(_ line: String) throws -> Int {
        let header = line.trimmingCharacters(in: .whitespacesAndNewlines)
        guard header.hasPrefix("\(magic) v") else { throw M10Error.invalidFormat }
        let versionString = String(header.dropFirst("\(magic) v".count))
        guard let version = Int(versionString) else { throw M10Error.invalidFormat }
        return version
    }

    private static func decodeJSON(_ json: Data, headerVersion: Int) throws -> Archive {
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        let archive = try decoder.decode(Archive.self, from: json)
        guard archive.version == headerVersion else { throw M10Error.invalidFormat }
        guard archive.version >= legacyVersion, archive.version <= currentVersion else {
            throw M10Error.unsupportedVersion(archive.version)
        }
        try validateStoredCodebook(archive)
        return archive
    }

    private static func validateStoredCodebook(_ archive: Archive) throws {
        if archive.keyMode == M10KeyMode.internalKey.rawValue {
            guard let codebook = archive.codebook else { throw M10Error.invalidFormat }
            let validated = try codebook.validated()
            guard validated.cipherSuite == archive.cipherSuite else { throw M10Error.invalidFormat }
            return
        }
        if archive.codebook != nil {
            throw M10Error.invalidFormat
        }
    }

    private static func readLine(from handle: FileHandle) throws -> String? {
        var data = Data()
        while true {
            guard let byte = try handle.read(upToCount: 1), !byte.isEmpty else {
                return data.isEmpty ? nil : String(data: data, encoding: .utf8)
            }
            if byte[0] == 0x0A { break }
            data.append(byte)
            if data.count > 1_048_576 { throw M10Error.invalidFormat }
        }
        return String(data: data, encoding: .utf8)
    }

    public static func suggestedArchiveFilename(encryptedSymbols: String, suite: M10CipherSuite) -> String {
        let stem: String
        switch suite {
        case .alpha36:
            let compact = encryptedSymbols
                .filter { Alpha36Symbols.isValidSymbol($0) }
                .uppercased()
            stem = compact.isEmpty ? "ENCRYPTED" : compact
        case .ascii:
            stem = asciiStem(encryptedSymbols)
        case .base256:
            let hexBody: String
            if let data = Base256Symbols.decodeFilenameCiphertext(encryptedSymbols) {
                hexBody = Base256Symbols.hex(data)
            } else {
                hexBody = Base256Symbols.hex(Base256Symbols.latin1Data(encryptedSymbols) ?? Data())
            }
            stem = hexBody.isEmpty ? "ENCRYPTED" : hexBody
        case .base512:
            let compact = encryptedSymbols.filter { Base512Symbols.isValidSymbol($0) }
            stem = compact.isEmpty ? "ENCRYPTED" : compact
        }
        return fitDiskFilename(stem)
    }

    public static func suggestedPlaintextArchiveFilename(_ filename: String) -> String {
        let sanitized = sanitizedFilename(filename)
        let basename = sanitized.isEmpty ? "file" : sanitized
        return fitDiskFilename(basename)
    }

    /// Trim complete characters so `stem.enigmam10` fits in 255 UTF-8 bytes.
    public static func fitDiskFilename(_ stem: String) -> String {
        let suffix = ".\(fileExtension)"
        let budget = maxDiskNameBytes - suffix.utf8.count
        guard budget > 0 else { return "ENCRYPTED.\(fileExtension)" }
        if stem.utf8.count <= budget {
            return stem.isEmpty ? "ENCRYPTED.\(fileExtension)" : stem + suffix
        }
        var result = ""
        result.reserveCapacity(budget)
        for character in stem {
            let next = result + String(character)
            if next.utf8.count > budget { break }
            result = next
        }
        return (result.isEmpty ? "ENCRYPTED" : result) + suffix
    }

    public static func sanitizedFilename(_ name: String) -> String {
        let trimmed = name.trimmingCharacters(in: .whitespacesAndNewlines)
        let last = (trimmed as NSString).lastPathComponent
        return last.replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: ":", with: "_")
            .replacingOccurrences(of: "\0", with: "")
    }

    private static let windowsUnsafe = CharacterSet(charactersIn: #"\/:*?"<>|"#)
    private static let windowsReserved: Set<String> = [
        "CON", "PRN", "AUX", "NUL",
        "COM0", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9",
        "LPT0", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9"
    ]

    private static func asciiStem(_ encrypted: String) -> String {
        let compact = encrypted.filter { Ascii94Symbols.isValidSymbol($0) }
        let safe = compact.unicodeScalars.map { scalar -> Character in
            windowsUnsafe.contains(scalar) ? "_" : Character(scalar)
        }
        var basename = safe.isEmpty ? "ENCRYPTED" : String(safe)
        if windowsReserved.contains(basename.uppercased()) {
            basename = "_" + basename
        }
        return basename
    }

    /// True when a JSON object (not ciphertext string values) has a machine-settings key.
    private static func jsonObjectContainsMachineSettings(_ json: String) -> Bool {
        guard let data = json.data(using: .utf8),
              let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            return true
        }
        let forbidden: Set<String> = [
            "configuration", "rotorNames", "plugPairs", "rings", "positions", "reflector"
        ]
        return !forbidden.isDisjoint(with: Set(object.keys))
    }

    public static let unauthenticatedOutputPrefix = "UNAUTHENTICATED-"

    public static func unauthenticatedOutputName(_ filename: String) -> String {
        if filename.hasPrefix(unauthenticatedOutputPrefix) { return filename }
        return unauthenticatedOutputPrefix + filename
    }

    public static func uniqueURL(in directory: URL, preferredName: String) -> URL {
        var url = directory.appendingPathComponent(preferredName)
        if !FileManager.default.fileExists(atPath: url.path) { return url }
        let ns = preferredName as NSString
        let ext = ns.pathExtension
        let stem = ns.deletingPathExtension
        for i in 2...9999 {
            let candidate = ext.isEmpty ? "\(stem) \(i)" : "\(stem) \(i).\(ext)"
            url = directory.appendingPathComponent(candidate)
            if !FileManager.default.fileExists(atPath: url.path) { return url }
        }
        return directory.appendingPathComponent("\(stem)-\(UUID().uuidString).\(ext)")
    }
}

public enum M10Codebook {
    public static func encode(_ configuration: M10Configuration) throws -> Data {
        let validated = try configuration.validated()
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        return try encoder.encode(validated)
    }

    public static func decode(_ data: Data) throws -> M10Configuration {
        let decoder = JSONDecoder()
        return try decoder.decode(M10Configuration.self, from: data).validated()
    }
}

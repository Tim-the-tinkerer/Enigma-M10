import Foundation
import CryptoKit
import Security

/// Per-archive message key. The daily codebook (rotors, rings, plugs, reflector,
/// and the codebook’s own start positions) stays out of the `.enigmam10` file.
/// A random nonce in the archive derives distinct start positions for the
/// filename and the payload so the two no longer share machine state, and so
/// encrypting the same file twice does not produce the same ciphertext.
public enum M10MessageKey {
    public enum Domain: String {
        case filename
        case payload
    }

    public static let nonceLength = 16

    public static func randomBytes(_ count: Int) throws -> Data {
        guard count > 0 else { return Data() }
        var bytes = [UInt8](repeating: 0, count: count)
        let status = SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes)
        guard status == errSecSuccess else { throw M10Error.randomGenerationFailed }
        return Data(bytes)
    }

    public static func randomNonce() throws -> Data {
        try randomBytes(nonceLength)
    }

    public static func canonicalCreatedAt(_ date: Date = Date()) -> Date {
        Date(timeIntervalSince1970: date.timeIntervalSince1970.rounded(.towardZero))
    }

    public static func hmacCreatedAtString(_ date: Date) -> String {
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime]
        return formatter.string(from: date)
    }

    public static func hex(_ data: Data) -> String {
        data.map { String(format: "%02x", $0) }.joined()
    }

    public static func parseHex(_ string: String?) -> Data? {
        guard let string, !string.isEmpty else { return nil }
        let compact = string.trimmingCharacters(in: .whitespacesAndNewlines)
        guard compact.count % 2 == 0, compact.count >= nonceLength * 2 else { return nil }
        var data = Data()
        data.reserveCapacity(compact.count / 2)
        var index = compact.startIndex
        while index < compact.endIndex {
            let next = compact.index(index, offsetBy: 2)
            guard let byte = UInt8(compact[index..<next], radix: 16) else { return nil }
            data.append(byte)
            index = next
        }
        return data
    }

    /// Copy of `base` whose start positions are derived from the nonce.
    /// `nonce == nil` keeps the codebook positions (legacy archives).
    public static func apply(
        _ base: M10Configuration,
        nonce: Data?,
        domain: Domain,
        unbiasedPositions: Bool = false
    ) throws -> M10Configuration {
        var copy = try base.validated()
        guard let nonce, !nonce.isEmpty else { return copy }
        copy.positions = derivedPositions(
            base: copy, nonce: nonce, domain: domain, unbiased: unbiasedPositions
        )
        return copy
    }

    public static func derivedPositions(
        base: M10Configuration,
        nonce: Data,
        domain: Domain,
        unbiased: Bool = false
    ) -> String {
        var material = Data("EnigmaM10-pos-v1".utf8)
        material.append(Data(base.codebookLine.utf8))
        material.append(nonce)
        material.append(Data(domain.rawValue.utf8))
        let digest = SHA256.hash(data: material)
        let size = base.cipherSuite.alphabetSize
        if unbiased, size != 256 {
            var rng = HMACDRBG(seed: SymmetricKey(data: Data(digest)))
            let indices = (0..<M10Catalog.rotorCount).map { _ in rng.uniform(size) }
            return M10Configuration.formatField(indices, suite: base.cipherSuite)
        }
        let bytes = Array(digest)
        if base.cipherSuite == .base256 {
            return Base256Symbols.formatField((0..<M10Catalog.rotorCount).map { index in
                Int(bytes[index])
            })
        }
        let alphabet = Array(base.cipherSuite.alphabet)
        return String((0..<M10Catalog.rotorCount).map { index in
            alphabet[Int(bytes[index]) % alphabet.count]
        })
    }

    /// Canonical fields that decide how an archive is interpreted, plus the
    /// recovered filename. Bound into the v2 HMAC with the payload.
    public struct Transcript: Sendable {
        public var version: Int
        public var kind: M10Format.Kind
        public var cipherSuite: M10CipherSuite
        public var filename: String
        public var filenameEncrypted: Bool
        public var payloadOriginalBytes: Int
        public var payloadStoredBytes: Int
        public var payloadCodec: String
        public var payloadOffset: Int
        public var payloadLength: Int
        public var nonce: Data
        public var crc32: UInt32

        public init(archive: M10Format.Archive, filename: String, nonce: Data) {
            version = archive.version
            kind = archive.kind
            cipherSuite = archive.cipherSuite
            self.filename = filename
            filenameEncrypted = archive.encryptedFilename != nil
            payloadOriginalBytes = archive.payloadOriginalBytes
            payloadStoredBytes = archive.payloadStoredBytes
            payloadCodec = archive.payloadCodec ?? "none"
            payloadOffset = archive.payloadOffset ?? -1
            payloadLength = archive.payloadLength ?? -1
            self.nonce = nonce
            crc32 = archive.crc32
        }
    }

    public static func ciphertextAuthTag(
        configuration: M10Configuration,
        archive: M10Format.Archive,
        ciphertext: Data,
        authKey: SymmetricKey? = nil
    ) throws -> String {
        guard let nonce = try nonce(from: archive) else { throw M10Error.authenticationFailed }
        let key = authKey ?? hmacKey("EnigmaM10-auth-v3", configuration: configuration, nonce: nonce)
        var hmac = HMAC<SHA256>(key: key)
        appendCiphertextTranscript(&hmac, archive: archive, nonce: nonce)
        hmac.update(data: ciphertext)
        return hex(Data(hmac.finalize()))
    }

    public static func ciphertextAuthTagFile(
        configuration: M10Configuration,
        archive: M10Format.Archive,
        ciphertextURL: URL,
        authKey: SymmetricKey? = nil
    ) throws -> String {
        guard let nonce = try nonce(from: archive) else { throw M10Error.authenticationFailed }
        let key = authKey ?? hmacKey("EnigmaM10-auth-v3", configuration: configuration, nonce: nonce)
        var hmac = HMAC<SHA256>(key: key)
        appendCiphertextTranscript(&hmac, archive: archive, nonce: nonce)
        try appendFile(&hmac, ciphertextURL)
        return hex(Data(hmac.finalize()))
    }

    public static func verifyCiphertext(
        archive: M10Format.Archive,
        configuration: M10Configuration,
        ciphertext: Data,
        authKey: SymmetricKey? = nil
    ) throws {
        guard archive.version >= M10Format.carrySteppingVersion else { return }
        guard let tag = archive.authTag, !tag.isEmpty else { throw M10Error.authenticationFailed }
        let expected = try ciphertextAuthTag(
            configuration: configuration, archive: archive, ciphertext: ciphertext, authKey: authKey
        )
        guard M10Secure.equalHex(expected, tag) else {
            throw authKey == nil ? M10Error.authenticationFailed : M10Error.wrongPassword
        }
    }

    public static func verifyCiphertextRegion(
        archive: M10Format.Archive,
        configuration: M10Configuration,
        file: URL,
        offset: UInt64,
        length: Int,
        authKey: SymmetricKey? = nil
    ) throws {
        guard archive.version >= M10Format.carrySteppingVersion else { return }
        guard let nonce = try nonce(from: archive) else { throw M10Error.authenticationFailed }
        guard let tag = archive.authTag, !tag.isEmpty else { throw M10Error.authenticationFailed }
        let key = authKey ?? hmacKey("EnigmaM10-auth-v3", configuration: configuration, nonce: nonce)
        var hmac = HMAC<SHA256>(key: key)
        appendCiphertextTranscript(&hmac, archive: archive, nonce: nonce)
        let input = try FileHandle(forReadingFrom: file)
        defer { try? input.close() }
        try input.seek(toOffset: offset)
        var remaining = length
        while remaining > 0 {
            let chunk = try input.read(upToCount: min(FileIO.chunkBytes, remaining)) ?? Data()
            if chunk.isEmpty { throw M10Error.authenticationFailed }
            hmac.update(data: chunk)
            remaining -= chunk.count
        }
        let expected = hex(Data(hmac.finalize()))
        guard M10Secure.equalHex(expected, tag) else {
            throw authKey == nil ? M10Error.authenticationFailed : M10Error.wrongPassword
        }
    }

    public static func verifyCiphertextFile(
        archive: M10Format.Archive,
        configuration: M10Configuration,
        ciphertextURL: URL,
        authKey: SymmetricKey? = nil
    ) throws {
        guard archive.version >= M10Format.carrySteppingVersion else { return }
        guard let tag = archive.authTag, !tag.isEmpty else { throw M10Error.authenticationFailed }
        let expected = try ciphertextAuthTagFile(
            configuration: configuration, archive: archive, ciphertextURL: ciphertextURL, authKey: authKey
        )
        guard M10Secure.equalHex(expected, tag) else {
            throw authKey == nil ? M10Error.authenticationFailed : M10Error.wrongPassword
        }
    }

    public static func nonce(from archive: M10Format.Archive) throws -> Data? {
        if archive.requiresAuthentication {
            guard let nonce = parseHex(archive.messageNonce), nonce.count == nonceLength else {
                throw M10Error.authenticationFailed
            }
            return nonce
        }
        return parseHex(archive.messageNonce)
    }

    public static func authTag(
        configuration: M10Configuration,
        transcript: Transcript,
        payload: Data,
        authKey: SymmetricKey? = nil
    ) -> String {
        hex(hmacV2(configuration: configuration, transcript: transcript, payload: payload, authKey: authKey))
    }

    public static func authTagFile(
        configuration: M10Configuration,
        transcript: Transcript,
        payloadURL: URL,
        authKey: SymmetricKey? = nil
    ) throws -> String {
        hex(try hmacV2File(configuration: configuration, transcript: transcript, payloadURL: payloadURL, authKey: authKey))
    }

    public static func verify(
        archive: M10Format.Archive,
        configuration: M10Configuration,
        filename: String,
        payload: Data,
        authKey: SymmetricKey? = nil
    ) throws {
        let nonce = try nonce(from: archive)
        if archive.requiresAuthentication {
            guard let nonce, let tag = archive.authTag, !tag.isEmpty else {
                throw M10Error.authenticationFailed
            }
            let transcript = Transcript(archive: archive, filename: filename, nonce: nonce)
            let expected = authTag(
                configuration: configuration, transcript: transcript, payload: payload, authKey: authKey
            )
            guard M10Secure.equalHex(expected, tag) else {
                throw authKey == nil ? M10Error.authenticationFailed : M10Error.wrongPassword
            }
            return
        }
        // v1: tag is optional. If present, check the original filename+payload MAC
        // so archives written before v2 still verify.
        guard let tag = archive.authTag, !tag.isEmpty else { return }
        guard let nonce else { throw M10Error.authenticationFailed }
        let expected = hex(hmacV1(configuration: configuration, nonce: nonce, filename: filename, payload: payload))
        guard M10Secure.equalHex(expected, tag) else { throw M10Error.authenticationFailed }
    }

    public static func verifyFile(
        archive: M10Format.Archive,
        configuration: M10Configuration,
        filename: String,
        payloadURL: URL,
        authKey: SymmetricKey? = nil
    ) throws {
        let nonce = try nonce(from: archive)
        if archive.requiresAuthentication {
            guard let nonce, let tag = archive.authTag, !tag.isEmpty else {
                throw M10Error.authenticationFailed
            }
            let transcript = Transcript(archive: archive, filename: filename, nonce: nonce)
            let expected = try authTagFile(
                configuration: configuration,
                transcript: transcript,
                payloadURL: payloadURL,
                authKey: authKey
            )
            guard M10Secure.equalHex(expected, tag) else {
                throw authKey == nil ? M10Error.authenticationFailed : M10Error.wrongPassword
            }
            return
        }
        guard let tag = archive.authTag, !tag.isEmpty else { return }
        guard let nonce else { throw M10Error.authenticationFailed }
        let expected = hex(
            try hmacV1File(
                configuration: configuration,
                nonce: nonce,
                filename: filename,
                payloadURL: payloadURL
            )
        )
        guard M10Secure.equalHex(expected, tag) else { throw M10Error.authenticationFailed }
    }

    private static func hmacKey(_ label: String, configuration: M10Configuration, nonce: Data) -> SymmetricKey {
        var material = Data(label.utf8)
        material.append(Data(configuration.codebookLine.utf8))
        material.append(nonce)
        let digest = SHA256.hash(data: material)
        return SymmetricKey(data: digest)
    }

    private static func hmacV1(
        configuration: M10Configuration,
        nonce: Data,
        filename: String,
        payload: Data
    ) -> Data {
        let key = hmacKey("EnigmaM10-auth-v1", configuration: configuration, nonce: nonce)
        var hmac = HMAC<SHA256>(key: key)
        hmac.update(data: Data(filename.utf8))
        hmac.update(data: Data([0]))
        hmac.update(data: payload)
        return Data(hmac.finalize())
    }

    private static func hmacV1File(
        configuration: M10Configuration,
        nonce: Data,
        filename: String,
        payloadURL: URL
    ) throws -> Data {
        let key = hmacKey("EnigmaM10-auth-v1", configuration: configuration, nonce: nonce)
        var hmac = HMAC<SHA256>(key: key)
        hmac.update(data: Data(filename.utf8))
        hmac.update(data: Data([0]))
        try appendFile(&hmac, payloadURL)
        return Data(hmac.finalize())
    }

    private static func hmacV2(
        configuration: M10Configuration,
        transcript: Transcript,
        payload: Data,
        authKey: SymmetricKey? = nil
    ) -> Data {
        let key = authKey ?? hmacKey("EnigmaM10-auth-v2", configuration: configuration, nonce: transcript.nonce)
        var hmac = HMAC<SHA256>(key: key)
        appendTranscript(&hmac, transcript)
        hmac.update(data: payload)
        return Data(hmac.finalize())
    }

    private static func hmacV2File(
        configuration: M10Configuration,
        transcript: Transcript,
        payloadURL: URL,
        authKey: SymmetricKey? = nil
    ) throws -> Data {
        let key = authKey ?? hmacKey("EnigmaM10-auth-v2", configuration: configuration, nonce: transcript.nonce)
        var hmac = HMAC<SHA256>(key: key)
        appendTranscript(&hmac, transcript)
        try appendFile(&hmac, payloadURL)
        return Data(hmac.finalize())
    }

    private static func appendCiphertextTranscript(
        _ hmac: inout HMAC<SHA256>,
        archive: M10Format.Archive,
        nonce: Data
    ) {
        appendString(&hmac, "EnigmaM10-aad-v3")
        appendString(&hmac, "\(archive.version)")
        appendString(&hmac, archive.kind.rawValue)
        appendString(&hmac, archive.cipherSuite.rawValue)
        appendString(&hmac, archive.encryptedFilename != nil ? "1" : "0")
        appendString(&hmac, archive.encryptedFilename ?? "")
        appendString(&hmac, archive.originalFilename ?? "")
        appendString(&hmac, "\(archive.payloadOriginalBytes)")
        appendString(&hmac, "\(archive.payloadStoredBytes)")
        appendString(&hmac, archive.payloadCodec ?? "none")
        appendString(&hmac, "\(archive.payloadOffset ?? -1)")
        appendString(&hmac, "\(archive.payloadLength ?? -1)")
        appendString(&hmac, hex(nonce))
        appendString(&hmac, "\(archive.crc32)")
        if archive.version >= M10Format.createdAtMacVersion {
            appendString(&hmac, hmacCreatedAtString(archive.createdAt))
        }
        if archive.version >= M10Format.independentMachinesVersion {
            appendString(&hmac, "\(archive.payloadPadBytes ?? 0)")
        }
        appendString(&hmac, archive.keyMode ?? "")
        if let codebook = archive.codebook {
            appendString(&hmac, codebook.codebookLine)
        }
        if let kdf = archive.kdf {
            appendString(&hmac, kdf.alg)
            appendString(&hmac, kdf.salt)
            appendString(&hmac, "\(kdf.memoryKiB)")
            appendString(&hmac, "\(kdf.iterations)")
            appendString(&hmac, "\(kdf.parallelism)")
            appendString(&hmac, "\(kdf.hashLength)")
        } else {
            appendString(&hmac, "-")
        }
        hmac.update(data: Data([0]))
    }

    /// Length-prefixed fields so names and integers cannot be confused.
    private static func appendTranscript(_ hmac: inout HMAC<SHA256>, _ transcript: Transcript) {
        appendString(&hmac, "EnigmaM10-aad-v2")
        appendString(&hmac, "\(transcript.version)")
        appendString(&hmac, transcript.kind.rawValue)
        appendString(&hmac, transcript.cipherSuite.rawValue)
        appendString(&hmac, transcript.filenameEncrypted ? "1" : "0")
        appendString(&hmac, transcript.filename)
        appendString(&hmac, "\(transcript.payloadOriginalBytes)")
        appendString(&hmac, "\(transcript.payloadStoredBytes)")
        appendString(&hmac, transcript.payloadCodec)
        appendString(&hmac, "\(transcript.payloadOffset)")
        appendString(&hmac, "\(transcript.payloadLength)")
        appendString(&hmac, hex(transcript.nonce))
        appendString(&hmac, "\(transcript.crc32)")
        hmac.update(data: Data([0]))
    }

    private static func appendString(_ hmac: inout HMAC<SHA256>, _ value: String) {
        let data = Data(value.utf8)
        var length = UInt64(data.count).bigEndian
        withUnsafeBytes(of: &length) { hmac.update(data: Data($0)) }
        hmac.update(data: data)
    }

    private static func appendFile(_ hmac: inout HMAC<SHA256>, _ url: URL) throws {
        let input = try FileHandle(forReadingFrom: url)
        defer { try? input.close() }
        while true {
            let chunk = try input.read(upToCount: FileIO.chunkBytes) ?? Data()
            if chunk.isEmpty { break }
            hmac.update(data: chunk)
        }
    }
}

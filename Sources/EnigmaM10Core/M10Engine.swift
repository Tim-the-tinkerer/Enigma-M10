import Foundation
import CryptoKit

public enum M10DecryptMode: Sendable {
    /// Normal open: authenticated v2 only. v1 is rejected so a downgrade cannot skip HMAC.
    case authenticated
    /// Explicit recovery of v1. Output is marked unauthenticated; kind and other fields are not trusted.
    case legacyImport
}

public enum M10Engine {
    public struct DecryptResult: Sendable {
        public var payload: Data
        public var filename: String
        public var kind: M10Format.Kind
        public var cipherSuite: M10CipherSuite
        public var payloadFile: URL? = nil
        public var isLegacyImport: Bool = false
    }

    public static func encrypt(
        data: Data,
        originalFilename: String,
        configuration: M10Configuration,
        encryptFilename: Bool = true,
        kind: M10Format.Kind = .file,
        password: String? = nil,
        kdf: M10KDFParams? = nil,
        formatVersion: Int = M10Format.currentVersion,
        keyMode: M10KeyMode = .external,
        forceScaledNotches: Bool? = nil
    ) throws -> M10Format.EncryptResult {
        guard data.count <= M10Format.maxPayloadBytes else { throw M10Error.payloadTooLarge }
        let keying = try materializeKey(
            configuration: configuration,
            password: password,
            kdf: kdf,
            keyMode: keyMode,
            scaledNotches: forceScaledNotches ?? (formatVersion >= M10Format.scaledNotchesVersion)
        )
        let validated = keying.config
        let stepping = M10Stepping.forArchiveVersion(formatVersion)
        let unbiased = formatVersion >= M10Format.carrySteppingVersion
        let nonce = try M10MessageKey.randomNonce()
        let nameMachine = try M10Machine(
            configuration: M10MessageKey.apply(
                validated, nonce: nonce, domain: .filename, unbiasedPositions: unbiased
            ),
            stepping: stepping
        )
        let bodyMachine = try M10Machine(
            configuration: M10MessageKey.apply(
                validated, nonce: nonce, domain: .payload, unbiasedPositions: unbiased
            ),
            stepping: stepping
        )
        let sanitized = M10Format.sanitizedFilename(originalFilename)
        let named = try sealName(
            sanitized,
            encrypt: encryptFilename,
            machine: nameMachine,
            suite: validated.cipherSuite,
            formatVersion: formatVersion
        )
        let originalFilenameField = named.original
        let encryptedFilenameField = named.encrypted
        let diskBasename = named.diskBasename

        let (packed, info) = DensePack.pack(data, suite: validated.cipherSuite)
        let crc = CRC32.hash(data)
        let sealed = formatVersion >= M10Format.sealedPaddingVersion
        let useHybridBytes = validated.cipherSuite == .base256
        let ciphertext: String?
        let encryptedBytes: Data
        if useHybridBytes {
            ciphertext = nil
            let wire = Base256Symbols.latin1Data(packed) ?? Data()
            let input = sealed
                ? (try M10SealedPayload.wrapBytes(crc: crc, info: info, packed: wire))
                : wire
            encryptedBytes = input.isEmpty ? Data() : bodyMachine.processBytes(input)
        } else {
            encryptedBytes = Data()
            let input = sealed
                ? (try M10SealedPayload.wrapSymbols(
                    crc: crc, info: info, packed: packed, suite: validated.cipherSuite
                ))
                : packed
            ciphertext = input.isEmpty ? "" : bodyMachine.processMessageInChunks(input)
        }
        var archive = M10Format.Archive(
            version: formatVersion,
            kind: kind,
            cipherSuite: validated.cipherSuite,
            originalFilename: originalFilenameField,
            encryptedFilename: encryptedFilenameField,
            ciphertext: ciphertext,
            createdAt: M10MessageKey.canonicalCreatedAt(),
            payloadOriginalBytes: sealed ? 0 : info.originalBytes,
            payloadStoredBytes: sealed ? 0 : info.storedBytes,
            payloadCodec: sealed ? nil : info.codec.jsonField,
            crc32: sealed ? 0 : crc,
            payloadOffset: useHybridBytes ? 0 : nil,
            payloadLength: useHybridBytes ? encryptedBytes.count : nil,
            messageNonce: M10MessageKey.hex(nonce),
            keyMode: keying.keyMode,
            kdf: keying.kdf,
            codebook: storedCodebook(mode: keying.keyMode, configuration: validated)
        )
        let transcript = M10MessageKey.Transcript(
            archive: archive, filename: sanitized, nonce: nonce
        )
        if formatVersion >= M10Format.carrySteppingVersion {
            let wire = useHybridBytes ? encryptedBytes : Data((ciphertext ?? "").utf8)
            archive.authTag = try M10MessageKey.ciphertextAuthTag(
                configuration: validated, archive: archive, ciphertext: wire, authKey: keying.authKey
            )
        } else {
            archive.authTag = M10MessageKey.authTag(
                configuration: validated, transcript: transcript, payload: data, authKey: keying.authKey
            )
        }

        if let kdf = keying.kdf, let authKey = keying.authKey {
            let cipherData = useHybridBytes ? encryptedBytes : Data((ciphertext ?? "").utf8)
            let blob = try M10PasswordBinary.encode(
                kind: kind,
                suite: validated.cipherSuite,
                kdf: kdf,
                nonce: nonce,
                originalBytes: info.originalBytes,
                storedBytes: info.storedBytes,
                zlib: info.codec == .zlib,
                crc32: crc,
                nameEncrypted: named.nameEncrypted,
                nameBytes: named.nameBytes,
                ciphertext: cipherData,
                authKey: authKey,
                formatVersion: formatVersion
            )
            return M10Format.EncryptResult(
                data: blob,
                suggestedFilename: M10PasswordBinary.opaqueBasename(nonce: nonce)
            )
        }

        let bytes: Data
        if useHybridBytes {
            bytes = try M10Format.encodeHybridHeader(archive) + encryptedBytes
        } else {
            bytes = try M10Format.encodeArchive(archive)
        }
        let suggested: String
        if encryptFilename {
            suggested = M10Format.suggestedArchiveFilename(
                encryptedSymbols: diskBasename,
                suite: validated.cipherSuite
            )
        } else {
            suggested = M10Format.suggestedPlaintextArchiveFilename(diskBasename)
        }
        return M10Format.EncryptResult(data: bytes, suggestedFilename: suggested)
    }

    public static func encryptFile(
        at url: URL,
        configuration: M10Configuration,
        encryptFilename: Bool = true,
        password: String? = nil,
        kdf: M10KDFParams? = nil,
        keyMode: M10KeyMode = .external
    ) throws -> M10Format.EncryptResult {
        let size = try FileIO.byteCount(at: url)
        if size >= M10Format.streamThresholdBytes {
            return try encryptStreaming(
                from: url,
                originalFilename: url.lastPathComponent,
                configuration: configuration,
                encryptFilename: encryptFilename,
                kind: .file,
                password: password,
                kdf: kdf,
                keyMode: keyMode
            )
        }
        guard size <= M10Format.maxPayloadBytes else { throw M10Error.payloadTooLarge }
        let data = try Data(contentsOf: url, options: [.mappedIfSafe])
        return try encrypt(
            data: data,
            originalFilename: url.lastPathComponent,
            configuration: configuration,
            encryptFilename: encryptFilename,
            kind: .file,
            password: password,
            kdf: kdf,
            keyMode: keyMode
        )
    }

    public static func encryptFolder(
        at url: URL,
        configuration: M10Configuration,
        encryptFilename: Bool = true,
        password: String? = nil,
        kdf: M10KDFParams? = nil,
        keyMode: M10KeyMode = .external
    ) throws -> M10Format.EncryptResult {
        let zipURL = try DirectoryBundle.packToFile(url)
        defer { try? FileManager.default.removeItem(at: zipURL) }
        let size = try FileIO.byteCount(at: zipURL)
        if size >= M10Format.streamThresholdBytes {
            return try encryptStreaming(
                from: zipURL,
                originalFilename: url.lastPathComponent,
                configuration: configuration,
                encryptFilename: encryptFilename,
                kind: .folder,
                password: password,
                kdf: kdf,
                keyMode: keyMode
            )
        }
        guard size <= M10Format.maxPayloadBytes else { throw M10Error.payloadTooLarge }
        let zipData = try Data(contentsOf: zipURL)
        return try encrypt(
            data: zipData,
            originalFilename: url.lastPathComponent,
            configuration: configuration,
            encryptFilename: encryptFilename,
            kind: .folder,
            password: password,
            kdf: kdf,
            keyMode: keyMode
        )
    }

    public static func encryptStreaming(
        from url: URL,
        originalFilename: String,
        configuration: M10Configuration,
        encryptFilename: Bool = true,
        kind: M10Format.Kind = .file,
        password: String? = nil,
        kdf: M10KDFParams? = nil,
        keyMode: M10KeyMode = .external
    ) throws -> M10Format.EncryptResult {
        let size = try FileIO.byteCount(at: url)
        guard size <= M10Format.maxStreamPayloadBytes else { throw M10Error.payloadTooLarge }
        let formatVersion = M10Format.currentVersion
        let keying = try materializeKey(
            configuration: configuration,
            password: password,
            kdf: kdf,
            keyMode: keyMode,
            scaledNotches: formatVersion >= M10Format.scaledNotchesVersion
        )
        let validated = keying.config
        let stepping = M10Stepping.forArchiveVersion(formatVersion)
        let unbiased = formatVersion >= M10Format.carrySteppingVersion
        let nonce = try M10MessageKey.randomNonce()
        let nameMachine = try M10Machine(
            configuration: M10MessageKey.apply(
                validated, nonce: nonce, domain: .filename, unbiasedPositions: unbiased
            ),
            stepping: stepping
        )
        let bodyMachine = try M10Machine(
            configuration: M10MessageKey.apply(
                validated, nonce: nonce, domain: .payload, unbiasedPositions: unbiased
            ),
            stepping: stepping
        )
        let sanitized = M10Format.sanitizedFilename(originalFilename)
        let named = try sealName(
            sanitized,
            encrypt: encryptFilename,
            machine: nameMachine,
            suite: validated.cipherSuite,
            formatVersion: formatVersion
        )
        let originalFilenameField = named.original
        let encryptedFilenameField = named.encrypted
        let diskBasename = named.diskBasename

        let symbolsURL = FileIO.temporaryURL("m10_sym")
        defer { try? FileManager.default.removeItem(at: symbolsURL) }
        let (info, crc) = try DensePack.packFile(
            at: url,
            to: symbolsURL,
            suite: validated.cipherSuite
        )
        let sealed = formatVersion >= M10Format.sealedPaddingVersion
        let rotorInputURL: URL
        if sealed {
            let wrapped = FileIO.temporaryURL("m10_inner")
            try M10SealedPayload.wrapFile(
                packedURL: symbolsURL,
                crc: crc,
                info: info,
                suite: validated.cipherSuite,
                to: wrapped
            )
            try? FileManager.default.removeItem(at: symbolsURL)
            rotorInputURL = wrapped
        } else {
            rotorInputURL = symbolsURL
        }
        defer {
            if sealed { try? FileManager.default.removeItem(at: rotorInputURL) }
        }
        let payloadLength = try FileIO.byteCount(at: rotorInputURL)
        var archive = M10Format.Archive(
            version: formatVersion,
            kind: kind,
            cipherSuite: validated.cipherSuite,
            originalFilename: originalFilenameField,
            encryptedFilename: encryptedFilenameField,
            ciphertext: nil,
            createdAt: M10MessageKey.canonicalCreatedAt(),
            payloadOriginalBytes: sealed ? 0 : info.originalBytes,
            payloadStoredBytes: sealed ? 0 : info.storedBytes,
            payloadCodec: sealed ? nil : info.codec.jsonField,
            crc32: sealed ? 0 : crc,
            payloadOffset: 0,
            payloadLength: payloadLength,
            messageNonce: M10MessageKey.hex(nonce),
            keyMode: keying.keyMode,
            kdf: keying.kdf,
            codebook: storedCodebook(mode: keying.keyMode, configuration: validated)
        )
        let cipherURL = FileIO.temporaryURL("m10_ct")
        defer { try? FileManager.default.removeItem(at: cipherURL) }
        let cipherHandle = try FileIO.createEmptyFile(at: cipherURL)
        if payloadLength > 0 {
            try bodyMachine.processMessageFromSymbolFile(at: rotorInputURL, to: cipherHandle)
        }
        try cipherHandle.close()
        archive.authTag = try M10MessageKey.ciphertextAuthTagFile(
            configuration: validated,
            archive: archive,
            ciphertextURL: cipherURL,
            authKey: keying.authKey
        )

        let suggested: String
        if encryptFilename {
            suggested = M10Format.suggestedArchiveFilename(
                encryptedSymbols: diskBasename,
                suite: validated.cipherSuite
            )
        } else {
            suggested = M10Format.suggestedPlaintextArchiveFilename(diskBasename)
        }

        let dest = FileIO.temporaryURL("m10_out").appendingPathExtension(M10Format.fileExtension)
        let output = try FileIO.createEmptyFile(at: dest)
        defer { try? output.close() }
        if let kdf = keying.kdf, let authKey = keying.authKey {
            let prefix = try M10PasswordBinary.encodePrefix(
                kind: kind,
                suite: validated.cipherSuite,
                kdf: kdf,
                nonce: nonce,
                originalBytes: info.originalBytes,
                storedBytes: info.storedBytes,
                zlib: info.codec == .zlib,
                crc32: crc,
                nameEncrypted: named.nameEncrypted,
                nameBytes: named.nameBytes,
                ciphertextURL: cipherURL,
                authKey: authKey,
                formatVersion: formatVersion
            )
            output.write(prefix)
            let cipherIn = try FileHandle(forReadingFrom: cipherURL)
            defer { try? cipherIn.close() }
            while true {
                let chunk = try cipherIn.read(upToCount: FileIO.chunkBytes) ?? Data()
                if chunk.isEmpty { break }
                output.write(chunk)
            }
            return M10Format.EncryptResult(
                data: Data(),
                suggestedFilename: M10PasswordBinary.opaqueBasename(nonce: nonce),
                writtenFile: dest
            )
        }
        output.write(try M10Format.encodeHybridHeader(archive))
        if payloadLength > 0 {
            let cipherIn = try FileHandle(forReadingFrom: cipherURL)
            defer { try? cipherIn.close() }
            while true {
                let chunk = try cipherIn.read(upToCount: FileIO.chunkBytes) ?? Data()
                if chunk.isEmpty { break }
                output.write(chunk)
            }
        }
        return M10Format.EncryptResult(data: Data(), suggestedFilename: suggested, writtenFile: dest)
    }

    public static func decrypt(
        data: Data,
        configuration: M10Configuration,
        mode: M10DecryptMode = .authenticated,
        password: String? = nil
    ) throws -> DecryptResult {
        if M10PasswordBinary.matches(data) {
            return try decryptPasswordBlob(data, configuration: configuration, password: password, mode: mode)
        }
        let layout = try M10Format.parseLayout(data)
        let archive = layout.archive
        try enforceDecryptMode(mode, archive: archive)
        return try withNotchProfiles(archive: archive, configuration: configuration, password: password) { config, authKey in
            if archive.version >= M10Format.carrySteppingVersion {
                let ciphertext: Data
                if archive.isHybrid {
                    ciphertext = try hybridSlice(data, layout: layout, archive: archive)
                } else {
                    ciphertext = Data((archive.ciphertext ?? "").utf8)
                }
                try M10MessageKey.verifyCiphertext(
                    archive: archive,
                    configuration: config,
                    ciphertext: ciphertext,
                    authKey: authKey
                )
            }
            if archive.isHybrid {
                let binary = try hybridSlice(data, layout: layout, archive: archive)
                if archive.cipherSuite == .base256 {
                    return try decryptHybridBytes(
                        archive: archive,
                        ciphertext: binary,
                        configuration: config,
                        isLegacyImport: mode == .legacyImport,
                        authKey: authKey
                    )
                }
                return try decryptHybrid(
                    archive: archive,
                    ciphertextSymbols: String(decoding: binary, as: UTF8.self),
                    configuration: config,
                    isLegacyImport: mode == .legacyImport,
                    authKey: authKey
                )
            }
            return try decryptInline(
                archive: archive,
                configuration: config,
                isLegacyImport: mode == .legacyImport,
                authKey: authKey
            )
        }
    }

    public static func decryptFile(
        at url: URL,
        configuration: M10Configuration,
        mode: M10DecryptMode = .authenticated,
        password: String? = nil
    ) throws -> DecryptResult {
        if M10PasswordBinary.matches(at: url) {
            return try decryptPasswordFile(at: url, configuration: configuration, password: password, mode: mode)
        }
        let header = try M10Format.readHeader(at: url)
        try enforceDecryptMode(mode, archive: header.archive)
        return try withNotchProfiles(archive: header.archive, configuration: configuration, password: password) { config, authKey in
        if header.archive.version >= M10Format.carrySteppingVersion, header.archive.isHybrid {
            let extra = header.archive.payloadOffset ?? 0
            let length = header.archive.payloadLength ?? 0
            try M10MessageKey.verifyCiphertextRegion(
                archive: header.archive,
                configuration: config,
                file: url,
                offset: header.binaryOffset + UInt64(extra),
                length: length,
                authKey: authKey
            )
        } else if header.archive.version >= M10Format.carrySteppingVersion {
            try M10MessageKey.verifyCiphertext(
                archive: header.archive,
                configuration: config,
                ciphertext: Data((header.archive.ciphertext ?? "").utf8),
                authKey: authKey
            )
        }
        if header.archive.isHybrid {
            return try decryptHybridFile(
                at: url,
                header: header,
                configuration: config,
                isLegacyImport: mode == .legacyImport,
                authKey: authKey
            )
        }
        return try decryptInline(
            archive: header.archive,
            configuration: config,
            isLegacyImport: mode == .legacyImport,
            authKey: authKey
        )
        }
    }

    private static func enforceDecryptMode(_ mode: M10DecryptMode, archive: M10Format.Archive) throws {
        switch mode {
        case .authenticated:
            guard archive.requiresAuthentication else {
                throw M10Error.legacyArchiveRequiresImport
            }
        case .legacyImport:
            guard !archive.requiresAuthentication else {
                throw M10Error.notALegacyArchive
            }
        }
    }

    public static func writeDecryptResult(
        _ result: DecryptResult,
        nextTo source: URL
    ) throws -> URL {
        let parent = source.deletingLastPathComponent()
        let outputName = result.isLegacyImport
            ? M10Format.unauthenticatedOutputName(result.filename)
            : result.filename
        if result.kind == .folder {
            let dest = M10Format.uniqueURL(in: parent, preferredName: outputName)
            if let payloadFile = result.payloadFile {
                try DirectoryBundle.unpackFile(payloadFile, to: dest)
                try? FileManager.default.removeItem(at: payloadFile)
            } else {
                try DirectoryBundle.unpack(result.payload, to: dest)
            }
            return dest
        }
        let dest = M10Format.uniqueURL(in: parent, preferredName: outputName)
        if let payloadFile = result.payloadFile {
            if FileManager.default.fileExists(atPath: dest.path) {
                throw M10Error.fileAlreadyExists(dest.path)
            }
            try FileManager.default.moveItem(at: payloadFile, to: dest)
            return dest
        }
        try result.payload.write(to: dest, options: .withoutOverwriting)
        return dest
    }

    public static func writeEncryptResult(
        _ result: M10Format.EncryptResult,
        nextTo source: URL,
        configuration: M10Configuration? = nil
    ) throws -> URL {
        let dest = M10Format.uniqueURL(
            in: source.deletingLastPathComponent(),
            preferredName: result.suggestedFilename
        )
        if let writtenFile = result.writtenFile {
            if FileManager.default.fileExists(atPath: dest.path) {
                throw M10Error.fileAlreadyExists(dest.path)
            }
            try FileManager.default.moveItem(at: writtenFile, to: dest)
        } else {
            try result.data.write(to: dest, options: .withoutOverwriting)
        }
        if let configuration {
            try writeSidecarCodebook(forArchive: dest, configuration: configuration)
        }
        return dest
    }

    public static func sidecarURL(forArchive archive: URL) -> URL {
        let directory = archive.deletingLastPathComponent()
        let stem = archive.deletingPathExtension().lastPathComponent
        return directory.appendingPathComponent(stem).appendingPathExtension(M10Format.codebookExtension)
    }

    public static func writeSidecarCodebook(
        forArchive archive: URL,
        configuration: M10Configuration
    ) throws {
        let url = sidecarURL(forArchive: archive)
        let data = try M10Codebook.encode(configuration)
        do {
            try data.write(to: url, options: .atomic)
        } catch {
            // Cloud/NAS volumes often reject atomic replace; write in place.
            try data.write(to: url, options: [])
        }
        guard FileManager.default.fileExists(atPath: url.path) else {
            throw M10Error.unreadableFile(url.lastPathComponent)
        }
    }

    public static func loadSidecarCodebook(forArchive archive: URL) throws -> M10Configuration? {
        let url = sidecarURL(forArchive: archive)
        guard FileManager.default.fileExists(atPath: url.path) else { return nil }
        return try M10Codebook.decode(Data(contentsOf: url))
    }

    private static func decryptPasswordBlob(
        _ data: Data,
        configuration: M10Configuration,
        password: String?,
        mode: M10DecryptMode
    ) throws -> DecryptResult {
        let parsed = try M10PasswordBinary.parse(data)
        try enforceDecryptMode(mode, archive: parsed.archive)
        return try withNotchProfiles(archive: parsed.archive, configuration: configuration, password: password) { config, authKey in
            guard let authKey else { throw M10Error.passwordRequired }
            try M10PasswordBinary.verify(parsed, authKey: authKey)
            if parsed.archive.cipherSuite == .base256 {
                return try decryptHybridBytes(
                    archive: parsed.archive,
                    ciphertext: parsed.ciphertext,
                    configuration: config,
                    isLegacyImport: false,
                    authKey: authKey
                )
            }
            return try decryptHybrid(
                archive: parsed.archive,
                ciphertextSymbols: String(decoding: parsed.ciphertext, as: UTF8.self),
                configuration: config,
                isLegacyImport: false,
                authKey: authKey
            )
        }
    }

    private static func decryptPasswordFile(
        at url: URL,
        configuration: M10Configuration,
        password: String?,
        mode: M10DecryptMode
    ) throws -> DecryptResult {
        let prefix = try M10PasswordBinary.readPrefix(at: url)
        try enforceDecryptMode(mode, archive: prefix.archive)
        return try withNotchProfiles(archive: prefix.archive, configuration: configuration, password: password) { config, authKey in
            guard let authKey else { throw M10Error.passwordRequired }
            try M10PasswordBinary.verifyFile(at: url, parsedHeader: prefix, authKey: authKey)
            let header = M10Format.Header(archive: prefix.archive, binaryOffset: prefix.binaryOffset)
            return try decryptHybridFile(
                at: url,
                header: header,
                configuration: config,
                isLegacyImport: false,
                authKey: authKey
            )
        }
    }

    private static func materializeKey(
        configuration: M10Configuration,
        password: String?,
        kdf: M10KDFParams? = nil,
        keyMode: M10KeyMode = .external,
        scaledNotches: Bool = true
    ) throws -> (config: M10Configuration, authKey: SymmetricKey?, kdf: M10KDFParams?, keyMode: String) {
        if let password {
            guard !password.isEmpty else { throw M10Error.passwordRequired }
            let params = try kdf ?? M10KDFParams.freshSalt()
            let derived = try M10Password.deriveConfiguration(
                password: password,
                suite: configuration.cipherSuite,
                params: params,
                scaledNotches: scaledNotches
            )
            return (
                try derived.configuration.validated(),
                M10Password.authKey(master: derived.master),
                params,
                M10KeyMode.password.rawValue
            )
        }
        if keyMode == .password { throw M10Error.passwordRequired }
        var validated = try configuration.validated()
        validated.scaledNotches = scaledNotches
        return (validated, nil, nil, keyMode.rawValue)
    }

    private static func storedCodebook(mode: String, configuration: M10Configuration) -> M10Configuration? {
        guard mode == M10KeyMode.internalKey.rawValue else { return nil }
        var copy = configuration
        copy.derivedMachine = nil
        return copy
    }

    private static func decryptMachines(
        configuration: M10Configuration,
        nonce: Data?,
        archive: M10Format.Archive
    ) throws -> (name: M10Machine, body: M10Machine) {
        let stepping = M10Stepping.forArchiveVersion(archive.version)
        let unbiased = archive.version >= M10Format.carrySteppingVersion
        let name = try M10Machine(
            configuration: M10MessageKey.apply(
                configuration, nonce: nonce, domain: .filename, unbiasedPositions: unbiased
            ),
            stepping: stepping
        )
        let body = try M10Machine(
            configuration: M10MessageKey.apply(
                configuration, nonce: nonce, domain: .payload, unbiasedPositions: unbiased
            ),
            stepping: stepping
        )
        return (name, body)
    }

    private static func sessionKeys(
        archive: M10Format.Archive,
        configuration: M10Configuration,
        password: String?,
        scaledNotches: Bool
    ) throws -> (config: M10Configuration, authKey: SymmetricKey?) {
        if archive.keyMode == M10KeyMode.internalKey.rawValue {
            guard let codebook = archive.codebook else { throw M10Error.invalidFormat }
            var validated = try codebook.validated()
            guard validated.cipherSuite == archive.cipherSuite else {
                throw M10Error.settingsMismatch
            }
            validated.scaledNotches = scaledNotches
            return (validated, nil)
        }
        if let kdf = archive.kdf {
            guard let password, !password.isEmpty else { throw M10Error.passwordRequired }
            let derived = try M10Password.deriveConfiguration(
                password: password,
                suite: archive.cipherSuite,
                params: kdf,
                scaledNotches: scaledNotches
            )
            return (try derived.configuration.validated(), M10Password.authKey(master: derived.master))
        }
        var validated = try configuration.validated()
        guard validated.cipherSuite == archive.cipherSuite else {
            throw M10Error.settingsMismatch
        }
        validated.scaledNotches = scaledNotches
        return (validated, nil)
    }

    private static func withNotchProfiles(
        archive: M10Format.Archive,
        configuration: M10Configuration,
        password: String?,
        _ body: (M10Configuration, SymmetricKey?) throws -> DecryptResult
    ) throws -> DecryptResult {
        let profiles = notchProfiles(for: archive)
        var lastError: Error?
        for (index, scaled) in profiles.enumerated() {
            do {
                let session = try sessionKeys(
                    archive: archive,
                    configuration: configuration,
                    password: password,
                    scaledNotches: scaled
                )
                return try body(session.config, session.authKey)
            } catch {
                lastError = error
                if index + 1 < profiles.count, isNotchProfileMismatch(error) {
                    continue
                }
                throw error
            }
        }
        throw lastError ?? M10Error.settingsMismatch
    }

    private static func notchProfiles(for archive: M10Format.Archive) -> [Bool] {
        let scaled = archive.version >= M10Format.scaledNotchesVersion
        if archive.cipherSuite == .base512,
           archive.version >= M10Format.sealedPaddingVersion,
           archive.version < M10Format.scaledNotchesVersion {
            return [false, true]
        }
        return [scaled]
    }

    private static func isNotchProfileMismatch(_ error: Error) -> Bool {
        guard let error = error as? M10Error else { return false }
        switch error {
        case .settingsMismatch, .corruptPayload, .corruptFilename, .invalidFormat:
            return true
        default:
            return false
        }
    }

    private static func decryptInline(
        archive: M10Format.Archive,
        configuration: M10Configuration,
        isLegacyImport: Bool,
        authKey: SymmetricKey? = nil
    ) throws -> DecryptResult {
        let validated = try configuration.validated()
        guard validated.cipherSuite == archive.cipherSuite else {
            throw M10Error.settingsMismatch
        }
        let nonce = try M10MessageKey.nonce(from: archive)
        let pair = try decryptMachines(configuration: validated, nonce: nonce, archive: archive)
        let nameMachine = pair.name
        let bodyMachine = pair.body
        let filename = try resolveFilename(from: archive, machine: nameMachine, configuration: validated)

        let compact = filteredCiphertext(archive.ciphertext ?? "", suite: archive.cipherSuite)
        if compact.isEmpty {
            guard archive.version < M10Format.sealedPaddingVersion,
                  archive.payloadOriginalBytes == 0, archive.crc32 == CRC32.hash(Data()) else {
                throw M10Error.settingsMismatch
            }
            if archive.version < M10Format.carrySteppingVersion {
            try M10MessageKey.verify(
                archive: archive,
                configuration: validated,
                filename: filename,
                payload: Data(),
                authKey: authKey
            )
            }
            return DecryptResult(
                payload: Data(),
                filename: filename,
                kind: archive.kind,
                cipherSuite: archive.cipherSuite,
                isLegacyImport: isLegacyImport
            )
        }

        let decodedSymbols = bodyMachine.processMessageInChunks(compact)
        let payload: Data
        do {
            payload = try unpackDecoded(
                symbols: decodedSymbols,
                bytes: nil,
                archive: archive
            )
        } catch {
            throw M10Error.settingsMismatch
        }
        if archive.version < M10Format.carrySteppingVersion {
        try M10MessageKey.verify(
            archive: archive,
            configuration: validated,
            filename: filename,
            payload: payload,
            authKey: authKey
        )
        }
        return DecryptResult(
            payload: payload,
            filename: filename,
            kind: archive.kind,
            cipherSuite: archive.cipherSuite,
            isLegacyImport: isLegacyImport
        )
    }

    private static func decryptHybridBytes(
        archive: M10Format.Archive,
        ciphertext: Data,
        configuration: M10Configuration,
        isLegacyImport: Bool,
        authKey: SymmetricKey? = nil
    ) throws -> DecryptResult {
        let validated = try configuration.validated()
        guard validated.cipherSuite == archive.cipherSuite else {
            throw M10Error.settingsMismatch
        }
        let nonce = try M10MessageKey.nonce(from: archive)
        let pair = try decryptMachines(configuration: validated, nonce: nonce, archive: archive)
        let nameMachine = pair.name
        let bodyMachine = pair.body
        let filename = try resolveFilename(from: archive, machine: nameMachine, configuration: validated)
        let decoded = ciphertext.isEmpty ? Data() : bodyMachine.processBytes(ciphertext)
        let payload: Data
        do {
            payload = try unpackDecoded(
                symbols: Base256Symbols.latin1String(decoded),
                bytes: decoded,
                archive: archive
            )
        } catch {
            throw M10Error.settingsMismatch
        }
        if archive.version < M10Format.carrySteppingVersion {
        try M10MessageKey.verify(
            archive: archive,
            configuration: validated,
            filename: filename,
            payload: payload,
            authKey: authKey
        )
        }
        return DecryptResult(
            payload: payload,
            filename: filename,
            kind: archive.kind,
            cipherSuite: archive.cipherSuite,
            isLegacyImport: isLegacyImport
        )
    }

    private static func decryptHybrid(
        archive: M10Format.Archive,
        ciphertextSymbols: String,
        configuration: M10Configuration,
        isLegacyImport: Bool,
        authKey: SymmetricKey? = nil
    ) throws -> DecryptResult {
        let validated = try configuration.validated()
        guard validated.cipherSuite == archive.cipherSuite else {
            throw M10Error.settingsMismatch
        }
        let nonce = try M10MessageKey.nonce(from: archive)
        let pair = try decryptMachines(configuration: validated, nonce: nonce, archive: archive)
        let nameMachine = pair.name
        let bodyMachine = pair.body
        let filename = try resolveFilename(from: archive, machine: nameMachine, configuration: validated)
        let compact = filteredCiphertext(ciphertextSymbols, suite: archive.cipherSuite)
        let decodedSymbols = compact.isEmpty ? "" : bodyMachine.processMessageInChunks(compact)
        let payload: Data
        do {
            payload = try unpackDecoded(
                symbols: decodedSymbols,
                bytes: nil,
                archive: archive
            )
        } catch {
            throw M10Error.settingsMismatch
        }
        if archive.version < M10Format.carrySteppingVersion {
        try M10MessageKey.verify(
            archive: archive,
            configuration: validated,
            filename: filename,
            payload: payload,
            authKey: authKey
        )
        }
        return DecryptResult(
            payload: payload,
            filename: filename,
            kind: archive.kind,
            cipherSuite: archive.cipherSuite,
            isLegacyImport: isLegacyImport
        )
    }

    private static func decryptHybridFile(
        at url: URL,
        header: M10Format.Header,
        configuration: M10Configuration,
        isLegacyImport: Bool,
        authKey: SymmetricKey? = nil
    ) throws -> DecryptResult {
        let archive = header.archive
        let validated = try configuration.validated()
        guard validated.cipherSuite == archive.cipherSuite else {
            throw M10Error.settingsMismatch
        }
        let length = archive.payloadLength ?? 0
        let extra = archive.payloadOffset ?? 0
        guard extra >= 0, length >= 0 else { throw M10Error.invalidFormat }
        let nonce = try M10MessageKey.nonce(from: archive)
        let pair = try decryptMachines(configuration: validated, nonce: nonce, archive: archive)
        let nameMachine = pair.name
        let bodyMachine = pair.body
        let filename = try resolveFilename(from: archive, machine: nameMachine, configuration: validated)

        let payloadFile = FileIO.temporaryURL("m10_plain")
        if length == 0 {
            FileManager.default.createFile(atPath: payloadFile.path, contents: Data())
            guard archive.version < M10Format.sealedPaddingVersion,
                  archive.payloadOriginalBytes == 0, archive.crc32 == CRC32.hash(Data()) else {
                throw M10Error.settingsMismatch
            }
            if archive.version < M10Format.carrySteppingVersion {
            try M10MessageKey.verifyFile(
                archive: archive,
                configuration: validated,
                filename: filename,
                payloadURL: payloadFile,
                authKey: authKey
            )
            }
            return DecryptResult(
                payload: Data(),
                filename: filename,
                kind: archive.kind,
                cipherSuite: archive.cipherSuite,
                payloadFile: payloadFile,
                isLegacyImport: isLegacyImport
            )
        }

        let input = try FileHandle(forReadingFrom: url)
        defer { try? input.close() }
        try input.seek(toOffset: header.binaryOffset + UInt64(extra))
        let symbolsURL = FileIO.temporaryURL("m10_dec_sym")
        defer { try? FileManager.default.removeItem(at: symbolsURL) }
        try bodyMachine.processMessageToSymbolFile(from: input, length: length, to: symbolsURL)

        let packedURL: URL
        let info: DensePack.Info
        let expectedCrc: UInt32
        if archive.version >= M10Format.sealedPaddingVersion {
            packedURL = FileIO.temporaryURL("m10_packed")
            let inner: M10SealedPayload.Inner
            do {
                inner = try M10SealedPayload.unwrapFile(
                    at: symbolsURL, suite: archive.cipherSuite, packedURL: packedURL
                )
            } catch {
                try? FileManager.default.removeItem(at: payloadFile)
                throw M10Error.settingsMismatch
            }
            info = inner.info
            expectedCrc = inner.crc
        } else {
            packedURL = symbolsURL
            let codec = try PayloadCodec.resolve(codecField: archive.payloadCodec)
            info = DensePack.Info(
                originalBytes: archive.payloadOriginalBytes,
                storedBytes: archive.payloadStoredBytes,
                codec: codec
            )
            expectedCrc = archive.crc32
        }
        defer {
            if packedURL != symbolsURL {
                try? FileManager.default.removeItem(at: packedURL)
            }
        }
        do {
            try DensePack.unpackFile(
                symbolsURL: packedURL,
                info: info,
                suite: archive.cipherSuite,
                to: payloadFile
            )
        } catch {
            try? FileManager.default.removeItem(at: payloadFile)
            throw M10Error.settingsMismatch
        }
        let crc = try CRC32.hashFile(at: payloadFile)
        guard crc == expectedCrc else {
            try? FileManager.default.removeItem(at: payloadFile)
            throw M10Error.settingsMismatch
        }
        if archive.version < M10Format.carrySteppingVersion {
        do {
            try M10MessageKey.verifyFile(
                archive: archive,
                configuration: validated,
                filename: filename,
                payloadURL: payloadFile,
                authKey: authKey
            )
        } catch {
            try? FileManager.default.removeItem(at: payloadFile)
            throw error
        }
        }
        return DecryptResult(
            payload: Data(),
            filename: filename,
            kind: archive.kind,
            cipherSuite: archive.cipherSuite,
            payloadFile: payloadFile,
            isLegacyImport: isLegacyImport
        )
    }

    private static func hybridSlice(
        _ data: Data,
        layout: M10Format.Header,
        archive: M10Format.Archive
    ) throws -> Data {
        let offset = try M10Secure.hybridOffset(
            binaryOffset: layout.binaryOffset,
            payloadOffset: archive.payloadOffset
        )
        return try M10Secure.slice(data, offset: offset, length: archive.payloadLength ?? 0)
    }

    private static func unpackDecoded(
        symbols: String,
        bytes: Data?,
        archive: M10Format.Archive
    ) throws -> Data {
        if archive.version >= M10Format.sealedPaddingVersion {
            let inner: M10SealedPayload.Inner
            if archive.cipherSuite == .base256 {
                let decoded = bytes ?? Base256Symbols.latin1Data(symbols) ?? Data()
                inner = try M10SealedPayload.unwrapBytes(decoded)
            } else {
                inner = try M10SealedPayload.unwrapSymbols(symbols, suite: archive.cipherSuite)
            }
            let payload = try DensePack.unpack(
                inner.packedSymbols, info: inner.info, suite: archive.cipherSuite
            )
            guard CRC32.hash(payload) == inner.crc else { throw M10Error.settingsMismatch }
            return payload
        }
        let codec = try PayloadCodec.resolve(codecField: archive.payloadCodec)
        let info = DensePack.Info(
            originalBytes: archive.payloadOriginalBytes,
            storedBytes: archive.payloadStoredBytes,
            codec: codec
        )
        let payload = try DensePack.unpack(symbols, info: info, suite: archive.cipherSuite)
        guard CRC32.hash(payload) == archive.crc32 else { throw M10Error.settingsMismatch }
        return payload
    }

    private static func resolveFilename(
        from archive: M10Format.Archive,
        machine: M10Machine,
        configuration: M10Configuration
    ) throws -> String {
        if archive.version >= M10Format.sealedPaddingVersion {
            if let encrypted = archive.encryptedFilename, !encrypted.isEmpty {
                let name = try M10Padding.decodeNameWire(
                    encrypted, suite: configuration.cipherSuite, encrypted: true, machine: machine
                )
                let sanitized = M10Format.sanitizedFilename(name)
                return sanitized.isEmpty ? (archive.kind == .folder ? "folder" : "file") : sanitized
            }
            if let original = archive.originalFilename, !original.isEmpty {
                let name = try M10Padding.decodeNameWire(
                    original, suite: configuration.cipherSuite, encrypted: false, machine: machine
                )
                let sanitized = M10Format.sanitizedFilename(name)
                return sanitized.isEmpty ? (archive.kind == .folder ? "folder" : "file") : sanitized
            }
            return archive.kind == .folder ? "folder" : "file"
        }
        if let encrypted = archive.encryptedFilename, !encrypted.isEmpty {
            let bytes: Data?
            if configuration.cipherSuite == .base256 {
                guard let cipher = Base256Symbols.decodeFilenameCiphertext(encrypted),
                      !cipher.isEmpty else {
                    throw M10Error.corruptFilename
                }
                bytes = machine.processBytes(cipher)
            } else {
                let decoded = machine.processMessage(encrypted)
                bytes = PairCodec.decode(decoded, suite: configuration.cipherSuite)
            }
            guard let bytes,
                  let name = String(data: bytes, encoding: .utf8),
                  !name.isEmpty else {
                throw M10Error.corruptFilename
            }
            return M10Format.sanitizedFilename(name)
        }
        if let original = archive.originalFilename, !original.isEmpty {
            return M10Format.sanitizedFilename(original)
        }
        return archive.kind == .folder ? "folder" : "file"
    }

    private static func sealName(
        _ name: String,
        encrypt: Bool,
        machine: M10Machine,
        suite: M10CipherSuite,
        formatVersion: Int
    ) throws -> (
        original: String?,
        encrypted: String?,
        nameBytes: Data,
        nameEncrypted: Bool,
        diskBasename: String
    ) {
        if formatVersion >= M10Format.sealedPaddingVersion {
            let wire = try M10Padding.encodeNameWire(
                name, suite: suite, encrypt: encrypt, machine: machine
            )
            if encrypt {
                return (nil, wire.field, wire.bytes, true, wire.field)
            }
            return (wire.field, nil, wire.bytes, false, name)
        }
        if encrypt {
            let field: String
            let bytes: Data
            if suite == .base256 {
                let cipher = machine.processBytes(Data(name.utf8))
                field = Base256Symbols.encodeFilenameCiphertext(cipher)
                bytes = cipher
            } else {
                field = machine.processMessage(PairCodec.encode(Data(name.utf8), suite: suite))
                bytes = Data(field.utf8)
            }
            return (nil, field, bytes, true, field)
        }
        return (name, nil, Data(name.utf8), false, name)
    }

    private static func filteredCiphertext(_ text: String, suite: M10CipherSuite) -> String {
        switch suite {
        case .alpha36: return Alpha36Symbols.filteredSymbols(text)
        case .ascii: return Ascii94Symbols.filteredSymbols(text)
        case .base256:
            return String(text.unicodeScalars.compactMap { scalar -> Character? in
                guard scalar.value <= 255 else { return nil }
                return Character(scalar)
            })
        case .base512: return Base512Symbols.filteredSymbols(text)
        }
    }
}

enum DirectoryBundle {
    static func packToFile(_ folder: URL) throws -> URL {
        var isDir: ObjCBool = false
        guard FileManager.default.fileExists(atPath: folder.path, isDirectory: &isDir),
              isDir.boolValue else {
            throw M10Error.unreadableFile(folder.lastPathComponent)
        }
        let tempZip = FileIO.temporaryURL("m10_zip").appendingPathExtension("zip")
        try zipDirectory(folder, to: tempZip)
        let size = try FileIO.byteCount(at: tempZip)
        guard size > 0 else {
            try? FileManager.default.removeItem(at: tempZip)
            throw M10Error.emptyFolder
        }
        guard size <= M10Format.maxStreamPayloadBytes else {
            try? FileManager.default.removeItem(at: tempZip)
            throw M10Error.payloadTooLarge
        }
        return tempZip
    }

    static func pack(_ folder: URL) throws -> Data {
        let zip = try packToFile(folder)
        defer { try? FileManager.default.removeItem(at: zip) }
        let data = try Data(contentsOf: zip)
        guard data.count <= M10Format.maxPayloadBytes else { throw M10Error.payloadTooLarge }
        return data
    }

    static func unpack(_ zipData: Data, to destination: URL) throws {
        let tempZip = FileIO.temporaryURL("m10_unz").appendingPathExtension("zip")
        defer { try? FileManager.default.removeItem(at: tempZip) }
        try zipData.write(to: tempZip, options: .atomic)
        try unpackFile(tempZip, to: destination)
    }

    static func unpackFile(_ zipURL: URL, to destination: URL) throws {
        let fm = FileManager.default
        let tempExtract = FileIO.temporaryURL("m10_ex")
        defer { try? fm.removeItem(at: tempExtract) }
        try fm.createDirectory(at: tempExtract, withIntermediateDirectories: true)
        try unzip(zipURL, toDirectory: tempExtract)
        let contents = try fm.contentsOfDirectory(
            at: tempExtract,
            includingPropertiesForKeys: nil,
            options: [.skipsHiddenFiles]
        )
        if contents.count == 1 {
            let only = contents[0]
            if fm.fileExists(atPath: destination.path) {
                throw M10Error.fileAlreadyExists(destination.path)
            }
            try fm.moveItem(at: only, to: destination)
        } else {
            try fm.createDirectory(at: destination, withIntermediateDirectories: false)
            for item in try fm.contentsOfDirectory(at: tempExtract, includingPropertiesForKeys: nil) {
                try fm.moveItem(
                    at: item,
                    to: destination.appendingPathComponent(item.lastPathComponent)
                )
            }
        }
    }

    private static func zipDirectory(_ source: URL, to zipURL: URL) throws {
        if FileManager.default.fileExists(atPath: zipURL.path) {
            try FileManager.default.removeItem(at: zipURL)
        }
        try runDitto(arguments: ["-c", "-k", "--keepParent", source.path, zipURL.path])
    }

    private static func unzip(_ zipURL: URL, toDirectory directory: URL) throws {
        try runDitto(arguments: ["-x", "-k", zipURL.path, directory.path])
    }

    private static func runDitto(arguments: [String]) throws {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/ditto")
        process.arguments = arguments
        let err = Pipe()
        process.standardError = err
        try process.run()
        process.waitUntilExit()
        guard process.terminationStatus == 0 else {
            throw M10Error.unreadableFile("ditto")
        }
    }
}

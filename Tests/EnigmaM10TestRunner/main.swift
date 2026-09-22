import Foundation
import EnigmaM10Core

var failures = 0

func expect(_ cond: @autoclosure () -> Bool, _ message: String = "", file: StaticString = #file, line: UInt = #line) {
    if !cond() {
        failures += 1
        print("FAIL \(file):\(line): \(message)")
    }
}

func expectEqual<T: Equatable>(_ a: T, _ b: T, _ message: String = "", file: StaticString = #file, line: UInt = #line) {
    if a != b {
        failures += 1
        print("FAIL \(file):\(line): \(message) — \(a) != \(b)")
    }
}

func expectThrows(_ body: () throws -> Void, _ message: String = "", file: StaticString = #file, line: UInt = #line) {
    do {
        try body()
        failures += 1
        print("FAIL \(file):\(line): expected throw — \(message)")
    } catch {
        // ok
    }
}

func catalogPermutationsAreValid() {
    for name in M10Catalog.rotorNames {
        let p = M10Catalog.Alpha36.rotorPermutation(name)!
        expectEqual(p.count, 36, "alpha36 \(name) length")
        expectEqual(Set(p), Set(0..<36), "alpha36 \(name) permutation")
        let a94 = M10Catalog.Ascii94.rotorWirings[name]!
        expectEqual(a94.count, 94, "ascii94 \(name) length")
        expectEqual(Set(a94), Set(0..<94), "ascii94 \(name) permutation")
        let b256 = M10Catalog.Base256.rotorWirings[name]!
        expectEqual(b256.count, 256, "base256 \(name) length")
        expectEqual(Set(b256), Set(0..<256), "base256 \(name) permutation")
    }
    for name in M10Catalog.reflectorNames {
        let r = M10Catalog.Alpha36.reflectorPermutation(name)!
        expectEqual(Set(r), Set(0..<36), "alpha36 reflector \(name)")
        for (i, j) in r.enumerated() {
            expect(i != j, "alpha36 \(name) fixed point \(i)")
            expectEqual(r[j], i, "alpha36 \(name) involution")
        }
        let r94 = M10Catalog.Ascii94.reflectorWirings[name]!
        expectEqual(Set(r94), Set(0..<94), "ascii94 reflector \(name)")
        for (i, j) in r94.enumerated() {
            expect(i != j, "ascii94 \(name) fixed point \(i)")
            expectEqual(r94[j], i, "ascii94 \(name) involution")
        }
        let r256 = M10Catalog.Base256.reflectorWirings[name]!
        expectEqual(Set(r256), Set(0..<256), "base256 reflector \(name)")
        for (i, j) in r256.enumerated() {
            expect(i != j, "base256 \(name) fixed point \(i)")
            expectEqual(r256[j], i, "base256 \(name) involution")
        }
    }
    print("OK catalogs")
}

func selfTest() {
    expect(M10SelfTest.run(), "factory Alpha-36 self-test")
    let machine = try! M10Machine(configuration: .alpha36Factory)
    expectEqual(machine.processMessage("00000"), "V661T")
    machine.resetPositions()
    expectEqual(machine.processMessage("V661T"), "00000")
    print("OK self-test V661T")
}

func roundTripText() {
    let machine = try! M10Machine(configuration: .alpha36Factory)
    let plain = "M10ENIGMA"
    let ct = machine.processMessage(plain)
    machine.resetPositions()
    expectEqual(machine.processMessage(ct), plain)
    expect(ct != plain, "ciphertext should differ")
    print("OK alpha36 text roundtrip")

    let ascii = try! M10Machine(configuration: .ascii94Factory)
    let asciiPlain = "Hello,M10-ASCII-94!"
    let asciiCT = ascii.processMessage(asciiPlain)
    ascii.resetPositions()
    expectEqual(ascii.processMessage(asciiCT), asciiPlain)
    print("OK ascii94 text roundtrip")

    let b256 = try! M10Machine(configuration: .base256Factory)
    let raw = Data((0...255).map { UInt8($0) })
    let enc = b256.processBytes(raw)
    b256.resetPositions()
    expectEqual(b256.processBytes(enc), raw)
    expect(enc != raw, "base256 should change payload")
    print("OK base256 byte roundtrip")
}

func densePackRoundTrip() {
    let samples: [Data] = [
        Data(),
        Data([0]),
        Data((0...255).map { UInt8($0) }),
        Data("Alpha-36 dense packing from EnigmaVault.".utf8),
        Data(repeating: 0x41, count: 17),
        Data(repeating: 0x7E, count: 100)
    ]
    for (i, sample) in samples.enumerated() {
        for suite in M10CipherSuite.allCases {
            let (symbols, info) = DensePack.pack(sample, suite: suite)
            let restored = try! DensePack.unpack(symbols, info: info, suite: suite)
            expectEqual(restored, sample, "dense \(suite) sample \(i)")
        }
    }
    print("OK dense pack")
}

func pairCodecRoundTrip() {
    let data = Data("filename.txt".utf8)
    expectEqual(PairCodec.decodeAlpha36(PairCodec.encodeAlpha36(data)), data)
    expectEqual(PairCodec.decodeAscii94(PairCodec.encodeAscii94(data)), data)
    print("OK pair codec")
}

func archiveOmitsSettings() throws {
    let payload = Data("Enigma M10 archive test payload.".utf8)
    let result = try M10Engine.encrypt(
        data: payload,
        originalFilename: "secret.txt",
        configuration: .alpha36Factory,
        encryptFilename: true
    )
    let text = String(decoding: result.data, as: UTF8.self)
    expect(text.hasPrefix("ENIGMAM10 v7\n"), "magic")
    expect(result.suggestedFilename.hasSuffix(".enigmam10"), "disk extension")
    expect(!text.contains("\"rotorNames\""), "no rotorNames")
    expect(!text.contains("\"plugPairs\""), "no plugPairs")
    expect(!text.contains("\"configuration\""), "no configuration")
    expect(!text.contains("ZENRR8AQVH"), "positions not in file")
    expect(!text.contains("T7O6AR65JS"), "rings not in file")
    expect(!text.contains("secret.txt"), "filename encrypted")

    let decoded = try M10Format.decodeArchive(result.data)
    expectEqual(decoded.cipherSuite, M10CipherSuite.alpha36)
    expect(decoded.encryptedFilename != nil, "encrypted filename present")
    expect(decoded.originalFilename == nil, "plaintext filename omitted")

    let decrypted = try M10Engine.decrypt(data: result.data, configuration: .alpha36Factory)
    expectEqual(decrypted.payload, payload)
    expectEqual(decrypted.filename, "secret.txt")
    print("OK archive omits settings")
}

func wrongSettingsFail() throws {
    let payload = Data("cannot read without the codebook".utf8)
    let result = try M10Engine.encrypt(
        data: payload,
        originalFilename: "x.bin",
        configuration: .alpha36Factory
    )
    var wrong = M10Configuration.alpha36Factory
    wrong.positions = "0000000000"
    expectThrows({
        _ = try M10Engine.decrypt(data: result.data, configuration: wrong)
    }, "wrong positions")
    expectThrows({
        _ = try M10Engine.decrypt(data: result.data, configuration: .ascii94Factory)
    }, "wrong suite")
    print("OK wrong settings fail")
}

func ascii94ArchiveRoundTrip() throws {
    let payload = Data("ASCII-94 v1 integration check. {\"rings\":\"nope\"}".utf8)
    let result = try M10Engine.encrypt(
        data: payload,
        originalFilename: "ascii94-test.bin",
        configuration: .ascii94Factory,
        encryptFilename: true
    )
    let text = String(decoding: result.data, as: UTF8.self)
    expect(!text.contains("ascii94-test.bin"), "ascii filename encrypted")
    expect(!text.contains("\"rings\""), "rings key absent")
    let decrypted = try M10Engine.decrypt(data: result.data, configuration: .ascii94Factory)
    expectEqual(decrypted.payload, payload)
    expectEqual(decrypted.filename, "ascii94-test.bin")
    print("OK ascii94 archive")
}

func base256ArchiveRoundTrip() throws {
    let payload = Data((0..<400).map { UInt8($0 & 0xFF) })
    let result = try M10Engine.encrypt(
        data: payload,
        originalFilename: "bytes.bin",
        configuration: .base256Factory,
        encryptFilename: true
    )
    let decoded = try M10Format.decodeArchive(result.data)
    expectEqual(decoded.cipherSuite, M10CipherSuite.base256)
    expect(decoded.isHybrid, "base256 uses hybrid binary payload")
    expect(!String(decoding: result.data, as: UTF8.self).contains("bytes.bin"), "filename encrypted")
    let decrypted = try M10Engine.decrypt(data: result.data, configuration: .base256Factory)
    expectEqual(decrypted.payload, payload)
    expectEqual(decrypted.filename, "bytes.bin")
    print("OK base256 archive")
}

func base256FilenamePreservesCRLF() throws {
    let crlf = Data([0x0D, 0x0A])
    expect(Base256Symbols.latin1String(crlf).count == 1, "Swift Character count collapses CR LF")
    expectEqual(Base256Symbols.hex(crlf), "0D0A")
    let stored = Base256Symbols.encodeFilenameCiphertext(Data([0x0D, 0x0A, 0x41]))
    expectEqual(stored, "hex:0D0A41")
    expectEqual(Base256Symbols.decodeFilenameCiphertext(stored), Data([0x0D, 0x0A, 0x41]))
    expect(!stored.contains("\r") && !stored.contains("\n"), "JSON field must not contain raw CR/LF")

    let machine = try M10Machine(configuration: .base256Factory)
    let cipher = machine.processBytes(crlf)
    machine.resetPositions()
    expectEqual(machine.processBytes(cipher), crlf)

    let name = "file\r\nname.txt"
    expect(Data(name.utf8) == Data([0x66, 0x69, 0x6C, 0x65, 0x0D, 0x0A, 0x6E, 0x61, 0x6D, 0x65, 0x2E, 0x74, 0x78, 0x74]))
    let result = try M10Engine.encrypt(
        data: Data("payload".utf8),
        originalFilename: name,
        configuration: .base256Factory,
        encryptFilename: true
    )
    let archive = try M10Format.decodeArchive(result.data)
    expect(archive.encryptedFilename?.hasPrefix("hex:") == true, "hex-encoded filename")
    expect(archive.encryptedFilename?.contains("\r") == false, "no raw CR in JSON")
    expect(archive.encryptedFilename?.contains("\n") == false, "no raw LF in JSON")
    let decrypted = try M10Engine.decrypt(data: result.data, configuration: .base256Factory)
    expectEqual(decrypted.filename, name)
    expectEqual(decrypted.payload, Data("payload".utf8))
    print("OK base256 filename CR/LF")
}

func base256LegacyRawFilenameStillDecrypts() throws {
    let crlf = Data([0x0D, 0x0A])
    expectEqual(Base256Symbols.latin1Data(Base256Symbols.latin1String(crlf)), crlf)

    let name = "file\r\nname.txt"
    let payload = Data("legacy-name-payload".utf8)
    let result = try M10Engine.encrypt(
        data: payload,
        originalFilename: name,
        configuration: .base256Factory,
        encryptFilename: true,
        formatVersion: 2
    )
    let layout = try M10Format.parseLayout(result.data)
    var archive = layout.archive
    guard let field = archive.encryptedFilename,
          let cipher = Base256Symbols.decodeFilenameCiphertext(field) else {
        failures += 1
        print("FAIL missing hex filename")
        return
    }
    expect(cipher.contains(0x0D) && cipher.contains(0x0A) || cipher.count >= 2)
    archive.encryptedFilename = Base256Symbols.latin1String(cipher)
    expect(archive.encryptedFilename?.hasPrefix("hex:") == false, "legacy raw field")
    let binary = result.data.subdata(in: Int(layout.binaryOffset)..<result.data.count)
    let rewritten = try M10Format.encodeHybridHeader(archive) + binary
    let decrypted = try M10Engine.decrypt(data: rewritten, configuration: .base256Factory)
    expectEqual(decrypted.filename, name)
    expectEqual(decrypted.payload, payload)
    print("OK base256 legacy raw filename")
}

func streamingRoundTrip() throws {
    let dir = FileManager.default.temporaryDirectory.appendingPathComponent("m10_stream_\(UUID().uuidString)")
    try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
    defer { try? FileManager.default.removeItem(at: dir) }

    let payload = Data((0..<1_100_000).map { UInt8($0 % 251) })
    let source = dir.appendingPathComponent("big.bin")
    try payload.write(to: source)

    let encrypted = try M10Engine.encryptFile(
        at: source,
        configuration: .alpha36Factory,
        encryptFilename: true
    )
    expect(encrypted.writtenFile != nil, "hybrid writes a file")
    let archiveURL = try M10Engine.writeEncryptResult(encrypted, nextTo: source)
    expect(archiveURL.pathExtension == "enigmam10", "extension")

    let header = try M10Format.readHeader(at: archiveURL)
    expect(header.archive.isHybrid, "hybrid layout")
    expectEqual(header.archive.version, 7, "scaled-notch version")
    expectEqual(header.archive.payloadOriginalBytes, 0, "sizes are not public")
    expect((header.archive.payloadLength ?? 0) % 4096 == 0, "ciphertext 4 KiB aligned")
    expect(header.archive.ciphertext == nil || header.archive.ciphertext?.isEmpty == true, "no inline ciphertext")
    expect(header.archive.payloadLength ?? 0 > 0, "payloadLength")
    let headBytes = try Data(contentsOf: archiveURL, options: [.mappedIfSafe]).prefix(4096)
    expect(!String(decoding: headBytes, as: UTF8.self).contains("\"rotorNames\""), "no settings")

    let decrypted = try M10Engine.decryptFile(at: archiveURL, configuration: .alpha36Factory)
    expectEqual(decrypted.filename, "big.bin")
    let dest = try M10Engine.writeDecryptResult(decrypted, nextTo: archiveURL)
    let restored = try Data(contentsOf: dest)
    expectEqual(restored, payload, "stream roundtrip")
    print("OK streaming roundtrip")
}

func packFileMatchesMemory() throws {
    let data = Data((0..<4_000).map { UInt8($0 % 251) })
    let (symbols, info) = DensePack.pack(data, suite: .alpha36, allowCompression: false)
    let dir = FileManager.default.temporaryDirectory.appendingPathComponent("m10_pack_\(UUID().uuidString)")
    try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
    defer { try? FileManager.default.removeItem(at: dir) }
    let src = dir.appendingPathComponent("in.bin")
    let out = dir.appendingPathComponent("out.sym")
    try data.write(to: src)
    let packed = try DensePack.packFile(at: src, to: out, suite: .alpha36, allowCompression: false)
    expectEqual(packed.info.originalBytes, info.originalBytes)
    expectEqual(packed.info.storedBytes, info.storedBytes)
    expectEqual(packed.info.codec, info.codec)
    let fileSymbols = try String(contentsOf: out, encoding: .utf8)
    expectEqual(fileSymbols, symbols, "dense pack file == memory")
    print("OK pack file matches memory")
}

func nonceAndAuth() throws {
    let payload = Data("same plaintext twice".utf8)
    let a = try M10Engine.encrypt(
        data: payload, originalFilename: "a.txt", configuration: .alpha36Factory
    )
    let b = try M10Engine.encrypt(
        data: payload, originalFilename: "a.txt", configuration: .alpha36Factory
    )
    expect(a.data != b.data, "nonce should change ciphertext")
    let headerA = try M10Format.decodeArchive(a.data)
    expectEqual(headerA.version, 7, "new archives are v7")
    expectEqual(headerA.payloadOriginalBytes, 0, "sizes sealed")
    expect(headerA.messageNonce != nil, "nonce stored")
    expect(headerA.authTag != nil, "auth tag stored")
    expect(headerA.ciphertext != nil, "inline ciphertext")
    expectEqual(
        try M10Engine.decrypt(data: a.data, configuration: .alpha36Factory).payload,
        payload
    )
    expectEqual(
        try M10Engine.decrypt(data: b.data, configuration: .alpha36Factory).payload,
        payload
    )

    let nonce = Data((0..<16).map { UInt8($0 + 1) })
    let namePos = M10MessageKey.derivedPositions(base: .alpha36Factory, nonce: nonce, domain: .filename)
    let bodyPos = M10MessageKey.derivedPositions(base: .alpha36Factory, nonce: nonce, domain: .payload)
    expect(namePos != bodyPos, "filename and payload start positions differ")
    expectEqual(namePos.count, 10)
    print("OK nonce and distinct start positions")
}

func authTagRejectsTamper() throws {
    let payload = Data("authenticated payload".utf8)
    let result = try M10Engine.encrypt(
        data: payload, originalFilename: "t.txt", configuration: .alpha36Factory
    )
    var archive = try M10Format.decodeArchive(result.data)
    guard let ciphertext = archive.ciphertext, let first = ciphertext.first else {
        failures += 1
        print("FAIL missing ciphertext")
        return
    }
    let flipped: Character = first == "A" ? "B" : "A"
    archive.ciphertext = String(flipped) + ciphertext.dropFirst()
    let tampered = try M10Format.encodeArchive(archive)
    expectThrows({
        _ = try M10Engine.decrypt(data: tampered, configuration: .alpha36Factory)
    }, "tampered ciphertext")
    print("OK auth/CRC rejects tamper")
}

func legacyArchiveWithoutNonceStillDecrypts() throws {
    let payload = Data("legacy v1 body".utf8)
    let machine = try M10Machine(configuration: .alpha36Factory)
    let packed = DensePack.pack(payload, suite: .alpha36)
    let encodedName = PairCodec.encode(Data("legacy.txt".utf8), suite: .alpha36)
    let encryptedName = machine.processMessage(encodedName)
    machine.resetPositions()
    let ciphertext = machine.processMessageInChunks(packed.symbols)
    let archive = M10Format.Archive(
        version: 1,
        kind: .file,
        cipherSuite: .alpha36,
        originalFilename: nil,
        encryptedFilename: encryptedName,
        ciphertext: ciphertext,
        createdAt: Date(),
        payloadOriginalBytes: packed.info.originalBytes,
        payloadStoredBytes: packed.info.storedBytes,
        payloadCodec: packed.info.codec.jsonField,
        crc32: CRC32.hash(payload)
    )
    let data = try M10Format.encodeArchive(archive)
    let decoded = try M10Format.decodeArchive(data)
    expect(decoded.messageNonce == nil, "legacy has no nonce")
    expect(decoded.authTag == nil, "legacy has no auth tag")
    expectThrows({
        _ = try M10Engine.decrypt(data: data, configuration: .alpha36Factory)
    }, "v1 is not opened by Decrypt")
    let result = try M10Engine.decrypt(
        data: data, configuration: .alpha36Factory, mode: .legacyImport
    )
    expectEqual(result.payload, payload)
    expectEqual(result.filename, "legacy.txt")
    expect(result.isLegacyImport, "legacy import flagged")
    let dest = try M10Engine.writeDecryptResult(
        result, nextTo: FileManager.default.temporaryDirectory
    )
    expect(dest.lastPathComponent.hasPrefix("UNAUTHENTICATED-"), "legacy output name")
    try? FileManager.default.removeItem(at: dest)
    print("OK legacy archive requires explicit import")
}

func v2RequiresNonceAndAuth() throws {
    let payload = Data("v2 must authenticate".utf8)
    let result = try M10Engine.encrypt(
        data: payload, originalFilename: "v2.txt", configuration: .alpha36Factory
    )
    var archive = try M10Format.decodeArchive(result.data)
    expectEqual(archive.version, 7)

    archive.authTag = nil
    expectThrows({
        _ = try M10Engine.decrypt(data: try M10Format.encodeArchive(archive), configuration: .alpha36Factory)
    }, "stripped authTag")

    archive = try M10Format.decodeArchive(result.data)
    archive.authTag = ""
    expectThrows({
        _ = try M10Engine.decrypt(data: try M10Format.encodeArchive(archive), configuration: .alpha36Factory)
    }, "empty authTag")

    archive = try M10Format.decodeArchive(result.data)
    archive.messageNonce = nil
    expectThrows({
        _ = try M10Engine.decrypt(data: try M10Format.encodeArchive(archive), configuration: .alpha36Factory)
    }, "stripped nonce")
    print("OK v2 requires nonce and authTag")
}

func v2AuthCoversKind() throws {
    let payload = Data("kind is authenticated".utf8)
    let result = try M10Engine.encrypt(
        data: payload, originalFilename: "k.txt", configuration: .alpha36Factory, kind: .file
    )
    var archive = try M10Format.decodeArchive(result.data)
    expectEqual(archive.kind, M10Format.Kind.file)
    archive.kind = .folder
    expectThrows({
        _ = try M10Engine.decrypt(data: try M10Format.encodeArchive(archive), configuration: .alpha36Factory)
    }, "kind flip")
    print("OK v2 HMAC covers kind")
}

func downgradeToV1IsRejected() throws {
    for suite in [M10CipherSuite.alpha36, .ascii, .base256] {
        let payload = Data("downgrade \(suite.rawValue) payload".utf8)
        let config = M10Configuration.factory(for: suite)
        let result = try M10Engine.encrypt(
            data: payload,
            originalFilename: "doc.txt",
            configuration: config,
            kind: .file
        )
        let layout = try M10Format.parseLayout(result.data)
        var archive = layout.archive
        archive.version = 1
        archive.authTag = nil
        archive.kind = .folder
        let downgraded: Data
        if archive.isHybrid {
            let binary = result.data.subdata(
                in: Int(layout.binaryOffset)..<result.data.count
            )
            downgraded = try M10Format.encodeHybridHeader(archive) + binary
        } else {
            downgraded = try M10Format.encodeArchive(archive)
        }
        expect(String(decoding: downgraded, as: UTF8.self).hasPrefix("ENIGMAM10 v1\n"), "\(suite) header is v1")
        expectThrows({
            _ = try M10Engine.decrypt(data: downgraded, configuration: config)
        }, "\(suite) authenticated decrypt rejects downgrade")
    }
    print("OK v3→v1 downgrade rejected")
}

func sidecarCodebookRoundTrip() throws {
    let dir = FileManager.default.temporaryDirectory.appendingPathComponent("m10_side_\(UUID().uuidString)")
    try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
    defer { try? FileManager.default.removeItem(at: dir) }
    let source = dir.appendingPathComponent("note.txt")
    let payload = Data("sidecar keeps the session key".utf8)
    try payload.write(to: source)
    let config = M10Configuration.random(suite: .base256)
    let encrypted = try M10Engine.encryptFile(at: source, configuration: config)
    let archiveURL = try M10Engine.writeEncryptResult(
        encrypted, nextTo: source, configuration: config
    )
    let sidecar = M10Engine.sidecarURL(forArchive: archiveURL)
    expect(FileManager.default.fileExists(atPath: sidecar.path), "sidecar written")
    let loaded = try M10Engine.loadSidecarCodebook(forArchive: archiveURL)
    expectEqual(loaded, try config.validated())
    expectThrows({
        _ = try M10Engine.decrypt(data: try Data(contentsOf: archiveURL), configuration: .base256Factory)
    }, "factory cannot open session archive")
    let decrypted = try M10Engine.decrypt(
        data: try Data(contentsOf: archiveURL), configuration: loaded!
    )
    expectEqual(decrypted.payload, payload)
    print("OK sidecar codebook")
}

func passwordModeRoundTrip() throws {
    var params = try M10KDFParams.freshSalt()
    params.memoryKiB = 32
    params.iterations = 1
    let password = "correct horse battery staple"
    let first = try M10Password.deriveConfiguration(password: password, suite: .base256, params: params)
    let second = try M10Password.deriveConfiguration(password: password, suite: .base256, params: params)
    expectEqual(first.configuration.rings, second.configuration.rings)
    expectEqual(first.configuration.positions, second.configuration.positions)
    expectEqual(first.master, second.master)
    expect(first.configuration.derivedMachine != nil)
    expectEqual(
        first.configuration.derivedMachine?.rotorWirings.first,
        second.configuration.derivedMachine?.rotorWirings.first
    )

    let payload = Data("argon2id derived enigma m10".utf8)
    let result = try M10Engine.encrypt(
        data: payload,
        originalFilename: "secret.txt",
        configuration: .base256Factory,
        password: password,
        kdf: params
    )
    expect(result.data.starts(with: M10PasswordBinary.magicV4), "M10PW04")
    expect(M10PasswordBinary.matches(result.data), "opaque password blob")
    expect(!String(decoding: result.data.prefix(32), as: UTF8.self).contains("{"), "not JSON")
    expect(!result.data.starts(with: Data("ENIGMAM10".utf8)), "not external-key JSON")
    let parsed = try M10PasswordBinary.parse(result.data)
    expect(parsed.archive.kdf != nil)
    expectEqual(parsed.archive.keyMode, "password")
    expect(parsed.archive.kdf?.salt.isEmpty == false, "salt present")
    expectEqual(parsed.archive.payloadOriginalBytes, 0, "sizes not in public header")
    expectEqual(parsed.archive.crc32, 0, "crc not in public header")
    expect(parsed.ciphertext.count % 4096 == 0, "padded ciphertext")
    expect(parsed.ciphertext.count >= 4096, "at least one pad block")

    let decrypted = try M10Engine.decrypt(
        data: result.data, configuration: .base256Factory, password: password
    )
    expectEqual(decrypted.payload, payload)
    expectEqual(decrypted.filename, "secret.txt")
    expectThrows({
        _ = try M10Engine.decrypt(data: result.data, configuration: .base256Factory, password: "wrong")
    }, "wrong password")
    expectThrows({
        _ = try M10Engine.decrypt(data: result.data, configuration: .base256Factory)
    }, "password required")
    let blobURL = FileManager.default.temporaryDirectory.appendingPathComponent("m10pw_\(UUID().uuidString).enigmam10")
    try result.data.write(to: blobURL)
    defer { try? FileManager.default.removeItem(at: blobURL) }
    let viaHeader = try M10Format.readHeader(at: blobURL)
    expect(viaHeader.archive.kdf != nil, "JSON header peek must not reject password blobs")
    print("OK password mode")
}

func carrySteppingDoesNotBurst() throws {
    let size = Alpha36Symbols.alphabetSize
    let identity = Array(0..<size)
    var reflector = Array(repeating: 0, count: size)
    for i in stride(from: 0, to: size, by: 2) {
        reflector[i] = i + 1
        reflector[i + 1] = i
    }
    var notches = Array(repeating: Set<Int>(), count: 10)
    notches[8] = [0]
    var config = M10Configuration.alpha36Factory
    config.rings = String(repeating: "0", count: 10)
    config.positions = String(repeating: "0", count: 10)
    config.plugPairs = []
    config.derivedMachine = M10DerivedMachine(
        rotorWirings: Array(repeating: identity, count: 10),
        rotorNotches: notches,
        reflectorWiring: reflector
    )
    let v2 = try M10Machine(configuration: config, stepping: .parkedNotch)
    let v3 = try M10Machine(configuration: config, stepping: .carryCascade)
    _ = v2.processMessage("AAAAA")
    _ = v3.processMessage("AAAAA")
    let v2pos = Array(v2.currentPositions())
    let v3pos = Array(v3.currentPositions())
    expect(v2pos[7] != "0", "v2 parked-notch bursts rotor 7")
    expectEqual(v3pos[7], Character("0"), "v3 carry does not burst rotor 7")
    print("OK v3 carry stepping")
}

func v2ArchivesStillDecrypt() throws {
    let payload = Data("frozen v2 stepping and plaintext hmac".utf8)
    let result = try M10Engine.encrypt(
        data: payload,
        originalFilename: "old.txt",
        configuration: .alpha36Factory,
        formatVersion: 2
    )
    expect(String(decoding: result.data, as: UTF8.self).hasPrefix("ENIGMAM10 v2\n"), "v2 magic")
    let decoded = try M10Format.decodeArchive(result.data)
    expectEqual(decoded.version, 2)
    let recovered = try M10Engine.decrypt(data: result.data, configuration: .alpha36Factory)
    expectEqual(recovered.payload, payload)
    expectEqual(recovered.filename, "old.txt")
    print("OK v2 decrypt preserved")
}

func v3ArchivesStillDecrypt() throws {
    let payload = Data("frozen v3 ciphertext hmac without createdAt".utf8)
    let result = try M10Engine.encrypt(
        data: payload,
        originalFilename: "v3.txt",
        configuration: .alpha36Factory,
        formatVersion: 3
    )
    expect(String(decoding: result.data, as: UTF8.self).hasPrefix("ENIGMAM10 v3\n"), "v3 magic")
    let recovered = try M10Engine.decrypt(data: result.data, configuration: .alpha36Factory)
    expectEqual(recovered.payload, payload)
    print("OK v3 decrypt preserved")
}

func v4HmacCoversCreatedAt() throws {
    let payload = Data("createdAt is authenticated".utf8)
    let result = try M10Engine.encrypt(
        data: payload, originalFilename: "t.txt", configuration: .alpha36Factory, formatVersion: 4
    )
    var archive = try M10Format.decodeArchive(result.data)
    expectEqual(archive.version, 4)
    archive.createdAt = archive.createdAt.addingTimeInterval(60)
    expectThrows({
        _ = try M10Engine.decrypt(data: try M10Format.encodeArchive(archive), configuration: .alpha36Factory)
    }, "createdAt flip")
    print("OK v4 HMAC covers createdAt")
}

func v2DowngradeNeedsLegacyImport() throws {
    let payload = Data("v2 downgrade body".utf8)
    let result = try M10Engine.encrypt(
        data: payload,
        originalFilename: "v2d.txt",
        configuration: .alpha36Factory,
        formatVersion: 2
    )
    var archive = try M10Format.decodeArchive(result.data)
    archive.version = 1
    archive.authTag = nil
    archive.kind = .folder
    let downgraded = try M10Format.encodeArchive(archive)
    expectThrows({
        _ = try M10Engine.decrypt(data: downgraded, configuration: .alpha36Factory)
    }, "v2 relabeled v1 still not opened by Decrypt")
    let imported = try M10Engine.decrypt(
        data: downgraded, configuration: .alpha36Factory, mode: .legacyImport
    )
    expect(imported.isLegacyImport)
    expectEqual(imported.payload, payload)
    print("OK v2→v1 only via Legacy Import")
}

func asciiPlugCommaIsNotADelimiter() {
    let comma = Ascii94Symbols.indexToChar(11) // ','
    let bang = Ascii94Symbols.indexToChar(0)   // '!'
    let pair = String([comma, bang])
    expectEqual(pair.count, 2)
    let parsed = M10Configuration.parsePlugPairs("AB \(pair) CD", suite: .ascii)
    expectEqual(parsed.count, 3)
    expect(parsed.contains(pair), "comma inside an ASCII-94 pair must stay in the token")
    var config = M10Configuration.ascii94Factory
    config.plugPairs = [pair, "AB"]
    expect((try? config.validated()) != nil, "ascii pair with comma validates")
    print("OK ascii plug comma")
}

func randomCodebookAlwaysValid() throws {
    for suite in M10CipherSuite.allCases {
        for i in 0..<80 {
            let config = M10Configuration.random(suite: suite)
            expect((try? config.validated()) != nil, "random \(suite) #\(i)")
        }
    }
    print("OK random codebook validates")
}

func suiteSwitchDoesNotDuplicatePlugs() throws {
    for i in 0..<80 {
        let base = M10Configuration.random(suite: .base256)
        let alpha = try base.withSuite(.alpha36).validated()
        let ascii = try base.withSuite(.ascii).validated()
        expect(alpha.plugPairs.count <= 12, "alpha plugs \(i)")
        expect(ascii.plugPairs.count <= 12, "ascii plugs \(i)")
        _ = try ascii.withSuite(.alpha36).validated()
        _ = try alpha.withSuite(.ascii).validated()
        _ = try alpha.withSuite(.base256).validated()
    }
    let colliding = M10Configuration(
        cipherSuite: .base256,
        rotorNames: M10Catalog.rotorNames,
        reflector: "UKW-M10",
        rings: M10Configuration.base256Factory.rings,
        positions: M10Configuration.base256Factory.positions,
        plugPairs: ["0001", "2402"]
    )
    let remapped = try colliding.withSuite(.alpha36).validated()
    expect(remapped.plugPairs.count == 1, "0 and 36 both become Alpha-36 0; keep one pair")
    print("OK suite switch plugs")
}

func nameFieldRoundTrip() throws {
    let field = try M10Padding.encodeNameField("a.txt")
    expectEqual(field.count, 256)
    expectEqual(try M10Padding.decodeNameField(field), "a.txt")
    expectEqual(try M10Padding.decodeNameField(try M10Padding.encodeNameField("")), "")
    var bad = field
    bad[0] = 0xFF
    bad[1] = 0xFF
    expectThrows({ _ = try M10Padding.decodeNameField(bad) }, "oversize name length")
    let cjk = String(repeating: "文", count: 200)
    let cjkDecoded = try M10Padding.decodeNameField(try M10Padding.encodeNameField(cjk))
    expect(cjk.hasPrefix(cjkDecoded), "CJK trim is a prefix")
    expect(cjkDecoded.utf8.count <= 254, "CJK fits the name field")
    expect(!cjkDecoded.isEmpty)
    let emoji = String(repeating: "🙂", count: 80)
    let emojiDecoded = try M10Padding.decodeNameField(try M10Padding.encodeNameField(emoji))
    expect(emoji.hasPrefix(emojiDecoded), "emoji trim is a prefix")
    expect(emojiDecoded.utf8.count <= 254)
    let params = try testKDF()
    let named = try M10Engine.encrypt(
        data: Data("named".utf8),
        originalFilename: cjk,
        configuration: .base256Factory,
        password: "pw",
        kdf: params
    )
    let opened = try M10Engine.decrypt(
        data: named.data, configuration: .base256Factory, password: "pw"
    )
    expectEqual(opened.filename, cjkDecoded)
    print("OK name field")
}

func internalKeyRoundTrip() throws {
    let config = M10Configuration.random(suite: .base256)
    let payload = Data("internal-key payload".utf8)
    let result = try M10Engine.encrypt(
        data: payload,
        originalFilename: "inside.bin",
        configuration: config,
        keyMode: .internalKey
    )
    expect(!result.data.starts(with: M10PasswordBinary.magicV3), "JSON not password binary")
    let text = String(decoding: result.data.prefix(min(result.data.count, 2000)), as: UTF8.self)
    expect(text.contains("\"keyMode\":\"internal\""), "keyMode internal")
    expect(text.contains("\"codebook\""), "codebook stored")
    expect(text.contains("\"rotorNames\""), "catalog rotors in codebook")
    let archive = try M10Format.parseLayout(result.data).archive
    expectEqual(archive.keyMode, "internal")
    expect(archive.codebook != nil)
    expectEqual(
        try M10Engine.decrypt(data: result.data, configuration: .base256Factory).payload,
        payload
    )
    var swapped = archive
    swapped.codebook = M10Configuration.random(suite: .base256)
    let tampered = try M10Format.encodeHybridHeader(swapped)
        + (archive.isHybrid
            ? result.data.subdata(in: Int(try M10Format.parseLayout(result.data).binaryOffset)..<result.data.count)
            : Data())
    if archive.isHybrid {
        expectThrows({
            _ = try M10Engine.decrypt(data: tampered, configuration: .base256Factory)
        }, "swapped internal codebook")
    }
    print("OK internal key roundtrip")
}

func base512SuiteRoundTrip() throws {
    let payload = Data("base512-three-modes".utf8)
    let packed = DensePack.pack(payload, suite: .base512, allowCompression: false)
    let unpacked = try DensePack.unpack(packed.symbols, info: packed.info, suite: .base512)
    expectEqual(unpacked, payload)

    let machine = try M10Machine(configuration: .base512Factory)
    let sample = String(Base512Symbols.alphabet.prefix(8))
    let cipher = machine.processMessage(sample)
    machine.resetPositions()
    expectEqual(machine.processMessage(cipher), sample)

    let params = try testKDF()
    let pw = try M10Engine.encrypt(
        data: payload,
        originalFilename: "b512.bin",
        configuration: .base512Factory,
        password: "pw",
        kdf: params
    )
    expect(pw.data.starts(with: M10PasswordBinary.magicV4))
    expectEqual(
        try M10Engine.decrypt(data: pw.data, configuration: .base512Factory, password: "pw").payload,
        payload
    )

    let config = M10Configuration.random(suite: .base512)
    let ext = try M10Engine.encrypt(
        data: payload,
        originalFilename: "b512.bin",
        configuration: config,
        keyMode: .external
    )
    expectEqual(
        try M10Engine.decrypt(data: ext.data, configuration: config).payload,
        payload
    )

    let inner = try M10Engine.encrypt(
        data: payload,
        originalFilename: "b512.bin",
        configuration: config,
        keyMode: .internalKey
    )
    expectEqual(
        try M10Engine.decrypt(data: inner.data, configuration: .base512Factory).payload,
        payload
    )
    let name = M10Format.suggestedArchiveFilename(
        encryptedSymbols: String(Base512Symbols.alphabet),
        suite: .base512
    )
    expect(name.utf8.count <= 255, "Base-512 archive name fits APFS")
    expect(name.hasSuffix(".enigmam10"))
    for name in M10Catalog.rotorNames {
        let n = M10Catalog.Base512.notchSet(name).count
        expect(n >= 8 && n <= 22, "catalog \(name) has \(n) notches")
    }
    let master = Data(repeating: 0x5A, count: 32)
    let derived = try M10Password.expandConfiguration(master: master, suite: .base512)
    for notches in derived.derivedMachine!.rotorNotches {
        expect(notches.count >= 8 && notches.count <= 22, "derived notches \(notches.count)")
    }
    for name in M10Catalog.rotorNames {
        expect(M10Catalog.Base512.notchSet(name, scaled: false).count <= 2, "v6 catalog \(name)")
        let n = M10Catalog.Base512.notchSet(name, scaled: true).count
        expect(n >= 8 && n <= 22, "v7 catalog \(name)")
    }
    print("OK base512 three modes")
}

func base512NotchVersionIdentity() throws {
    let payload = Data("Origin story of how pirate Captain Jankface, got his unique name".utf8)
    let config = M10Configuration.random(suite: .base512)
    let v7 = try M10Engine.encrypt(
        data: payload, originalFilename: "story.txt", configuration: config, keyMode: .internalKey
    )
    expectEqual(try M10Format.parseLayout(v7.data).archive.version, 7)
    expectEqual(try M10Engine.decrypt(data: v7.data, configuration: .base512Factory).payload, payload)

    let v6legacy = try M10Engine.encrypt(
        data: payload, originalFilename: "story.txt", configuration: config,
        formatVersion: 6, keyMode: .internalKey
    )
    expectEqual(try M10Format.parseLayout(v6legacy.data).archive.version, 6)
    expectEqual(try M10Engine.decrypt(data: v6legacy.data, configuration: .base512Factory).payload, payload)

    let v6scaled = try M10Engine.encrypt(
        data: payload, originalFilename: "story.txt", configuration: config,
        formatVersion: 6, keyMode: .internalKey, forceScaledNotches: true
    )
    expectEqual(try M10Format.parseLayout(v6scaled.data).archive.version, 6)
    expectEqual(try M10Engine.decrypt(data: v6scaled.data, configuration: .base512Factory).payload, payload)
    expect(v6legacy.data != v6scaled.data, "v6 1–2-notch ciphertext differs from v6 20-notch")

    let params = try testKDF()
    let pw7 = try M10Engine.encrypt(
        data: payload, originalFilename: "story.txt", configuration: .base512Factory,
        password: "pw", kdf: params
    )
    expect(pw7.data.starts(with: M10PasswordBinary.magicV4))
    expectEqual(
        try M10Engine.decrypt(data: pw7.data, configuration: .base512Factory, password: "pw").payload,
        payload
    )
    let pw6 = try M10Engine.encrypt(
        data: payload, originalFilename: "story.txt", configuration: .base512Factory,
        password: "pw", kdf: params, formatVersion: 6
    )
    expect(pw6.data.starts(with: M10PasswordBinary.magicV3))
    expectEqual(
        try M10Engine.decrypt(data: pw6.data, configuration: .base512Factory, password: "pw").payload,
        payload
    )
    print("OK base512 notch version identity")
}

func testKDF() throws -> M10KDFParams {
    var params = try M10KDFParams.freshSalt()
    params.memoryKiB = 32
    params.iterations = 1
    return params
}

func automaticPaddingHidesSizes() throws {
    let params = try testKDF()
    let password = "pad-secret"
    let payload = Data(repeating: 0x41, count: 12345)
    let result = try M10Engine.encrypt(
        data: payload,
        originalFilename: "sized.bin",
        configuration: .base256Factory,
        password: password,
        kdf: params
    )
    expect(result.data.starts(with: M10PasswordBinary.magicV4), "PW04")
    let parsed = try M10PasswordBinary.parse(result.data)
    expectEqual(parsed.archive.payloadOriginalBytes, 0)
    expectEqual(parsed.archive.payloadStoredBytes, 0)
    expectEqual(parsed.archive.crc32, 0)
    expect(parsed.ciphertext.count % 4096 == 0, "4 KiB aligned")
    expect(parsed.ciphertext.count != 12345, "on-disk size is not plaintext size")
    expect(parsed.ciphertext.count != payload.count, "on-disk size is not payload")
    var needle = Data()
    var orig = UInt64(12345).bigEndian
    needle.append(Data(bytes: &orig, count: 8))
    expect(result.data.range(of: needle) == nil, "plaintext length not in public bytes")
    let decrypted = try M10Engine.decrypt(
        data: result.data, configuration: .base256Factory, password: password
    )
    expectEqual(decrypted.payload, payload)

    let empty = try M10Engine.encrypt(
        data: Data(),
        originalFilename: "empty.bin",
        configuration: .base256Factory,
        password: password,
        kdf: params
    )
    let emptyParsed = try M10PasswordBinary.parse(empty.data)
    expectEqual(emptyParsed.ciphertext.count, 4096, "empty still one 4 KiB block")

    expectEqual(M10Padding.boundary(forUnpaddedCount: 100), 4_096)
    expectEqual(M10Padding.boundary(forUnpaddedCount: 65_536), 65_536)
    let large = try M10MessageKey.randomBytes(80_000)
    let largeResult = try M10Engine.encrypt(
        data: large,
        originalFilename: "large.bin",
        configuration: .base256Factory,
        password: password,
        kdf: params
    )
    let largeParsed = try M10PasswordBinary.parse(largeResult.data)
    expect(largeParsed.ciphertext.count % 65_536 == 0, "64 KiB boundary for larger inner")
    expectEqual(
        try M10Engine.decrypt(data: largeResult.data, configuration: .base256Factory, password: password).payload,
        large
    )

    let json = try M10Engine.encrypt(
        data: payload,
        originalFilename: "ext.txt",
        configuration: .alpha36Factory
    )
    let archive = try M10Format.decodeArchive(json.data)
    expectEqual(archive.version, 7)
    expectEqual(archive.payloadOriginalBytes, 0, "JSON v6 hides originalBytes")
    expectEqual(archive.crc32, 0, "JSON v6 hides crc")
    expectEqual(
        try M10Engine.decrypt(data: json.data, configuration: .alpha36Factory).payload,
        payload
    )
    let zeros = Data(repeating: 0, count: 80_000)
    let zerosResult = try M10Engine.encrypt(
        data: zeros,
        originalFilename: "zeros.bin",
        configuration: .base256Factory,
        password: password,
        kdf: params
    )
    let zerosParsed = try M10PasswordBinary.parse(zerosResult.data)
    expect(zerosParsed.ciphertext.count % 65_536 == 0, "large original uses 64 KiB bucket even if zlib shrinks")
    expect(zerosParsed.ciphertext.count >= 65_536, "not a 4 KiB blob")
    expectEqual(
        try M10Engine.decrypt(data: zerosResult.data, configuration: .base256Factory, password: password).payload,
        zeros
    )

    let shortName = try M10Engine.encrypt(
        data: Data("n".utf8),
        originalFilename: "a.txt",
        configuration: .base256Factory,
        password: password,
        kdf: params
    ).data
    let longName = try M10Engine.encrypt(
        data: Data("n".utf8),
        originalFilename: "quarterly-payroll-2026.xlsx",
        configuration: .base256Factory,
        password: password,
        kdf: params
    ).data
    let shortLayout = try pw03Layout(shortName)
    let longLayout = try pw03Layout(longName)
    expectEqual(shortLayout.nameLen, M10Padding.nameFieldBytes)
    expectEqual(longLayout.nameLen, M10Padding.nameFieldBytes)
    expectEqual(
        try M10Engine.decrypt(data: shortName, configuration: .base256Factory, password: password).filename,
        "a.txt"
    )
    expectEqual(
        try M10Engine.decrypt(data: longName, configuration: .base256Factory, password: password).filename,
        "quarterly-payroll-2026.xlsx"
    )
    print("OK automatic padding hides sizes")
}

func legacyPasswordBlobStillDecrypts() throws {
    let params = try testKDF()
    let password = "old-pw"
    let payload = Data("m10pw01 still opens".utf8)
    let result = try M10Engine.encrypt(
        data: payload,
        originalFilename: "old.txt",
        configuration: .base256Factory,
        password: password,
        kdf: params,
        formatVersion: 4
    )
    expect(result.data.starts(with: M10PasswordBinary.magicV1), "PW01")
    let parsed = try M10PasswordBinary.parse(result.data)
    expectEqual(parsed.archive.payloadOriginalBytes, payload.count)
    expectEqual(
        try M10Engine.decrypt(data: result.data, configuration: .base256Factory, password: password).payload,
        payload
    )
    print("OK M10PW01 decrypt preserved")
}

func sealedInnerCrcMismatch() throws {
    let payload = Data("crc-inside".utf8)
    let (packed, info) = DensePack.pack(payload, suite: .base256, allowCompression: false)
    let wire = Base256Symbols.latin1Data(packed) ?? Data()
    var inner = try M10SealedPayload.wrapBytes(crc: CRC32.hash(payload), info: info, packed: wire)
    inner[0] ^= 0xFF
    let parsed = try M10SealedPayload.unwrapBytes(inner)
    expect(parsed.crc != CRC32.hash(payload), "flipped inner CRC")
    expectThrows({
        var bad = try M10SealedPayload.wrapBytes(crc: CRC32.hash(payload), info: info, packed: wire)
        bad[20] = 0x02
        _ = try M10SealedPayload.unwrapBytes(bad)
    }, "unknown inner flag")
    expectThrows({
        _ = try M10SealedPayload.unwrapBytes(Data(repeating: 0, count: 10))
    }, "truncated inner")
    var huge = try M10SealedPayload.wrapBytes(crc: 0, info: info, packed: wire)
    huge[4] = 0xFF
    huge[5] = 0xFF
    huge[6] = 0xFF
    huge[7] = 0xFF
    huge[8] = 0xFF
    huge[9] = 0xFF
    huge[10] = 0xFF
    huge[11] = 0xFF
    expectThrows({ _ = try M10SealedPayload.unwrapBytes(huge) }, "absurd originalBytes")
    print("OK inner CRC / flag fuzz")
}

struct SplitMix64: RandomNumberGenerator {
    var state: UInt64
    mutating func next() -> UInt64 {
        state &+= 0x9E3779B97F4A7C15
        var z = state
        z = (z ^ (z >> 30)) &* 0xBF58476D1CE4E5B9
        z = (z ^ (z >> 27)) &* 0x94D049BB133111EB
        return z ^ (z >> 31)
    }
}

struct PW03Layout {
    var saltLenOff: Int
    var nameLenOff: Int
    var nameOff: Int
    var nameLen: Int
    var tagOff: Int
    var ctOff: Int
}

func pw03Layout(_ blob: Data) throws -> PW03Layout {
    guard blob.count > 20 else { throw M10Error.invalidFormat }
    let saltLenOff = 7 + 1 + 4 + 4 + 1 + 1
    let saltLen = Int(blob[saltLenOff])
    let nameLenOff = saltLenOff + 1 + saltLen + 16
    guard blob.count > nameLenOff + 2 else { throw M10Error.invalidFormat }
    let nameLen = (Int(blob[nameLenOff]) << 8) | Int(blob[nameLenOff + 1])
    let nameOff = nameLenOff + 2
    let tagOff = nameOff + nameLen
    let ctOff = tagOff + 32
    return PW03Layout(
        saltLenOff: saltLenOff,
        nameLenOff: nameLenOff,
        nameOff: nameOff,
        nameLen: nameLen,
        tagOff: tagOff,
        ctOff: ctOff
    )
}

func parserFuzz() throws {
    expectThrows({ _ = try M10PasswordBinary.parse(Data()) }, "empty")
    expectThrows({ _ = try M10PasswordBinary.parse(Data("M10PW03".utf8)) }, "truncated magic")
    expectThrows({ _ = try M10Format.decodeArchive(Data()) }, "empty JSON")
    expectThrows({ _ = try M10Format.decodeArchive(Data("ENIGMAM10 v6\n".utf8)) }, "header only")
    expectThrows({ _ = try M10Format.decodeArchive(Data("ENIGMAM10 v99\n{}".utf8)) }, "unsupported version")
    expectThrows({ _ = try M10Format.decodeArchive(Data("ENIGMAM10 v6\n{".utf8)) }, "truncated JSON")
    expectThrows({
        _ = try M10Format.decodeArchive(Data("ENIGMAM10 v6\n{\"version\":6,\"kind\":\"file\"}".utf8))
    }, "JSON missing required fields")

    let params = try testKDF()
    let blob = try M10Engine.encrypt(
        data: Data("fuzz".utf8),
        originalFilename: "f.bin",
        configuration: .base256Factory,
        password: "pw",
        kdf: params
    ).data
    let layout = try pw03Layout(blob)
    let parsed = try M10PasswordBinary.parse(blob)
    expectEqual(Int(parsed.binaryOffset), layout.ctOff)

    expectThrows({
        var short = blob
        short.removeLast(max(1, blob.count / 2))
        _ = try M10PasswordBinary.parse(short)
    }, "truncated archive")
    expectThrows({
        var odd = blob
        odd.append(0x00)
        _ = try M10PasswordBinary.parse(odd)
    }, "ciphertext not 4 KiB aligned")

    var hugeName = blob
    hugeName[layout.nameLenOff] = 0xFF
    hugeName[layout.nameLenOff + 1] = 0xFF
    expectThrows({ _ = try M10PasswordBinary.parse(hugeName) }, "absurd nameLen")

    var badSalt = blob
    badSalt[layout.saltLenOff] = 1
    expectThrows({ _ = try M10PasswordBinary.parse(badSalt) }, "saltLen too small")
    badSalt[layout.saltLenOff] = 255
    expectThrows({ _ = try M10PasswordBinary.parse(badSalt) }, "saltLen too large")

    var badIter = blob
    let iterOffset = 7 + 1 + 4
    for i in 0..<4 { badIter[iterOffset + i] = 0 }
    expectThrows({ _ = try M10PasswordBinary.parse(badIter) }, "iterations 0")

    var badMem = blob
    let memOffset = 7 + 1
    for i in 0..<4 { badMem[memOffset + i] = 0 }
    expectThrows({ _ = try M10PasswordBinary.parse(badMem) }, "memoryKiB 0")

    var badPar = blob
    badPar[16] = 0
    expectThrows({ _ = try M10PasswordBinary.parse(badPar) }, "parallelism 0")
    badPar = blob
    badPar[17] = 1
    expectThrows({ _ = try M10PasswordBinary.parse(badPar) }, "hashLength 1")
    badPar = blob
    badPar[17] = 255
    expectThrows({ _ = try M10PasswordBinary.parse(badPar) }, "hashLength 255")

    var badFlags = blob
    badFlags[7] |= 0b10
    expectThrows({ _ = try M10PasswordBinary.parse(badFlags) }, "unknown zlib flag on PW03")
    badFlags = blob
    badFlags[7] |= 0b1000_0000
    expectThrows({ _ = try M10PasswordBinary.parse(badFlags) }, "unknown high flag")
    badFlags = blob
    badFlags[7] = (badFlags[7] & 0b1110_0111) | (0b11 << 3)
    expectThrows({ _ = try M10PasswordBinary.parse(badFlags) }, "suite code 3")

    let truncatedTag = Data(blob.prefix(layout.tagOff + 16))
    expectThrows({ _ = try M10PasswordBinary.parse(truncatedTag) }, "truncated tag")

    var badUTF = try M10Engine.encrypt(
        data: Data("utf8".utf8),
        originalFilename: "plain.txt",
        configuration: .base256Factory,
        encryptFilename: false,
        password: "pw",
        kdf: params
    ).data
    let utfLayout = try pw03Layout(badUTF)
    expectEqual(utfLayout.nameLen, M10Padding.nameFieldBytes)
    if utfLayout.nameLen > 2 {
        badUTF[utfLayout.nameOff] = 0xFF
        badUTF[utfLayout.nameOff + 1] = 0xFF
        _ = try M10PasswordBinary.parse(badUTF)
        expectThrows({
            _ = try M10Engine.decrypt(data: badUTF, configuration: .base256Factory, password: "pw")
        }, "absurd padded name length")
    }

    let prefixURL = FileManager.default.temporaryDirectory.appendingPathComponent("m10_prefix_\(UUID().uuidString).enigmam10")
    try blob.write(to: prefixURL)
    defer { try? FileManager.default.removeItem(at: prefixURL) }
    let viaPrefix = try M10PasswordBinary.readPrefix(at: prefixURL)
    expectEqual(viaPrefix.archive.payloadLength, parsed.ciphertext.count)

    var unaligned = blob
    unaligned.append(0x00)
    let unalignedURL = FileManager.default.temporaryDirectory.appendingPathComponent("m10_unaligned_\(UUID().uuidString).enigmam10")
    try unaligned.write(to: unalignedURL)
    defer { try? FileManager.default.removeItem(at: unalignedURL) }
    expectThrows({ _ = try M10PasswordBinary.readPrefix(at: unalignedURL) }, "readPrefix rejects unaligned")

    _ = try M10PasswordBinary.parse(blob)
    print("OK parser fuzz")
}

func jsonV6RejectsUnaligned() throws {
    let result = try M10Engine.encrypt(
        data: Data("align-me".utf8),
        originalFilename: "a.txt",
        configuration: .alpha36Factory
    )
    var archive = try M10Format.decodeArchive(result.data)
    expectEqual(archive.version, 7)
    archive.ciphertext = "ABC"
    expectThrows({
        _ = try M10Format.decodeArchive(try M10Format.encodeArchive(archive))
    }, "v6 inline not 4 KiB aligned")

    let hybrid = try M10Engine.encrypt(
        data: Data((0..<400).map { UInt8($0 & 0xFF) }),
        originalFilename: "b.bin",
        configuration: .base256Factory
    )
    let layout = try M10Format.parseLayout(hybrid.data)
    var hybridArchive = layout.archive
    hybridArchive.payloadLength = 1
    let broken = try M10Format.encodeHybridHeader(hybridArchive) + Data([0x00])
    expectThrows({ _ = try M10Format.parseLayout(broken) }, "v6 hybrid not 4 KiB aligned")
    print("OK JSON v6 alignment")
}

func streamingPasswordRoundTrip() throws {
    let params = try testKDF()
    let dir = FileManager.default.temporaryDirectory.appendingPathComponent("m10_pwstream_\(UUID().uuidString)")
    try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
    defer { try? FileManager.default.removeItem(at: dir) }
    let payload = try M10MessageKey.randomBytes(1_100_000)
    let source = dir.appendingPathComponent("big.bin")
    try payload.write(to: source)
    let encrypted = try M10Engine.encryptFile(
        at: source,
        configuration: .base256Factory,
        password: "stream-pw",
        kdf: params
    )
    let archiveURL = try M10Engine.writeEncryptResult(encrypted, nextTo: source)
    let size = (try FileManager.default.attributesOfItem(atPath: archiveURL.path)[.size] as? NSNumber)?.intValue ?? 0
    expect(size > 1_048_576, "archive larger than readPrefix window")
    let prefix = try M10PasswordBinary.readPrefix(at: archiveURL)
    expect(prefix.archive.payloadLength ?? 0 > 1_048_576, "ciphertext spans past 1 MiB window")
    expectEqual((prefix.archive.payloadLength ?? 1) % 4096, 0)
    let decrypted = try M10Engine.decryptFile(
        at: archiveURL, configuration: .base256Factory, password: "stream-pw"
    )
    let dest = try M10Engine.writeDecryptResult(decrypted, nextTo: archiveURL)
    expectEqual(try Data(contentsOf: dest), payload)
    print("OK streaming password roundtrip")
}

func sealedInnerCrcRejectedByDecrypt() throws {
    let params = try testKDF()
    let password = "crc-pw"
    let payload = Data("crc-inside-engine".utf8)
    let derived = try M10Password.deriveConfiguration(password: password, suite: .base256, params: params)
    let nonce = try M10MessageKey.randomNonce()
    let bodyConfig = try M10MessageKey.apply(
        derived.configuration, nonce: nonce, domain: .payload, unbiasedPositions: true
    )
    let machine = try M10Machine(configuration: bodyConfig)
    let (packed, info) = DensePack.pack(payload, suite: .base256, allowCompression: false)
    let wire = Base256Symbols.latin1Data(packed) ?? Data()
    let inner = try M10SealedPayload.wrapBytes(crc: 0xDEADBEEF, info: info, packed: wire)
    let ciphertext = machine.processBytes(inner)
    let blob = try M10PasswordBinary.encode(
        kind: .file,
        suite: .base256,
        kdf: params,
        nonce: nonce,
        originalBytes: 0,
        storedBytes: 0,
        zlib: false,
        crc32: 0,
        nameEncrypted: false,
        nameBytes: Data("x.bin".utf8),
        ciphertext: ciphertext,
        authKey: M10Password.authKey(master: derived.master)
    )
    expectThrows({
        _ = try M10Engine.decrypt(data: blob, configuration: .base256Factory, password: password)
    }, "wrong inner CRC after valid HMAC")
    print("OK inner CRC rejected on decrypt")
}

func randomMutationFuzz() throws {
    let params = try testKDF()
    let blob = try M10Engine.encrypt(
        data: Data("mutation-corpus".utf8),
        originalFilename: "corpus.bin",
        configuration: .base256Factory,
        password: "pw",
        kdf: params
    ).data
    let layout = try pw03Layout(blob)
    var rng = SplitMix64(state: 0x4D313033)
    var parsedOK = 0
    var threw = 0
    let tmp = FileManager.default.temporaryDirectory.appendingPathComponent("m10_mut_\(UUID().uuidString)")
    defer { try? FileManager.default.removeItem(at: tmp) }

    func mutate(_ original: Data) -> Data {
        var mutant = original
        let mode = Int.random(in: 0..<6, using: &rng)
        switch mode {
        case 0:
            let headerEnd = min(layout.ctOff, mutant.count)
            guard headerEnd > 0 else { break }
            let flips = Int.random(in: 1...8, using: &rng)
            for _ in 0..<flips {
                let index = Int.random(in: 0..<headerEnd, using: &rng)
                mutant[index] ^= UInt8.random(in: 1...255, using: &rng)
            }
        case 1:
            if mutant.count > layout.ctOff {
                let flips = Int.random(in: 1...8, using: &rng)
                for _ in 0..<flips {
                    let index = Int.random(in: layout.ctOff..<mutant.count, using: &rng)
                    mutant[index] ^= UInt8.random(in: 1...255, using: &rng)
                }
            }
        case 2:
            if mutant.count > 1 {
                mutant.removeLast(Int.random(in: 1...mutant.count, using: &rng))
            } else {
                mutant = Data()
            }
        case 3:
            let extra = (0..<Int.random(in: 1...128, using: &rng)).map { _ in
                UInt8.random(in: 0...255, using: &rng)
            }
            mutant.append(contentsOf: extra)
        case 4:
            if !mutant.isEmpty {
                let index = Int.random(in: 0...mutant.count, using: &rng)
                mutant.insert(UInt8.random(in: 0...255, using: &rng), at: index)
            }
        default:
            mutant = Data((0..<Int.random(in: 0...48, using: &rng)).map { _ in
                UInt8.random(in: 0...255, using: &rng)
            })
        }
        return mutant
    }

    for _ in 0..<1500 {
        let mutant = mutate(blob)
        do {
            _ = try M10PasswordBinary.parse(mutant)
            parsedOK += 1
        } catch {
            threw += 1
        }
        try? mutant.write(to: tmp)
        do {
            _ = try M10PasswordBinary.readPrefix(at: tmp)
        } catch {
            // throw or return is success; crash would fail the process
        }
    }
    expectEqual(parsedOK + threw, 1500, "every mutant parse returned or threw")

    var decryptThrew = 0
    for _ in 0..<80 {
        var mutant = blob
        let flips = Int.random(in: 1...8, using: &rng)
        for _ in 0..<flips where !mutant.isEmpty {
            let index = Int.random(in: 0..<mutant.count, using: &rng)
            mutant[index] ^= UInt8.random(in: 1...255, using: &rng)
        }
        do {
            _ = try M10Engine.decrypt(
                data: mutant, configuration: .base256Factory, password: "pw"
            )
        } catch {
            decryptThrew += 1
        }
    }
    expectEqual(decryptThrew, 80, "mutated ciphertext must not decrypt")
    print("OK random mutation fuzz (\(threw) threw, \(parsedOK) parsed)")
}

func fuzzDecrypt(_ data: Data, password: String? = nil) {
    let modes: [M10DecryptMode] = [.authenticated, .legacyImport]
    for suite in M10CipherSuite.allCases {
        let config = M10Configuration.factory(for: suite)
        for mode in modes {
            do {
                _ = try M10Engine.decrypt(
                    data: data, configuration: config, mode: mode, password: password
                )
            } catch {
                // throw or return; a trap fails the process
            }
        }
    }
}

func hybridOffsetOverflowThrows() throws {
    let result = try M10Engine.encrypt(
        data: Data("hybrid-overflow".utf8),
        originalFilename: "h.bin",
        configuration: .base256Factory,
        formatVersion: 4
    )
    let layout = try M10Format.parseLayout(result.data)
    var archive = layout.archive
    archive.payloadOffset = Int.max
    archive.payloadLength = 4096
    let binary = result.data.subdata(in: Int(layout.binaryOffset)..<result.data.count)
    let crafted = try M10Format.encodeHybridHeader(archive) + binary
    expectThrows({
        _ = try M10Engine.decrypt(data: crafted, configuration: .base256Factory)
    }, "hybrid offset overflow")
    print("OK hybrid offset overflow")
}

func legacyHugeStoredBytesThrows() throws {
    let payload = Data("legacy v1 body".utf8)
    let machine = try M10Machine(configuration: .alpha36Factory)
    let packed = DensePack.pack(payload, suite: .alpha36)
    machine.resetPositions()
    let ciphertext = machine.processMessageInChunks(packed.symbols)
    let archive = M10Format.Archive(
        version: 1,
        kind: .file,
        cipherSuite: .alpha36,
        originalFilename: "legacy.txt",
        encryptedFilename: nil,
        ciphertext: ciphertext,
        createdAt: Date(),
        payloadOriginalBytes: packed.info.originalBytes,
        payloadStoredBytes: Int.max,
        payloadCodec: packed.info.codec.jsonField,
        crc32: CRC32.hash(payload)
    )
    let data = try M10Format.encodeArchive(archive)
    expectThrows({
        _ = try M10Engine.decrypt(data: data, configuration: .alpha36Factory, mode: .legacyImport)
    }, "huge storedBytes")
    expect(DensePack.dense36Decode("AAAAA", storedLength: Int.max) == nil, "decodeSymbols rejects Int.max")
    print("OK huge storedBytes")
}

func decryptMutationFuzz() throws {
    let jsonV6 = try M10Engine.encrypt(
        data: Data("json-v6-fuzz".utf8),
        originalFilename: "j.txt",
        configuration: .alpha36Factory
    ).data
    let jsonV4 = try M10Engine.encrypt(
        data: Data("json-v4-hybrid".utf8),
        originalFilename: "h.bin",
        configuration: .base256Factory,
        formatVersion: 4
    ).data
    let v1Machine = try M10Machine(configuration: .alpha36Factory)
    let packed = DensePack.pack(Data("v1-fuzz".utf8), suite: .alpha36)
    v1Machine.resetPositions()
    let v1 = try M10Format.encodeArchive(M10Format.Archive(
        version: 1,
        kind: .file,
        cipherSuite: .alpha36,
        originalFilename: "v1.txt",
        encryptedFilename: nil,
        ciphertext: v1Machine.processMessageInChunks(packed.symbols),
        createdAt: Date(),
        payloadOriginalBytes: packed.info.originalBytes,
        payloadStoredBytes: packed.info.storedBytes,
        payloadCodec: packed.info.codec.jsonField,
        crc32: CRC32.hash(Data("v1-fuzz".utf8))
    ))
    let params = try testKDF()
    let passwordBlob = try M10Engine.encrypt(
        data: Data("pw-fuzz".utf8),
        originalFilename: "p.bin",
        configuration: .base256Factory,
        password: "pw",
        kdf: params
    ).data

    var rng = SplitMix64(state: 0x44534352)
    func mutate(_ original: Data) -> Data {
        var mutant = original
        if mutant.isEmpty { return Data([UInt8.random(in: 0...255, using: &rng)]) }
        let mode = Int.random(in: 0..<5, using: &rng)
        switch mode {
        case 0:
            let flips = Int.random(in: 1...12, using: &rng)
            for _ in 0..<flips {
                let index = Int.random(in: 0..<mutant.count, using: &rng)
                mutant[index] ^= UInt8.random(in: 1...255, using: &rng)
            }
        case 1:
            mutant.removeLast(Int.random(in: 1...max(1, mutant.count / 2), using: &rng))
        case 2:
            mutant.append(contentsOf: (0..<Int.random(in: 1...64, using: &rng)).map { _ in
                UInt8.random(in: 0...255, using: &rng)
            })
        case 3:
            let index = Int.random(in: 0...mutant.count, using: &rng)
            mutant.insert(UInt8.random(in: 0...255, using: &rng), at: index)
        default:
            if let off = Int(exactly: UInt8.random(in: 0...255, using: &rng)), off + 8 <= mutant.count {
                for i in 0..<8 { mutant[off + i] = 0xFF }
            }
        }
        return mutant
    }

    let corpora = [jsonV6, jsonV4, v1, passwordBlob]
    for original in corpora {
        fuzzDecrypt(original, password: "pw")
        for _ in 0..<200 {
            fuzzDecrypt(mutate(original), password: "pw")
        }
    }
    print("OK decrypt mutation fuzz")
}

func factoryValidation() {
    expect(try! M10Configuration.alpha36Factory.validated() == M10Configuration.alpha36Factory.validated())
    expect(try! M10Configuration.ascii94Factory.validated() == M10Configuration.ascii94Factory.validated())
    expect(try! M10Configuration.base256Factory.validated() == M10Configuration.base256Factory.validated())
    var bad = M10Configuration.alpha36Factory
    bad.rotorNames = Array(M10Catalog.rotorNames.prefix(9))
    expectThrows({ _ = try bad.validated() }, "need 10 rotors")
    print("OK validation")
}

catalogPermutationsAreValid()
selfTest()
roundTripText()
densePackRoundTrip()
pairCodecRoundTrip()
asciiPlugCommaIsNotADelimiter()
factoryValidation()
do {
    try randomCodebookAlwaysValid()
    try suiteSwitchDoesNotDuplicatePlugs()
    try nameFieldRoundTrip()
    try internalKeyRoundTrip()
    try base512SuiteRoundTrip()
    try base512NotchVersionIdentity()
} catch {
    failures += 1
    print("FAIL thrown: \(error)")
}
do {
    try archiveOmitsSettings()
    try wrongSettingsFail()
    try ascii94ArchiveRoundTrip()
    try base256ArchiveRoundTrip()
    try base256FilenamePreservesCRLF()
    try base256LegacyRawFilenameStillDecrypts()
    try packFileMatchesMemory()
    try streamingRoundTrip()
    try nonceAndAuth()
    try authTagRejectsTamper()
    try legacyArchiveWithoutNonceStillDecrypts()
    try v2RequiresNonceAndAuth()
    try v2AuthCoversKind()
    try downgradeToV1IsRejected()
    try sidecarCodebookRoundTrip()
    try passwordModeRoundTrip()
    try carrySteppingDoesNotBurst()
    try v2ArchivesStillDecrypt()
    try v3ArchivesStillDecrypt()
    try v4HmacCoversCreatedAt()
    try v2DowngradeNeedsLegacyImport()
    try automaticPaddingHidesSizes()
    try legacyPasswordBlobStillDecrypts()
    try sealedInnerCrcMismatch()
    try parserFuzz()
    try jsonV6RejectsUnaligned()
    try streamingPasswordRoundTrip()
    try sealedInnerCrcRejectedByDecrypt()
    try randomMutationFuzz()
    try hybridOffsetOverflowThrows()
    try legacyHugeStoredBytesThrows()
    try decryptMutationFuzz()
} catch {
    failures += 1
    print("FAIL thrown: \(error)")
}

if failures == 0 {
    print("ALL TESTS PASSED")
    exit(0)
} else {
    print("\(failures) FAILURES")
    exit(1)
}

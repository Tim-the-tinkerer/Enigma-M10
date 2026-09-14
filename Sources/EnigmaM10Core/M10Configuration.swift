import Foundation

public enum M10CipherSuite: String, Codable, CaseIterable, Identifiable, Sendable {
    case alpha36
    case ascii
    case base256

    public var id: String { rawValue }

    public var title: String {
        switch self {
        case .alpha36: return "Alpha-36"
        case .ascii: return "ASCII-94"
        case .base256: return "Base-256"
        }
    }

    public var detail: String {
        switch self {
        case .alpha36:
            return "0–9A–Z · dense base-36 packing from EnigmaVault"
        case .ascii:
            return "!–~ printable ASCII · dense base-94 packing from EnigmaVault"
        case .base256:
            return "all 256 bytes · 1:1 packing after optional zlib"
        }
    }

    public var alphabetSize: Int {
        switch self {
        case .alpha36: return Alpha36Symbols.alphabetSize
        case .ascii: return Ascii94Symbols.alphabetSize
        case .base256: return Base256Symbols.alphabetSize
        }
    }

    public var alphabet: String {
        switch self {
        case .alpha36: return Alpha36Symbols.alphabet
        case .ascii: return Ascii94Symbols.alphabet
        case .base256: return Base256Symbols.alphabet
        }
    }

    public var usesHexSettings: Bool { self == .base256 }

    public var fieldPlaceholder: String {
        usesHexSettings ? "20 hex digits" : "10 symbols"
    }

    public var plugPlaceholder: String {
        usesHexSettings ? "A1B2 C3D4 …" : "A0 B1 C2 …"
    }

    public func charToIndex(_ character: Character) -> Int? {
        switch self {
        case .alpha36: return Alpha36Symbols.charToIndex(character)
        case .ascii: return Ascii94Symbols.charToIndex(character)
        case .base256: return Base256Symbols.charToIndex(character)
        }
    }

    public func indexToChar(_ index: Int) -> Character {
        switch self {
        case .alpha36: return Alpha36Symbols.indexToChar(index)
        case .ascii: return Ascii94Symbols.indexToChar(index)
        case .base256: return Base256Symbols.indexToChar(index)
        }
    }
}

public struct M10Configuration: Equatable, Codable, Sendable {
    public var cipherSuite: M10CipherSuite
    public var rotorNames: [String]
    public var reflector: String
    public var rings: String
    public var positions: String
    public var plugPairs: [String]
    /// Password-derived wirings. Never written to `.enigmam10` or `.m10key`.
    public var derivedMachine: M10DerivedMachine? = nil

    public init(
        cipherSuite: M10CipherSuite,
        rotorNames: [String],
        reflector: String,
        rings: String,
        positions: String,
        plugPairs: [String],
        derivedMachine: M10DerivedMachine? = nil
    ) {
        self.cipherSuite = cipherSuite
        self.rotorNames = rotorNames
        self.reflector = reflector
        self.rings = rings
        self.positions = positions
        self.plugPairs = plugPairs
        self.derivedMachine = derivedMachine
    }

    enum CodingKeys: String, CodingKey {
        case cipherSuite
        case rotorNames
        case reflector
        case rings
        case positions
        case plugPairs
    }

    /// Factory daily key for Alpha-36. Never written into `.enigmam10` archives.
    public static let alpha36Factory = M10Configuration(
        cipherSuite: .alpha36,
        rotorNames: ["X", "VII", "III", "IX", "I", "VI", "II", "VIII", "V", "IV"],
        reflector: "UKW-M10",
        rings: "T7O6AR65JS",
        positions: "ZENRR8AQVH",
        plugPairs: ["A0", "B1", "C2", "D3", "E4", "F5", "G6", "H7", "I8", "J9", "KL", "MN"]
    )

    /// Factory daily key for ASCII-94. Never written into `.enigmam10` archives.
    public static let ascii94Factory = M10Configuration(
        cipherSuite: .ascii,
        rotorNames: ["X", "VII", "III", "IX", "I", "VI", "II", "VIII", "V", "IV"],
        reflector: "UKW-M10",
        rings: "k#M9q+R5b!",
        positions: "N4p&W1h^C~",
        plugPairs: ["A0", "B1", "C2", "D3", "E4", "F5", "G6", "H7", "I8", "J9", "K{", "L}"]
    )

    /// Factory daily key for Base-256. Rings/positions/plugs are hex.
    public static let base256Factory = M10Configuration(
        cipherSuite: .base256,
        rotorNames: ["X", "VII", "III", "IX", "I", "VI", "II", "VIII", "V", "IV"],
        reflector: "UKW-M10",
        rings: "16B254A41D32BCAADFC1",
        positions: "ACEB432F0A870737BE96",
        plugPairs: ["49CA", "B9C1", "21EF", "5446", "FC7C", "9AFA", "4E81", "28D1", "5C24", "2F43", "F8BD", "5700"]
    )

    public static func factory(for suite: M10CipherSuite) -> M10Configuration {
        switch suite {
        case .alpha36: return alpha36Factory
        case .ascii: return ascii94Factory
        case .base256: return base256Factory
        }
    }

    /// Public demonstration codebook shipped in the app. Anyone with the source
    /// or a stock build can decrypt archives made with these settings.
    public var isFactory: Bool {
        self == M10Configuration.factory(for: cipherSuite)
            || self == M10Configuration.alpha36Factory
            || self == M10Configuration.ascii94Factory
            || self == M10Configuration.base256Factory
    }

    public static func random(suite: M10CipherSuite) -> M10Configuration {
        var names = M10Catalog.rotorNames
        names.shuffle()
        func randomField() -> String {
            if suite.usesHexSettings {
                return Base256Symbols.formatField((0..<M10Catalog.rotorCount).map { _ in Int.random(in: 0..<256) })
            }
            let alphabet = Array(suite.alphabet)
            return String((0..<M10Catalog.rotorCount).map { _ in alphabet.randomElement()! })
        }
        var unused = Array(0..<suite.alphabetSize)
        unused.shuffle()
        var pairs: [String] = []
        var index = 0
        while pairs.count < 12, index + 1 < unused.count {
            if suite.usesHexSettings {
                pairs.append(Base256Symbols.formatPlugPair(unused[index], unused[index + 1]))
            } else {
                let a = suite.indexToChar(unused[index])
                let b = suite.indexToChar(unused[index + 1])
                pairs.append(String([a, b]))
            }
            index += 2
        }
        return M10Configuration(
            cipherSuite: suite,
            rotorNames: names,
            reflector: M10Catalog.reflectorNames.randomElement() ?? "UKW-M10",
            rings: randomField(),
            positions: randomField(),
            plugPairs: pairs
        )
    }

    /// Same daily key, symbols remapped by index onto another alphabet.
    public func withSuite(_ suite: M10CipherSuite) -> M10Configuration {
        guard suite != cipherSuite else { return self }
        let ringIdx = Self.fieldIndices(rings, suite: cipherSuite)
        let posIdx = Self.fieldIndices(positions, suite: cipherSuite)
        var used = Set<Int>()
        var plugs: [String] = []
        for pair in plugPairs {
            guard let (a, b) = Self.plugIndices(pair, suite: cipherSuite) else { continue }
            let na = a % suite.alphabetSize
            let nb = b % suite.alphabetSize
            guard na != nb, !used.contains(na), !used.contains(nb) else { continue }
            used.insert(na)
            used.insert(nb)
            plugs.append(Self.formatPlug(na, nb, suite: suite))
        }
        let rings = ringIdx.count == M10Catalog.rotorCount
            ? Self.formatField(ringIdx.map { $0 % suite.alphabetSize }, suite: suite)
            : M10Configuration.random(suite: suite).rings
        let positions = posIdx.count == M10Catalog.rotorCount
            ? Self.formatField(posIdx.map { $0 % suite.alphabetSize }, suite: suite)
            : M10Configuration.random(suite: suite).positions
        return M10Configuration(
            cipherSuite: suite,
            rotorNames: rotorNames,
            reflector: reflector,
            rings: rings,
            positions: positions,
            plugPairs: plugs
        )
    }

    static func fieldIndices(_ value: String, suite: M10CipherSuite) -> [Int] {
        switch suite {
        case .base256:
            return Base256Symbols.parseField(value) ?? []
        case .alpha36, .ascii:
            return value.filter { !$0.isWhitespace }.compactMap { suite.charToIndex($0) }
        }
    }

    static func formatField(_ indices: [Int], suite: M10CipherSuite) -> String {
        switch suite {
        case .base256:
            return Base256Symbols.formatField(indices)
        case .alpha36, .ascii:
            return String(indices.map { suite.indexToChar($0) })
        }
    }

    static func plugIndices(_ token: String, suite: M10CipherSuite) -> (Int, Int)? {
        switch suite {
        case .base256:
            return Base256Symbols.parsePlugPair(token)
        case .alpha36, .ascii:
            let symbols = Array(token.filter { suite.charToIndex($0) != nil })
            guard symbols.count == 2,
                  let a = suite.charToIndex(symbols[0]),
                  let b = suite.charToIndex(symbols[1]) else { return nil }
            return (a, b)
        }
    }

    static func formatPlug(_ a: Int, _ b: Int, suite: M10CipherSuite) -> String {
        switch suite {
        case .base256:
            return Base256Symbols.formatPlugPair(a, b)
        case .alpha36, .ascii:
            return String([suite.indexToChar(a), suite.indexToChar(b)])
        }
    }

    public var rotorOrderString: String {
        rotorNames.joined(separator: "-")
    }

    public var plugString: String {
        plugPairs.joined(separator: " ")
    }

    public var codebookLine: String {
        let plugs = plugPairs.isEmpty ? "-" : plugPairs.joined(separator: ",")
        return "M10/\(cipherSuite.rawValue)/\(rotorOrderString)/\(reflector)/\(rings)/\(positions)/\(plugs)"
    }

    public static func parseRotorOrder(_ text: String) -> [String] {
        text
            .split(whereSeparator: { $0 == "-" || $0 == "," || $0 == " " || $0 == "/" })
            .map { $0.trimmingCharacters(in: .whitespacesAndNewlines).uppercased() }
            .filter { !$0.isEmpty }
    }

    public static func parsePlugPairs(_ text: String, suite: M10CipherSuite) -> [String] {
        // ASCII-94 includes comma and semicolon; only whitespace is a delimiter.
        let tokens: [String]
        switch suite {
        case .ascii:
            tokens = text.split(whereSeparator: { $0.isWhitespace })
                .map { String($0) }
                .filter { !$0.isEmpty }
        case .alpha36, .base256:
            tokens = text.split(whereSeparator: { $0 == " " || $0 == "," || $0 == ";" })
                .map { String($0).trimmingCharacters(in: .whitespacesAndNewlines) }
                .filter { !$0.isEmpty }
        }
        return tokens.map { token in
            switch suite {
            case .alpha36, .base256:
                return token.uppercased()
            case .ascii:
                return token
            }
        }
    }

    public func validated() throws -> M10Configuration {
        var copy = self
        if copy.cipherSuite == .alpha36 || copy.cipherSuite == .base256 {
            copy.rings = copy.rings.filter { !$0.isWhitespace }.uppercased()
            copy.positions = copy.positions.filter { !$0.isWhitespace }.uppercased()
            copy.plugPairs = copy.plugPairs.map { $0.filter { !$0.isWhitespace }.uppercased() }
            copy.rotorNames = copy.rotorNames.map {
                let u = $0.uppercased()
                if u == "I" || u == "II" || u == "III" || u == "IV" || u == "V"
                    || u == "VI" || u == "VII" || u == "VIII" || u == "IX" || u == "X" {
                    return u
                }
                return $0
            }
        }

        guard copy.rotorNames.count == M10Catalog.rotorCount else {
            throw M10Error.invalidSettings("M10 uses exactly \(M10Catalog.rotorCount) rotors.")
        }
        var seen = Set<String>()
        for name in copy.rotorNames {
            guard M10Catalog.rotorNames.contains(name) else {
                throw M10Error.invalidSettings("Unknown rotor \(name).")
            }
            if seen.contains(name) {
                throw M10Error.invalidSettings("Rotor \(name) is used twice.")
            }
            seen.insert(name)
        }
        if let derived = copy.derivedMachine {
            try Self.validateDerived(derived, suite: copy.cipherSuite)
        } else {
            guard M10Catalog.reflectorNames.contains(copy.reflector) else {
                throw M10Error.invalidSettings("Unknown reflector \(copy.reflector).")
            }
        }

        try validateSymbolField(copy.rings, name: "Rings", suite: copy.cipherSuite)
        try validateSymbolField(copy.positions, name: "Positions", suite: copy.cipherSuite)
        try validatePlugPairs(copy.plugPairs, suite: copy.cipherSuite)
        return copy
    }

    private static func validateDerived(_ derived: M10DerivedMachine, suite: M10CipherSuite) throws {
        let size = suite.alphabetSize
        guard derived.rotorWirings.count == M10Catalog.rotorCount,
              derived.rotorNotches.count == M10Catalog.rotorCount,
              derived.reflectorWiring.count == size else {
            throw M10Error.invalidSettings("Derived machine tables are incomplete.")
        }
        let universe = Set(0..<size)
        for wiring in derived.rotorWirings {
            guard Set(wiring) == universe else {
                throw M10Error.invalidSettings("Derived rotor is not a permutation.")
            }
        }
        let reflector = derived.reflectorWiring
        for (i, j) in reflector.enumerated() {
            guard j >= 0, j < size, i != j, reflector[j] == i else {
                throw M10Error.invalidSettings("Derived reflector is not a fixed-point-free involution.")
            }
        }
    }

    private func validateSymbolField(_ value: String, name: String, suite: M10CipherSuite) throws {
        switch suite {
        case .base256:
            guard Base256Symbols.parseField(value) != nil else {
                throw M10Error.invalidSettings("\(name) must be \(M10Catalog.rotorCount) bytes as 20 hex digits.")
            }
        case .alpha36, .ascii:
            let compact = value.filter { !$0.isWhitespace }
            guard compact.count == M10Catalog.rotorCount else {
                throw M10Error.invalidSettings("\(name) must be \(M10Catalog.rotorCount) symbols (one per rotor).")
            }
            for character in compact {
                switch suite {
                case .alpha36:
                    guard Alpha36Symbols.charToIndex(character) != nil else {
                        throw M10Error.invalidSettings("\(name) uses invalid Alpha-36 symbol \(character).")
                    }
                case .ascii:
                    guard Ascii94Symbols.isValidSymbol(character) else {
                        throw M10Error.invalidSettings("\(name) uses invalid ASCII-94 symbol.")
                    }
                case .base256:
                    break
                }
            }
        }
    }

    private func validatePlugPairs(_ pairs: [String], suite: M10CipherSuite) throws {
        guard pairs.count <= M10Catalog.maxPlugPairs else {
            throw M10Error.invalidSettings("At most \(M10Catalog.maxPlugPairs) plugboard pairs.")
        }
        var used = Set<Int>()
        for pair in pairs {
            let a: Int
            let b: Int
            switch suite {
            case .base256:
                guard let pairBytes = Base256Symbols.parsePlugPair(pair) else {
                    throw M10Error.invalidSettings("Each plugboard pair must be two bytes as 4 hex digits.")
                }
                a = pairBytes.0
                b = pairBytes.1
            case .alpha36:
                let symbols = Array(pair.uppercased().filter { Alpha36Symbols.isValidSymbol($0) })
                guard symbols.count == 2 else {
                    throw M10Error.invalidSettings("Each plugboard pair must be two symbols.")
                }
                a = Alpha36Symbols.charToIndex(symbols[0])!
                b = Alpha36Symbols.charToIndex(symbols[1])!
            case .ascii:
                let symbols = Array(pair.filter { Ascii94Symbols.isValidSymbol($0) })
                guard symbols.count == 2 else {
                    throw M10Error.invalidSettings("Each plugboard pair must be two symbols.")
                }
                a = Ascii94Symbols.charToIndex(symbols[0])!
                b = Ascii94Symbols.charToIndex(symbols[1])!
            }
            guard a != b else {
                throw M10Error.invalidSettings("A plug cannot connect a symbol to itself.")
            }
            if used.contains(a) || used.contains(b) {
                throw M10Error.invalidSettings("A symbol appears in more than one plugboard pair.")
            }
            used.insert(a)
            used.insert(b)
        }
    }
}

public enum M10Error: LocalizedError, Equatable {
    case invalidFormat
    case unsupportedVersion(Int)
    case corruptPayload
    case corruptFilename
    case settingsMismatch
    case authenticationFailed
    case passwordRequired
    case wrongPassword
    case kdfInvalid
    case keyDerivationFailed
    case randomGenerationFailed
    case legacyArchiveRequiresImport
    case notALegacyArchive
    case publicCodebook
    case invalidSettings(String)
    case emptyInput
    case payloadTooLarge
    case archiveTooLarge
    case fileAlreadyExists(String)
    case emptyFolder
    case unreadableFile(String)

    public var errorDescription: String? {
        switch self {
        case .invalidFormat:
            return "This file is not a valid Enigma – M 10 archive."
        case .unsupportedVersion(let version):
            return "Unsupported Enigma – M 10 format version: \(version)."
        case .corruptPayload:
            return "The encrypted payload could not be decoded."
        case .corruptFilename:
            return "The encrypted filename could not be decoded."
        case .settingsMismatch:
            return "These machine settings do not decrypt this archive. Load the matching codebook."
        case .authenticationFailed:
            return "The archive failed its codebook authenticator. Wrong codebook, or the file was altered."
        case .passwordRequired:
            return "This archive is password-protected. Enter the password."
        case .wrongPassword:
            return "Incorrect password, or the archive was altered."
        case .kdfInvalid:
            return "The archive’s Argon2 parameters are missing or not allowed."
        case .keyDerivationFailed:
            return "Password derivation failed."
        case .randomGenerationFailed:
            return "The system random generator failed. Encryption was not started."
        case .legacyArchiveRequiresImport:
            return "This is an unauthenticated ENIGMAM10 v1 archive. Use Legacy Import to recover it; the output will be marked UNAUTHENTICATED- and is not integrity-checked."
        case .notALegacyArchive:
            return "This is an authenticated v2 archive. Use Decrypt, not Legacy Import."
        case .publicCodebook:
            return "The demonstration codebook is public — it ships in the app. Create or load a personal codebook before encrypting."
        case .invalidSettings(let message):
            return message
        case .emptyInput:
            return "No file was selected."
        case .payloadTooLarge:
            return "The file is larger than the maximum supported size (2 GB)."
        case .archiveTooLarge:
            return "This archive exceeds the maximum supported size."
        case .fileAlreadyExists(let path):
            return "Refusing to overwrite existing file: \(path)."
        case .emptyFolder:
            return "The folder contains no encryptable files."
        case .unreadableFile(let name):
            return "Cannot read file: \(name)."
        }
    }
}

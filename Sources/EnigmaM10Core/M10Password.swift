import Foundation
import CryptoKit
import CArgon2

public enum M10KeyMode: String, Codable, Sendable, CaseIterable, Identifiable {
    case password
    case external
    case internalKey = "internal"

    public var id: String { rawValue }

    public var title: String {
        switch self {
        case .password: return "Password"
        case .external: return "External key"
        case .internalKey: return "Internal key"
        }
    }
}

public struct M10KDFParams: Equatable, Codable, Sendable {
    public var alg: String
    public var salt: String
    public var memoryKiB: UInt32
    public var iterations: UInt32
    public var parallelism: UInt32
    public var hashLength: Int

    public static let defaultMemoryKiB: UInt32 = 65_536
    public static let defaultIterations: UInt32 = 3
    public static let defaultParallelism: UInt32 = 1
    public static let defaultHashLength = 32
    public static let saltLength = 16

    public static let maxMemoryKiB: UInt32 = 256 * 1024
    public static let maxIterations: UInt32 = 16
    public static let maxParallelism: UInt32 = 8

    public static func freshSalt() throws -> M10KDFParams {
        M10KDFParams(
            alg: "argon2id",
            salt: M10MessageKey.hex(try M10MessageKey.randomNonce()),
            memoryKiB: defaultMemoryKiB,
            iterations: defaultIterations,
            parallelism: defaultParallelism,
            hashLength: defaultHashLength
        )
    }

    public func validated() throws -> M10KDFParams {
        guard alg == "argon2id" else { throw M10Error.kdfInvalid }
        guard let saltData = M10MessageKey.parseHex(salt),
              saltData.count >= 8, saltData.count <= 64 else {
            throw M10Error.kdfInvalid
        }
        guard memoryKiB >= 8, memoryKiB <= Self.maxMemoryKiB else { throw M10Error.kdfInvalid }
        guard iterations >= 1, iterations <= Self.maxIterations else { throw M10Error.kdfInvalid }
        guard parallelism >= 1, parallelism <= Self.maxParallelism else { throw M10Error.kdfInvalid }
        guard hashLength >= 16, hashLength <= 64 else { throw M10Error.kdfInvalid }
        return self
    }

    public var saltData: Data? { M10MessageKey.parseHex(salt) }
}

public struct M10DerivedMachine: Equatable, Sendable {
    public var rotorWirings: [[Int]]
    public var rotorNotches: [Set<Int>]
    public var reflectorWiring: [Int]

    public init(rotorWirings: [[Int]], rotorNotches: [Set<Int>], reflectorWiring: [Int]) {
        self.rotorWirings = rotorWirings
        self.rotorNotches = rotorNotches
        self.reflectorWiring = reflectorWiring
    }
}

public enum M10Password {
    public static func deriveMaster(password: String, params: M10KDFParams) throws -> Data {
        let params = try params.validated()
        guard let salt = params.saltData else { throw M10Error.kdfInvalid }
        let passwordData = Data(password.utf8)
        var output = Data(count: params.hashLength)
        let status = output.withUnsafeMutableBytes { outBuf -> Int32 in
            passwordData.withUnsafeBytes { pwdBuf in
                salt.withUnsafeBytes { saltBuf in
                    enclave_argon2id_raw(
                        pwdBuf.bindMemory(to: UInt8.self).baseAddress,
                        pwdBuf.count,
                        saltBuf.bindMemory(to: UInt8.self).baseAddress,
                        saltBuf.count,
                        params.iterations,
                        params.memoryKiB,
                        params.parallelism,
                        outBuf.bindMemory(to: UInt8.self).baseAddress,
                        params.hashLength
                    )
                }
            }
        }
        guard status == 0 else { throw M10Error.keyDerivationFailed }
        return output
    }

    public static func deriveConfiguration(
        password: String,
        suite: M10CipherSuite,
        params: M10KDFParams
    ) throws -> (configuration: M10Configuration, master: Data) {
        let master = try deriveMaster(password: password, params: params)
        return (try expandConfiguration(master: master, suite: suite), master)
    }

    public static func expandConfiguration(master: Data, suite: M10CipherSuite) throws -> M10Configuration {
        let size = suite.alphabetSize
        var rotors: [[Int]] = []
        var notches: [Set<Int>] = []
        for index in 0..<M10Catalog.rotorCount {
            var rng = HMACDRBG(seed: domainKey(master, "M10-ROTOR-\(index)"))
            rotors.append(fisherYates(count: size, rng: &rng))
            notches.append(notchSet(size: size, rng: &rng))
        }
        var refRng = HMACDRBG(seed: domainKey(master, "M10-REFLECTOR"))
        let reflector = involution(count: size, rng: &refRng)
        var posRng = HMACDRBG(seed: domainKey(master, "M10-POSITIONS"))
        var ringRng = HMACDRBG(seed: domainKey(master, "M10-RINGS"))
        var plugRng = HMACDRBG(seed: domainKey(master, "M10-PLUGS"))
        let positions = randomField(suite: suite, rng: &posRng)
        let rings = randomField(suite: suite, rng: &ringRng)
        let plugs = randomPlugs(suite: suite, rng: &plugRng)
        return M10Configuration(
            cipherSuite: suite,
            rotorNames: M10Catalog.rotorNames,
            reflector: "derived",
            rings: rings,
            positions: positions,
            plugPairs: plugs,
            derivedMachine: M10DerivedMachine(
                rotorWirings: rotors,
                rotorNotches: notches,
                reflectorWiring: reflector
            )
        )
    }

    /// HKDF subkeys so filename and payload get independent rotors, reflector, rings, positions, and plugs.
    public static func domainMaster(
        master: Data,
        nonce: Data,
        domain: M10MessageKey.Domain
    ) -> Data {
        let info: String
        switch domain {
        case .filename: info = "M10-FILENAME-MACHINE"
        case .payload: info = "M10-PAYLOAD-MACHINE"
        }
        let key = HKDF<SHA256>.deriveKey(
            inputKeyMaterial: SymmetricKey(data: master),
            salt: nonce,
            info: Data(info.utf8),
            outputByteCount: 32
        )
        return key.withUnsafeBytes { Data($0) }
    }

    public static func expandIndependentPair(
        master: Data,
        suite: M10CipherSuite,
        nonce: Data
    ) throws -> (filename: M10Configuration, payload: M10Configuration) {
        let filename = try expandConfiguration(
            master: domainMaster(master: master, nonce: nonce, domain: .filename),
            suite: suite
        )
        let payload = try expandConfiguration(
            master: domainMaster(master: master, nonce: nonce, domain: .payload),
            suite: suite
        )
        return (filename, payload)
    }

    /// External-key v5: codebook identity seeds two derived machines; catalog wirings are not used on the wire.
    public static func expandIndependentPair(
        configuration: M10Configuration,
        nonce: Data
    ) throws -> (filename: M10Configuration, payload: M10Configuration) {
        var material = Data("M10-CODEBOOK-MASTER".utf8)
        material.append(Data(configuration.codebookLine.utf8))
        let digest = Data(SHA256.hash(data: material))
        return try expandIndependentPair(master: digest, suite: configuration.cipherSuite, nonce: nonce)
    }

    public static func authKey(master: Data) -> SymmetricKey {
        domainKey(master, "M10-AUTH")
    }

    private static func domainKey(_ master: Data, _ info: String) -> SymmetricKey {
        HKDF<SHA256>.deriveKey(
            inputKeyMaterial: SymmetricKey(data: master),
            info: Data(info.utf8),
            outputByteCount: 32
        )
    }

    private static func fisherYates(count: Int, rng: inout HMACDRBG) -> [Int] {
        var values = Array(0..<count)
        if count > 1 {
            for i in stride(from: count - 1, through: 1, by: -1) {
                let j = rng.uniform(i + 1)
                values.swapAt(i, j)
            }
        }
        return values
    }

    private static func involution(count: Int, rng: inout HMACDRBG) -> [Int] {
        let shuffled = fisherYates(count: count, rng: &rng)
        var result = Array(repeating: 0, count: count)
        var i = 0
        while i + 1 < shuffled.count {
            let a = shuffled[i]
            let b = shuffled[i + 1]
            result[a] = b
            result[b] = a
            i += 2
        }
        return result
    }

    private static func notchSet(size: Int, rng: inout HMACDRBG) -> Set<Int> {
        let count = 1 + rng.uniform(2)
        var set = Set<Int>()
        while set.count < count {
            set.insert(rng.uniform(size))
        }
        return set
    }

    private static func randomField(suite: M10CipherSuite, rng: inout HMACDRBG) -> String {
        let indices = (0..<M10Catalog.rotorCount).map { _ in rng.uniform(suite.alphabetSize) }
        return M10Configuration.formatField(indices, suite: suite)
    }

    private static func randomPlugs(suite: M10CipherSuite, rng: inout HMACDRBG) -> [String] {
        var unused = Array(0..<suite.alphabetSize)
        if unused.count > 1 {
            for i in stride(from: unused.count - 1, through: 1, by: -1) {
                unused.swapAt(i, rng.uniform(i + 1))
            }
        }
        var pairs: [String] = []
        var index = 0
        while pairs.count < 12, index + 1 < unused.count {
            pairs.append(M10Configuration.formatPlug(unused[index], unused[index + 1], suite: suite))
            index += 2
        }
        return pairs
    }
}

struct HMACDRBG {
    private let key: SymmetricKey
    private var counter: UInt64 = 0
    private var buffer = [UInt8]()
    private var offset = 0

    init(seed: SymmetricKey) {
        key = seed
    }

    mutating func nextByte() -> UInt8 {
        if offset >= buffer.count {
            var block = counter.bigEndian
            let mac = HMAC<SHA256>.authenticationCode(
                for: Data(bytes: &block, count: 8),
                using: key
            )
            buffer = Array(mac)
            offset = 0
            counter += 1
        }
        let value = buffer[offset]
        offset += 1
        return value
    }

    mutating func nextUInt32() -> UInt32 {
        let b0 = UInt32(nextByte())
        let b1 = UInt32(nextByte())
        let b2 = UInt32(nextByte())
        let b3 = UInt32(nextByte())
        return (b0 << 24) | (b1 << 16) | (b2 << 8) | b3
    }

    /// Unbiased integer in `0..<bound`.
    mutating func uniform(_ bound: Int) -> Int {
        precondition(bound > 0)
        let b = UInt32(bound)
        let limit = UInt32.max - UInt32.max % b
        while true {
            let value = nextUInt32()
            if value < limit { return Int(value % b) }
        }
    }
}

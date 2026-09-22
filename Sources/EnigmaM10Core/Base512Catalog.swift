import Foundation
import CryptoKit

extension M10Catalog {
    /// Base-512 catalog: permutations of 0..<512, seeded so every build matches.
    public enum Base512 {
        public static let rotorWirings: [String: [Int]] = {
            var result: [String: [Int]] = [:]
            for name in M10Catalog.rotorNames {
                var rng = HMACDRBG(seed: SymmetricKey(data: Data("EnigmaM10-B512-ROTOR-\(name)".utf8)))
                result[name] = permutation(size: Base512Symbols.alphabetSize, rng: &rng)
            }
            return result
        }()

        public static let rotorNotches: [String: Set<Int>] = notches(scaled: true)
        /// v6 Base-512 (1.4.0/1.4.1): one or two notches per rotor.
        public static let rotorNotchesLegacy: [String: Set<Int>] = notches(scaled: false)

        public static func notchSet(_ name: String, scaled: Bool = true) -> Set<Int> {
            (scaled ? rotorNotches : rotorNotchesLegacy)[name] ?? []
        }

        private static func notches(scaled: Bool) -> [String: Set<Int>] {
            var result: [String: Set<Int>] = [:]
            for name in M10Catalog.rotorNames {
                var rng = HMACDRBG(seed: SymmetricKey(data: Data("EnigmaM10-B512-NOTCH-\(name)".utf8)))
                let count: Int
                if scaled {
                    count = M10Catalog.notchCount(
                        alphabetSize: Base512Symbols.alphabetSize, rng: &rng
                    )
                } else {
                    count = 1 + rng.uniform(2)
                }
                var set = Set<Int>()
                while set.count < count {
                    set.insert(rng.uniform(Base512Symbols.alphabetSize))
                }
                result[name] = set
            }
            return result
        }

        public static let reflectorWirings: [String: [Int]] = {
            var result: [String: [Int]] = [:]
            for name in M10Catalog.reflectorNames {
                var rng = HMACDRBG(seed: SymmetricKey(data: Data("EnigmaM10-B512-REF-\(name)".utf8)))
                result[name] = involution(size: Base512Symbols.alphabetSize, rng: &rng)
            }
            return result
        }()

        private static func permutation(size: Int, rng: inout HMACDRBG) -> [Int] {
            var values = Array(0..<size)
            if size > 1 {
                for i in stride(from: size - 1, through: 1, by: -1) {
                    values.swapAt(i, rng.uniform(i + 1))
                }
            }
            return values
        }

        private static func involution(size: Int, rng: inout HMACDRBG) -> [Int] {
            let shuffled = permutation(size: size, rng: &rng)
            var result = Array(repeating: 0, count: size)
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
    }
}

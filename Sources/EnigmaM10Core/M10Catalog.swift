import Foundation

/// Custom M10 rotor bank: ten stepping rotors plus two thick reflectors.
/// Alpha-36: permutations of `0–9A–Z`. ASCII-94: printable ASCII `!`–`~`.
/// Base-256: permutations of `0..<256` (see `Base256Catalog.swift`).
/// Base-512: permutations of `0..<512` (see `Base512Catalog.swift`).
public enum M10Catalog {
    public static let rotorNames = ["I", "II", "III", "IV", "V", "VI", "VII", "VIII", "IX", "X"]
    public static let reflectorNames = ["UKW-M10", "UKW-M10B"]
    public static let rotorCount = 10
    public static let maxPlugPairs = 15

    /// Classic Enigma turns over about once per 26. Alphabets under 512 keep 1–2
    /// notches so existing Alpha-36 / ASCII-94 / Base-256 password files still open.
    static func notchCount(alphabetSize: Int, rng: inout HMACDRBG) -> Int {
        guard alphabetSize >= 512 else { return 1 + rng.uniform(2) }
        let target = max(8, (alphabetSize + 13) / 26)
        return min(alphabetSize / 2, max(8, target + rng.uniform(5) - 2))
    }

    public enum Alpha36 {
        public static let rotorWirings: [String: String] = [
            "I": "NC9HRGB843EMJLIY1Z7W5XK0DFSVP26UTOQA",
            "II": "HP42BW71U09QVLJNTED6FC3XSAI5MYG8ZOKR",
            "III": "V9ABTMGP5QXSO8D4ZRC0W23JYU7NH1FKEI6L",
            "IV": "7N4YK0JDH5I91ZGWQ62ABT3UOLVECS8RMFPX",
            "V": "25VYQUTJB871DAOGH0WC6NSXI34EPLMFK9RZ",
            "VI": "G6LJ0W4957SHBI8FOUXZVYQEMCT23DANRKP1",
            "VII": "P4GX18Y7JK5DFOHWUC6L02RSVAN3BQETZI9M",
            "VIII": "Q8TMKAZN4G1OBSXD93RJCU5E2H6F7I0WLPVY",
            "IX": "9CTWXRIAON7YF40DQB3LPV1US8KMGE2Z5J6H",
            "X": "A9M6NKYZ4U0CT2FSEXD1I5WR8OGBJPHQL73V"
        ]

        public static let rotorNotches: [String: String] = [
            "I": "Q",
            "II": "E",
            "III": "V",
            "IV": "J",
            "V": "Z",
            "VI": "0M",
            "VII": "9K",
            "VIII": "5A",
            "IX": "2T",
            "X": "7H"
        ]

        public static let reflectorWirings: [String: String] = [
            "UKW-M10": "QFMZNHYALW7DPBV1K5OTG824IC0UXJRE9S63",
            "UKW-M10B": "J4AP165GKO2WTEDU7MN08RHI93SLQCFXBVZY"
        ]

        public static func rotorPermutation(_ name: String) -> [Int]? {
            guard let wiring = rotorWirings[name] else { return nil }
            return wiring.compactMap(Alpha36Symbols.charToIndex)
        }

        public static func reflectorPermutation(_ name: String) -> [Int]? {
            guard let wiring = reflectorWirings[name] else { return nil }
            return wiring.compactMap(Alpha36Symbols.charToIndex)
        }

        public static func notchSet(_ name: String) -> Set<Int> {
            Set((rotorNotches[name] ?? "").compactMap(Alpha36Symbols.charToIndex))
        }
    }

    public enum Ascii94 {
        /// Index permutations of the ASCII-94 alphabet (0 = `!` … 93 = `~`).
        public static let rotorWirings: [String: [Int]] = [
            "I": [88, 12, 14, 25, 33, 70, 18, 24, 77, 40, 23, 43, 61, 57, 50, 90, 51, 41, 42, 84, 7, 49, 46, 47, 89, 63, 15, 76, 29, 34, 35, 82, 32, 74, 67, 4, 1, 8, 62, 73, 26, 71, 86, 39, 27, 54, 5, 36, 92, 48, 38, 68, 45, 83, 21, 10, 69, 60, 30, 31, 79, 93, 80, 17, 53, 16, 66, 13, 72, 9, 91, 2, 65, 85, 3, 11, 0, 37, 87, 59, 75, 6, 44, 19, 64, 20, 28, 55, 58, 52, 22, 56, 78, 81],
            "II": [63, 9, 76, 79, 82, 6, 71, 84, 64, 1, 69, 62, 10, 11, 58, 68, 4, 83, 88, 32, 36, 90, 20, 67, 12, 74, 60, 75, 28, 33, 22, 15, 91, 13, 85, 18, 19, 73, 16, 89, 30, 86, 53, 57, 38, 48, 59, 34, 35, 29, 40, 92, 26, 25, 77, 54, 47, 17, 24, 80, 43, 72, 0, 93, 21, 51, 39, 56, 87, 50, 70, 27, 31, 61, 14, 65, 7, 55, 23, 81, 49, 46, 45, 3, 8, 66, 5, 78, 37, 44, 2, 52, 41, 42],
            "III": [24, 75, 83, 36, 6, 15, 76, 72, 16, 12, 11, 17, 4, 32, 1, 64, 2, 92, 47, 30, 43, 66, 67, 60, 79, 26, 87, 3, 18, 58, 49, 53, 89, 44, 27, 9, 62, 20, 91, 56, 50, 10, 88, 80, 74, 33, 14, 23, 63, 29, 31, 90, 21, 73, 82, 54, 37, 19, 52, 85, 46, 57, 22, 0, 55, 86, 8, 13, 25, 42, 7, 5, 34, 65, 40, 38, 51, 39, 93, 70, 68, 41, 45, 84, 61, 48, 35, 59, 78, 69, 77, 81, 71, 28],
            "IV": [12, 74, 64, 78, 57, 50, 37, 42, 3, 71, 49, 76, 87, 88, 92, 53, 39, 19, 36, 58, 2, 24, 91, 4, 25, 54, 85, 65, 93, 15, 35, 5, 1, 14, 52, 38, 22, 60, 48, 46, 20, 75, 40, 21, 23, 79, 56, 82, 45, 69, 30, 16, 80, 7, 51, 34, 27, 33, 83, 66, 84, 86, 17, 68, 90, 31, 13, 47, 29, 55, 18, 26, 32, 0, 10, 72, 41, 59, 77, 44, 6, 70, 8, 63, 28, 73, 67, 43, 9, 89, 11, 61, 81, 62],
            "V": [60, 79, 14, 74, 0, 28, 42, 70, 29, 83, 30, 93, 46, 12, 43, 58, 86, 13, 31, 9, 7, 90, 5, 63, 72, 2, 56, 82, 37, 26, 89, 57, 33, 34, 40, 45, 76, 38, 71, 59, 48, 50, 61, 67, 85, 53, 78, 44, 35, 39, 68, 54, 21, 18, 11, 22, 8, 41, 1, 88, 66, 81, 24, 52, 92, 16, 80, 4, 15, 77, 84, 27, 6, 25, 55, 87, 47, 75, 3, 20, 32, 91, 19, 62, 65, 23, 51, 64, 17, 49, 69, 36, 10, 73],
            "VI": [37, 51, 84, 44, 52, 2, 91, 49, 50, 40, 77, 90, 5, 64, 74, 25, 24, 14, 57, 72, 45, 16, 28, 34, 20, 60, 68, 0, 18, 53, 35, 31, 79, 41, 76, 56, 67, 58, 66, 22, 6, 93, 82, 86, 26, 3, 81, 43, 4, 87, 33, 88, 27, 19, 89, 42, 71, 70, 8, 1, 78, 7, 54, 46, 59, 17, 75, 85, 47, 73, 55, 9, 38, 39, 61, 65, 10, 69, 30, 13, 63, 48, 12, 11, 80, 21, 36, 62, 92, 23, 29, 15, 83, 32],
            "VII": [67, 20, 58, 92, 38, 82, 54, 5, 91, 69, 21, 48, 42, 25, 12, 83, 78, 88, 36, 45, 6, 24, 7, 72, 77, 32, 70, 31, 71, 16, 22, 85, 29, 56, 14, 3, 89, 47, 80, 51, 0, 87, 10, 65, 15, 66, 55, 27, 44, 34, 61, 8, 18, 53, 2, 64, 23, 74, 62, 37, 79, 11, 73, 75, 52, 84, 17, 63, 26, 19, 93, 81, 46, 35, 49, 68, 50, 40, 57, 43, 4, 9, 39, 59, 76, 41, 90, 86, 60, 1, 33, 30, 13, 28],
            "VIII": [68, 84, 91, 93, 71, 86, 30, 28, 43, 74, 7, 26, 5, 24, 20, 9, 16, 4, 18, 50, 12, 57, 22, 51, 54, 70, 64, 82, 21, 17, 25, 58, 79, 80, 44, 78, 15, 29, 73, 8, 35, 11, 92, 33, 69, 61, 40, 52, 31, 62, 23, 88, 32, 37, 56, 55, 72, 10, 60, 81, 66, 2, 0, 53, 41, 83, 14, 27, 90, 38, 67, 77, 46, 3, 89, 65, 59, 63, 19, 36, 48, 34, 1, 49, 42, 76, 85, 47, 75, 87, 13, 39, 45, 6],
            "IX": [62, 14, 29, 79, 83, 70, 76, 9, 71, 90, 44, 46, 20, 64, 63, 48, 11, 68, 69, 74, 58, 77, 91, 24, 6, 73, 55, 7, 66, 42, 53, 22, 16, 26, 80, 43, 52, 92, 85, 51, 57, 60, 28, 82, 27, 12, 40, 25, 78, 3, 13, 4, 61, 38, 5, 35, 36, 10, 65, 8, 49, 86, 2, 75, 93, 34, 72, 19, 67, 41, 56, 31, 47, 54, 32, 17, 50, 0, 23, 15, 59, 39, 88, 84, 45, 18, 33, 30, 37, 87, 21, 1, 81, 89],
            "X": [33, 48, 55, 28, 72, 53, 41, 37, 16, 45, 39, 50, 30, 9, 27, 70, 2, 0, 40, 25, 74, 17, 81, 82, 52, 89, 8, 35, 34, 29, 59, 46, 15, 84, 83, 85, 23, 31, 71, 22, 63, 62, 58, 1, 86, 56, 12, 21, 13, 5, 75, 93, 88, 57, 24, 47, 51, 64, 11, 42, 4, 61, 91, 73, 49, 43, 14, 66, 32, 44, 87, 10, 18, 76, 19, 92, 69, 90, 79, 65, 67, 77, 20, 3, 78, 54, 36, 60, 26, 6, 80, 68, 38, 7]
        ]

        public static let rotorNotches: [String: String] = [
            "I": "Q",
            "II": "E",
            "III": "V",
            "IV": "J",
            "V": "Z",
            "VI": "0m",
            "VII": "9K",
            "VIII": "5a",
            "IX": "2T",
            "X": "7h"
        ]

        public static let reflectorWirings: [String: [Int]] = [
            "UKW-M10": [27, 17, 37, 21, 72, 61, 13, 85, 46, 24, 38, 57, 91, 6, 67, 92, 78, 1, 71, 74, 55, 3, 79, 40, 9, 28, 56, 0, 25, 88, 75, 63, 52, 45, 48, 42, 84, 2, 10, 68, 23, 64, 35, 77, 65, 33, 8, 60, 34, 86, 59, 58, 32, 83, 82, 20, 26, 11, 51, 50, 47, 5, 76, 31, 41, 44, 90, 14, 39, 93, 89, 18, 4, 80, 19, 30, 62, 43, 16, 22, 73, 87, 54, 53, 36, 7, 49, 81, 29, 70, 66, 12, 15, 69],
            "UKW-M10B": [35, 41, 73, 90, 66, 12, 21, 75, 19, 39, 18, 24, 5, 70, 69, 67, 54, 89, 10, 8, 30, 6, 63, 76, 11, 27, 55, 25, 38, 56, 20, 42, 36, 93, 86, 0, 32, 48, 28, 9, 44, 1, 31, 88, 40, 84, 91, 49, 37, 47, 80, 58, 72, 85, 16, 26, 29, 83, 51, 77, 79, 87, 68, 22, 92, 71, 4, 15, 62, 14, 13, 65, 52, 2, 78, 7, 23, 59, 74, 60, 50, 82, 81, 57, 45, 53, 34, 61, 43, 17, 3, 46, 64, 33]
        ]

        public static func notchSet(_ name: String) -> Set<Int> {
            Set((rotorNotches[name] ?? "").compactMap(Ascii94Symbols.charToIndex))
        }
    }
}

import Foundation

/// Full-byte alphabet: every `UInt8` is a symbol (index == byte).
public enum Base256Symbols {
    public static let alphabetSize = 256

    public static let alphabet: String = {
        String((0...255).map { Character(UnicodeScalar($0)!) })
    }()

    public static func charToIndex(_ character: Character) -> Int? {
        guard character.unicodeScalars.count == 1,
              let value = character.unicodeScalars.first?.value,
              value <= 255 else { return nil }
        return Int(value)
    }

    public static func indexToChar(_ index: Int) -> Character {
        let normalized = ((index % alphabetSize) + alphabetSize) % alphabetSize
        return Character(UnicodeScalar(normalized)!)
    }

    public static func latin1String(_ data: Data) -> String {
        String(data.map { Character(UnicodeScalar(Int($0))!) })
    }

    public static func latin1Data(_ string: String) -> Data? {
        var data = Data()
        data.reserveCapacity(string.unicodeScalars.count)
        for scalar in string.unicodeScalars {
            guard scalar.value <= 255 else { return nil }
            data.append(UInt8(scalar.value))
        }
        return data
    }

    public static func hex(_ data: Data) -> String {
        data.map { String(format: "%02X", $0) }.joined()
    }

    public static func parseHex(_ string: String) -> Data? {
        let compact = string.filter { !$0.isWhitespace }.uppercased()
        guard compact.count % 2 == 0, !compact.isEmpty || string.filter({ !$0.isWhitespace }).isEmpty else {
            return compact.isEmpty ? Data() : nil
        }
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

    /// 10 rotor settings as 20 hex digits.
    public static func parseField(_ string: String) -> [Int]? {
        guard let data = parseHex(string), data.count == M10Catalog.rotorCount else { return nil }
        return data.map { Int($0) }
    }

    public static func formatField(_ indices: [Int]) -> String {
        hex(Data(indices.map { UInt8($0 & 0xFF) }))
    }

    public static func parsePlugPair(_ token: String) -> (Int, Int)? {
        guard let data = parseHex(token), data.count == 2 else { return nil }
        let a = Int(data[0])
        let b = Int(data[1])
        guard a != b else { return nil }
        return (a, b)
    }

    public static func formatPlugPair(_ a: Int, _ b: Int) -> String {
        String(format: "%02X%02X", a & 0xFF, b & 0xFF)
    }

    /// JSON-safe encoding of Base-256 filename ciphertext. Do not store raw
    /// ciphertext in a Swift `String`: U+000D U+000A collapses to one Character.
    public static let filenameHexPrefix = "hex:"

    public static func encodeFilenameCiphertext(_ data: Data) -> String {
        filenameHexPrefix + hex(data)
    }

    public static func decodeFilenameCiphertext(_ field: String) -> Data? {
        let trimmed = field.trimmingCharacters(in: .whitespacesAndNewlines)
        if trimmed.hasPrefix(filenameHexPrefix) {
            let body = String(trimmed.dropFirst(filenameHexPrefix.count))
            return parseHex(body)
        }
        // Pre-1.0.4 archives stored raw ciphertext as a JSON string. Read
        // unicode scalars, not Character, so CR/LF (U+000D U+000A) stay two bytes.
        return latin1Data(field)
    }
}

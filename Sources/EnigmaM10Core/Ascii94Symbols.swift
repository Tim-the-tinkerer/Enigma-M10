import Foundation

/// ASCII-94 alphabet from EnigmaVault: printable ASCII `0x21...0x7E` (no space). Case-sensitive.
public enum Ascii94Symbols {
    public static let alphabet: String = {
        String((0x21...0x7E).map { Character(UnicodeScalar($0)!) })
    }()
    public static let alphabetSize = 94
    public static let denseBlockBytes = 17
    public static let denseBlockSymbols = 21

    public static func isValidSymbol(_ character: Character) -> Bool {
        guard character.isASCII, let value = character.asciiValue else { return false }
        return value >= 0x21 && value <= 0x7E
    }

    public static func charToIndex(_ character: Character) -> Int? {
        guard isValidSymbol(character), let value = character.asciiValue else { return nil }
        return Int(value - 0x21)
    }

    public static func indexToChar(_ index: Int) -> Character {
        let normalized = ((index % alphabetSize) + alphabetSize) % alphabetSize
        let scalar = UInt8(0x21 + normalized)
        return Character(UnicodeScalar(scalar))
    }

    public static func filteredSymbols(_ text: String) -> String {
        String(text.filter { isValidSymbol($0) })
    }
}

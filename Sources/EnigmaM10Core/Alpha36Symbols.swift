import Foundation

/// Alpha-36 alphabet from EnigmaVault: `0–9` then `A–Z` (36 symbols).
public enum Alpha36Symbols {
    public static let alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    public static let alphabetSize = 36
    public static let denseBlockBytes = 17
    public static let denseBlockSymbols = 27

    public static func isValidSymbol(_ character: Character) -> Bool {
        guard character.isASCII else { return false }
        if character >= "0", character <= "9" { return true }
        if character.isLetter, character.isUppercase { return true }
        return false
    }

    public static func charToIndex(_ character: Character) -> Int? {
        guard let scalar = character.uppercased().first, scalar.isASCII else { return nil }
        if scalar >= "0", scalar <= "9",
           let value = scalar.asciiValue,
           let base = Character("0").asciiValue {
            return Int(value - base)
        }
        if scalar >= "A", scalar <= "Z",
           let value = scalar.asciiValue,
           let base = Character("A").asciiValue {
            return 10 + Int(value - base)
        }
        return nil
    }

    public static func indexToChar(_ index: Int) -> Character {
        let normalized = ((index % alphabetSize) + alphabetSize) % alphabetSize
        let scalar = UInt8(alphabet.utf8[alphabet.index(alphabet.startIndex, offsetBy: normalized)])
        return Character(UnicodeScalar(scalar))
    }

    public static func filteredSymbols(_ text: String) -> String {
        String(text.compactMap { character -> Character? in
            if isValidSymbol(character) { return character }
            if character.isLetter, let upper = character.uppercased().first, isValidSymbol(upper) {
                return upper
            }
            return nil
        })
    }
}

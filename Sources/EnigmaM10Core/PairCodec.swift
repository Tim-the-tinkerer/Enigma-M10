import Foundation

/// Pair encoding from EnigmaVault Alpha-36 / ASCII-94: two symbols per byte.
public enum PairCodec {
    public static func encodeAlpha36(_ data: Data) -> String {
        var symbols = ""
        symbols.reserveCapacity(data.count * 2)
        for byte in data {
            let value = Int(byte)
            symbols.append(Alpha36Symbols.indexToChar(value / 36))
            symbols.append(Alpha36Symbols.indexToChar(value % 36))
        }
        return symbols
    }

    public static func decodeAlpha36(_ symbols: String) -> Data? {
        let filtered = Alpha36Symbols.filteredSymbols(symbols)
        guard filtered.count % 2 == 0 else { return nil }
        var output = Data()
        output.reserveCapacity(filtered.count / 2)
        var iterator = filtered.makeIterator()
        while let first = iterator.next(), let second = iterator.next() {
            guard let high = Alpha36Symbols.charToIndex(first),
                  let low = Alpha36Symbols.charToIndex(second) else {
                return nil
            }
            let value = high * 36 + low
            guard value <= 255 else { return nil }
            output.append(UInt8(value))
        }
        return output
    }

    public static func encodeAscii94(_ data: Data) -> String {
        var symbols = ""
        symbols.reserveCapacity(data.count * 2)
        let n = Ascii94Symbols.alphabetSize
        for byte in data {
            let value = Int(byte)
            symbols.append(Ascii94Symbols.indexToChar(value / n))
            symbols.append(Ascii94Symbols.indexToChar(value % n))
        }
        return symbols
    }

    public static func decodeAscii94(_ symbols: String) -> Data? {
        let filtered = Ascii94Symbols.filteredSymbols(symbols)
        guard filtered.count % 2 == 0 else { return nil }
        var output = Data()
        output.reserveCapacity(filtered.count / 2)
        let n = Ascii94Symbols.alphabetSize
        var iterator = filtered.makeIterator()
        while let first = iterator.next(), let second = iterator.next() {
            guard let high = Ascii94Symbols.charToIndex(first),
                  let low = Ascii94Symbols.charToIndex(second) else {
                return nil
            }
            let value = high * n + low
            guard value <= 255 else { return nil }
            output.append(UInt8(value))
        }
        return output
    }

    public static func encode(_ data: Data, suite: M10CipherSuite) -> String {
        switch suite {
        case .alpha36: return encodeAlpha36(data)
        case .ascii: return encodeAscii94(data)
        case .base256: return Base256Symbols.latin1String(data)
        }
    }

    public static func decode(_ symbols: String, suite: M10CipherSuite) -> Data? {
        switch suite {
        case .alpha36: return decodeAlpha36(symbols)
        case .ascii: return decodeAscii94(symbols)
        case .base256: return Base256Symbols.latin1Data(symbols)
        }
    }
}

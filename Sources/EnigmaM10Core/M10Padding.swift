import Foundation

/// Automatic ciphertext padding so the container does not leak the exact packed size.
/// Writes pick 4 KiB when the unpadded inner payload is under 64 KiB, otherwise 64 KiB.
public enum M10Padding: Int, CaseIterable, Sendable {
    case none = 0
    case fourKiB = 4_096
    case sixtyFourKiB = 65_536

    public static let smallBoundary = 4_096
    public static let largeBoundary = 65_536

    /// Bits 5–6 of leftover `M10PW02` flags (decrypt only).
    var flagCode: UInt8 {
        switch self {
        case .none: return 0
        case .fourKiB: return 1
        case .sixtyFourKiB: return 2
        }
    }

    static func fromFlag(_ code: UInt8) throws -> M10Padding {
        switch code {
        case 0: return .none
        case 1: return .fourKiB
        case 2: return .sixtyFourKiB
        default: throw M10Error.invalidFormat
        }
    }

    public static let nameFieldBytes = 256

    public static func expectedNameWireBytes(suite: M10CipherSuite) -> Int {
        switch suite {
        case .base256: return nameFieldBytes
        case .alpha36, .ascii: return nameFieldBytes * 2
        case .base512: return Base512Symbols.symbolCount(for: nameFieldBytes) * Base512Symbols.utf8BytesPerSymbol
        }
    }

    /// 4 KiB only when both the original file and the unpadded inner payload are under 64 KiB.
    /// A large compressible file therefore does not land in a 4 KiB bucket after zlib.
    public static func boundary(originalBytes: Int, unpaddedCount: Int) -> Int {
        max(originalBytes, unpaddedCount) < largeBoundary ? smallBoundary : largeBoundary
    }

    public static func boundary(forUnpaddedCount n: Int) -> Int {
        boundary(originalBytes: 0, unpaddedCount: n)
    }

    /// Always add a full block when already aligned so exact multiples do not leak.
    public static func padCount(cipherBytes: Int, boundary: Int) -> Int {
        guard boundary > 0, cipherBytes >= 0 else { return 0 }
        let rem = cipherBytes % boundary
        return rem == 0 ? boundary : boundary - rem
    }

    public static func padData(_ data: Data, originalBytes: Int = 0) throws -> Data {
        let extra = padCount(
            cipherBytes: data.count,
            boundary: boundary(originalBytes: originalBytes, unpaddedCount: data.count)
        )
        guard extra > 0 else { return data }
        return data + (try M10MessageKey.randomBytes(extra))
    }

    public static func encodeNameField(_ name: String) throws -> Data {
        let utf8 = utf8Fitting(name, maxBytes: nameFieldBytes - 2)
        var field = Data()
        var length = UInt16(utf8.count).bigEndian
        field.append(Data(bytes: &length, count: 2))
        field.append(utf8)
        let extra = nameFieldBytes - field.count
        if extra > 0 {
            field.append(try M10MessageKey.randomBytes(extra))
        }
        return field
    }

    /// Drop trailing unicode scalars until the UTF-8 encoding fits. Never splits a codepoint.
    static func utf8Fitting(_ name: String, maxBytes: Int) -> Data {
        guard maxBytes > 0 else { return Data() }
        var data = Data()
        data.reserveCapacity(min(maxBytes, name.utf8.count))
        for scalar in name.unicodeScalars {
            let encoded = String(scalar).utf8
            let width = encoded.count
            if data.count + width > maxBytes { break }
            data.append(contentsOf: encoded)
        }
        return data
    }

    public static func decodeNameField(_ field: Data) throws -> String {
        guard field.count == nameFieldBytes else { throw M10Error.corruptFilename }
        let length = (Int(field[0]) << 8) | Int(field[1])
        guard length <= nameFieldBytes - 2 else { throw M10Error.corruptFilename }
        if length == 0 { return "" }
        let slice = field[2..<(2 + length)]
        guard let name = String(data: Data(slice), encoding: .utf8) else {
            throw M10Error.corruptFilename
        }
        return name
    }

    public static func encodeNameWire(
        _ name: String,
        suite: M10CipherSuite,
        encrypt: Bool,
        machine: M10Machine
    ) throws -> (bytes: Data, field: String) {
        let field = try encodeNameField(name)
        if suite == .base256 {
            let raw = encrypt ? machine.processBytes(field) : field
            return (raw, Base256Symbols.encodeFilenameCiphertext(raw))
        }
        var symbols = PairCodec.encode(field, suite: suite)
        if encrypt {
            symbols = machine.processMessage(symbols)
        }
        return (Data(symbols.utf8), symbols)
    }

    public static func decodeNameWire(
        _ field: String,
        suite: M10CipherSuite,
        encrypted: Bool,
        machine: M10Machine
    ) throws -> String {
        let plain: Data
        if suite == .base256 {
            guard let raw = Base256Symbols.decodeFilenameCiphertext(field),
                  raw.count == nameFieldBytes else {
                throw M10Error.corruptFilename
            }
            plain = encrypted ? machine.processBytes(raw) : raw
        } else {
            let symbols = encrypted ? machine.processMessage(field) : field
            guard let data = PairCodec.decode(symbols, suite: suite, storedLength: nameFieldBytes) else {
                throw M10Error.corruptFilename
            }
            plain = data
        }
        return try decodeNameField(plain)
    }

    public static func randomSymbols(count: Int, suite: M10CipherSuite) throws -> String {
        guard count > 0 else { return "" }
        if suite == .base256 {
            return Base256Symbols.latin1String(try M10MessageKey.randomBytes(count))
        }
        let size = suite.alphabetSize
        var symbols = ""
        symbols.reserveCapacity(count)
        while symbols.count < count {
            let need = max(32, (count - symbols.count) * 2)
            let chunk = try M10MessageKey.randomBytes(need)
            if size <= 256 {
                let limit = (256 / size) * size
                for byte in chunk {
                    let value = Int(byte)
                    guard value < limit else { continue }
                    symbols.append(suite.indexToChar(value % size))
                    if symbols.count == count { break }
                }
            } else {
                var i = 0
                while i + 1 < chunk.count, symbols.count < count {
                    let value = (Int(chunk[i]) << 8) | Int(chunk[i + 1])
                    i += 2
                    let limit = (65_536 / size) * size
                    guard value < limit else { continue }
                    symbols.append(suite.indexToChar(value % size))
                }
            }
        }
        return symbols
    }
}

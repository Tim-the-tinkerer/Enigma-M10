import Foundation

enum ZlibCodec {
    static func compress(_ data: Data) -> Data? {
        guard !data.isEmpty else { return Data() }
        return try? (data as NSData).compressed(using: .zlib) as Data
    }

    static func decompress(_ data: Data, expectedSize: Int) -> Data? {
        if expectedSize == 0 { return Data() }
        guard expectedSize > 0, expectedSize <= M10Format.maxStreamPayloadBytes else { return nil }
        guard let out = try? (data as NSData).decompressed(using: .zlib) as Data else { return nil }
        guard out.count == expectedSize else { return nil }
        return out
    }
}

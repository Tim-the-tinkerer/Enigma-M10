import Foundation
import Compression

enum M10Secure {
    static func equal(_ a: Data, _ b: Data) -> Bool {
        guard a.count == b.count else { return false }
        var diff: UInt8 = 0
        for index in 0..<a.count {
            diff |= a[index] ^ b[index]
        }
        return diff == 0
    }

    static func equalHex(_ a: String, _ b: String) -> Bool {
        equal(Data(a.lowercased().utf8), Data(b.lowercased().utf8))
    }

    /// `offset + length` without wrapping. Rejects before the add can overflow.
    static func slice(_ data: Data, offset: Int, length: Int) throws -> Data {
        let range = try range(offset: offset, length: length, in: data.count)
        return data.subdata(in: range)
    }

    static func range(offset: Int, length: Int, in count: Int) throws -> Range<Int> {
        guard offset >= 0, length >= 0, count >= 0 else { throw M10Error.invalidFormat }
        guard offset <= count, length <= count - offset else { throw M10Error.invalidFormat }
        return offset..<(offset + length)
    }

    static func hybridOffset(binaryOffset: UInt64, payloadOffset: Int?) throws -> Int {
        guard binaryOffset <= UInt64(Int.max) else { throw M10Error.invalidFormat }
        let extra = payloadOffset ?? 0
        guard extra >= 0 else { throw M10Error.invalidFormat }
        let (sum, overflow) = Int(binaryOffset).addingReportingOverflow(extra)
        guard !overflow else { throw M10Error.invalidFormat }
        return sum
    }
}

enum FileIO {
    static let chunkBytes = 2_097_152

    static func byteCount(at url: URL) throws -> Int {
        let attrs = try FileManager.default.attributesOfItem(atPath: url.path)
        guard let size = attrs[.size] as? NSNumber else {
            throw M10Error.unreadableFile(url.lastPathComponent)
        }
        let value = size.intValue
        guard value >= 0 else { throw M10Error.unreadableFile(url.lastPathComponent) }
        return value
    }

    static func createEmptyFile(at url: URL) throws -> FileHandle {
        let parent = url.deletingLastPathComponent()
        try FileManager.default.createDirectory(at: parent, withIntermediateDirectories: true)
        if FileManager.default.fileExists(atPath: url.path) {
            try FileManager.default.removeItem(at: url)
        }
        FileManager.default.createFile(atPath: url.path, contents: nil)
        return try FileHandle(forWritingTo: url)
    }

    static func temporaryURL(_ prefix: String) -> URL {
        FileManager.default.temporaryDirectory.appendingPathComponent(
            "\(prefix)_\(UUID().uuidString)"
        )
    }

    static func copyContents(from url: URL, to handle: FileHandle) throws {
        let input = try FileHandle(forReadingFrom: url)
        defer { try? input.close() }
        while true {
            let chunk = try input.read(upToCount: chunkBytes) ?? Data()
            if chunk.isEmpty { break }
            handle.write(chunk)
        }
    }
}

public enum CRC32 {
    private static let table: [UInt32] = (0..<256).map { index in
        var crc = UInt32(index)
        for _ in 0..<8 {
            crc = (crc & 1) != 0 ? (crc >> 1) ^ 0xEDB88320 : crc >> 1
        }
        return crc
    }

    struct Hasher {
        private var crc: UInt32 = 0xFFFFFFFF

        mutating func update(_ data: Data) {
            for byte in data {
                let idx = Int((crc ^ UInt32(byte)) & 0xFF)
                crc = table[idx] ^ (crc >> 8)
            }
        }

        var value: UInt32 { crc ^ 0xFFFFFFFF }
    }

    public static func hash(_ data: Data) -> UInt32 {
        var hasher = Hasher()
        hasher.update(data)
        return hasher.value
    }

    static func hashFile(at url: URL) throws -> UInt32 {
        var hasher = Hasher()
        let input = try FileHandle(forReadingFrom: url)
        defer { try? input.close() }
        while true {
            let chunk = try input.read(upToCount: FileIO.chunkBytes) ?? Data()
            if chunk.isEmpty { break }
            hasher.update(chunk)
        }
        return hasher.value
    }
}

enum StreamZlib {
    private static let bufferSize = 65_536

    static func compress(from input: URL, to output: URL) throws {
        try transcode(operation: COMPRESSION_STREAM_ENCODE, from: input, to: output)
    }

    static func decompress(from input: URL, to output: URL, expectedSize: Int) throws {
        try transcode(operation: COMPRESSION_STREAM_DECODE, from: input, to: output)
        let size = try FileIO.byteCount(at: output)
        guard size == expectedSize else { throw M10Error.corruptPayload }
    }

    private static func transcode(
        operation: compression_stream_operation,
        from input: URL,
        to output: URL
    ) throws {
        let src = try FileHandle(forReadingFrom: input)
        defer { try? src.close() }
        let dst = try FileIO.createEmptyFile(at: output)
        defer { try? dst.close() }

        let dummy = UnsafeMutablePointer<UInt8>.allocate(capacity: 1)
        defer { dummy.deallocate() }
        var stream = compression_stream(
            dst_ptr: dummy,
            dst_size: 0,
            src_ptr: UnsafePointer(dummy),
            src_size: 0,
            state: nil
        )
        let initStatus = compression_stream_init(&stream, operation, COMPRESSION_ZLIB)
        guard initStatus == COMPRESSION_STATUS_OK else { throw M10Error.corruptPayload }
        defer { compression_stream_destroy(&stream) }

        let srcBuffer = UnsafeMutablePointer<UInt8>.allocate(capacity: bufferSize)
        let dstBuffer = UnsafeMutablePointer<UInt8>.allocate(capacity: bufferSize)
        defer {
            srcBuffer.deallocate()
            dstBuffer.deallocate()
        }

        var eof = false
        while true {
            if stream.src_size == 0, !eof {
                let chunk = try src.read(upToCount: bufferSize) ?? Data()
                if chunk.isEmpty {
                    eof = true
                    stream.src_size = 0
                    stream.src_ptr = UnsafePointer(srcBuffer)
                } else {
                    chunk.copyBytes(to: srcBuffer, count: chunk.count)
                    stream.src_ptr = UnsafePointer(srcBuffer)
                    stream.src_size = chunk.count
                }
            }

            stream.dst_ptr = dstBuffer
            stream.dst_size = bufferSize
            let flags: Int32 = eof ? Int32(COMPRESSION_STREAM_FINALIZE.rawValue) : 0
            let status = compression_stream_process(&stream, flags)
            let produced = bufferSize - stream.dst_size
            if produced > 0 {
                dst.write(Data(bytes: dstBuffer, count: produced))
            }

            switch status {
            case COMPRESSION_STATUS_END:
                return
            case COMPRESSION_STATUS_OK:
                continue
            default:
                throw M10Error.corruptPayload
            }
        }
    }
}

import Foundation

public enum M10Stepping: String, Sendable {
    /// v1/v2: a rotor steps when its right neighbor *sits* on a notch.
    case parkedNotch
    /// v3: a rotor steps only when its right neighbor is *itself stepping* and on a notch.
    case carryCascade

    public static func forArchiveVersion(_ version: Int) -> M10Stepping {
        version >= M10Format.carrySteppingVersion ? .carryCascade : .parkedNotch
    }
}

/// Ten-rotor Enigma.
public final class M10Machine {
    private struct Rotor {
        let forward: [Int]
        let reverse: [Int]
        let notches: Set<Int>
    }

    private let suite: M10CipherSuite
    private let alphabetSize: Int
    private var rotors: [Rotor] = []
    private var reflector: [Int] = []
    private var rings: [Int] = []
    private var positions: [Int] = []
    private var plugboard: [Int] = []
    private var initialPositions: [Int] = []
    private var derivedMachine: M10DerivedMachine?
    private let stepping: M10Stepping

    public init(configuration: M10Configuration, stepping: M10Stepping = .carryCascade) throws {
        let config = try configuration.validated()
        suite = config.cipherSuite
        alphabetSize = config.cipherSuite.alphabetSize
        derivedMachine = config.derivedMachine
        self.stepping = stepping
        plugboard = Array(0..<alphabetSize)
        reset(
            rotorNames: config.rotorNames,
            reflector: config.reflector,
            rings: config.rings,
            positions: config.positions
        )
        try setPlugboard(pairs: config.plugPairs)
    }

    public func reset(
        rotorNames: [String],
        reflector reflectorKey: String,
        rings: String,
        positions: String
    ) {
        if let derived = derivedMachine {
            rotors = (0..<M10Catalog.rotorCount).map { index in
                rotor(forward: derived.rotorWirings[index], notches: derived.rotorNotches[index])
            }
            reflector = derived.reflectorWiring
        } else {
            rotors = rotorNames.map { makeRotor(name: $0) }
            reflector = makeReflector(name: reflectorKey)
        }
        self.rings = symbolsToIndices(rings)
        self.positions = symbolsToIndices(positions)
        initialPositions = self.positions
        precondition(rotors.count == M10Catalog.rotorCount)
        precondition(self.rings.count == M10Catalog.rotorCount)
        precondition(self.positions.count == M10Catalog.rotorCount)
        precondition(reflector.count == alphabetSize)
    }

    public func resetPositions() {
        positions = initialPositions
    }

    public func currentPositions() -> String {
        if suite == .base256 {
            return Base256Symbols.formatField(positions)
        }
        return positions.map { indexToChar($0) }.map(String.init).joined()
    }

    public func processBytes(_ data: Data) -> Data {
        var output = Data()
        output.reserveCapacity(data.count)
        for byte in data {
            output.append(UInt8(encryptSymbolIndex(Int(byte))))
        }
        return output
    }

    public func processMessage(_ text: String) -> String {
        guard !text.isEmpty else { return "" }
        var result = ""
        result.reserveCapacity(text.count)
        for character in text {
            guard let index = charToIndex(character) else { continue }
            result.append(indexToChar(encryptSymbolIndex(index)))
        }
        return result
    }

    public func processMessageInChunks(_ text: String, chunkSize: Int = 1_048_576) -> String {
        guard !text.isEmpty else { return "" }
        var result = ""
        result.reserveCapacity(text.count)
        var index = text.startIndex
        while index < text.endIndex {
            let end = text.index(index, offsetBy: chunkSize, limitedBy: text.endIndex) ?? text.endIndex
            result.append(processMessage(String(text[index..<end])))
            index = end
        }
        return result
    }

    /// Stream symbol bytes from disk through the machine into a ciphertext file.
    public func processMessageFromSymbolFile(at url: URL, to output: FileHandle) throws {
        let input = try FileHandle(forReadingFrom: url)
        defer { try? input.close() }
        var writeBuf = Data()
        writeBuf.reserveCapacity(65_536)
        while true {
            let chunk = try input.read(upToCount: FileIO.chunkBytes) ?? Data()
            if chunk.isEmpty { break }
            for byte in chunk {
                if suite == .base256 {
                    writeBuf.append(UInt8(encryptSymbolIndex(Int(byte))))
                } else {
                    let character = Character(UnicodeScalar(byte))
                    guard let index = charToIndex(character),
                          let ascii = indexToChar(encryptSymbolIndex(index)).asciiValue else { continue }
                    writeBuf.append(ascii)
                }
                if writeBuf.count >= 65_536 {
                    output.write(writeBuf)
                    writeBuf.removeAll(keepingCapacity: true)
                }
            }
        }
        if !writeBuf.isEmpty { output.write(writeBuf) }
    }

    /// Stream ciphertext symbols from disk through the machine into a plaintext-symbol file.
    public func processMessageToSymbolFile(from input: FileHandle, length: Int, to output: URL) throws {
        let dest = try FileIO.createEmptyFile(at: output)
        defer { try? dest.close() }
        guard length > 0 else { return }
        var remaining = length
        var writeBuf = Data()
        writeBuf.reserveCapacity(65_536)
        while remaining > 0 {
            let toRead = min(FileIO.chunkBytes, remaining)
            let chunk = try input.read(upToCount: toRead) ?? Data()
            if chunk.isEmpty { throw M10Error.corruptPayload }
            remaining -= chunk.count
            for byte in chunk {
                if suite == .base256 {
                    writeBuf.append(UInt8(encryptSymbolIndex(Int(byte))))
                } else {
                    let character = Character(UnicodeScalar(byte))
                    guard let index = charToIndex(character),
                          let ascii = indexToChar(encryptSymbolIndex(index)).asciiValue else { continue }
                    writeBuf.append(ascii)
                }
                if writeBuf.count >= 65_536 {
                    dest.write(writeBuf)
                    writeBuf.removeAll(keepingCapacity: true)
                }
            }
        }
        if !writeBuf.isEmpty { dest.write(writeBuf) }
    }

    private func encryptSymbolIndex(_ signal: Int) -> Int {
        var value = plugboard[signal]
        step()
        for index in stride(from: rotors.count - 1, through: 0, by: -1) {
            value = applyRotor(value, rotor: rotors[index], position: positions[index], ring: rings[index], forward: true)
        }
        value = reflector[value]
        for index in 0..<rotors.count {
            value = applyRotor(value, rotor: rotors[index], position: positions[index], ring: rings[index], forward: false)
        }
        return plugboard[value]
    }

    /// Rightmost rotor always advances.
    /// - parkedNotch (v2): left rotor steps if the right neighbor currently sits on a notch.
    /// - carryCascade (v3): left rotor steps only if that neighbor is itself stepping and on a notch.
    private func step() {
        let count = rotors.count
        var willStep = [Bool](repeating: false, count: count)
        willStep[count - 1] = true
        for index in stride(from: count - 2, through: 0, by: -1) {
            let neighborOnNotch = rotors[index + 1].notches.contains(positions[index + 1])
            switch stepping {
            case .parkedNotch:
                willStep[index] = neighborOnNotch
            case .carryCascade:
                willStep[index] = willStep[index + 1] && neighborOnNotch
            }
        }
        for index in 0..<count where willStep[index] {
            positions[index] = (positions[index] + 1) % alphabetSize
        }
    }

    private func applyRotor(_ value: Int, rotor: Rotor, position: Int, ring: Int, forward: Bool) -> Int {
        let offset = (position - ring + alphabetSize) % alphabetSize
        var signal = (value + offset) % alphabetSize
        signal = forward ? rotor.forward[signal] : rotor.reverse[signal]
        return (signal - offset + alphabetSize) % alphabetSize
    }

    private func setPlugboard(pairs: [String]) throws {
        plugboard = Array(0..<alphabetSize)
        for pair in pairs {
            let symbols: [Character]
            switch suite {
            case .base256:
                guard let (a, b) = Base256Symbols.parsePlugPair(pair) else { continue }
                plugboard[a] = b
                plugboard[b] = a
                continue
            case .alpha36:
                symbols = Array(pair.uppercased().filter { Alpha36Symbols.isValidSymbol($0) })
            case .ascii:
                symbols = Array(pair.filter { Ascii94Symbols.isValidSymbol($0) })
            }
            let a = charToIndex(symbols[0])!
            let b = charToIndex(symbols[1])!
            plugboard[a] = b
            plugboard[b] = a
        }
    }

    private func rotor(forward: [Int], notches: Set<Int>) -> Rotor {
        var reverse = Array(repeating: 0, count: alphabetSize)
        for (input, output) in forward.enumerated() {
            reverse[output] = input
        }
        return Rotor(forward: forward, reverse: reverse, notches: notches)
    }

    private func makeRotor(name: String) -> Rotor {
        let forward: [Int]
        let notches: Set<Int>
        switch suite {
        case .alpha36:
            guard let wiring = M10Catalog.Alpha36.rotorPermutation(name) else {
                preconditionFailure("Invalid rotor after validation: \(name)")
            }
            forward = wiring
            notches = M10Catalog.Alpha36.notchSet(name)
        case .ascii:
            guard let wiring = M10Catalog.Ascii94.rotorWirings[name] else {
                preconditionFailure("Invalid rotor after validation: \(name)")
            }
            forward = wiring
            notches = M10Catalog.Ascii94.notchSet(name)
        case .base256:
            guard let wiring = M10Catalog.Base256.rotorWirings[name] else {
                preconditionFailure("Invalid rotor after validation: \(name)")
            }
            forward = wiring
            notches = M10Catalog.Base256.notchSet(name)
        }
        return rotor(forward: forward, notches: notches)
    }

    private func makeReflector(name: String) -> [Int] {
        switch suite {
        case .alpha36:
            guard let wiring = M10Catalog.Alpha36.reflectorPermutation(name) else {
                preconditionFailure("Invalid reflector after validation: \(name)")
            }
            return wiring
        case .ascii:
            guard let wiring = M10Catalog.Ascii94.reflectorWirings[name] else {
                preconditionFailure("Invalid reflector after validation: \(name)")
            }
            return wiring
        case .base256:
            guard let wiring = M10Catalog.Base256.reflectorWirings[name] else {
                preconditionFailure("Invalid reflector after validation: \(name)")
            }
            return wiring
        }
    }

    private func charToIndex(_ character: Character) -> Int? {
        switch suite {
        case .alpha36: return Alpha36Symbols.charToIndex(character)
        case .ascii: return Ascii94Symbols.charToIndex(character)
        case .base256: return Base256Symbols.charToIndex(character)
        }
    }

    private func indexToChar(_ index: Int) -> Character {
        switch suite {
        case .alpha36: return Alpha36Symbols.indexToChar(index)
        case .ascii: return Ascii94Symbols.indexToChar(index)
        case .base256: return Base256Symbols.indexToChar(index)
        }
    }

    private func symbolsToIndices(_ value: String) -> [Int] {
        switch suite {
        case .alpha36:
            return value.uppercased().compactMap(Alpha36Symbols.charToIndex)
        case .ascii:
            return value.compactMap(Ascii94Symbols.charToIndex)
        case .base256:
            return Base256Symbols.parseField(value) ?? []
        }
    }
}

public enum M10SelfTest {
    /// Factory Alpha-36: `00000` → `V661T`.
    public static let alpha36Plain = "00000"
    public static let alpha36Cipher = "V661T"

    public static func run() -> Bool {
        guard let machine = try? M10Machine(configuration: .alpha36Factory) else { return false }
        let out = machine.processMessage(alpha36Plain)
        guard out == alpha36Cipher else { return false }
        machine.resetPositions()
        return machine.processMessage(out) == alpha36Plain
    }
}

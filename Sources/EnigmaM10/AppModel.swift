import SwiftUI
import AppKit
import UniformTypeIdentifiers
import Combine
import EnigmaM10Core

@MainActor
final class AppModel: ObservableObject {
    struct Item: Identifiable, Equatable {
        enum Kind: Equatable, Sendable { case plain, directory, archive }
        enum Status: Equatable {
            case ready
            case working
            case done(URL)
            case failed(String)
        }

        let id: UUID
        let url: URL
        let kind: Kind
        let byteCount: Int
        var status: Status

        init(id: UUID = UUID(), url: URL, kind: Kind, byteCount: Int, status: Status = .ready) {
            self.id = id
            self.url = url
            self.kind = kind
            self.byteCount = byteCount
            self.status = status
        }

        var name: String { url.lastPathComponent }

        var sizeLabel: String {
            switch kind {
            case .directory:
                return byteCount <= 0
                    ? "Folder"
                    : "Folder · \(ByteCountFormatter.string(fromByteCount: Int64(byteCount), countStyle: .file))"
            case .plain, .archive:
                return ByteCountFormatter.string(fromByteCount: Int64(byteCount), countStyle: .file)
            }
        }

        var actionLabel: String {
            switch kind {
            case .plain: return "Encrypt → .enigmam10"
            case .directory: return "Encrypt folder → .enigmam10"
            case .archive: return "Decrypt"
            }
        }
    }

    @Published var cipherSuite: M10CipherSuite = .base256 {
        didSet {
            guard !applyingConfig, oldValue != cipherSuite else { return }
            let previous = M10Configuration(
                cipherSuite: oldValue,
                rotorNames: M10Configuration.parseRotorOrder(rotorOrder),
                reflector: reflector,
                rings: rings,
                positions: positions,
                plugPairs: M10Configuration.parsePlugPairs(plugs, suite: oldValue)
            )
            let converted = (try? previous.validated())?.withSuite(cipherSuite)
                ?? M10Configuration.random(suite: cipherSuite)
            apply(converted)
        }
    }
    @Published var rotorOrder: String = M10Configuration.base256Factory.rotorOrderString
    @Published var reflector: String = M10Configuration.base256Factory.reflector
    @Published var rings: String = M10Configuration.base256Factory.rings
    @Published var positions: String = M10Configuration.base256Factory.positions
    @Published var plugs: String = M10Configuration.base256Factory.plugString
    @Published var encryptFileNames = true
    @Published var keyMode: M10KeyMode = .password
    @Published var password = ""

    @Published var items: [Item] = []
    @Published var statusMessage: String?
    @Published var alertMessage: String?
    @Published var isBusy = false
    @Published var selfTestPassed = M10SelfTest.run()

    @Published var textInput = "HELLO M10"
    @Published var textDecrypt = false
    @Published var showText = false

    private var workTask: Task<Void, Never>?
    private var recentOpenKeys: [String: Date] = [:]
    private var applyingConfig = false
    private let fileWorker = FileWorkActor()

    init() {
        apply(M10Configuration.random(suite: cipherSuite))
        statusMessage = "Password mode. Argon2id derives a unique machine per file. External key writes a .m10key. Internal key stores the codebook in the archive."
    }

    var configuration: M10Configuration {
        M10Configuration(
            cipherSuite: cipherSuite,
            rotorNames: M10Configuration.parseRotorOrder(rotorOrder),
            reflector: reflector,
            rings: rings,
            positions: positions,
            plugPairs: M10Configuration.parsePlugPairs(plugs, suite: cipherSuite)
        )
    }

    var settingsError: String? {
        if keyMode == .password { return nil }
        do {
            _ = try configuration.validated()
            return nil
        } catch {
            return error.localizedDescription
        }
    }

    var settingsAreValid: Bool { settingsError == nil }

    var isPublicDemonstration: Bool {
        (keyMode == .external || keyMode == .internalKey) && configuration.isFactory
    }

    var codebookStatus: String {
        switch keyMode {
        case .password:
            return "Password mode — salt + Argon2id params in the archive; rotors are not stored"
        case .external:
            if isPublicDemonstration {
                return "Demonstration codebook (public — anyone with this app can decrypt)"
            }
            return "External key — this machine is unused. Encrypt once; the .m10key keeps it. A new machine is generated after."
        case .internalKey:
            if isPublicDemonstration {
                return "Demonstration codebook (public — anyone with this app can decrypt)"
            }
            return "Internal key — the codebook is stored in the archive. Anyone with the file can decrypt."
        }
    }

    var textOutput: String {
        guard settingsAreValid else { return "" }
        let machine: M10Machine
        do {
            machine = try M10Machine(configuration: configuration)
        } catch {
            return ""
        }
        if textDecrypt {
            return machine.processMessage(textInput)
        }
        return machine.processMessage(textInput)
    }

    func resetFactory() {
        apply(M10Configuration.factory(for: cipherSuite))
        statusMessage = "Demonstration codebook loaded. It is public; use it only to open old demo archives."
    }

    func generatePersonalCodebook() {
        apply(M10Configuration.random(suite: cipherSuite))
        switch keyMode {
        case .internalKey:
            statusMessage = "New random codebook for this session. Internal key mode stores it in the archive on encrypt."
        case .external, .password:
            statusMessage = "New random codebook for this session. Save a .m10key to decrypt these files later."
        }
    }

    func apply(_ config: M10Configuration) {
        applyingConfig = true
        cipherSuite = config.cipherSuite
        rotorOrder = config.rotorOrderString
        reflector = config.reflector
        rings = config.rings
        positions = config.positions
        plugs = config.plugString
        applyingConfig = false
    }

    func saveCodebook() {
        guard settingsAreValid else {
            alertMessage = settingsError
            return
        }
        let panel = NSSavePanel()
        panel.title = "Save M10 Codebook"
        panel.nameFieldStringValue = "M10-\(cipherSuite.rawValue).\(M10Format.codebookExtension)"
        panel.allowedContentTypes = [UTType(filenameExtension: M10Format.codebookExtension) ?? .json]
        panel.canCreateDirectories = true
        guard panel.runModal() == .OK, let url = panel.url else { return }
        do {
            let data = try M10Codebook.encode(try configuration.validated())
            try data.write(to: url, options: .atomic)
            statusMessage = "Saved codebook \(url.lastPathComponent)"
        } catch {
            alertMessage = error.localizedDescription
        }
    }

    func loadCodebook() {
        let panel = NSOpenPanel()
        panel.title = "Load M10 Codebook"
        panel.allowsMultipleSelection = false
        panel.canChooseDirectories = false
        panel.allowedContentTypes = [.json, .item]
        panel.allowsOtherFileTypes = true
        guard panel.runModal() == .OK, let url = panel.url else { return }
        loadCodebook(from: url)
    }

    func loadCodebook(from url: URL) {
        do {
            let data = try Data(contentsOf: url)
            let config = try M10Codebook.decode(data)
            apply(config)
            statusMessage = isPublicDemonstration
                ? "Loaded demonstration codebook (public)"
                : "Loaded codebook \(url.lastPathComponent)"
        } catch {
            alertMessage = "Could not load codebook: \(error.localizedDescription)"
        }
    }

    func copyOutput() {
        let s = textOutput
        guard !s.isEmpty else { return }
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(s, forType: .string)
        statusMessage = "Copied ciphertext"
    }

    func openFiles() {
        let panel = NSOpenPanel()
        panel.title = "Choose Files or Folders"
        panel.message = "Pick files or folders to encrypt, or .enigmam10 files to decrypt."
        panel.allowsMultipleSelection = true
        panel.canChooseDirectories = true
        panel.canChooseFiles = true
        panel.allowedContentTypes = [.item]
        panel.allowsOtherFileTypes = true
        panel.treatsFilePackagesAsDirectories = true
        guard panel.runModal() == .OK else { return }
        add(panel.urls)
    }

    @discardableResult
    func add(_ urls: [URL], autoDecryptArchives: Bool = true) -> [UUID] {
        let filtered = dedupeIncoming(urls)
        var newIDs: [UUID] = []
        for url in filtered {
            guard url.isFileURL else { continue }
            if url.pathExtension.lowercased() == M10Format.codebookExtension {
                loadCodebook(from: url)
                continue
            }
            var isDir: ObjCBool = false
            guard FileManager.default.fileExists(atPath: url.path, isDirectory: &isDir) else {
                continue
            }
            if let existing = items.firstIndex(where: {
                $0.url.standardizedFileURL == url.standardizedFileURL
            }) {
                if items[existing].kind == .archive, autoDecryptArchives {
                    items[existing].status = .ready
                    newIDs.append(items[existing].id)
                }
                continue
            }

            let kind: Item.Kind
            let size: Int
            if isDir.boolValue {
                kind = .directory
                size = 0
            } else if url.pathExtension.lowercased() == M10Format.fileExtension
                        || M10Format.isArchive(at: url) {
                kind = .archive
                size = (try? FileManager.default.attributesOfItem(atPath: url.path)[.size] as? NSNumber)?.intValue ?? 0
            } else {
                kind = .plain
                size = (try? FileManager.default.attributesOfItem(atPath: url.path)[.size] as? NSNumber)?.intValue ?? 0
            }
            let item = Item(url: url, kind: kind, byteCount: size)
            items.append(item)
            newIDs.append(item.id)
        }

        if autoDecryptArchives {
            let archiveIDs = newIDs.filter { id in
                items.first(where: { $0.id == id })?.kind == .archive
            }
            if !archiveIDs.isEmpty {
                runJobs(ids: archiveIDs)
            } else if !newIDs.isEmpty {
                statusMessage = "Added \(newIDs.count) item\(newIDs.count == 1 ? "" : "s")"
            }
        }
        return newIDs
    }

    func handleOpenedFiles(_ urls: [URL]) {
        NSApp.activate(ignoringOtherApps: true)
        add(urls)
    }

    func remove(_ id: UUID) {
        items.removeAll { $0.id == id }
    }

    func clearFinished() {
        items.removeAll {
            if case .done = $0.status { return true }
            return false
        }
    }

    func processAll() {
        let ids = items.filter {
            if case .ready = $0.status { return true }
            if case .failed = $0.status { return true }
            return false
        }.map(\.id)
        runJobs(ids: ids, decryptMode: .authenticated)
    }

    func process(id: UUID) {
        runJobs(ids: [id], decryptMode: .authenticated)
    }

    func legacyImportArchives() {
        let ids = items.filter { $0.kind == .archive }.map(\.id)
        guard !ids.isEmpty else {
            alertMessage = "Drop a .enigmam10 archive first."
            return
        }
        let alert = NSAlert()
        alert.messageText = "Legacy Import"
        alert.informativeText = """
        ENIGMAM10 v1 files have no required authentication. Relabeling a v2–v4 archive as v1 is rejected on this path.

        Recovered items are named UNAUTHENTICATED-… and should not be treated as authentic.
        """
        alert.addButton(withTitle: "Import as Unauthenticated")
        alert.addButton(withTitle: "Cancel")
        guard alert.runModal() == .alertFirstButtonReturn else { return }
        runJobs(ids: ids, decryptMode: .legacyImport)
    }

    private func snapshotNeedsEncrypt(_ ids: [UUID]) -> Bool {
        items.contains { item in
            ids.contains(item.id) && (item.kind == .plain || item.kind == .directory)
        }
    }

    private func runJobs(ids: [UUID], decryptMode: M10DecryptMode = .authenticated) {
        guard !ids.isEmpty else { return }
        guard settingsAreValid else {
            alertMessage = settingsError
            return
        }
        let encrypting = snapshotNeedsEncrypt(ids)
        if encrypting, keyMode == .password, password.isEmpty {
            alertMessage = M10Error.passwordRequired.errorDescription
            return
        }
        if encrypting, isPublicDemonstration {
            alertMessage = M10Error.publicCodebook.errorDescription
            return
        }
        workTask?.cancel()
        isBusy = true
        let config: M10Configuration
        do {
            config = keyMode == .password
                ? M10Configuration.factory(for: cipherSuite)
                : try configuration.validated()
        } catch {
            alertMessage = error.localizedDescription
            isBusy = false
            return
        }
        let encryptNames = encryptFileNames
        let jobPassword = keyMode == .password ? password : nil
        let writeSidecar = keyMode == .external
        let burnsMachine = keyMode == .external || keyMode == .internalKey
        let jobKeyMode = keyMode
        let snapshot = ids.compactMap { id -> (UUID, URL, Item.Kind)? in
            guard let item = items.first(where: { $0.id == id }) else { return nil }
            return (item.id, item.url, item.kind)
        }
        for (id, _, _) in snapshot {
            if let idx = items.firstIndex(where: { $0.id == id }) {
                items[idx].status = .working
            }
        }

        workTask = Task {
            var lastURL: URL?
            var failures = 0
            var successes = 0
            var liveConfig = config
            var burned = 0
            for (id, url, kind) in snapshot {
                if Task.isCancelled { break }
                do {
                    let dest = try await fileWorker.process(
                        url: url,
                        kind: kind,
                        configuration: liveConfig,
                        encryptFilename: encryptNames,
                        decryptMode: decryptMode,
                        password: jobPassword,
                        writeSidecar: writeSidecar,
                        keyMode: jobKeyMode
                    )
                    if burnsMachine, kind == .plain || kind == .directory {
                        liveConfig = M10Configuration.random(suite: liveConfig.cipherSuite)
                        apply(liveConfig)
                        burned += 1
                    }
                    if let idx = items.firstIndex(where: { $0.id == id }) {
                        items[idx].status = .done(dest)
                    }
                    lastURL = dest
                    successes += 1
                } catch {
                    if let idx = items.firstIndex(where: { $0.id == id }) {
                        items[idx].status = .failed(error.localizedDescription)
                    }
                    failures += 1
                }
            }
            isBusy = false
            if successes == 1, failures == 0, let lastURL {
                if decryptMode == .legacyImport {
                    statusMessage = "Legacy import (unauthenticated): \(lastURL.lastPathComponent)"
                    NSWorkspace.shared.activateFileViewerSelecting([lastURL])
                } else {
                    let sidecar = M10Engine.sidecarURL(forArchive: lastURL)
                    if FileManager.default.fileExists(atPath: sidecar.path) {
                        statusMessage = burned > 0
                            ? "\(lastURL.lastPathComponent) + \(sidecar.lastPathComponent). Machine burned; new unused machine ready."
                            : "\(lastURL.lastPathComponent) + \(sidecar.lastPathComponent)"
                        NSWorkspace.shared.activateFileViewerSelecting([lastURL, sidecar])
                    } else if burned > 0 {
                        statusMessage = "\(lastURL.lastPathComponent). Codebook stored in the archive; new unused machine ready."
                        NSWorkspace.shared.activateFileViewerSelecting([lastURL])
                    } else {
                        statusMessage = lastURL.lastPathComponent
                        NSWorkspace.shared.activateFileViewerSelecting([lastURL])
                    }
                }
            } else if successes > 0, failures == 0 {
                statusMessage = burned > 0
                    ? (writeSidecar
                        ? "Finished \(successes). Each archive has its own .m10key; a new unused machine is ready."
                        : "Finished \(successes). Each archive stores its codebook; a new unused machine is ready.")
                    : "Finished \(successes) item\(successes == 1 ? "" : "s")"
            } else if failures > 0 {
                statusMessage = "Finished \(successes), failed \(failures)"
            }
        }
    }

    private func dedupeIncoming(_ urls: [URL]) -> [URL] {
        let now = Date()
        recentOpenKeys = recentOpenKeys.filter { now.timeIntervalSince($0.value) < 2.0 }
        var result: [URL] = []
        for url in urls {
            let key = url.standardizedFileURL.path
            if let last = recentOpenKeys[key], now.timeIntervalSince(last) < 1.5 {
                continue
            }
            recentOpenKeys[key] = now
            result.append(url)
        }
        return result
    }
}

private actor FileWorkActor {
    func process(
        url: URL,
        kind: AppModel.Item.Kind,
        configuration: M10Configuration,
        encryptFilename: Bool,
        decryptMode: M10DecryptMode,
        password: String?,
        writeSidecar: Bool,
        keyMode: M10KeyMode
    ) throws -> URL {
        switch kind {
        case .plain:
            let result = try M10Engine.encryptFile(
                at: url,
                configuration: configuration,
                encryptFilename: encryptFilename,
                password: password,
                keyMode: keyMode
            )
            return try M10Engine.writeEncryptResult(
                result, nextTo: url, configuration: writeSidecar ? configuration : nil
            )
        case .directory:
            let result = try M10Engine.encryptFolder(
                at: url,
                configuration: configuration,
                encryptFilename: encryptFilename,
                password: password,
                keyMode: keyMode
            )
            return try M10Engine.writeEncryptResult(
                result, nextTo: url, configuration: writeSidecar ? configuration : nil
            )
        case .archive:
            if M10PasswordBinary.matches(at: url) {
                let decrypted = try M10Engine.decryptFile(
                    at: url,
                    configuration: configuration,
                    mode: decryptMode,
                    password: password
                )
                return try M10Engine.writeDecryptResult(decrypted, nextTo: url)
            }
            let header = try M10Format.readHeader(at: url)
            let decryptConfig: M10Configuration
            let decryptPassword: String?
            if header.archive.keyMode == M10KeyMode.internalKey.rawValue,
               let stored = header.archive.codebook {
                decryptConfig = stored
                decryptPassword = nil
            } else if header.archive.kdf != nil {
                decryptConfig = configuration
                decryptPassword = password
            } else {
                decryptConfig = try M10Engine.loadSidecarCodebook(forArchive: url) ?? configuration
                decryptPassword = nil
            }
            let decrypted = try M10Engine.decryptFile(
                at: url,
                configuration: decryptConfig,
                mode: decryptMode,
                password: decryptPassword
            )
            return try M10Engine.writeDecryptResult(decrypted, nextTo: url)
        }
    }
}

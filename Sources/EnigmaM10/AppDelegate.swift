import AppKit
import SwiftUI

final class AppDelegate: NSObject, NSApplicationDelegate {
    weak var model: AppModel?
    private var pendingURLs: [URL] = []

    func applicationDidFinishLaunching(_ notification: Notification) {
        NSApp.activate(ignoringOtherApps: true)
    }

    func application(_ application: NSApplication, open urls: [URL]) {
        enqueue(urls)
    }

    func application(_ sender: NSApplication, openFile filename: String) -> Bool {
        enqueue([URL(fileURLWithPath: filename)])
        return true
    }

    func application(_ sender: NSApplication, openFiles filenames: [String]) {
        enqueue(filenames.map { URL(fileURLWithPath: $0) })
        sender.reply(toOpenOrPrint: .success)
    }

    @MainActor
    func attach(model: AppModel) {
        self.model = model
        flushPending()
    }

    private func enqueue(_ urls: [URL]) {
        Task { @MainActor in
            pendingURLs.append(contentsOf: urls)
            flushPending()
        }
    }

    @MainActor
    private func flushPending() {
        guard let model, !pendingURLs.isEmpty else { return }
        let urls = pendingURLs
        pendingURLs.removeAll()
        model.handleOpenedFiles(urls)
    }
}

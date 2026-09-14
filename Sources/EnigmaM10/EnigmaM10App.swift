import SwiftUI
import AppKit
import EnigmaM10Core

@main
struct EnigmaM10App: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) private var appDelegate
    @StateObject private var model = AppModel()

    var body: some Scene {
        WindowGroup {
            ContentView()
                .environmentObject(model)
                .tint(Color(red: 0.64, green: 0.89, blue: 0.21))
                .onAppear {
                    appDelegate.attach(model: model)
                }
                .onOpenURL { url in
                    model.handleOpenedFiles([url])
                }
        }
        .defaultSize(width: 860, height: 780)
        .commands {
            CommandGroup(replacing: .newItem) {
                Button("Open Files…") {
                    model.openFiles()
                }
                .keyboardShortcut("o", modifiers: .command)
            }
            CommandGroup(after: .saveItem) {
                Button("Encrypt / Decrypt All") {
                    model.processAll()
                }
                .keyboardShortcut(.return, modifiers: .command)
                .disabled(model.items.isEmpty || model.isBusy)
                Button("Legacy Import…") {
                    model.legacyImportArchives()
                }
                .keyboardShortcut("i", modifiers: [.command, .shift])
                .disabled(model.items.isEmpty || model.isBusy)
                Button("New Codebook") {
                    model.generatePersonalCodebook()
                }
                .keyboardShortcut("n", modifiers: [.command, .shift])
                Button("Demonstration Codebook") {
                    model.resetFactory()
                }
                .keyboardShortcut("f", modifiers: [.command, .shift])
                Button("Save Codebook…") {
                    model.saveCodebook()
                }
                .keyboardShortcut("s", modifiers: [.command, .shift])
                Button("Load Codebook…") {
                    model.loadCodebook()
                }
                .keyboardShortcut("l", modifiers: [.command, .shift])
            }
            CommandGroup(replacing: .help) {
                Button("Enigma – M 10 Help") {
                    showHelp()
                }
            }
        }
    }

    private func showHelp() {
        let alert = NSAlert()
        alert.messageText = "How it works"
        alert.informativeText = """
        Enigma – M 10 is a ten-rotor Enigma (Alpha-36, ASCII-94, Base-256). Experimental — not FileVault, age, or GPG.

        MACHINE
        • 10 rotors. New writes: carry cascade (a rotor steps only when its right neighbour is itself stepping and on a notch). v2 parked-notch decrypt is preserved.
        • Reflector never maps a symbol to itself (classic Enigma; keeps encrypt = decrypt).

        CIPHER SUITES
        • Base-256 (default) — every byte; 1:1 after optional zlib
        • Alpha-36 — 0–9A–Z, dense base-36
        • ASCII-94 — printable ASCII !–~, dense base-94. Plug pairs are space-separated (comma is a symbol).

        PASSWORD MODE (default)
        Argon2id (64 MiB / 3 / 1) + HKDF derives the whole machine. Output is opaque binary M10PW03 (salt, Argon2 params, nonce, HMAC, padded ciphertext). Exact sizes and CRC sit inside the ciphertext. Decrypt with the same password. No .m10key.

        EXTERNAL KEY MODE
        You carry a catalog configuration, not a password. Encrypt writes a .m10key beside the ENIGMAM10 v6 JSON archive, then generates a new unused machine. Decrypt loads the sidecar. Demonstration codebook is public and cannot encrypt.

        INTERNAL KEY MODE
        The catalog codebook is stored inside the archive. No password and no .m10key. Anyone who has the file can decrypt. Demonstration codebook cannot encrypt.

        PADDING
        New writes pad ciphertext to 4 KiB, or 64 KiB when the original file or inner payload is 64 KiB or larger. Filenames are stored in a fixed 256-byte field.

        DECRYPT
        Password files: Password mode + password, drop the .enigmam10.
        External-key files: drop the archive (sidecar loads automatically).
        Internal-key files: drop the archive; the stored codebook is used.
        v6/v5/v4/v3/v2 JSON and M10PW03/02/01 still decrypt. v1 needs Legacy Import… (output UNAUTHENTICATED-).
        """
        alert.addButton(withTitle: "OK")
        alert.runModal()
    }
}

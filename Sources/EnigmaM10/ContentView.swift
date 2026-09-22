import SwiftUI
import AppKit
import EnigmaM10Core

struct ContentView: View {
    @EnvironmentObject private var model: AppModel

    private let labelWidth: CGFloat = 72

    var body: some View {
        VStack(spacing: 0) {
            header
            Divider()
            machineBar
            Divider()
            fileArea
            if model.showText {
                Divider()
                textArea
            }
            Divider()
            footer
        }
        .frame(minWidth: 760, minHeight: 640)
        .background(Color(nsColor: .windowBackgroundColor))
        .onFileDrop { model.add($0) }
        .alert("Enigma – M 10", isPresented: alertBinding) {
            Button("OK", role: .cancel) { model.alertMessage = nil }
        } message: {
            Text(model.alertMessage ?? "")
        }
    }

    private var alertBinding: Binding<Bool> {
        Binding(
            get: { model.alertMessage != nil },
            set: { if !$0 { model.alertMessage = nil } }
        )
    }

    // MARK: - Header

    private var header: some View {
        HStack(spacing: 12) {
            Image(systemName: "circle.grid.3x3.fill")
                .font(.system(size: 26, weight: .medium))
                .foregroundStyle(.tint)

            VStack(alignment: .leading, spacing: 2) {
                Text("Enigma – M 10")
                    .font(.title2.weight(.semibold))
                Text("Ten-rotor Enigma · password, external key, or internal key · Base-256 / Alpha-36 / ASCII-94 / Base-512")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
            }

            Spacer(minLength: 8)

            HStack(spacing: 6) {
                Circle()
                    .fill(model.selfTestPassed ? Color.green : Color.red)
                    .frame(width: 8, height: 8)
                Text(model.selfTestPassed ? "Self-test OK" : "Self-test failed")
                    .font(.caption2)
                    .foregroundStyle(.secondary)
            }

            Button {
                model.showText.toggle()
            } label: {
                Label(model.showText ? "Hide Text" : "Text", systemImage: "text.alignleft")
            }
            .controlSize(.small)
        }
        .padding(.horizontal, 20)
        .padding(.vertical, 10)
    }

    // MARK: - Machine

    private var machineBar: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack(spacing: 12) {
                rowLabel("Key")
                Picker("Key", selection: $model.keyMode) {
                    ForEach(M10KeyMode.allCases) { mode in
                        Text(mode.title).tag(mode)
                    }
                }
                .pickerStyle(.segmented)
                .frame(width: 360)
                if model.keyMode == .password {
                    SecureField("Password", text: $model.password)
                        .textFieldStyle(.roundedBorder)
                        .frame(maxWidth: 280)
                }
                Spacer()
            }

            HStack(spacing: 12) {
                rowLabel("Suite")
                Picker("Suite", selection: $model.cipherSuite) {
                    ForEach(M10CipherSuite.allCases) { suite in
                        Text(suite.title).tag(suite)
                    }
                }
                .pickerStyle(.segmented)
                .frame(width: 480)
                Text(model.cipherSuite.detail)
                    .font(.caption2)
                    .foregroundStyle(.tertiary)
                    .lineLimit(1)
                Spacer()
                Toggle("Encrypt file names", isOn: $model.encryptFileNames)
                    .toggleStyle(.checkbox)
                    .controlSize(.small)
            }

            if model.keyMode == .external || model.keyMode == .internalKey {
            HStack(spacing: 12) {
                rowLabel("Rotors")
                TextField("X-VII-III-IX-I-VI-II-VIII-V-IV", text: $model.rotorOrder)
                    .textFieldStyle(.roundedBorder)
                    .font(.system(.body, design: .monospaced))
                Picker("Reflector", selection: $model.reflector) {
                    ForEach(M10Catalog.reflectorNames, id: \.self) { name in
                        Text(name).tag(name)
                    }
                }
                .frame(width: 140)
            }

            HStack(spacing: 12) {
                rowLabel("Rings")
                TextField(model.cipherSuite.fieldPlaceholder, text: $model.rings)
                    .textFieldStyle(.roundedBorder)
                    .font(.system(.body, design: .monospaced))
                Text("Pos")
                    .font(.subheadline.weight(.semibold))
                    .foregroundStyle(.secondary)
                TextField(model.cipherSuite.fieldPlaceholder, text: $model.positions)
                    .textFieldStyle(.roundedBorder)
                    .font(.system(.body, design: .monospaced))
            }

            HStack(spacing: 12) {
                rowLabel("Plugs")
                TextField(model.cipherSuite.plugPlaceholder, text: $model.plugs)
                    .textFieldStyle(.roundedBorder)
                    .font(.system(.body, design: .monospaced))
            }

            RotorStripView(
                rotorNames: M10Configuration.parseRotorOrder(model.rotorOrder),
                positions: model.positions,
                hexBytes: model.cipherSuite.usesHexSettings
            )

            } // external codebook fields

            HStack(spacing: 8) {
                if model.keyMode == .external || model.keyMode == .internalKey {
                Button("New Codebook") { model.generatePersonalCodebook() }
                    .controlSize(.small)
                    .help("Discard this unused machine and generate another. Encrypting also burns the current machine.")
                Button("Demonstration") { model.resetFactory() }
                    .controlSize(.small)
                    .help("Public factory settings. Anyone with this app can decrypt files made with them.")
                Button("Save Codebook…") { model.saveCodebook() }
                    .controlSize(.small)
                Button("Load Codebook…") { model.loadCodebook() }
                    .controlSize(.small)
                }
                if let error = model.settingsError {
                    Text(error)
                        .font(.caption2)
                        .foregroundStyle(.red)
                        .lineLimit(2)
                } else {
                    Text(model.codebookStatus)
                        .font(.caption2)
                        .foregroundStyle(model.isPublicDemonstration ? AnyShapeStyle(Color.orange) : AnyShapeStyle(.tertiary))
                        .lineLimit(2)
                }
            }
        }
        .padding(.horizontal, 20)
        .padding(.vertical, 10)
    }

    private func rowLabel(_ text: String) -> some View {
        Text(text)
            .font(.subheadline.weight(.semibold))
            .foregroundStyle(.secondary)
            .frame(width: labelWidth, alignment: .leading)
    }

    // MARK: - Files

    private var fileArea: some View {
        VStack(spacing: 0) {
            HStack {
                Text("Files")
                    .font(.subheadline.weight(.semibold))
                Spacer()
                Button("Open…") { model.openFiles() }
                    .controlSize(.small)
                Button("Encrypt / Decrypt All") { model.processAll() }
                    .controlSize(.small)
                    .disabled(model.items.isEmpty || model.isBusy || !model.settingsAreValid)
                Button("Legacy Import…") { model.legacyImportArchives() }
                    .controlSize(.small)
                    .disabled(model.items.allSatisfy { $0.kind != .archive } || model.isBusy || !model.settingsAreValid)
                    .help("Recover unauthenticated v1 archives. Output is named UNAUTHENTICATED- and is not integrity-checked.")
                Button("Clear Done") { model.clearFinished() }
                    .controlSize(.small)
                    .disabled(model.items.allSatisfy {
                        if case .done = $0.status { return false }
                        return true
                    })
            }
            .padding(.horizontal, 20)
            .padding(.top, 10)
            .padding(.bottom, 6)

            if model.items.isEmpty {
                VStack(spacing: 8) {
                    Image(systemName: "lock.doc")
                        .font(.system(size: 28))
                        .foregroundStyle(.tint)
                    Text("Drop files or folders to encrypt")
                        .font(.headline)
                    Text("Drop a .enigmam10 to decrypt. Unauthenticated v1 JSON needs Legacy Import…")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else {
                List {
                    ForEach(model.items) { item in
                        fileRow(item)
                    }
                }
                .listStyle(.inset)
            }
        }
    }

    private func fileRow(_ item: AppModel.Item) -> some View {
        HStack(spacing: 10) {
            Image(systemName: iconName(for: item.kind))
                .foregroundStyle(.tint)
                .frame(width: 18)
            VStack(alignment: .leading, spacing: 2) {
                Text(item.name)
                    .lineLimit(1)
                Text(item.sizeLabel)
                    .font(.caption2)
                    .foregroundStyle(.secondary)
            }
            Spacer()
            statusView(item.status)
            Button(item.actionLabel) {
                model.process(id: item.id)
            }
            .controlSize(.small)
            .disabled(
                model.isBusy
                    || !model.settingsAreValid
                    || (item.kind != .archive && model.isPublicDemonstration)
                    || (item.kind != .archive && model.keyMode == .password && model.password.isEmpty)
            )
            Button {
                model.remove(item.id)
            } label: {
                Image(systemName: "xmark.circle.fill")
                    .foregroundStyle(.tertiary)
            }
            .buttonStyle(.plain)
        }
        .padding(.vertical, 2)
    }

    private func iconName(for kind: AppModel.Item.Kind) -> String {
        switch kind {
        case .plain: return "doc"
        case .directory: return "folder.fill"
        case .archive: return "lock.doc"
        }
    }

    @ViewBuilder
    private func statusView(_ status: AppModel.Item.Status) -> some View {
        switch status {
        case .ready:
            EmptyView()
        case .working:
            ProgressView()
                .controlSize(.small)
        case .done(let url):
            Button(url.lastPathComponent) {
                NSWorkspace.shared.activateFileViewerSelecting([url])
            }
            .buttonStyle(.link)
            .font(.caption)
        case .failed(let message):
            Text(message)
                .font(.caption2)
                .foregroundStyle(.red)
                .lineLimit(2)
                .frame(maxWidth: 220, alignment: .trailing)
        }
    }

    // MARK: - Text workshop

    private var textArea: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                Text("Workshop")
                    .font(.subheadline.weight(.semibold))
                Toggle("Decrypt", isOn: $model.textDecrypt)
                    .toggleStyle(.checkbox)
                    .controlSize(.small)
                Spacer()
                Button("Copy") { model.copyOutput() }
                    .controlSize(.small)
                    .disabled(model.textOutput.isEmpty)
            }
            HStack(alignment: .top, spacing: 12) {
                TextEditor(text: $model.textInput)
                    .font(.system(.body, design: .monospaced))
                    .frame(minHeight: 80)
                TextEditor(text: .constant(model.textOutput))
                    .font(.system(.body, design: .monospaced))
                    .frame(minHeight: 80)
                    .disabled(true)
            }
        }
        .padding(.horizontal, 20)
        .padding(.vertical, 10)
        .frame(minHeight: 140)
    }

    // MARK: - Footer

    private var footer: some View {
        HStack {
            Text(model.statusMessage ?? "Ready. Password derives rotors; external key writes a .m10key; internal key stores the codebook in the archive.")
                .font(.caption)
                .foregroundStyle(.secondary)
                .lineLimit(2)
            Spacer()
            if model.isBusy {
                ProgressView()
                    .controlSize(.small)
            }
        }
        .padding(.horizontal, 20)
        .padding(.vertical, 8)
    }
}

struct RotorStripView: View {
    let rotorNames: [String]
    let positions: String
    var hexBytes: Bool = false

    var body: some View {
        HStack(spacing: 6) {
            ForEach(0..<M10Catalog.rotorCount, id: \.self) { index in
                VStack(spacing: 2) {
                    Text(name(at: index))
                        .font(.system(size: 9, weight: .semibold, design: .monospaced))
                        .foregroundStyle(.secondary)
                    Text(position(at: index))
                        .font(.system(size: hexBytes ? 11 : 16, weight: .bold, design: .monospaced))
                        .frame(width: hexBytes ? 32 : 28, height: 28)
                        .background(Color.primary.opacity(0.06))
                        .clipShape(RoundedRectangle(cornerRadius: 6, style: .continuous))
                        .overlay(
                            RoundedRectangle(cornerRadius: 6, style: .continuous)
                                .strokeBorder(Color.primary.opacity(0.12), lineWidth: 1)
                        )
                }
                .frame(maxWidth: .infinity)
            }
        }
        .padding(.top, 2)
    }

    private func name(at index: Int) -> String {
        guard index < rotorNames.count else { return "—" }
        return rotorNames[index]
    }

    private func position(at index: Int) -> String {
        let compact = positions.filter { !$0.isWhitespace }
        if hexBytes {
            let start = index * 2
            guard start + 1 < compact.count else { return "··" }
            let i = compact.index(compact.startIndex, offsetBy: start)
            let j = compact.index(i, offsetBy: 2)
            return String(compact[i..<j])
        }
        guard index < compact.count else { return "·" }
        let i = compact.index(compact.startIndex, offsetBy: index)
        return String(compact[i])
    }
}

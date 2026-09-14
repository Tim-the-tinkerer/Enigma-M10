import SwiftUI
import UniformTypeIdentifiers

struct FileDropModifier: ViewModifier {
    let onDrop: ([URL]) -> Void

    func body(content: Content) -> some View {
        content.onDrop(of: [.fileURL], isTargeted: nil) { providers in
            Task {
                let urls = await Self.loadFileURLs(from: providers)
                if !urls.isEmpty {
                    await MainActor.run { onDrop(urls) }
                }
            }
            return true
        }
    }

    private static func loadFileURLs(from providers: [NSItemProvider]) async -> [URL] {
        var urls: [URL] = []
        for provider in providers {
            guard provider.hasItemConformingToTypeIdentifier(UTType.fileURL.identifier) else {
                continue
            }
            let typeID = UTType.fileURL.identifier
            guard let item = try? await provider.loadItem(forTypeIdentifier: typeID) else {
                continue
            }
            if let url = item as? URL {
                urls.append(url)
            } else if let data = item as? Data {
                if let url = URL(dataRepresentation: data, relativeTo: nil) {
                    urls.append(url)
                } else if let s = String(data: data, encoding: .utf8)?
                    .trimmingCharacters(in: .whitespacesAndNewlines),
                   let url = URL(string: s) {
                    urls.append(url)
                }
            } else if let s = item as? String, let url = URL(string: s) {
                urls.append(url)
            }
        }
        return urls
    }
}

extension View {
    func onFileDrop(perform: @escaping ([URL]) -> Void) -> some View {
        modifier(FileDropModifier(onDrop: perform))
    }
}

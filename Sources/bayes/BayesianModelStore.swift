// by cipher.org.uk
import CryptoKit
import Foundation

/// Manages persisted, user-named Bayesian classifier models in
/// ~/Library/Application Support/Karma Pro/models/.
final class ModelStore {
    static let shared = ModelStore()

    private let dir: URL

    /// A shipped model that has been imported into the library. `sha256`
    /// fingerprints the bundled resource at import time so an updated model
    /// ships to existing installs; `file` is the library file the import
    /// landed in (models are stored under their internal name, which can
    /// differ from the resource name).
    private struct BundledImport: Codable {
        let resource: String
        let file: String
        let sha256: String
    }

    init() {
        let base = FileManager.default
            .urls(for: .applicationSupportDirectory, in: .userDomainMask).first!
            .appendingPathComponent("Karma Pro", isDirectory: true)
        dir = base.appendingPathComponent("models", isDirectory: true)
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        preloadBundledModels()
    }

    /// Imports the bundled pretrained models into the user library. Models are
    /// saved under their internal name, which can differ from the bundled
    /// resource name (e.g. "C-CVEs" used to ship as "CVEs-ALL"), so a filename
    /// probe cannot tell whether a model was imported. Imported resources are
    /// therefore tracked — with a fingerprint of the resource — in a
    /// `.bundled-imports` manifest: each model is imported once, a changed
    /// bundle replaces the previous import, and models the user deleted stay
    /// deleted.
    private func preloadBundledModels() {
        let bundledNames = ["C-CVEs", "Java patches", "Kernel patches"]
        let manifestURL = dir.appendingPathComponent(".bundled-imports")

        var imports: [BundledImport] = []
        var haveManifest = false
        if let data = try? Data(contentsOf: manifestURL) {
            if let decoded = try? JSONDecoder().decode([BundledImport].self, from: data) {
                imports = decoded
                haveManifest = true
            } else if let names = try? JSONDecoder().decode([String].self, from: data) {
                // Manifest from the first manifest release: resource names only.
                imports = names.map { BundledImport(resource: $0, file: $0 + ".json", sha256: "") }
                haveManifest = true
            }
        }

        let libraryHasModels = !listModels().isEmpty
        var changed = false
        for name in bundledNames {
            guard let path = Bundle.main.path(forResource: name, ofType: "karmamodel", inDirectory: "Models") ?? Bundle.main.path(forResource: name, ofType: "karmamodel"),
                  let sha = Self.sha256(of: URL(fileURLWithPath: path)) else { continue }

            if let idx = imports.firstIndex(where: { $0.resource == name }) {
                guard imports[idx].sha256 != sha else { continue }
                // The bundled model changed since it was imported: import the
                // update, and if the model now lands under a different name,
                // remove the file the previous import created.
                guard let data = try? Data(contentsOf: URL(fileURLWithPath: path)),
                      let imported = importModel(fromData: data).model else { continue }
                let newFile = url(for: imported.name).lastPathComponent
                if imports[idx].file.lowercased() != newFile.lowercased() {
                    try? FileManager.default.removeItem(at: dir.appendingPathComponent(imports[idx].file))
                }
                imports[idx] = BundledImport(resource: name, file: newFile, sha256: sha)
            } else if haveManifest || !libraryHasModels {
                // Never imported: either a bundled model added after this
                // install first ran, or a fresh install.
                guard let data = try? Data(contentsOf: URL(fileURLWithPath: path)),
                      let imported = importModel(fromData: data).model else { continue }
                imports.append(BundledImport(resource: name, file: url(for: imported.name).lastPathComponent, sha256: sha))
            } else {
                // No manifest but the library already has models: this install
                // predates the manifest, so the bundled models were either
                // imported by an earlier version or deliberately removed.
                imports.append(BundledImport(resource: name, file: name + ".json", sha256: sha))
            }
            changed = true
        }

        if changed, let data = try? JSONEncoder().encode(imports) {
            try? data.write(to: manifestURL, options: .atomic)
        }
    }

    private static func sha256(of url: URL) -> String? {
        guard let handle = try? FileHandle(forReadingFrom: url) else { return nil }
        defer { try? handle.close() }
        var hasher = SHA256()
        while let chunk = try? handle.read(upToCount: 1 << 20), !chunk.isEmpty {
            hasher.update(data: chunk)
        }
        return hasher.finalize().map { String(format: "%02x", $0) }.joined()
    }

    /// URL for the JSON file backing a named model (sanitized filename).
    private func url(for name: String) -> URL {
        let safe = name
            .trimmingCharacters(in: .whitespacesAndNewlines)
            .replacingOccurrences(of: "/", with: "-")
            .replacingOccurrences(of: ":", with: "-")
        return dir.appendingPathComponent(safe + ".json")
    }

    /// List of model names present on disk, sorted alphabetically.
    func listModels() -> [String] {
        guard let files = try? FileManager.default.contentsOfDirectory(at: dir, includingPropertiesForKeys: nil) else {
            return []
        }
        return files
            .filter { $0.pathExtension.lowercased() == "json" }
            .map { $0.deletingPathExtension().lastPathComponent }
            .sorted()
    }

    @discardableResult
    func save(_ model: BayesianClassifier) -> Bool {
        do {
            let data = try model.jsonData()
            try data.write(to: url(for: model.name), options: .atomic)
            return true
        } catch {
            return false
        }
    }

    func load(named name: String) -> BayesianClassifier? {
        let u = url(for: name)
        guard let data = try? Data(contentsOf: u) else { return nil }
        return try? BayesianClassifier.from(data: data)
    }

    func delete(named name: String) {
        try? FileManager.default.removeItem(at: url(for: name))
    }

    /// Writes a model's JSON bundle to the given URL (used for export).
    @discardableResult
    func export(_ model: BayesianClassifier, to url: URL) -> Bool {
        do {
            let data = try model.jsonData()
            try data.write(to: url, options: .atomic)
            return true
        } catch {
            return false
        }
    }

    /// Reads a model bundle from the given URL, decodes it, and stores it in the
    /// local library. Returns the imported model on success, or a message on failure.
    func importModel(from url: URL) -> (model: BayesianClassifier?, error: String) {
        guard let data = try? Data(contentsOf: url) else {
            return (nil, "Could not read the file.")
        }
        return importModel(fromData: data)
    }

    /// Decodes model data from a bundle (file or downloaded from the web), validates
    /// it, and stores it in the local library.
    func importModel(fromData data: Data) -> (model: BayesianClassifier?, error: String) {
        guard let model = try? BayesianClassifier.from(data: data) else {
            return (nil, "Not a valid Karma Pro model file.")
        }
        guard !model.name.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
            return (nil, "The model file has no valid name.")
        }
        let ok = save(model)
        return (ok ? model : nil, ok ? "" : "Failed to save the imported model into the library.")
    }
}

/// Trainers that consume patch/diff files and feed labeled lines to the classifier.
enum PatchTrainer {

    /// True if the URL is a patch or diff file.
    static func isPatchFile(_ url: URL) -> Bool {
        let ext = url.pathExtension.lowercased()
        return ext == "patch" || ext == "diff"
    }

    /// Recursively collects all patch/diff files under `root`, skipping hidden/build dirs.
    static func collectPatches(in root: URL) -> [URL] {
        let fm = FileManager.default
        guard let it = fm.enumerator(at: root,
                                     includingPropertiesForKeys: [.isRegularFileKey],
                                     options: [.skipsHiddenFiles]) else { return [] }
        var result: [URL] = []
        for case let url as URL in it {
            let path = url.path
            if path.contains("/build/") || path.contains("/vendor/") ||
               path.contains("/node_modules/") || path.contains("/.git/") { continue }
            if isPatchFile(url) {
                result.append(url)
            }
        }
        return result
    }

    /// Scans every line of every patch and trains the classifier.
    /// `+` lines -> good, `-` lines -> bad. `nil` progress means no callback.
    /// When `language` is provided, only +/- lines belonging to files whose
    /// extension matches the selected language are trained; lines from files
    /// of other extensions or extension-less files are skipped.
    /// Returns (patchesProcessed, linesSeen).
    static func train(model: BayesianClassifier,
                      in root: URL,
                      language: Language? = nil,
                      progress: ((Int, Int) -> Void)? = nil) -> (Int, Int) {
        let patches = collectPatches(in: root)
        let total = max(patches.count, 1)
        var patchesDone = 0
        var linesSeen = 0

        for (i, url) in patches.enumerated() {
            guard let text = try? String(contentsOf: url, encoding: .utf8) else { continue }
            var currentPath: String?
            for line in text.components(separatedBy: "\n") {
                if line.hasPrefix("--- ") || line.hasPrefix("+++ ") {
                    var path = String(line.dropFirst(4))
                    if path.hasPrefix("a/") || path.hasPrefix("b/") {
                        path = String(path.dropFirst(2))
                    }
                    path = path.trimmingCharacters(in: .whitespacesAndNewlines)
                    currentPath = path
                    continue
                }
                let trimmedLeading = line.dropFirst()
                guard !trimmedLeading.isEmpty else { continue }
                if line.hasPrefix("+") {
                    if line.hasPrefix("+++") { continue }
                    guard language == nil ||
                              (currentPath != nil && language!.contains(URL(fileURLWithPath: currentPath!))) else {
                        continue
                    }
                    let content = String(trimmedLeading)
                    model.train(line: content, isBad: false)
                    linesSeen += 1
                } else if line.hasPrefix("-") {
                    if line.hasPrefix("---") { continue }
                    guard language == nil ||
                              (currentPath != nil && language!.contains(URL(fileURLWithPath: currentPath!))) else {
                        continue
                    }
                    let content = String(trimmedLeading)
                    model.train(line: content, isBad: true)
                    linesSeen += 1
                }
            }
            patchesDone += 1
            progress?(i + 1, total)
        }
        return (patchesDone, linesSeen)
    }
}

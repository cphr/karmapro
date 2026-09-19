// by cipher.org.uk
import Foundation

/// Persists small per-line notes keyed by file path + line number to a JSON file
/// on disk, so notes survive app restarts and reappear for the same source file.
final class NoteStore {
    static let shared = NoteStore()

    private var notes: [String: [Int: String]] = [:]
    private let fileURL: URL

    init() {
        let dir = FileManager.default
            .urls(for: .applicationSupportDirectory, in: .userDomainMask).first!
            .appendingPathComponent("Karma Pro", isDirectory: true)
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        fileURL = dir.appendingPathComponent("notes.json")
        load()
    }

    private func load() {
        guard let data = try? Data(contentsOf: fileURL),
              let raw = try? JSONSerialization.jsonObject(with: data) as? [String: [String: String]]
        else { return }
        var result: [String: [Int: String]] = [:]
        for (path, lines) in raw {
            var lineMap: [Int: String] = [:]
            for (key, value) in lines {
                if let line = Int(key) { lineMap[line] = value }
            }
            result[path] = lineMap
        }
        notes = result
    }

    private func save() {
        var raw: [String: [String: String]] = [:]
        for (path, lines) in notes {
            var lm: [String: String] = [:]
            for (line, text) in lines { lm["\(line)"] = text }
            raw[path] = lm
        }
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        if let data = try? encoder.encode(raw) {
            try? data.write(to: fileURL, options: .atomic)
        }
    }

    func note(for file: URL, line: Int) -> String? {
        notes[file.path]?[line]
    }

    /// Sets the note for a line; an empty string removes it. Returns false if nothing changed.
    @discardableResult
    func setNote(for file: URL, line: Int, text: String?) -> Bool {
        let trimmed = (text ?? "").trimmingCharacters(in: .whitespacesAndNewlines)
        if notes[file.path] == nil { notes[file.path] = [:] }
        if trimmed.isEmpty {
            let removed = notes[file.path]!.removeValue(forKey: line) != nil
            if notes[file.path]!.isEmpty { notes[file.path] = nil }
            save()
            return removed
        } else {
            let exists = notes[file.path]![line] == trimmed
            notes[file.path]![line] = trimmed
            save()
            return !exists
        }
    }

    func lineNumbers(for file: URL) -> Set<Int> {
        if let lines = notes[file.path] {
            return Set(lines.keys)
        }
        return []
    }

    /// A single note with its keyed file path and line.
    struct StoredNote {
        let path: String
        let line: Int
        let text: String
    }

    /// Returns every note in the store, oldest-to-newest by path then line.
    func allNotes() -> [StoredNote] {
        var result: [StoredNote] = []
        for (path, lines) in notes {
            for (line, text) in lines {
                result.append(StoredNote(path: path, line: line, text: text))
            }
        }
        result.sort {
            if $0.path != $1.path { return $0.path < $1.path }
            return $0.line < $1.line
        }
        return result
    }

    /// Returns only the notes belonging to the given project folder (notes whose
    /// file path is inside `root`). This keeps the "show all notes" window limited
    /// to the currently open project rather than mixing in notes from other projects.
    func notes(forProject root: URL) -> [StoredNote] {
        let rootPath = root.standardizedFileURL.path
        return allNotes().filter { note in
            let p = URL(fileURLWithPath: note.path).standardizedFileURL.path
            return p == rootPath || p.hasPrefix(rootPath + "/")
        }
    }

    /// Writes the full notes collection to the given URL in the exchange format.
    /// When a `projectRoot` is provided, file keys are stored as paths **relative to
    /// the project root** so the file is portable across users whose project lives at
    /// a different location (e.g. a different home directory). Without a root, the
    /// legacy absolute keys are written unchanged.
    @discardableResult
    func export(to url: URL, projectRoot: URL? = nil) -> Bool {
        let root = projectRoot?.standardizedFileURL.path
        var raw: [String: [String: String]] = [:]
        for (path, lines) in notes {
            var lm: [String: String] = [:]
            for (line, text) in lines { lm["\(line)"] = text }
            raw[exportKey(for: path, root: root)] = lm
        }
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        guard let data = try? encoder.encode(raw) else { return false }
        do {
            try data.write(to: url, options: .atomic)
            return true
        } catch {
            return false
        }
    }

    /// The key written to an exported file for an absolute keyed note path.
    /// With a root, this is the path relative to the root **prefixed with the
    /// project's directory name** (e.g. `MyProject/src/main.c`), so the exported
    /// keys start with the project's initial directory and contain no user-specific
    /// paths. Without a root, the absolute path is written unchanged.
    private func exportKey(for path: String, root: String?) -> String {
        guard let root = root else { return path }
        let projectName = (root as NSString).lastPathComponent
        let stdPath = URL(fileURLWithPath: path).standardizedFileURL.path
        if stdPath == root { return projectName }
        if stdPath.hasPrefix(root + "/") {
            let relative = String(stdPath.dropFirst(root.count + 1))
            return "\(projectName)/\(relative)"
        }
        return path
    }

    /// Merges notes decoded from data into the store (imported values win on exact
    /// path + line collisions). Returns the number of notes added/updated.
    ///
    /// When `projectRoot` is provided, keys that are relative (no leading "/") are
    /// re-rooted against it, so a portable export imports to the recipient's copy of
    /// the project. Absolute keys (legacy exports) are left untouched.
    func importFrom(data: Data, projectRoot: URL? = nil) -> (count: Int, error: String) {
        guard let root = projectRoot?.standardizedFileURL.path else {
            return importFromDataAbsolute(raw: data)
        }
        guard let raw = try? JSONSerialization.jsonObject(with: data) as? [String: [String: String]] else {
            return (0, "Not a valid Karma Pro notes file.")
        }
        var added = 0
        for (key, lines) in raw {
            let path: String
            if key.hasPrefix("/") {
                path = key
            } else {
                // Exported keys start with the project's directory name (e.g.
                // "MyProject/src/main.c"). The recipient's project folder may be
                // named differently, so the leading component is discarded and only
                // the remainder is re-rooted against the recipient's project root.
                var relative = key
                let slash = key.firstIndex(of: "/")
                if let idx = slash {
                    relative = String(key[key.index(after: idx)...])
                } else {
                    relative = ""
                }
                path = relative.isEmpty ? root : root + "/" + relative
            }
            var fileNotes = notes[path] ?? [:]
            for (lineKey, value) in lines {
                guard let line = Int(lineKey) else { continue }
                let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
                guard !trimmed.isEmpty else { continue }
                if fileNotes[line] != trimmed {
                    fileNotes[line] = trimmed
                    added += 1
                }
            }
            if !fileNotes.isEmpty { notes[path] = fileNotes }
        }
        if added > 0 { save() }
        return (added, "")
    }

    /// Back-compat: merge an exchange file using keys exactly as written (absolute).
    private func importFromDataAbsolute(raw data: Data) -> (count: Int, error: String) {
        guard let raw = try? JSONSerialization.jsonObject(with: data) as? [String: [String: String]] else {
            return (0, "Not a valid Karma Pro notes file.")
        }
        var added = 0
        for (path, lines) in raw {
            var fileNotes = notes[path] ?? [:]
            for (key, value) in lines {
                guard let line = Int(key) else { continue }
                let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
                guard !trimmed.isEmpty else { continue }
                if fileNotes[line] != trimmed {
                    fileNotes[line] = trimmed
                    added += 1
                }
            }
            if !fileNotes.isEmpty { notes[path] = fileNotes }
        }
        if added > 0 { save() }
        return (added, "")
    }

    /// Reads a notes file from the given URL and merges it into the store.
    func importFrom(url: URL, projectRoot: URL? = nil) -> (count: Int, error: String) {
        guard let data = try? Data(contentsOf: url) else {
            return (0, "Could not read the file.")
        }
        return importFrom(data: data, projectRoot: projectRoot)
    }
}

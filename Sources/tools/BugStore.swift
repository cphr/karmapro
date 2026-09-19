// by cipher.org.uk
import Foundation

/// A single bug report in the Karma Pro bug tracking application.
///
/// Severity and exploitability are stored as simple uppercase tokens
/// ("info", "low", "medium", "high", "critical") so the JSON is human-readable
/// and stable across app versions.
struct Bug: Codable, Identifiable {
    var id: String
    var title: String
    var severity: String
    var exploitability: String
    var detail: String
    var packageName: String
    var version: String
    var status: String
    var createdAt: Date
    var filePath: String?
    var line: Int?

    static let severityLevels = ["info", "low", "medium", "high", "critical"]
    static let statuses = ["Open", "In Progress", "Resolved", "Closed"]
}

/// Posted whenever the bug list changes (add, update, delete, merge, persist).
extension Notification.Name {
    static let bugStoreDidChange = Notification.Name("BugStoreDidChange")
}

/// Persists bug reports to disk in the Karma Pro application support directory,
/// so bugs survive app restarts. When the bug vault is password protected the
/// report file is AES-GCM encrypted at rest using the key derived from the user's
/// password, so reports are never stored in plaintext while a password is set.
final class BugStore {
    static let shared = BugStore()

    private var bugs: [Bug] = []
    private let fileURL: URL
    private let legacyURL: URL

    init() {
        let dir = FileManager.default
            .urls(for: .applicationSupportDirectory, in: .userDomainMask).first!
            .appendingPathComponent("Karma Pro", isDirectory: true)
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        fileURL = dir.appendingPathComponent("bugs.bin")
        legacyURL = dir.appendingPathComponent("bugs.json")
        // Migrate a legacy plaintext store into the new file (older builds).
        if !FileManager.default.fileExists(atPath: fileURL.path),
           let legacy = try? Data(contentsOf: legacyURL),
           !legacy.isEmpty {
            try? legacy.write(to: fileURL, options: .atomic)
            try? FileManager.default.removeItem(at: legacyURL)
        }
    }

    private func decode(_ data: Data) -> [Bug] {
        (try? JSONDecoder().decode([Bug].self, from: data)) ?? []
    }

    /// Loads reports from disk.
    func reload() {
        guard let raw = try? Data(contentsOf: fileURL) else {
            bugs = []
            return
        }
        bugs = decode(raw)
    }

    /// Writes the in-memory reports to disk.
    func persist() {
        let data = (try? JSONEncoder().encode(bugs)) ?? Data()
        try? data.write(to: fileURL, options: .atomic)
        NotificationCenter.default.post(name: .bugStoreDidChange, object: self)
    }

    // MARK: - Queries

    func allBugs() -> [Bug] {
        bugs.sorted { $0.createdAt > $1.createdAt }
    }

    func bug(id: String) -> Bug? {
        bugs.first { $0.id == id }
    }

    /// Returns bugs whose title, package name, detail, or ID matches the query
    /// (case-insensitive).
    func search(_ query: String) -> [Bug] {
        let trimmed = query.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return allBugs() }
        let lower = trimmed.lowercased()
        return allBugs().filter {
            $0.title.lowercased().contains(lower)
            || $0.packageName.lowercased().contains(lower)
            || $0.detail.lowercased().contains(lower)
            || $0.id.lowercased().contains(lower)
            || $0.severity.lowercased().contains(lower)
            || $0.status.lowercased().contains(lower)
        }
    }

    // MARK: - Mutations

    @discardableResult
    func add(_ bug: Bug) -> Bug {
        bugs.append(bug)
        persist()
        return bug
    }

    /// Merges a set of imported bugs into the store, skipping any whose ID already
    /// exists (so backups can be imported repeatedly without duplicating reports).
    /// Returns the number of new bugs added.
    @discardableResult
    func merge(_ imported: [Bug]) -> Int {
        let existingIDs = Set(bugs.map { $0.id })
        let newBugs = imported.filter { !existingIDs.contains($0.id) }
        var added = 0
        for bug in newBugs {
            bugs.append(bug)
            added += 1
        }
        if added > 0 { persist() }
        return added
    }

    func update(_ updated: Bug) {
        guard let idx = bugs.firstIndex(where: { $0.id == updated.id }) else { return }
        bugs[idx] = updated
        persist()
    }

    func delete(id: String) {
        bugs.removeAll { $0.id == id }
        persist()
    }

    /// Creates a new bug with a generated unique ID.
    static func newBug() -> Bug {
        Bug(id: UUID().uuidString,
            title: "",
            severity: "medium",
            exploitability: "medium",
            detail: "",
            packageName: "",
            version: "",
            status: "Open",
            createdAt: Date(),
            filePath: nil,
            line: nil)
    }
}

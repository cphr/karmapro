// by cipher.org.uk
import Foundation

/// A single reusable prompt template shown in the AI assistant's dropdown.
/// `isBuiltin` marks prompts that shipped with the app (they are editable, and
/// once edited they are persisted in the user's store so edits survive relaunch).
struct PromptTemplate: Codable {
    var id: String
    var title: String
    var promptText: String
    var isBuiltin: Bool
}

/// Persists prompt templates to disk in the Karma Pro application support
/// directory (same location pattern as `BugStore`). On first launch the store
/// is seeded from the bundled `AIPrompts.json` resource; from then on the
/// user's file is authoritative so built-in prompts can be edited, removed,
/// and new ones added freely while surviving app restarts.
final class PromptStore {
    static let shared = PromptStore()

    private(set) var prompts: [PromptTemplate] = []

    private let fileURL: URL

    init() {
        let dir = FileManager.default
            .urls(for: .applicationSupportDirectory, in: .userDomainMask).first!
            .appendingPathComponent("Karma Pro", isDirectory: true)
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        fileURL = dir.appendingPathComponent("ai_prompts.json")

        if let data = try? Data(contentsOf: fileURL),
           let stored = try? JSONDecoder().decode([PromptTemplate].self, from: data),
           !stored.isEmpty {
            prompts = stored
        } else {
            prompts = Self.loadBuiltinPrompts()
            persist()
        }
    }

    /// Loads the predefined prompts shipped in the app bundle, falling back to
    /// a small hardcoded set when the resource is missing (e.g. CLI builds).
    private static func loadBuiltinPrompts() -> [PromptTemplate] {
        var list: [PromptTemplate] = []
        if let url = Bundle.main.url(forResource: "AIPrompts", withExtension: "json"),
           let data = try? Data(contentsOf: url),
           let decoded = try? JSONDecoder().decode([PromptTemplate].self, from: data) {
            list = decoded
        } else {
            list = [
                PromptTemplate(id: "builtin-c-security",
                               title: "Review Security",
                               promptText: "Scan this code for critical issues only: security risks, potential data leaks, race conditions, overflows and how to fix them.",
                               isBuiltin: true),
                PromptTemplate(id: "builtin-code-reviewer",
                               title: "Code reviewer",
                               promptText: "You are an application security engineer, your role is to perform thorough, security code reviews that identify vulnerabilities and provide where possible fixes. Do that for this project.",
                               isBuiltin: true),
                PromptTemplate(id: "builtin-security-engineer",
                               title: "Security engineer",
                               promptText: "Review the code and identify attacker-controlled data from entry to sink and identify as many security issues as possible",
                               isBuiltin: true),
                PromptTemplate(id: "builtin-owasp",
                               title: "OWASP",
                               promptText: "Review the source code against OWASP Top 10 and report the issue from higher risk to lower risk",
                               isBuiltin: true),
                PromptTemplate(id: "builtin-sql-injection",
                               title: "Parametarised queries",
                               promptText: "Review this source code and check if all SQL queries are parameterised",
                               isBuiltin: true),
                PromptTemplate(id: "builtin-hardcoded-keys",
                               title: "Hard coded keys",
                               promptText: "Scan the code and identify hardcoded keys and tokens, credentials in connection strings, private keys, secrets in comments or example config",
                               isBuiltin: true),
                PromptTemplate(id: "builtin-server-authorisation",
                               title: "Server authorisation",
                               promptText: "Check authorisation executes server-side on every request and there are not client-side checks or hidden UI for misplaced access controls",
                               isBuiltin: true),
                PromptTemplate(id: "builtin-input-sanitisation",
                               title: "Input sanitisation",
                               promptText: "You are a code reviewer and you are looking to find every part of the source code where user input is processed and check if it is sanitized",
                               isBuiltin: true)
            ]
        }
        return list.map { var p = $0; p.isBuiltin = true; return p }
    }

    private func persist() {
        if let data = try? JSONEncoder().encode(prompts) {
            try? data.write(to: fileURL, options: .atomic)
        }
    }

    // MARK: - Queries

    func prompt(id: String) -> PromptTemplate? {
        prompts.first { $0.id == id }
    }

    // MARK: - Mutations

    @discardableResult
    func add(title: String, promptText: String) -> PromptTemplate {
        let p = PromptTemplate(id: UUID().uuidString, title: title, promptText: promptText, isBuiltin: false)
        prompts.append(p)
        persist()
        return p
    }

    func update(id: String, title: String, promptText: String) {
        guard let idx = prompts.firstIndex(where: { $0.id == id }) else { return }
        prompts[idx].title = title
        prompts[idx].promptText = promptText
        persist()
    }

    func remove(id: String) {
        prompts.removeAll { $0.id == id }
        persist()
    }

    /// Restores the factory prompt list (discards user edits/additions).
    func resetToBuiltins() {
        prompts = Self.loadBuiltinPrompts()
        persist()
    }

    // MARK: - Export / Import

    /// Serializes every stored prompt template to JSON for export.
    func exportData() -> Data {
        (try? JSONEncoder().encode(prompts)) ?? Data()
    }

    /// Imports prompt templates from a JSON export, skipping entries that are
    /// already stored (same title, case-insensitive, or same text). Imported
    /// prompts get fresh IDs and are treated as user prompts.
    /// Returns the number added and the number skipped as duplicates, or an
    /// error message when the data is not a valid prompts file.
    func importData(_ data: Data) -> (added: Int, skipped: Int, error: String?) {
        guard let imported = try? JSONDecoder().decode([PromptTemplate].self, from: data) else {
            return (0, 0, "Import failed: the file is not a valid Karma Pro prompts export.")
        }
        var existingTitles = Set(prompts.map {
            $0.title.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        })
        var existingTexts = Set(prompts.map { $0.promptText })
        var added = 0
        var skipped = 0
        for var template in imported {
            let title = template.title.trimmingCharacters(in: .whitespacesAndNewlines)
            if title.isEmpty
                || existingTitles.contains(title.lowercased())
                || existingTexts.contains(template.promptText) {
                skipped += 1
                continue
            }
            template.title = title
            template.id = UUID().uuidString
            template.isBuiltin = false
            prompts.append(template)
            existingTitles.insert(title.lowercased())
            existingTexts.insert(template.promptText)
            added += 1
        }
        if added > 0 { persist() }
        return (added, skipped, nil)
    }
}

// by cipher.org.uk
import AppKit
import Foundation

/// Global private wiki. Pages are rich-text documents (RTF) stored under
/// `~/Library/Application Support/Karma Pro/Wiki/` and shared across all
/// projects. A `manifest.json` keeps title/slug and timestamps; the pages
/// themselves live in a `pages/` subdirectory as `<slug>.rtf`.
///
/// Backups are written as a `.karmawiki` archive (zip of the manifest and
/// page files), optionally encrypted with `BackupCrypto` when a password is
/// given. Imports accept an (optionally encrypted) archive or a plain folder
/// containing `manifest.json`/`pages` or bare `.rtf` files.
final class WikiStore {
    static let shared = WikiStore()

    struct PageInfo: Codable, Equatable {
        var slug: String
        var title: String
        var created: Double
        var updated: Double
    }

    enum WikiError: LocalizedError {
        case noManifest
        case corruptData
        case invalidArchive
        case importFailed(String)
        var errorDescription: String? {
            switch self {
            case .noManifest: return "The archive or folder contains no wiki manifest."
            case .corruptData: return "The wiki data is corrupted or unreadable."
            case .invalidArchive: return "The selected file is not a valid wiki archive."
            case .importFailed(let m): return m
            }
        }
    }

    enum Conflict {
        case overwrite, rename, skip
    }

    let wikiDir: URL
    let pagesDir: URL
    private let manifestURL: URL

    private var manifest: [String: PageInfo] = [:]

    init() {
        let base = FileManager.default
            .urls(for: .applicationSupportDirectory, in: .userDomainMask).first!
            .appendingPathComponent("Karma Pro", isDirectory: true)
            .appendingPathComponent("Wiki", isDirectory: true)
        wikiDir = base
        pagesDir = base.appendingPathComponent("pages", isDirectory: true)
        manifestURL = base.appendingPathComponent("manifest.json")
        try? FileManager.default.createDirectory(at: pagesDir, withIntermediateDirectories: true)
        loadManifest()
    }

    private func loadManifest() {
        guard let data = try? Data(contentsOf: manifestURL) else { return }
        let decoder = JSONDecoder()
        if let list = try? decoder.decode([PageInfo].self, from: data) {
            manifest = Dictionary(uniqueKeysWithValues: list.map { ($0.slug, $0) })
        }
    }

    private func saveManifest() {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        let list = manifest.values.sorted { $0.slug < $1.slug }
        if let data = try? encoder.encode(list) {
            try? data.write(to: manifestURL, options: .atomic)
        }
    }

    /// Enumerates the pages directory so pages added out-of-band (e.g. by a
    /// previous import) appear even when the manifest was empty.
    private func rescanFiles() {
        guard let urls = try? FileManager.default.contentsOfDirectory(
            at: pagesDir, includingPropertiesForKeys: nil)
        else { return }
        for url in urls where url.pathExtension == "rtf" {
            let slug = url.deletingPathExtension().lastPathComponent
            if manifest[slug] == nil {
                manifest[slug] = PageInfo(slug: slug,
                                          title: titleFromSlug(slug),
                                          created: Date().timeIntervalSince1970,
                                          updated: Date().timeIntervalSince1970)
            }
        }
    }

    private func titleFromSlug(_ slug: String) -> String {
        slug.split(separator: "-").map { $0.capitalized }.joined(separator: " ")
    }

    // MARK: - Page access

    /// All pages, newest first.
    func allPages() -> [PageInfo] {
        rescanFiles()
        return manifest.values.sorted { $0.updated > $1.updated }
    }

    func pageInfo(slug: String) -> PageInfo? {
        manifest[slug]
    }

    /// Resolves a link target (a page name or slug as typed by the user) to
    /// the stored page. Matches either the slug or the title, case-insensitively.
    func resolve(_ target: String) -> String? {
        let trimmed = target.trimmingCharacters(in: .whitespacesAndNewlines)
        rescanFiles()
        let folded = fold(trimmed)
        let slugged = slugify(trimmed)
        if manifest[slugged] != nil { return slugged }
        for (slug, info) in manifest where fold(info.title) == folded {
            return slug
        }
        return nil
    }

    func pageURL(slug: String) -> URL {
        pagesDir.appendingPathComponent(slug).appendingPathExtension("rtf")
    }

    /// Loads the rich-text body of a page. Returns nil if the page is missing.
    func body(slug: String) -> NSAttributedString? {
        guard let data = try? Data(contentsOf: pageURL(slug: slug)) else { return nil }
        return NSAttributedString(rtf: data, documentAttributes: nil)
    }

    func bodyPlain(slug: String) -> String {
        body(slug: slug)?.string ?? ""
    }

    // MARK: - Page mutations

    /// Creates a page from rich text. `title` is used to derive the slug when
    /// `slug` is not provided. Returns the slug of the stored page.
    @discardableResult
    func createPage(title: String, body: NSAttributedString, slug: String? = nil) -> String {
        rescanFiles()
        let now = Date().timeIntervalSince1970
        let finalSlug = slug ?? uniqueSlug(from: title)
        manifest[finalSlug] = PageInfo(slug: finalSlug, title: title.title, created: now, updated: now)
        writeBody(body, slug: finalSlug)
        saveManifest()
        return finalSlug
    }

    /// Overwrites the body (and title) of an existing page. Returns false if
    /// the page does not exist.
    @discardableResult
    func savePage(slug: String, title: String, body: NSAttributedString) -> Bool {
        guard manifest[slug] != nil else { return false }
        var info = manifest[slug]!
        info.title = title.title
        info.updated = Date().timeIntervalSince1970
        manifest[slug] = info
        writeBody(body, slug: slug)
        saveManifest()
        return true
    }

    private func writeBody(_ body: NSAttributedString, slug: String) {
        let whole = NSRange(location: 0, length: body.length)
        guard let data = try? body.data(from: whole, documentAttributes: [
            .documentType: NSAttributedString.DocumentType.rtf,
            .characterEncoding: String.Encoding.utf8.rawValue
        ]) else { return }
        try? data.write(to: pageURL(slug: slug), options: .atomic)
    }

    @discardableResult
    func deletePage(slug: String) -> Bool {
        rescanFiles()
        guard manifest.removeValue(forKey: slug) != nil else { return false }
        try? FileManager.default.removeItem(at: pageURL(slug: slug))
        saveManifest()
        return true
    }

    /// Renames a page, moving its file and rewriting the slug. Links that point
    /// at the old name are not rewritten (resolution falls back to matching by
    /// title via `resolve`). Returns the new slug, or nil on conflict/failure.
    func renamePage(slug: String, newTitle: String) -> String? {
        rescanFiles()
        guard var info = manifest[slug] else { return nil }
        let newSlug = uniqueSlug(from: newTitle, excluding: slug)
        info.slug = newSlug
        info.title = newTitle.title
        info.updated = Date().timeIntervalSince1970
        manifest.removeValue(forKey: slug)
        manifest[newSlug] = info

        let oldURL = pageURL(slug: slug)
        let newURL = pageURL(slug: newSlug)
        if FileManager.default.fileExists(atPath: oldURL.path) {
            try? FileManager.default.moveItem(at: oldURL, to: newURL)
        }
        saveManifest()
        return newSlug
    }

    /// Builds a unique slug for a title. If the title already exists (or slug
    /// was not given), a numeric suffix is appended.
    func uniqueSlug(from title: String, excluding: String? = nil) -> String {
        rescanFiles()
        var base = slugify(title)
        if base.isEmpty { base = "untitled" }
        if base == excluding {
            return base
        }
        if manifest[base] == nil { return base }
        var candidate = base
        var n = 2
        while true {
            candidate = "\(base)-\(n)"
            if manifest[candidate] == nil { return candidate }
            n += 1
        }
    }

    /// Lowercases and normalises identifiers/titles without changing language.
    private func fold(_ s: String) -> String {
        s.folding(options: [.caseInsensitive, .diacriticInsensitive], locale: .current)
            .lowercased()
            .trimmingCharacters(in: .whitespacesAndNewlines)
    }

    /// Converts an arbitrary page name into a filesystem-safe slug.
    func slugify(_ s: String) -> String {
        let folded = fold(s)
        var result = ""
        for ch in folded {
            if ch.isLetter || ch.isNumber {
                result.append(ch.lowercased())
            } else {
                result.append("-")
            }
        }
        while result.contains("--") { result = result.replacingOccurrences(of: "--", with: "-") }
        result = result.trimmingCharacters(in: CharacterSet(charactersIn: "-"))
        return result
    }

    // MARK: - Search

    func search(_ query: String) -> [PageInfo] {
        let trimmed = query.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return allPages() }
        let folded = fold(trimmed)
        return allPages().filter { info in
            if fold(info.title).contains(folded) { return true }
            return fold(bodyPlain(slug: info.slug)).contains(folded)
        }
    }

    // MARK: - Backup / import

    /// Writes a `.karmawiki` archive. When `password` is non-nil the archive is
    /// encrypted with `BackupCrypto` before being written. Returns pages written.
    @discardableResult
    func backup(to url: URL, password: String?) throws -> Int {
        rescanFiles()
        let temp = FileManager.default.temporaryDirectory
            .appendingPathComponent("karmawiki-\(UUID().uuidString)", isDirectory: true)
        defer { try? FileManager.default.removeItem(at: temp) }
        let pagesURL = temp.appendingPathComponent("pages", isDirectory: true)
        try FileManager.default.createDirectory(at: pagesURL, withIntermediateDirectories: true)

        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        let list = manifest.values.sorted { $0.slug < $1.slug }
        let manifestData = try encoder.encode(list)
        try manifestData.write(to: temp.appendingPathComponent("manifest.json"))

        for info in list {
            if FileManager.default.fileExists(atPath: pageURL(slug: info.slug).path) {
                try? FileManager.default.copyItem(at: pageURL(slug: info.slug),
                                                  to: pagesURL.appendingPathComponent(info.slug + ".rtf"))
            }
        }

        let zipURL = temp.appendingPathComponent("wiki.karmawiki")
        try WikiZip.zip(directory: temp, to: zipURL)
        var bytes = try Data(contentsOf: zipURL)
        if let password = password, !password.isEmpty {
            bytes = try BackupCrypto.seal(bytes, password: password)
        }
        try bytes.write(to: url, options: .atomic)
        return list.count
    }

    /// Restores pages from a `.karmawiki` archive or a plain folder (pages/
    /// + manifest.json, or bare .rtf files). `password` is required when the
    /// archive is encrypted. Conflicts are resolved through `onConflict`.
    /// Returns (imported, overwritten, renamed, skipped) counts.
    func `import`(from url: URL, password: String?, onConflict: (String) -> Conflict) throws -> (imported: Int, overwritten: Int, renamed: Int, skipped: Int) {
        var data: Data?
        if url.hasDirectoryPath {
            return try importFromFolder(url, onConflict: onConflict)
        } else {
            data = try Data(contentsOf: url)
        }
        guard var bytes = data else { throw WikiError.invalidArchive }

        if BackupCrypto.isEncrypted(bytes) {
            guard let pw = password, !pw.isEmpty else {
                throw BackupError.wrongPassword
            }
            bytes = try BackupCrypto.open(bytes, password: pw)
        }

        let temp = FileManager.default.temporaryDirectory
            .appendingPathComponent("karmawiki-import-\(UUID().uuidString)", isDirectory: true)
        defer { try? FileManager.default.removeItem(at: temp) }
        try FileManager.default.createDirectory(at: temp, withIntermediateDirectories: true)
        let zipURL = temp.appendingPathComponent("blob.karmawiki")
        try bytes.write(to: zipURL)
        guard (try? WikiZip.unzip(zipURL: zipURL, into: temp)) == true else {
            throw WikiError.invalidArchive
        }
        return try importFromFolder(temp, onConflict: onConflict)
    }

    private func importFromFolder(_ folder: URL, onConflict: (String) -> Conflict) throws -> (imported: Int, overwritten: Int, renamed: Int, skipped: Int) {
        rescanFiles()
        var result = (imported: 0, overwritten: 0, renamed: 0, skipped: 0)

        var pending: [String: PageInfo] = [:]
        var pageURLs: [String: URL] = [:]

        let manifestFile = folder.appendingPathComponent("manifest.json")
        if let data = try? Data(contentsOf: manifestFile),
           let list = try? JSONDecoder().decode([PageInfo].self, from: data) {
            pending = Dictionary(uniqueKeysWithValues: list.map { ($0.slug, $0) })
        }

        var pagesFolder = folder.appendingPathComponent("pages", isDirectory: true)
        if !FileManager.default.fileExists(atPath: pagesFolder.path) {
            pagesFolder = folder
        }
        if let urls = try? FileManager.default.contentsOfDirectory(at: pagesFolder, includingPropertiesForKeys: nil) {
            for url in urls where url.pathExtension == "rtf" {
                let slug = url.deletingPathExtension().lastPathComponent
                if pending[slug] == nil {
                    pending[slug] = PageInfo(slug: slug,
                                             title: titleFromSlug(slug),
                                             created: Date().timeIntervalSince1970,
                                             updated: Date().timeIntervalSince1970)
                }
                pageURLs[slug] = url
            }
        }

        guard !pending.isEmpty else { throw WikiError.noManifest }

        for (slug, info) in pending {
            let loaded: NSAttributedString
            if let bodyURL = pageURLs[slug], let data = try? Data(contentsOf: bodyURL) {
                loaded = NSAttributedString(rtf: data, documentAttributes: nil) ?? NSAttributedString(string: info.title)
            } else {
                loaded = NSAttributedString(string: info.title)
            }

            if manifest[slug] != nil {
                switch onConflict(slug) {
                case .overwrite:
                    manifest[slug] = info
                    writeBody(loaded, slug: slug)
                    result.overwritten += 1
                case .rename:
                    let newSlug = uniqueSlug(from: info.title)
                    manifest[newSlug] = PageInfo(slug: newSlug, title: info.title,
                                                 created: info.created, updated: info.updated)
                    writeBody(loaded, slug: newSlug)
                    result.renamed += 1
                case .skip:
                    result.skipped += 1
                }
            } else {
                manifest[slug] = info
                writeBody(loaded, slug: slug)
                result.imported += 1
            }
        }
        saveManifest()
        return result
    }
}

/// Minimal zip/unzip helpers around the system tools. Used by `WikiStore` so
/// backups round-trip without pulling in a third-party archive dependency.
enum WikiZip {
    /// Zips the entire directory (relative paths preserved) into `to`.
    @discardableResult
    static func zip(directory: URL, to: URL) throws -> Bool {
        try? FileManager.default.removeItem(at: to)
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/zip")
        process.arguments = ["-r", "-q", to.path, "."]
        process.currentDirectoryURL = directory
        try process.run()
        process.waitUntilExit()
        return process.terminationStatus == 0
    }

    /// Extracts a zip archive into the destination directory.
    @discardableResult
    static func unzip(zipURL: URL, into: URL) throws -> Bool {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/unzip")
        process.arguments = ["-q", "-o", zipURL.path, "-d", into.path]
        try process.run()
        process.waitUntilExit()
        return process.terminationStatus == 0
    }
}

private extension String {
    /// Title-cases a string used as a page title (keeps the rest of the casing).
    var title: String {
        let t = trimmingCharacters(in: .whitespacesAndNewlines)
        if t.isEmpty { return "Untitled" }
        return prefix(1).uppercased() + dropFirst()
    }
}
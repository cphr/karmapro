// by cipher.org.uk
import Foundation

/// One indexed source file: its URL, full text, token stream and the
/// function/method definitions parsed once for the project. The call-site
/// popup system, the variable-flow tracer, the security scan and the class
/// usage window all reuse these entries, so the tree is walked, read and
/// parsed a single time per project rather than once per subsystem.
struct ProjectSourceEntry {
    let url: URL
    let source: String
    let tokens: [CAstToken]
    let funcs: [CCFunctionParser.FunctionDef]
}

/// Project-wide source cache built when a folder is opened. Construction runs
/// off the main thread: each file is read, tokenized and parsed once, on a
/// worker thread; results are merged in file order so downstream derivations
/// stay deterministic. `progress` reports (filesProcessed, totalFiles) and
/// `cancellation` is polled per file so closing/cancelling stops the work.
final class ProjectSourceIndex {
    let root: URL
    private(set) var entries: [URL: ProjectSourceEntry]
    /// Set when indexing stopped because the caller cancelled; the index is
    /// partial and must not be consumed.
    private(set) var wasCancelled = false

    static let maxChars = 1_000_000

    /// Source filename extensions considered by the source viewers (call-site
    /// popups + variable flow). The superset of the old DefinitionIndex and
    /// VariableFlowTracer lists.
    static let viewerExtensions: Set<String> = [
        "c", "h", "cpp", "cc", "cxx", "hpp", "hxx", "hh", "c++", "h++",
        "m", "mm", "objc", "java", "cs", "csx", "sol",
        "kt", "kts", "py", "rb", "rake", "gemspec", "go", "rs",
        "php", "phtml", "js", "jsx", "ts", "tsx", "swift"
    ]

    /// Source filename extensions considered by the security scanner.
    static let scanExtensions: Set<String> = [
        "c", "h", "cpp", "cc", "cxx", "hpp", "hxx", "hh", "c++", "h++",
        "m", "mm", "objc", "java", "cs", "csx", "sol",
        "kt", "kts", "py", "rb", "go", "rs",
        "php", "phtml", "inc", "js", "jsx", "ts", "tsx", "swift"
    ]

    init(projectRoot: URL,
         extensions: Set<String> = ProjectSourceIndex.viewerExtensions,
         cancellation: VariableFlowCancellation? = nil,
         progress: ((Int, Int) -> Void)? = nil) {
        self.root = projectRoot.standardizedFileURL
        let urls = SourceTree.enumerate(extensions: extensions, in: self.root)
        let total = urls.count

        var parsed = [ProjectSourceEntry?](repeating: nil, count: total)
        let lock = NSLock()
        var done = 0
        let step = max(1, total / 200)

        DispatchQueue.concurrentPerform(iterations: total) { i in
            if cancellation?.isCancelled == true { return }
            let entry = Self.parse(url: urls[i])
            lock.lock()
            parsed[i] = entry
            done += 1
            let notify = done == total || done % step == 0
            lock.unlock()
            if notify { progress?(done, total) }
        }

        if cancellation?.isCancelled == true {
            self.wasCancelled = true
        }

        var entries: [URL: ProjectSourceEntry] = [:]
        for entry in parsed {
            guard let entry = entry else { continue }
            entries[entry.url] = entry
        }
        self.entries = entries
    }

    private static func parse(url: URL) -> ProjectSourceEntry? {
        let stdURL = url.standardizedFileURL
        let ext = stdURL.pathExtension.lowercased()
        guard let source = try? String(contentsOf: stdURL, encoding: .utf8),
              source.count <= maxChars,
              DiagramLanguage.from(ext: ext) != nil else { return nil }
        let tokens = CTokenizer(source: source).tokenize()
        let funcs = diagramDefinitions(source: source, ext: ext)
        return ProjectSourceEntry(url: stdURL, source: source, tokens: tokens, funcs: funcs)
    }
}

/// The single source-tree walker, replacing the near-identical copies that used
/// to live in DefinitionIndex, VariableFlowTracer, ProjectIndex,
/// VulnerabilityScanner, ClassUsageWindowController and MLScanWindowController.
/// Callers choose their own extension set; the directory skip-list is shared.
enum SourceTree {
    private static func isExcluded(_ path: String) -> Bool {
        path.contains("/build/") || path.contains("/vendor/") ||
        path.contains("/node_modules/") || path.contains("/.git/")
    }

    static func enumerate(extensions: Set<String>, in root: URL) -> [URL] {
        let fm = FileManager.default
        guard let files = fm.enumerator(at: root,
                                        includingPropertiesForKeys: [.isRegularFileKey],
                                        options: [.skipsHiddenFiles]) else { return [] }
        var result: [URL] = []
        for case let url as URL in files {
            let ext = url.pathExtension.lowercased()
            guard extensions.contains(ext) else { continue }
            if isExcluded(url.path) { continue }
            result.append(url)
        }
        return result
    }

    /// Walks every non-hidden file (skipping the same build/vendor/node_modules/
    /// .git directories) without filtering on extension. The ML scan uses this
    /// when no language set is selected.
    static func enumerateAll(in root: URL) -> [URL] {
        let fm = FileManager.default
        guard let files = fm.enumerator(at: root,
                                        includingPropertiesForKeys: [.isRegularFileKey],
                                        options: [.skipsHiddenFiles]) else { return [] }
        var result: [URL] = []
        for case let url as URL in files where !isExcluded(url.path) {
            result.append(url)
        }
        return result
    }
}
// by cipher.org.uk
import Foundation

/// A single receive-API call/property site in a source file.
struct EntrySite {
    let fileURL: URL
    let line: Int
    let column: Int
    /// UTF-16 offset of the matched leaf token, used to locate the enclosing
    /// function when tracing the flow of `entryVariable`.
    let charIndex: Int
    /// Matched leaf name (e.g. `getParameter`, `sender`).
    let apiName: String
    /// Receiver path struck against, normalized with dots (`msg`, `request`,
    /// `System`, `ProcessInfo.processInfo`, ...) or the bare leaf.
    let apiPath: String
    let category: String
    let origin: EntryOrigin
    let confidence: EntryConfidence
    /// Variable the receive call/property is assigned to, if determinable from
    /// the surrounding statement. `nil` sites are still recorded as entries but
    /// have no variable to trace.
    let entryVariable: String?
    /// The trimmed source line for display.
    let snippet: String
}

/// One results-list group: a receive category with its sites.
struct EntryGroup {
    let category: String
    let origin: EntryOrigin
    let confidence: EntryConfidence
    var sites: [EntrySite] = []

    static func orderIndex(_ confidence: EntryConfidence, _ origin: EntryOrigin) -> Int {
        switch (confidence, origin) {
        case (.primary, .internet): return 0
        case (.primary, .local): return 1
        case (.indirect, _): return 2
        }
    }
}

/// Walks a project's token streams and matches the receive-API catalog to find
/// user-controlled entry points. Each file is matched independently against the
/// language's entries (C-family files reuse the C table; ObjC gets both).
enum EntryPointCollector {

    /// Hard cap on the number of entry point sites collected in one pass.
    static let siteCap = 500

    /// Collect all entry-point sites across the indexed project.
    /// - Parameters:
    ///   - includeIndirect: when true, indirect tiers (file reads, persisted
    ///     data, deserialization) are scanned too. Primary tiers are always
    ///     scanned. Callers satisfy `includeIndirect` lazily via this param.
    ///   - progress: (processedFiles, totalFiles) — called frequently.
    static func collect(sourceIndex: ProjectSourceIndex,
                        includeIndirect: Bool,
                        progress: ((Int, Int) -> Void)? = nil) -> [EntryGroup] {
        let files = Array(sourceIndex.entries.values).sorted { $0.url.path < $1.url.path }
        var groups: [String: EntryGroup] = [:]
        var seen: Set<String> = []
        var total = 0
        var truncated = false
        let totalCount = files.count
        var done = 0
        let flushEvery = max(1, totalCount / 200)

        progress?(0, totalCount)

        outer: for entry in files {
            for site in Self.matchedSites(source: entry.source,
                                          tokens: entry.tokens,
                                          url: entry.url,
                                          includeIndirect: includeIndirect) {
                let key = "\(site.fileURL.path)#\(site.charIndex)#\(site.apiName)"
                guard seen.insert(key).inserted else { continue }
                if total >= Self.siteCap {
                    truncated = true
                    break outer
                }
                total += 1
                var group = groups[site.category] ?? EntryGroup(category: site.category,
                                                                origin: site.origin,
                                                                confidence: site.confidence)
                group.sites.append(site)
                groups[site.category] = group
            }
            done += 1
            if done % flushEvery == 0 { progress?(done, totalCount) }
        }
        progress?(totalCount, totalCount)

        let result = groups
            .values
            .sorted { lhs, rhs in
                let li = EntryGroup.orderIndex(lhs.confidence, lhs.origin)
                let ri = EntryGroup.orderIndex(rhs.confidence, rhs.origin)
                if li != ri { return li < ri }
                return lhs.category < rhs.category
            }

        Self.truncationWarning = truncated
        return result
    }

    /// Set by `collect` when the site cap was hit.
    private(set) static var truncationWarning = false

    // MARK: - Per-file matching

    /// Catalog indexed by leaf name so token scanning is O(tokens), not
    /// O(tokens × catalog).
    static let entriesByLeaf: [String: [EPEntry]] = {
        var map: [String: [EPEntry]] = [:]
        for entry in EntryPointCatalog.entries {
            map[entry.leaf, default: []].append(entry)
        }
        return map
    }()

    static func matchedSites(source: String, tokens: [CAstToken], url: URL,
                             includeIndirect: Bool) -> [EntrySite] {
        guard let lang = EPLanguage.from(ext: url.pathExtension) else { return [] }
        let lines = source.components(separatedBy: "\n")
        var sites: [EntrySite] = []

        for (i, token) in tokens.enumerated() {
            guard token.kind == .identifier else { continue }
            guard let candidates = entriesByLeaf[token.text] else { continue }
            for entry in candidates {
                guard entry.applies(to: lang) else { continue }
                guard entry.confidence == .primary || includeIndirect else { continue }
                guard let site = Self.match(entry: entry, tokens: tokens, index: i,
                                            lines: lines, url: url) else { continue }
                sites.append(site)
                break
            }
        }
        return sites
    }

    /// Matches `entry` against the token at `i`. Returns a site on success.
    static func match(entry: EPEntry, tokens: [CAstToken], index i: Int,
                      lines: [String], url: URL) -> EntrySite? {
        let leaf = tokens[i]
        guard leaf.text == entry.leaf else { return nil }
        let chain = receiverPath(tokens, i)
        let prefix = entry.prefix
        let prefixOK = prefix == nil || chain == prefix || chain.hasSuffix("." + prefix!)

        let isCall = i + 1 < tokens.count && tokens[i + 1].text == "("
        // `func foo(`, `public String foo(` etc. are declarations, not calls.
        // CTokenizer.classify knows C/Java keywords only, so Swift's `func` and
        // Python's `def` arrive as identifiers — accept either kind. Also bail
        // on a leading type + visibility/modifier (`public String getParameter`),
        // which is a method signature, not a receive site.
        var precededByDeclarationKeyword = false
        if i > 0 {
            var k = 1
            while k <= 3, i - k >= 0 {
                let t = tokens[i - k]
                let direct = ["func", "function", "def", "sub", "fn", "method",
                              "proc", "fun", "class", "interface", "struct", "enum"]
                let modifier = ["public", "private", "protected", "internal", "static",
                                "final", "abstract", "override", "virtual", "sync",
                                "async", "export", "def", "func", "function", "sub",
                                "fn", "fun"]
                if direct.contains(t.text) || modifier.contains(t.text) {
                    precededByDeclarationKeyword = true
                    break
                }
                k += 1
            }
        }

        var matchedLeaf: String? = nil
        if entry.match != .property, isCall, !precededByDeclarationKeyword, prefixOK {
            matchedLeaf = leaf.text
        } else if entry.match != .call, prefix != nil, prefixOK {
            matchedLeaf = leaf.text
        } else if entry.match != .call, prefix == nil, entry.allowBareProperty,
                  i == 0 || (tokens[i - 1].text != "." && tokens[i - 1].text != "::"),
                  !(i + 1 < tokens.count && [")", ",", ";", "="].contains(tokens[i + 1].text)) {
            // Bare property read (argv, environ, $_GET, …). The next-token check
            // skips parameter lists and declarations (`char **argv)`), which are
            // not receive sites — only later uses of the identifier are.
            matchedLeaf = leaf.text
        }

        guard let apiName = matchedLeaf else { return nil }

        let variable = Self.receiverVariable(entry: entry, tokens: tokens, index: i)
        let line = max(1, leaf.line)
        let snippet = line <= lines.count
            ? lines[line - 1].trimmingCharacters(in: .whitespacesAndNewlines)
            : ""
        let displayPath: String
        if let p = prefix {
            displayPath = p
        } else if !chain.isEmpty {
            displayPath = chain
        } else {
            displayPath = leaf.text
        }
        return EntrySite(fileURL: url,
                         line: line,
                         column: leaf.column,
                         charIndex: leaf.offset,
                         apiName: apiName,
                         apiPath: displayPath,
                         category: entry.category,
                         origin: entry.origin,
                         confidence: entry.confidence,
                         entryVariable: variable,
                         snippet: snippet)
    }

    /// Normalized receiver path before `tokens[i]`, e.g.
    /// `os.Getenv` → `os`, `ProcessInfo.processInfo.environment` →
    /// `ProcessInfo.processInfo`, `std::env::var` → `std.env`.
    static func receiverPath(_ tokens: [CAstToken], _ i: Int) -> String {
        var parts: [String] = []
        var j = i - 1
        var expectingSeparator = true
        while j >= 0 {
            let t = tokens[j]
            if expectingSeparator {
                if t.text == "." || t.text == "::" { expectingSeparator = false }
                else { break }
            } else {
                if t.kind == .identifier {
                    parts.append(t.text)
                    expectingSeparator = true
                } else { break }
            }
            j -= 1
        }
        return parts.reversed().joined(separator: ".")
    }

    /// Resolves the variable whose data-flow receives the entry's value, in
    /// order of precision:
    /// 1. write-style receive calls: the buffer/out argument they fill
    ///    (fgets/scanf/read/recv/copy_from_user/get_user/...);
    /// 2. the assignment target (`x = getenv("…")` → `x`);
    /// 3. property/bare sites read off an object that is itself the entry value
    ///    (`msg.sender` → `msg`, `userActivity.webpageURL` → `userActivity`,
    ///    bare `argv`/`environ` → the identifier itself).
    /// Returns nil only when the value is genuinely consumed inline with no
    /// stored receiver the tracer could follow.
    static func receiverVariable(entry: EPEntry, tokens: [CAstToken], index i: Int) -> String? {
        if let arg = entry.receiverArg,
           let v = argumentVariable(tokens: tokens, callIndex: i, argIndex: arg) {
            return v
        }
        if let v = entry.entryVariable(tokens: tokens, callIndex: i) { return v }
        if entry.match == .call { return nil }
        return selfReceiver(entry: entry, tokens: tokens, index: i)
    }

    /// The variable data lands in at `argIndex` of the write-style receive call
    /// at `callIndex`, skimming `&x` / `*p` prefixes and string-literal format
    /// arguments.
    static func argumentVariable(tokens: [CAstToken], callIndex: Int, argIndex: Int) -> String? {
        var j = callIndex + 2
        var depth = 0
        var arg = 0
        var found: String?
        while j < tokens.count {
            let t = tokens[j]
            switch t.text {
            case "(":
                depth += 1
            case ")":
                if depth == 0 { return found }
                depth -= 1
            case ",":
                if depth == 0 {
                    if arg >= argIndex { return found }
                    arg += 1
                    found = nil
                }
            default:
                if depth == 0, arg == argIndex, found == nil, t.kind == .identifier {
                    found = t.text
                }
            }
            j += 1
        }
        return found
    }

    /// For property/bare entries, the receiver object itself carries the
    /// external data and can be traced (`msg.sender` → `msg`, bare `argv`).
    static func selfReceiver(entry: EPEntry, tokens: [CAstToken], index i: Int) -> String? {
        if entry.allowBareProperty {
            guard ["argv", "environ", "ARGV", "ENV", "_ENV",
                    "_GET", "_POST", "_REQUEST", "_COOKIE", "_FILES", "_SERVER"].contains(entry.leaf),
                  looksLikeIdentifier(entry.leaf) else { return nil }
            return entry.leaf
        }
        let chain = receiverPath(tokens, i)
        let comps = chain.split(separator: ".").map(String.init)
            .filter { $0 != "self" && $0 != "this" }
        guard let n = comps.last, looksLikeIdentifier(n), n != entry.leaf else { return nil }
        return n
    }

    private static func looksLikeIdentifier(_ s: String) -> Bool {
        guard let first = s.first else { return false }
        guard first == "_" || first.isLetter || first == "$" else { return false }
        return s.allSatisfy { $0 == "_" || $0.isLetter || $0.isNumber || $0 == "$" }
    }
}

extension EPEntry {

    /// Best-effort name of the variable this receive call is assigned to, by
    /// scanning the statement backwards from the call for an assignment.
    ///
    /// Switches on token *text* (not `kind`): the C tokenizer classifies only
    /// `()[]{};,.?:#` as `.punct`, so `=`, `<`, `>`, `!` etc. arrive as
    /// `.operator` — gating on `.punct` would silently skip the `=`.
    func entryVariable(tokens: [CAstToken], callIndex: Int) -> String? {
        var j = callIndex - 1
        if j >= 0, tokens[j].text == "(" { j -= 1 }
        var depth = 0
        while j >= 0 {
            let t = tokens[j]
            switch t.text {
            case ")":
                depth += 1
            case "(":
                if depth == 0 { return nil }
                depth -= 1
            case "=":
                if depth == 0 { return assignmentTarget(tokens: tokens, eq: j) }
            case ";", "{", "}", ":":
                if depth == 0 { return nil }
            default:
                if t.kind == .keyword, depth == 0,
                   ["if", "while", "for", "return", "switch", "case", "catch",
                    "else", "do", "until", "begin", "when", "unless"].contains(t.text) {
                    return nil
                }
            }
            j -= 1
        }
        return nil
    }

    /// The identifier being assigned, if the `=` at `eq` is a plain assignment
    /// (not `==`, `<=`, `!=`, `+=`, ...) to a plain variable (not a property
    /// like `foo.bar =` or `arr[i] =`).
    private func assignmentTarget(tokens: [CAstToken], eq: Int) -> String? {
        guard eq > 0 else { return nil }
        let prev = tokens[eq - 1]
        if prev.kind == .punct,
           ["=", "<", ">", "!", "+", "-", "*", "/", "%", "&", "|", "^", "~"].contains(prev.text) {
            return nil
        }
        guard prev.kind == .identifier else { return nil }
        if eq >= 2 {
            let q = tokens[eq - 2]
            if q.text == "." || q.text == "::" { return nil }
        }
        return prev.text
    }
}
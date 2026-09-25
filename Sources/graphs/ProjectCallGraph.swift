// by cipher.org.uk
import Foundation

/// How a function can be entered from outside the project.
/// Used to colour the origin boxes at the top of the reachability diagram.
enum ProjectCallEntry: Hashable {
    /// Receives data that arrives from outside the program (HTTP handlers,
    /// argv/env-bound parameters, sockets, deserialized input, …).
    case remote
    /// Internal program entry (main(), module entry points, …).
    case local
}

/// One function/method definition taking part in the project-wide call graph.
struct ProjectCallFunc {
    let name: String
    let fileURL: URL
    let bodyRange: NSRange
    /// Signature ∪ body — the whole region the definition occupies. Used to map
    /// a charIndex (an entry site, a click) back to its enclosing function.
    let enclosingRange: NSRange
    /// UTF-16 range `name .. ')'` of the parameter list. Skipped while scanning
    /// bodies so a declaration line (`def run(user):`) is never read as a call.
    let signatureRange: NSRange
    /// Offset of the name token (the jump target when a node is clicked).
    let nameOffset: Int
    /// 1-based source line of the name token.
    let nameLine: Int
}

/// A call found inside a caller's body.
struct ProjectCallEdge {
    let calleeName: String
    /// 1-based call-site line, kept for diagnostics.
    let line: Int
}

/// One node in the rendered reachability diagram.
struct ReachabilityNode {
    let displayName: String
    let functionName: String
    let fileURL: URL
    let line: Int
    let isStart: Bool
    /// True when the node has no caller inside the shown reverse subgraph
    /// (the amber candidates / the nodes the Topmost box tops).
    let isTopmost: Bool
    let entryKinds: Set<ProjectCallEntry>
    /// True when the node is part of the forward overlay only — the functions
    /// the start node calls *directly* — drawn grey with black text on top of
    /// the reverse chain.
    let isForwardOverlay: Bool
}

/// The finished reachability diagram, described with display names ready to be
/// passed to the diagram window. One combined diagram: the full reverse caller
/// chain (up to Remote / Local, or an amber Topmost box when no entry is
/// reached) with the direct callees overlaid as grey boxes.
struct ReachabilityResult {
    let functionName: String
    let fileURL: URL
    /// Whether the reverse chain reaches at least one *remote* (outside) entry.
    let remoteReachable: Bool
    /// Whether the reverse chain reaches at least one *local* entry (main …).
    let localReachable: Bool
    /// True when the reverse chain reaches no entry at all — the window tops
    /// the diagram with an amber "Topmost" box.
    let unverified: Bool
    let nodes: [ReachabilityNode]
    let edges: [(String, String)]
    let warnings: [String]
}

/// Project-wide call graph built once per project: every function definition,
/// every call between project-defined functions, and each function's entry
/// classification (remote / local). Call resolution is intentionally name-based
/// (the same approximation the variable-flow tracer, the taint engine and the
/// scanner already make), so cross-file call edges are closed over globally
/// defined names rather than parser type information.
final class ProjectCallGraph {

    /// Unique identity of a definition: one (file, name) pair. Function names
    /// can be shared across files; duplicates inside one file are collapsed
    /// (rare and consistent with the app's other name-based subsystems).
    struct FuncRef: Hashable {
        let fileURL: URL
        let name: String
    }

    /// Classic program / script entry names, treated as *local* entries when the
    /// project defines them. Mirrors the names the scanner seeds its per-file
    /// reachability with, minus the too-generic "handler".
    static let fallbackEntryNames = [
        "main", "wmain", "WinMain", "_tmain", "Main", "MainAsync",
        "exports", "module.exports"
    ]

    let root: URL
    private(set) var defs: [FuncRef: ProjectCallFunc] = [:]
    private(set) var byName: [String: [FuncRef]] = [:]
    /// Definitions of a file, in source order (for the enclosing-function lookup).
    private(set) var fileRefs: [URL: [FuncRef]] = [:]
    /// caller -> calls inside its body.
    private(set) var callees: [FuncRef: [ProjectCallEdge]] = [:]
    /// Reverse index: callee name -> definitions that call it.
    private(set) var callers: [String: Set<FuncRef>] = [:]
    private(set) var remoteEntries: Set<FuncRef> = []
    private(set) var localEntries: Set<FuncRef> = []
    /// Set when indexing stopped because the caller cancelled; the graph then
    /// holds a partial (possibly empty) index and must not be cached.
    private(set) var wasCancelled = false

    private static let maxDepth = 12
    private static let maxNodes = 80

    /// Builds the call graph on demand from the tree on disk. `progress` gives
    /// (filesProcessed, totalFiles) as indexing advances, and `cancellation` is
    /// polled per file so a closed window stops the work. Prefer
    /// `init(sourceIndex:)` so the tree is only read/parsed once.
    convenience init(projectRoot: URL,
                     cancellation: VariableFlowCancellation? = nil,
                     progress: ((Int, Int) -> Void)? = nil) {
        let index = ProjectSourceIndex(projectRoot: projectRoot,
                                       cancellation: cancellation,
                                       progress: progress)
        self.init(sourceIndex: index)
        self.wasCancelled = index.wasCancelled
    }

    /// Builds the call graph from a load-time `ProjectSourceIndex` fully in
    /// memory: files were already read, tokenized and parsed once, so this pass
    /// only derives the definition table, the call edges and the entry status.
    convenience init(sourceIndex: ProjectSourceIndex) {
        var defs: [FuncRef: ProjectCallFunc] = [:]
        var byName: [String: [FuncRef]] = [:]
        var fileRefs: [URL: [FuncRef]] = [:]

        for (url, entry) in sourceIndex.entries.sorted(by: { $0.key.path < $1.key.path }) {
            var refs: [FuncRef] = []
            for def in entry.funcs {
                guard let f = Self.callFunc(fromDef: def,
                                            source: entry.source,
                                            tokens: entry.tokens,
                                            url: url) else { continue }
                let ref = FuncRef(fileURL: url, name: f.name)
                defs[ref] = f
                byName[f.name, default: []].append(ref)
                refs.append(ref)
            }
            guard !refs.isEmpty else { continue }
            fileRefs[url] = refs
        }

        var callees: [FuncRef: [ProjectCallEdge]] = [:]
        var callers: [String: Set<FuncRef>] = [:]
        for (ref, f) in defs.sorted(by: { $0.key.name < $1.key.name }) {
            let edges = Self.scanCalls(body: f.bodyRange,
                                       signature: f.signatureRange,
                                       tokens: sourceIndex.entries[f.fileURL]?.tokens ?? [],
                                       callerName: f.name,
                                       lookup: byName)
            if !edges.isEmpty { callees[ref] = edges }
            for e in edges where byName[e.calleeName] != nil {
                callers[e.calleeName, default: []].insert(ref)
            }
        }

        var remoteEntries = Set<FuncRef>()
        var localEntries = Set<FuncRef>()
        let groups = EntryPointCollector.collect(sourceIndex: sourceIndex, includeIndirect: false)
        for group in groups {
            for site in group.sites {
                guard let ref = Self.enclosingRef(containing: site.charIndex,
                                                  in: site.fileURL,
                                                  defs: defs,
                                                  fileRefs: fileRefs) else { continue }
                if site.origin == .internet {
                    remoteEntries.insert(ref)
                } else {
                    localEntries.insert(ref)
                }
            }
        }
        for name in Self.fallbackEntryNames {
            for ref in byName[name] ?? [] where !remoteEntries.contains(ref) {
                localEntries.insert(ref)
            }
        }

        self.init(root: sourceIndex.root, defs: defs, byName: byName, fileRefs: fileRefs,
                  callees: callees, callers: callers,
                  remoteEntries: remoteEntries, localEntries: localEntries,
                  wasCancelled: sourceIndex.wasCancelled)
    }

    private init(root: URL,
                 defs: [FuncRef: ProjectCallFunc],
                 byName: [String: [FuncRef]],
                 fileRefs: [URL: [FuncRef]],
                 callees: [FuncRef: [ProjectCallEdge]],
                 callers: [String: Set<FuncRef>],
                 remoteEntries: Set<FuncRef>,
                 localEntries: Set<FuncRef>,
                 wasCancelled: Bool) {
        self.root = root.standardizedFileURL
        self.defs = defs
        self.byName = byName
        self.fileRefs = fileRefs
        self.callees = callees
        self.callers = callers
        self.remoteEntries = remoteEntries
        self.localEntries = localEntries
        self.wasCancelled = wasCancelled
    }

    // MARK: - Definition derivation

    /// Derives a call-graph function from a parsed definition, or nil when the
    /// definition cannot participate (bad ranges or a function-like macro).
    private static func callFunc(fromDef def: CCFunctionParser.FunctionDef,
                                 source: String,
                                 tokens: [CAstToken],
                                 url: URL) -> ProjectCallFunc? {
        let nameR = def.nameRange
        let bodyR = def.bodyRange
        var sigR = def.signatureRange
        guard nameR.location != NSNotFound, nameR.length > 0,
              bodyR.location != NSNotFound, bodyR.length > 0 else { return nil }
        if sigR.location == NSNotFound || sigR.length <= 0 { sigR = nameR }
        // Skip function-like macros (no real body to scan for calls). A macro is
        // recognised by its *name* being declared by `#define` on the same line
        // (`#define NAME(...) ...`). Never by the coarse signature range: the C
        // function parser's ranges can span earlier lines, so a real function
        // whose range overlaps a file-scope `#define` (common in kernel drivers)
        // must not be dropped as a macro.
        let nameLoc = nameR.location
        if nameLoc != NSNotFound,
           nameR.length > 0,
           nameLoc <= (source as NSString).length {
            let ns = source as NSString
            var lineStart = nameLoc
            while lineStart > 0, ns.character(at: lineStart - 1) != 0x0A { lineStart -= 1 }
            let prefix = ns.substring(with: NSRange(location: lineStart, length: nameLoc - lineStart))
            if prefix.trimmingCharacters(in: .whitespaces).hasPrefix("#define") {
                return nil
            }
        }
        let enclosingR = NSUnionRange(sigR, bodyR)
        return ProjectCallFunc(name: def.name,
                               fileURL: url,
                               bodyRange: bodyR,
                               enclosingRange: enclosingR,
                               signatureRange: sigR,
                               nameOffset: nameR.location,
                               nameLine: Self.line(of: nameR.location, in: source))
    }

    /// 1-based line number of the UTF-16 offset in `source`.
    private static func line(of utf16Offset: Int, in source: String) -> Int {
        let ns = source as NSString
        let end = min(max(utf16Offset, 0), ns.length)
        var line = 1
        for i in 0..<end where ns.character(at: i) == 0x0A { line += 1 }
        return line
    }

    private static func substring(_ source: String, _ r: NSRange) -> String? {
        let ns = source as NSString
        guard r.location != NSNotFound, r.length > 0,
              r.location >= 0, r.location + r.length <= ns.length else { return nil }
        return ns.substring(with: r)
    }

    /// Finds the innermost definition whose enclosing range contains `charIndex`.
    private static func enclosingRef(containing charIndex: Int,
                                     in fileURL: URL,
                                     defs: [FuncRef: ProjectCallFunc],
                                     fileRefs: [URL: [FuncRef]]) -> FuncRef? {
        let std = fileURL.standardizedFileURL
        var bestRef: FuncRef?
        var bestLen = Int.max
        for ref in fileRefs[std] ?? [] {
            guard let f = defs[ref] else { continue }
            let r = f.enclosingRange
            guard r.location != NSNotFound, r.length > 0 else { continue }
            if charIndex >= r.location, charIndex < r.location + r.length, r.length < bestLen {
                bestRef = ref
                bestLen = r.length
            }
        }
        return bestRef
    }

    // MARK: - Call edge extraction

    /// Scans a function body for `identifier(` tokens that resolve to a
    /// project-defined function. Signature region and the caller's own name are
    /// excluded so declaration lines and self-calls don't create edges.
    private static func scanCalls(body: NSRange,
                                  signature: NSRange,
                                  tokens: [CAstToken],
                                  callerName: String,
                                  lookup: [String: [FuncRef]]) -> [ProjectCallEdge] {
        guard body.location != NSNotFound, body.length > 0, !tokens.isEmpty else { return [] }
        let bodyStart = body.location
        let bodyEnd = body.location + body.length

        // Binary-search the token window [startIdx, endIdx) that lies in the body.
        var lo = 0
        var hi = tokens.count
        while lo < hi {
            let m = (lo + hi) / 2
            if tokens[m].offset < bodyStart { lo = m + 1 } else { hi = m }
        }
        let startIdx = lo
        lo = startIdx
        hi = tokens.count
        while lo < hi {
            let m = (lo + hi) / 2
            if tokens[m].offset < bodyEnd { lo = m + 1 } else { hi = m }
        }
        let endIdx = lo

        var edges: [ProjectCallEdge] = []
        var seen = Set<String>()
        var i = startIdx
        while i + 1 < endIdx {
            let tok = tokens[i]
            if tok.kind == .identifier,
               !Self.inRange(tok.offset, signature),
               tokens[i + 1].text == "(",
               tok.text != callerName,
               lookup[tok.text] != nil,
               seen.insert(tok.text).inserted {
                edges.append(ProjectCallEdge(calleeName: tok.text, line: tok.line))
            }
            i += 1
        }
        return edges
    }

    private static func inRange(_ offset: Int, _ r: NSRange) -> Bool {
        offset >= r.location && offset < r.location + r.length
    }

    // MARK: - Reachability

    /// Computes the combined reachability diagram for `functionName`: the full
    /// reverse caller chain plus the direct callees overlaid on it.
    /// Prefers the definition in `fileURL` when the name is defined in several
    /// files.
    func reachability(of functionName: String,
                      in fileURL: URL) -> ReachabilityResult {
        let stdURL = fileURL.standardizedFileURL
        let candidates = byName[functionName] ?? []
        guard !candidates.isEmpty else {
            return ReachabilityResult(functionName: functionName,
                                      fileURL: fileURL,
                                      remoteReachable: false,
                                      localReachable: false,
                                      unverified: true,
                                      nodes: [],
                                      edges: [],
                                      warnings: ["No project-defined function named “\(functionName)” was found in the index."])
        }
        let start = candidates.first(where: { $0.fileURL == stdURL }) ?? candidates.first!
        let f = defs[start]!

        let (reverse, revLimit) = ancestorClosure(start: start)
        let forward = directCallees(start: start)

        var warnings: [String] = []
        if revLimit.nodes { warnings.append("Caller chain truncated — showing the first \(Self.maxNodes) functions.") }
        if revLimit.depth { warnings.append("Stopped following callers beyond depth \(Self.maxDepth).") }

        let remoteReachable = !reverse.isDisjoint(with: remoteEntries)
        let localReachable = !reverse.isDisjoint(with: localEntries)
        let unverified = !(remoteReachable || localReachable)

        let (nodes, edges) = compose(reverse: reverse, forward: forward, start: start)
        return ReachabilityResult(functionName: f.name,
                                  fileURL: f.fileURL,
                                  remoteReachable: remoteReachable,
                                  localReachable: localReachable,
                                  unverified: unverified,
                                  nodes: nodes,
                                  edges: edges,
                                  warnings: warnings)
    }

    /// Reverse closure: every definition that (transitively) calls `start`,
    /// without pruning — the complete caller chain up to the top.
    private func ancestorClosure(start: FuncRef) -> (set: Set<FuncRef>, limit: (nodes: Bool, depth: Bool)) {
        var seen = Set<FuncRef>([start])
        var depth: [FuncRef: Int] = [start: 0]
        var queue: [FuncRef] = [start]
        var nodesLimit = false
        while let cur = queue.popLast() {
            guard let d = depth[cur], d < Self.maxDepth else { continue }
            for caller in callers[cur.name] ?? [] {
                if seen.insert(caller).inserted {
                    depth[caller] = d + 1
                    if seen.count >= Self.maxNodes {
                        nodesLimit = true
                    } else {
                        queue.append(caller)
                    }
                }
            }
        }
        return (seen, (nodesLimit, (depth.values.max() ?? 0) >= Self.maxDepth))
    }

    /// Forward overlay: the definitions `start` calls *directly* — one level
    /// only, never the callees of its callees. Deliberately shallow so the
    /// overlay shows what this one function/method invokes, not a recursive
    /// expansion of the call graph.
    private func directCallees(start: FuncRef) -> Set<FuncRef> {
        var direct = Set<FuncRef>()
        for e in callees[start] ?? [] {
            for c in byName[e.calleeName] ?? [] {
                direct.insert(c)
            }
        }
        return direct
    }

    /// Builds the display nodes/edges for the combined graph. Nodes in the
    /// reverse set are the primary chain; nodes only in the forward set are
    /// flagged as the grey overlay.
    private func compose(reverse: Set<FuncRef>,
                         forward: Set<FuncRef>,
                         start: FuncRef) -> ([ReachabilityNode], [(String, String)]) {
        let merged = reverse.union(forward)

        // In-degree within the reverse subgraph: a reverse node is "topmost"
        // when no displayed reverse definition calls it (the amber candidates
        // and the nodes the Unverified box tops).
        var hasCaller = Set<FuncRef>()
        for ref in reverse {
            for e in callees[ref] ?? [] {
                for c in byName[e.calleeName] ?? [] where reverse.contains(c) {
                    hasCaller.insert(c)
                }
            }
        }

        var used = Set<String>()
        var display: [FuncRef: String] = [:]
        for ref in orderedRefs(merged, startFirst: start) {
            display[ref] = displayName(for: ref, isStart: ref == start, used: &used)
        }

        var nodes: [ReachabilityNode] = []
        for ref in orderedRefs(merged, startFirst: start) {
            guard let f = defs[ref] else { continue }
            var kinds = Set<ProjectCallEntry>()
            if remoteEntries.contains(ref) { kinds.insert(.remote) }
            if localEntries.contains(ref) { kinds.insert(.local) }
            let isForwardOverlay = !reverse.contains(ref) && forward.contains(ref)
            nodes.append(ReachabilityNode(displayName: display[ref] ?? f.name,
                                          functionName: f.name,
                                          fileURL: f.fileURL,
                                          line: f.nameLine,
                                          isStart: ref == start,
                                          isTopmost: !hasCaller.contains(ref),
                                          entryKinds: kinds,
                                          isForwardOverlay: isForwardOverlay))
        }

        var edgeSet = Set<String>()
        var edges: [(String, String)] = []
        for ref in merged {
            guard let from = display[ref] else { continue }
            for e in callees[ref] ?? [] {
                for c in byName[e.calleeName] ?? [] where merged.contains(c) {
                    guard let to = display[c], from != to else { continue }
                    let key = from + "\u{1}" + to
                    if edgeSet.insert(key).inserted { edges.append((from, to)) }
                }
            }
        }
        return (nodes, edges)
    }

    /// Deterministic ordering: the start first (so it gets the exact display
    /// name), then the rest by file path + name.
    private func orderedRefs(_ set: Set<FuncRef>, startFirst: FuncRef) -> [FuncRef] {
        var refs = Array(set)
        refs.sort { ($0.fileURL.path, $0.name) < ($1.fileURL.path, $1.name) }
        if let idx = refs.firstIndex(of: startFirst) {
            refs.remove(at: idx)
            refs.insert(startFirst, at: 0)
        }
        return refs
    }

    private func displayName(for ref: FuncRef, isStart: Bool, used: inout Set<String>) -> String {
        let baseName = defs[ref]?.name ?? ref.name
        if isStart {
            used.insert(baseName)
            return baseName
        }
        var base = baseName
        if (byName[baseName]?.count ?? 0) > 1 {
            base = "\(baseName) (\(fileHint(for: ref.fileURL)))"
        }
        var candidate = base
        var n = 2
        while used.contains(candidate) {
            candidate = "\(base) \(n)"
            n += 1
        }
        used.insert(candidate)
        return candidate
    }

    private func fileHint(for url: URL) -> String {
        let path = url.path
        let rootPrefix = root.path + "/"
        if path.hasPrefix(rootPrefix) { return String(path.dropFirst(rootPrefix.count)) }
        return url.lastPathComponent
    }
}
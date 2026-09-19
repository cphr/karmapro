// by cipher.org.uk
import Foundation

/// One node in the variable-flow diagram: a function frame in which the traced
/// variable (or the parameter it was mapped to) is used.
struct VariableFlowNode {
    let id: String
    let functionName: String
    /// The identifier being traced inside this frame (the highlighted variable
    /// for the start node, otherwise the mapped callee parameter).
    let variableName: String
    let fileURL: URL
    let fileHint: String
    /// Number of argument-passing hops from the start node (0 = start frame).
    let depth: Int
    /// 1-based source lines where the identifier is used, in source order.
    let lines: [Int]
    /// Source text of each line in `lines`, aligned one-to-one. Used to show the
    /// actual code inside callee-callout boxes.
    let useText: [String]
    let isStart: Bool

    var displayLineSummary: String {
        guard !lines.isEmpty else { return "no uses found" }
        if lines.count <= 6 {
            return "lines: " + lines.map(String.init).joined(separator: ", ")
        }
        let shown = lines.prefix(6).map(String.init).joined(separator: ", ")
        return "lines: \(shown), … (\(lines.count) total)"
    }
}

/// An edge meaning "the traced value was passed as an argument" from a caller
/// frame to a callee frame, recorded at the caller's call-site line.
struct VariableFlowEdge {
    let from: String
    let to: String
    let callLine: Int
}

/// The complete trace produced by the tracer, shown in the diagram window.
struct VariableFlowResult {
    let variableName: String
    let startFunction: String
    let nodes: [VariableFlowNode]
    let edges: [VariableFlowEdge]
    let warnings: [String]
    /// Full source of the start frame's file (for the enclosing-function
    /// flowchart) and its file extension (determines the flowchart dialect).
    let startFileSource: String
    let startFileExt: String
}

/// One "callee box" in the refined diagram: the traced value was passed into
/// `functionName` at `callLine`; `useLines` is the source lines where the mapped
/// parameter is used in the callee, plus each line's text. `children` are the
/// deeper calls it participates in (recursively).
struct VariableFlowCallout {
    let callLine: Int
    let functionName: String
    let variableName: String
    let fileURL: URL
    let fileHint: String
    let useLines: [(line: Int, text: String)]
    let children: [VariableFlowCallout]
}

/// Thread-safe cancellation flag for a background variable-flow search. Created
/// by the requester and polled by the tracer's indexing loop, so closing the
/// window abandons the work instead of letting it run to completion.
final class VariableFlowCancellation {
    private let lock = NSLock()
    private var cancelled = false

    var isCancelled: Bool {
        lock.lock(); defer { lock.unlock() }
        return cancelled
    }

    func cancel() {
        lock.lock(); defer { lock.unlock() }
        cancelled = true
    }
}

/// Project-wide token-based tracer that follows a variable through every use
/// inside its enclosing function and, when the variable is passed as an
/// argument to a project-defined function, maps it to the callee's parameter
/// (by argument position) and recurses into the callee.
///
/// Call resolution is intentionally name-based (no type/overload resolution),
/// the same approximation the existing taint engine already makes. Recursive /
/// cyclic calls terminate via a visited-function set along the current path.
final class VariableFlowTracer {

    private struct FileInfo {
        let url: URL
        let source: String
        let tokens: [CAstToken]
        let funcs: [ProjectFunc]
    }

    private struct ProjectFunc {
        let name: String
        let fileURL: URL
        let bodyRange: NSRange
        /// Signature ∪ body. Used only to find the enclosing function for a
        /// click; Swift/JS report a `bodyRange` that starts at `{`, so a
        /// right-click on a parameter in the signature would otherwise miss.
        let enclosingRange: NSRange
        let nameOffset: Int
        /// Offset just past the closing ')' of the parameter list.
        let paramCloseOffset: Int
        let paramNames: [String]
    }

    private struct Pass {
        let calleeName: String
        let argIndex: Int
        let line: Int
        /// True when the call was written as a member call (`obj.method(x)`).
        /// Python instance/class methods carry an explicit `self`/`cls` first
        /// parameter that is *not* present at the call site, so the explicit
        /// argument position must be shifted past it.
        let isMemberCall: Bool
    }

    private let projectRoot: URL
    private let files: [URL: FileInfo]
    private let index: [String: [ProjectFunc]]
    /// Set when indexing stopped because the caller cancelled; the tracer then
    /// holds a partial (possibly empty) index and must not be cached.
    private(set) var wasCancelled = false

    private static let maxDepth = 12
    private static let maxNodes = 80

    private var nodeIDCounter = 0
    private var nodesBuffer: [VariableFlowNode] = []
    private var edgesBuffer: [VariableFlowEdge] = []
    private var warningSet = Set<String>()

    /// Builds the project-wide definition index on demand. `progress` is called
    /// with `(filesProcessed, totalFiles)` as indexing advances (throttled), and
    /// `cancellation` is polled per file so a closed window stops the work.
    /// Prefer `init(sourceIndex:)` on the load-time `ProjectSourceIndex` so the
    /// tree is only read/parsed once; this I/O path is the small fallback used
    /// when the shared index is unavailable (e.g. opened before it loaded).
    convenience init(projectRoot: URL,
                     cancellation: VariableFlowCancellation? = nil,
                     progress: ((Int, Int) -> Void)? = nil) {
        let index = ProjectSourceIndex(projectRoot: projectRoot,
                                       cancellation: cancellation,
                                       progress: progress)
        self.init(sourceIndex: index)
        self.wasCancelled = index.wasCancelled
    }

    /// Builds the tracer from a load-time `ProjectSourceIndex` fully in memory:
    /// every file was already read, tokenized and parsed once, so this pass
    /// only derives the parameter lists and the name → definition table.
    convenience init(sourceIndex: ProjectSourceIndex) {
        var files: [URL: FileInfo] = [:]
        var index: [String: [ProjectFunc]] = [:]
        for (url, entry) in sourceIndex.entries.sorted(by: { $0.key.path < $1.key.path }) {
            let lang = DiagramLanguage.from(ext: url.pathExtension)
            var funcs: [ProjectFunc] = []
            for def in entry.funcs {
                if let f = Self.projectFunc(fromDef: def, source: entry.source,
                                            tokens: entry.tokens, lang: lang, url: url) {
                    funcs.append(f)
                }
            }
            guard !funcs.isEmpty else { continue }
            files[url] = FileInfo(url: url, source: entry.source, tokens: entry.tokens, funcs: funcs)
            for f in funcs { index[f.name, default: []].append(f) }
        }
        self.init(projectRoot: sourceIndex.root,
                  files: files,
                  index: index,
                  wasCancelled: sourceIndex.wasCancelled)
    }

    /// The designated initializer: takes the derived file/function tables
    /// directly (they come from a `ProjectSourceIndex` — either the load-time
    /// one or a small on-demand build — so files are read and parsed only once).
    private init(projectRoot: URL, files: [URL: FileInfo], index: [String: [ProjectFunc]], wasCancelled: Bool) {
        self.projectRoot = projectRoot.standardizedFileURL
        self.files = files
        self.index = index
        self.wasCancelled = wasCancelled
    }

    /// Derives a traceable `ProjectFunc` from a parsed definition, or nil when
    /// the definition cannot be traced (bad ranges, macro-like bodies, or an
    /// unparseable parameter list).
    private static func projectFunc(fromDef def: CCFunctionParser.FunctionDef,
                                    source: String,
                                    tokens: [CAstToken],
                                    lang: DiagramLanguage?,
                                    url: URL) -> ProjectFunc? {
        let nameR = def.nameRange
        let bodyR = def.bodyRange
        guard nameR.location != NSNotFound, nameR.length > 0,
              bodyR.location != NSNotFound else { return nil }
        // Skip function-like macros (`#define F(x) ...`): they have no
        // real body lines to trace and no meaningful parameter names.
        if let sig = Self.substring(source, def.signatureRange),
           sig.contains("#define") { return nil }
        guard let lang = lang else { return nil }
        guard let (names, closeOffset) = Self.scanParams(tokens: tokens,
                                                         nameOffset: nameR.location,
                                                         lang: lang) else { return nil }
        let sigR = def.signatureRange
        let enclosingR: NSRange
        if sigR.location != NSNotFound, sigR.length > 0 {
            enclosingR = NSUnionRange(sigR, bodyR)
        } else {
            enclosingR = bodyR
        }
        return ProjectFunc(name: def.name,
                           fileURL: url,
                           bodyRange: bodyR,
                           enclosingRange: enclosingR,
                           nameOffset: nameR.location,
                           paramCloseOffset: closeOffset,
                           paramNames: names)
    }

    /// Traces `variableName` starting at the UTF-16 offset `charIndex` inside
    /// `fileURL` (the position of the right-clicked / highlighted identifier).
    func trace(variableName: String, in fileURL: URL, charIndex: Int) -> VariableFlowResult {
        let stdURL = fileURL.standardizedFileURL
        var warnings: [String] = []
        guard !variableName.isEmpty else {
            return VariableFlowResult(variableName: variableName, startFunction: "",
                                      nodes: [], edges: [],
                                      warnings: ["No variable was selected."],
                                      startFileSource: "", startFileExt: "")
        }
        guard let file = files[stdURL] else {
            return VariableFlowResult(variableName: variableName, startFunction: "",
                                      nodes: [], edges: [],
                                      warnings: ["No analyzable source found for \(fileURL.lastPathComponent)."],
                                      startFileSource: "", startFileExt: "")
        }
        guard let enclosing = Self.enclosingFunction(containing: charIndex, in: file.funcs) else {
            return VariableFlowResult(variableName: variableName, startFunction: "",
                                      nodes: [], edges: [],
                                      warnings: ["Could not locate the function enclosing the highlighted variable."],
                                      startFileSource: file.source,
                                      startFileExt: stdURL.pathExtension)
        }

        nodeIDCounter = 0
        nodesBuffer.removeAll()
        edgesBuffer.removeAll()
        warningSet.removeAll()

        if let rootID = traceFrame(file: file,
                                   currentFunc: enclosing,
                                   searchName: variableName,
                                   depth: 0,
                                   path: [],
                                   parentID: nil,
                                   parentCallLine: nil,
                                   warnings: &warnings) {
            _ = rootID
            return VariableFlowResult(variableName: variableName,
                                      startFunction: enclosing.name,
                                      nodes: nodesBuffer,
                                      edges: edgesBuffer,
                                      warnings: warnings + warningSet.sorted(),
                                      startFileSource: file.source,
                                      startFileExt: stdURL.pathExtension)
        }
        return VariableFlowResult(variableName: variableName, startFunction: "",
                                  nodes: [], edges: [], warnings: warnings,
                                  startFileSource: file.source,
                                  startFileExt: stdURL.pathExtension)
    }

    /// Recursively collects the uses of `searchName` inside `currentFunc` and
    /// follows any call site where it is passed to a project-defined function.
    /// Returns the created node id (nil when a frame was not expanded).
    private func traceFrame(file: FileInfo,
                            currentFunc: ProjectFunc,
                            searchName: String,
                            depth: Int,
                            path: Set<String>,
                            parentID: String?,
                            parentCallLine: Int?,
                            warnings: inout [String]) -> String? {
        guard depth <= Self.maxDepth else {
            warningSet.insert("Stopped following calls beyond depth \(Self.maxDepth).")
            return nil
        }
        guard nodesBuffer.count < Self.maxNodes else {
            warningSet.insert("Stopped expanding: the diagram reached \(Self.maxNodes) nodes.")
            return nil
        }

        let frameKey = "\(currentFunc.fileURL.lastPathComponent)#\(currentFunc.name)"
        if path.contains(frameKey) {
            warningSet.insert("Stopped at a recursive/cyclic call into '\(currentFunc.name)'.")
            return nil
        }

        let id = nextID()
        let myPath = path.union([frameKey])
        let bodyTokens = Self.tokens(in: currentFunc.bodyRange, from: file.tokens)
        let excludeRegion = NSRange(location: currentFunc.nameOffset,
                                    length: max(0, currentFunc.paramCloseOffset - currentFunc.nameOffset))

        var lines: [Int] = []
        var passes: [Pass] = []
        var i = 0
        while i < bodyTokens.count {
            let tok = bodyTokens[i]
            if tok.kind == .identifier {
                if tok.text == searchName, !NSLocationInRange(tok.offset, excludeRegion) {
                    lines.append(tok.line)
                }
                // Identifier followed by '(' whose name resolves to a project
                // function: check whether the traced identifier is an argument.
                // The signature region (name .. ')' of the param list) is
                // excluded too — otherwise a function's own declaration line
                // (`def run(user):`) would be treated as a self-call and every
                // frame would spuriously report a recursive/cyclic call.
                if i + 1 < bodyTokens.count, bodyTokens[i + 1].text == "(",
                   !NSLocationInRange(tok.offset, excludeRegion),
                   index[tok.text] != nil {
                    if let argIdx = Self.argumentIndexContaining(searchName,
                                                                 tokens: bodyTokens,
                                                                 callOpen: i + 1) {
                        let isMemberCall = i > 0 && bodyTokens[i - 1].text == "."
                        passes.append(Pass(calleeName: tok.text, argIndex: argIdx,
                                           line: tok.line, isMemberCall: isMemberCall))
                    }
                }
            }
            i += 1
        }

        let node = VariableFlowNode(id: id,
                                    functionName: currentFunc.name,
                                    variableName: searchName,
                                    fileURL: currentFunc.fileURL,
                                    fileHint: fileHint(for: currentFunc.fileURL),
                                    depth: depth,
                                    lines: Array(Set(lines)).sorted(),
                                    useText: Array(Set(lines)).sorted()
                                        .map { Self.sourceText(line: $0, in: file.source) },
                                    isStart: parentID == nil)
        nodesBuffer.append(node)

        for pass in passes {
            guard let callee = resolveCallee(named: pass.calleeName, preferred: currentFunc.fileURL) else { continue }
            // A member call into a method with an explicit receiver parameter
            // (`self`/`cls`) omits that receiver at the call site, so the
            // explicit argument index is one lower than the declared parameter.
            let receiverShift = (pass.isMemberCall && callee.paramNames.first.map(Self.isReceiverName) == true) ? 1 : 0
            let effectiveIndex = pass.argIndex + receiverShift
            let paramName = callee.paramNames.indices.contains(effectiveIndex)
                ? callee.paramNames[effectiveIndex] : ""
            guard !paramName.isEmpty else { continue }
            guard let childFile = files[callee.fileURL] else { continue }
            if let childID = traceFrame(file: childFile,
                                        currentFunc: callee,
                                        searchName: paramName,
                                        depth: depth + 1,
                                        path: myPath,
                                        parentID: id,
                                        parentCallLine: pass.line,
                                        warnings: &warnings) {
                edgesBuffer.append(VariableFlowEdge(from: id, to: childID, callLine: pass.line))
            }
        }
        return id
    }

    private func nextID() -> String {
        nodeIDCounter += 1
        return "n\(nodeIDCounter)"
    }

    private func resolveCallee(named name: String, preferred: URL) -> ProjectFunc? {
        guard let list = index[name], !list.isEmpty else { return nil }
        if let sameFile = list.first(where: { $0.fileURL == preferred.standardizedFileURL }) {
            return sameFile
        }
        return list[0]
    }

    private func fileHint(for url: URL) -> String {
        let path = url.path
        let rootPrefix = projectRoot.path + "/"
        if path.hasPrefix(rootPrefix) {
            return String(path.dropFirst(rootPrefix.count))
        }
        return url.lastPathComponent
    }

    // MARK: - Enclosing function

    /// The innermost function whose body rectangle contains `charIndex`.
    private static func enclosingFunction(containing charIndex: Int, in funcs: [ProjectFunc]) -> ProjectFunc? {
        var best: ProjectFunc?
        var bestLen = Int.max
        for f in funcs {
            let r = f.enclosingRange
            guard r.location != NSNotFound, r.length > 0 else { continue }
            if charIndex >= r.location, charIndex < r.location + r.length, r.length < bestLen {
                best = f
                bestLen = r.length
            }
        }
        return best
    }

    // MARK: - Signature / parameter scanning

    /// Extracts positional parameter names for the function whose name token is
    /// at `nameOffset`, plus the end offset of its parameter list.
    private static func scanParams(tokens: [CAstToken],
                                   nameOffset: Int,
                                   lang: DiagramLanguage) -> ([String], Int)? {
        guard let nameIdx = tokens.firstIndex(where: { $0.offset == nameOffset }) else { return nil }
        let n = tokens.count
        var i = nameIdx + 1
        // Skip a generic clause between the name and the parameter list:
        // Swift/Rust/C# `<T: X>`, Go `[T any]`.
        while i < n {
            if tokens[i].text == "<", let close = matchingAngleClose(tokens, i) {
                i = close + 1
                continue
            }
            if lang == .go, tokens[i].text == "[", let close = matchingBracketClose(tokens, i) {
                i = close + 1
                continue
            }
            break
        }
        let nameEnd = tokens[nameIdx].offset + tokens[nameIdx].text.utf16.count

        guard i < n, tokens[i].text == "(" else { return ([], nameEnd) }
        let open = i
        guard let close = matchingParenClose(tokens, open) else { return ([], nameEnd) }

        let slices = argumentSlices(tokens, open: open, close: close)
        let names = slices.map { paramName(for: $0, lang: lang) }
        let closeEnd = tokens[close].offset + tokens[close].text.utf16.count
        return (names, closeEnd)
    }

    /// Heuristic parameter name for one top-level signature group (e.g. the
    /// `int x` inside `foo(int x, char c)`), per language conventions.
    private static func paramName(for group: [CAstToken], lang: DiagramLanguage) -> String {
        let top = topLevelTokens(group)
        let topIdentsNonKw = top.filter { $0.kind == .identifier }

        switch lang {
        case .go:
            // Go: `name type` -> the first identifier is the parameter.
            return topIdentsNonKw.first?.text ?? ""

        case .php:
            // PHP: `type $name` / `$name`; the `$` token precedes the name.
            for (idx, t) in group.enumerated()
                where t.text == "$" && idx + 1 < group.count && group[idx + 1].kind == .identifier {
                return group[idx + 1].text
            }
            return topIdentsNonKw.last?.text ?? ""

        case .kotlin, .rust, .swift:
            // `label name: Type` -> identifier just before the first top-level ':'.
            if let ci = top.firstIndex(where: { $0.text == ":" }),
               let b = top.prefix(ci).filter({ $0.kind == .identifier }).last {
                return b.text
            }
            return topIdentsNonKw.last?.text ?? ""

        case .python, .ruby:
            if let ci = top.firstIndex(where: { $0.text == ":" }),
               let b = top.prefix(ci).filter({ $0.kind == .identifier }).last {
                return b.text
            }
            if let e = top.firstIndex(where: { $0.text == "=" }),
               let b = top.prefix(e).filter({ $0.kind == .identifier }).last {
                return b.text
            }
            return topIdentsNonKw.last?.text ?? ""

        default:
            // c / objc / java / csharp / solidity / javascript: `Type name`,
            // may carry a default (`int x = 5`) -> identifier before '=', else
            // the last non-keyword identifier.
            if let e = top.firstIndex(where: { $0.text == "=" }),
               let b = top.prefix(e).filter({ $0.kind == .identifier }).last {
                return b.text
            }
            return topIdentsNonKw.last?.text ?? ""
        }
    }

    /// Tokens of a signature group that sit at paren/bracket/angle depth 0.
    private static func topLevelTokens(_ group: [CAstToken]) -> [CAstToken] {
        var out: [CAstToken] = []
        var depth = 0
        for t in group {
            switch t.text {
            case "(", "[", "{", "<", "<<":
                depth += (t.text == "<<" ? 2 : 1)
            case ")", "]", "}", ">", ">>":
                depth = max(0, depth - (t.text == ">>" ? 2 : 1))
            default:
                if depth == 0 { out.append(t) }
            }
        }
        return out
    }

    // MARK: - Call-site argument mapping

    /// True for the implicit receiver parameter names used by Python methods.
    private static func isReceiverName(_ name: String) -> Bool {
        name == "self" || name == "cls"
    }

    /// The 0-based index of the first top-level argument whose tokens include a
    /// token whose text equals `name`. The callee `(` is at `callOpen`.
    private static func argumentIndexContaining(_ name: String,
                                                tokens: [CAstToken],
                                                callOpen: Int) -> Int? {
        guard let close = matchingParenClose(tokens, callOpen) else { return nil }
        let slices = argumentSlices(tokens, open: callOpen, close: close)
        for (idx, slice) in slices.enumerated()
            where slice.contains(where: { $0.text == name }) {
            return idx
        }
        return nil
    }

    /// Splits the token range between `open` and `close` into top-level
    /// comma-separated argument groups.
    private static func argumentSlices(_ tokens: [CAstToken], open: Int, close: Int) -> [[CAstToken]] {
        var slices: [[CAstToken]] = []
        var current: [CAstToken] = []
        var depth = 0
        var i = open + 1
        while i < close {
            let t = tokens[i]
            switch t.text {
            case "(", "[", "{", "<", "<<":
                depth += (t.text == "<<" ? 2 : 1)
                current.append(t)
            case ")", "]", "}", ">", ">>":
                depth = max(0, depth - (t.text == ">>" ? 2 : 1))
                current.append(t)
            case ",":
                if depth == 0 {
                    slices.append(current)
                    current = []
                } else {
                    current.append(t)
                }
            default:
                current.append(t)
            }
            i += 1
        }
        if !current.isEmpty { slices.append(current) }
        return slices
    }

    private static func matchingParenClose(_ tokens: [CAstToken], _ open: Int) -> Int? {
        var depth = 0
        var i = open
        while i < tokens.count {
            if tokens[i].text == "(" { depth += 1 }
            else if tokens[i].text == ")" {
                depth -= 1
                if depth == 0 { return i }
            }
            i += 1
        }
        return nil
    }

    private static func matchingAngleClose(_ tokens: [CAstToken], _ open: Int) -> Int? {
        var depth = 0
        var i = open
        while i < tokens.count {
            let tx = tokens[i].text
            if tx == "<" || tx == "<<" { depth += (tx == "<<" ? 2 : 1) }
            else if tx == ">" || tx == ">>" {
                depth -= (tx == ">>" ? 2 : 1)
                if depth <= 0 { return i }
            }
            i += 1
        }
        return nil
    }

    private static func matchingBracketClose(_ tokens: [CAstToken], _ open: Int) -> Int? {
        var depth = 0
        var i = open
        while i < tokens.count {
            if tokens[i].text == "[" { depth += 1 }
            else if tokens[i].text == "]" {
                depth -= 1
                if depth == 0 { return i }
            }
            i += 1
        }
        return nil
    }

    // MARK: - Token filtering

    private static func tokens(in range: NSRange, from tokens: [CAstToken]) -> [CAstToken] {
        let lo = range.location
        let hi = range.location + range.length
        guard hi > lo else { return [] }
        return tokens.filter { $0.offset >= lo && $0.offset < hi && $0.kind != .eof }
    }

    private static func substring(_ s: String, _ r: NSRange) -> String? {
        guard r.location != NSNotFound, r.location >= 0 else { return nil }
        let ns = s as NSString
        guard r.location + r.length <= ns.length else { return nil }
        return ns.substring(with: r)
    }

    /// The trimmed text of the 1-based source line `line` in `source`.
    private static func sourceText(line: Int, in source: String) -> String {
        let ns = source as NSString
        var lineStart = 0
        var current = 1
        while current < line, lineStart < ns.length {
            lineStart = NSMaxRange(ns.lineRange(for: NSRange(location: lineStart, length: 0)))
            current += 1
        }
        let r = ns.lineRange(for: NSRange(location: min(lineStart, ns.length), length: 0))
        return ns.substring(with: r).trimmingCharacters(in: .newlines)
    }

    // MARK: - Callout tree (refined diagram)

    /// Rebuilds the nested callee-box tree for a trace. The start frame is the
    /// root; each callout is one frame the value was passed into, listing the
    /// callee lines where its mapped parameter is used.
    static func calloutTree(from result: VariableFlowResult) -> [VariableFlowCallout] {
        let byID = Dictionary(result.nodes.map { ($0.id, $0) }) { a, _ in a }
        var childrenMap: [String: [(callLine: Int, node: VariableFlowNode)]] = [:]
        for e in result.edges {
            guard let child = byID[e.to] else { continue }
            childrenMap[e.from, default: []].append((callLine: e.callLine, node: child))
        }
        func build(_ node: VariableFlowNode, callLine: Int) -> VariableFlowCallout {
            let uses = zip(node.lines, node.useText).map { (line: $0, text: $1) }
            let kids = (childrenMap[node.id] ?? [])
                .sorted { $0.callLine < $1.callLine }
                .map { build($0.node, callLine: $0.callLine) }
            return VariableFlowCallout(callLine: callLine,
                                       functionName: node.functionName,
                                       variableName: node.variableName,
                                       fileURL: node.fileURL,
                                       fileHint: node.fileHint,
                                       useLines: uses,
                                       children: kids)
        }
        return result.nodes.filter { $0.isStart }.map { build($0, callLine: 0) }
    }
}
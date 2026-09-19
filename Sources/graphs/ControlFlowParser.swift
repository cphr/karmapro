// by cipher.org.uk
import Foundation

/// Parses a single C/C++ function body into a control-flow structure: the
/// cyclomatic complexity plus a flowchart made of statement/decision nodes
/// and the edges connecting them.
///
/// The flowchart is a *structured* control-flow graph.
final class ControlFlowParser {

    // MARK: - Flow graph model

    final class Node {
        enum Kind: Equatable {
            case entry
            case exit
            case block(String)      // sequential statements
            case decision(String)   // if / while / for condition
            case switchCase(String) // a case/default arm
            case join               // branch merge point / loop exit
        }
        let id: Int
        var kind: Kind
        /// UTF-16 offset of the statement's first token **within the analyzed body
        /// substring** (nil for entry/exit/join/empty). Use it to map a flowchart
        /// node back to a source line in the owning file.
        var loc: Int?
        /// 1-based source line in the owning file, resolved during `analyze`.
        /// Unlike `line(forOffset:…)` this is populated for indentation dialects
        /// (Python/Ruby) too, by way of the normalization line map.
        var sourceLine: Int?
        init(id: Int, kind: Kind, loc: Int? = nil) {
            self.id = id
            self.kind = kind
            self.loc = loc
        }
    }

    struct Edge {
        let from: Int
        let to: Int
        var branch: String?   // "T" / "F" / case label / nil for plain flow
        var isBackEdge: Bool  // loop back-edge
    }

    let nodes: [Node]
    let edges: [Edge]
    let complexity: Int

    init(nodes: [Node], edges: [Edge], complexity: Int) {
        self.nodes = nodes
        self.edges = edges
        self.complexity = complexity
    }

    /// 1-based source line of a statement node recorded via `Node.loc` (the
    /// offset of its first token within the analyzed body substring), given the
    /// body's range in the owning file. Returns nil when the offset is not a
    /// reliable file position (nodes without a location, or indentation dialects
    /// whose bodies are normalized to braces before analysis).
    static func line(forOffset offset: Int?,
                     bodyRange: NSRange,
                     in source: String,
                     indentationNormalized: Bool = false) -> Int? {
        guard let offset = offset else { return nil }
        guard !indentationNormalized else { return nil }
        let ns = source as NSString
        guard offset >= 0,
              bodyRange.location != NSNotFound,
              bodyRange.location >= 0,
              bodyRange.location + offset <= ns.length else { return nil }
        let fileOffset = bodyRange.location + offset
        var newlines = 0
        for i in 0..<fileOffset where ns.character(at: i) == 0x0A { newlines += 1 }
        return newlines + 1
    }

    /// The node where execution resumes after the statement at `anchor`: for a
    /// decision/switch this is the merge (`join`) point of its branches and the
    /// node following it — so a call sitting in an `if`/loop condition rejoins
    /// after the whole construct instead of jumping into a branch body. For any
    /// other node it is the next non-back-edge successor. Nil when there is none.
    static func continuationNode(after anchor: Int,
                                 nodes: [Node],
                                 edges: [Edge]) -> Int? {
        func kindOf(_ id: Int) -> Node.Kind? { nodes.first { $0.id == id }?.kind }
        func outgoing(_ id: Int) -> [Int] {
            edges.filter { $0.from == id && !$0.isBackEdge }.map { $0.to }
        }
        guard let k = kindOf(anchor) else { return nil }
        let branching: Bool
        switch k {
        case .decision, .switchCase: branching = true
        default: branching = false
        }
        guard branching else { return outgoing(anchor).first }
        var seen = Set<Int>()
        var queue = outgoing(anchor)
        while !queue.isEmpty {
            let id = queue.removeFirst()
            if !seen.insert(id).inserted { continue }
            if kindOf(id) == .join { return outgoing(id).first }
            queue.append(contentsOf: outgoing(id))
        }
        return outgoing(anchor).first
    }

    // MARK: - Entry points

    /// Analyzes a function body using the per-language definition parser. Supports
    /// C/C++/ObjC, Java, C#, Kotlin, Go, Rust (brace bodies) and Python/Ruby (whose
    /// indentation/`end`-based bodies are normalized to braces first).
    static func analyze(source: String, ext: String, functionName: String) -> ControlFlowParser? {
        let defs = diagramDefinitions(source: source, ext: ext)
        guard let def = defs.first(where: { $0.name == functionName }) else { return nil }
        return analyze(bodySource: source, bodyRange: def.bodyRange,
                       functionName: functionName, ext: ext)
    }

    /// Analyzes the (already known) function source body text for the C-like
    /// languages. `bodySource` is the whole text of the function definition.
    static func analyze(bodySource: String, functionName: String) -> ControlFlowParser? {
        // Locate the function's body with the existing definition parser.
        let defParser = CCFunctionParser(source: bodySource)
        guard let def = defParser.parseDefinitions().first(where: { $0.name == functionName }) else {
            return nil
        }
        return analyze(bodySource: bodySource, bodyRange: def.bodyRange,
                       functionName: functionName, ext: "")
    }

    /// Core flow builder over an exact function body range. `ext` is needed only
    /// for Python/Ruby bodies, which are normalized to brace form first.
    private static func analyze(bodySource: String, bodyRange: NSRange,
                                functionName: String, ext: String) -> ControlFlowParser? {
        let ns = bodySource as NSString
        let start = bodyRange.location
        let end = start + bodyRange.length
        guard start >= 0, start < ns.length, end <= ns.length else { return nil }

        var body = ns.substring(with: bodyRange)
        let lang = DiagramLanguage.from(ext: ext)
        var normalizedLineMap: [Int]?
        if let lang = lang, lang.usesIndentation {
            guard let braced = diagramBodyToBraced(body, language: lang) else { return nil }
            body = braced.text
            normalizedLineMap = braced.lineMap
        }

        let newlineTerminators = lang?.usesNewlineTerminators == true
        let scanner = FlowTokenizer(source: body, newlinesAsStatements: newlineTerminators)
        let tokens = scanner.tokenize(in: NSRange(location: 0, length: (body as NSString).length))
        // The body contains the signature too; start parsing at the opening '{'.
        guard let bodyOpen = tokens.firstIndex(where: { $0.kind == .symbol && $0.text == "{" }) else {
            return nil
        }
        let builder = Builder(tokens: tokens, bodyOpenIndex: bodyOpen, newlineTerminators: newlineTerminators)
        let result = builder.build()
        Self.assignSourceLines(to: result.nodes,
                               body: body,
                               bodySource: bodySource,
                               bodyRange: bodyRange,
                               lineMap: normalizedLineMap)
        return ControlFlowParser(
            nodes: result.nodes,
            edges: result.edges,
            complexity: 1 + result.decisionCount + result.logicalOperatorCount
        )
    }

    /// Resolves each node's `sourceLine` while the body text and its range in the
    /// owning file are still known. For normalized (Python/Ruby) bodies the
    /// `lineMap` translates a line in the braced text back to the original line.
    private static func assignSourceLines(to nodes: [Node],
                                          body: String,
                                          bodySource: String,
                                          bodyRange: NSRange,
                                          lineMap: [Int]?) {
        let baseLine = fileLine(ofOffset: bodyRange.location, in: bodySource)
        for node in nodes {
            guard let loc = node.loc else { continue }
            let bodyLineIndex = newlinesBefore(loc, in: body)
            if let map = lineMap {
                guard bodyLineIndex >= 0, bodyLineIndex < map.count else { continue }
                node.sourceLine = baseLine + map[bodyLineIndex] - 1
            } else {
                node.sourceLine = baseLine + bodyLineIndex
            }
        }
    }

    /// 1-based line number of `offset` within `source`.
    private static func fileLine(ofOffset offset: Int, in source: String) -> Int {
        newlinesBefore(offset, in: source) + 1
    }

    /// Number of newlines preceding `offset` (the 0-based line index of `offset`).
    private static func newlinesBefore(_ offset: Int, in text: String) -> Int {
        let ns = text as NSString
        guard offset > 0 else { return 0 }
        var count = 0
        for i in 0..<min(offset, ns.length) where ns.character(at: i) == 0x0A { count += 1 }
        return count
    }
}

// MARK: - Tokenizer

/// Lightweight C/C++ tokenizer for the subset needed by the flowchart.
final class FlowTokenizer {
    struct Token {
        enum Kind: Equatable { case identifier, number, symbol, string }
        let kind: Kind
        let text: String
        let location: Int
    }

    let source: String
    let ns: NSString
    /// When true (languages whose statements are newline-terminated, e.g. Swift),
    /// line breaks are emitted as `\n` symbol tokens instead of being dropped, so
    /// the statement parser can find statement boundaries.
    let newlinesAsStatements: Bool

    init(source: String, newlinesAsStatements: Bool = false) {
        self.source = source
        self.ns = source as NSString
        self.newlinesAsStatements = newlinesAsStatements
    }

    func tokenize(in range: NSRange) -> [Token] {
        var out: [Token] = []
        var i = range.location
        let end = range.location + range.length

        while i < end {
            let c = ns.character(at: i)

            if c == 0x20 || c == 0x09 || c == 0x0A || c == 0x0D || c == 0x0B || c == 0x0C {
                if newlinesAsStatements && c == 0x0A {
                    out.append(Token(kind: .symbol, text: "\n", location: i))
                }
                i += 1; continue
            }
            // line comment
            if c == 0x2F && i + 1 < end && ns.character(at: i + 1) == 0x2F {
                while i < end && ns.character(at: i) != 0x0A { i += 1 }
                continue
            }
            // block comment
            if c == 0x2F && i + 1 < end && ns.character(at: i + 1) == 0x2A {
                i += 2
                while i + 1 < end && !(ns.character(at: i) == 0x2A && ns.character(at: i + 1) == 0x2F) { i += 1 }
                i += 2
                continue
            }
            // preprocessor
            if c == 0x23 {
                while i < end && ns.character(at: i) != 0x0A { i += 1 }
                continue
            }
            // string/char literal
            if c == 0x22 || c == 0x27 {
                let quote = c, startLoc = i
                i += 1
                while i < end && ns.character(at: i) != quote {
                    if ns.character(at: i) == 0x5C { i += 2 } else { i += 1 }
                }
                i += 1
                let s = ns.substring(with: NSRange(location: startLoc, length: i - startLoc))
                out.append(Token(kind: .string, text: s, location: startLoc))
                continue
            }
            // identifier
            if isIdentStart(c) {
                let startLoc = i
                while i < end && isIdent(ns.character(at: i)) { i += 1 }
                out.append(Token(kind: .identifier, text: ns.substring(with: NSRange(location: startLoc, length: i - startLoc)) as String, location: startLoc))
                continue
            }
            // number
            if c >= 0x30 && c <= 0x39 {
                let startLoc = i
                while i < end {
                    let d = ns.character(at: i)
                    if isIdent(d) { i += 1; continue }
                    if d == 0x2E {
                        // A '.' followed by another '.' starts a range operator
                        // (`..<` / `...`), not a decimal point — stop the number.
                        if i + 1 < end && ns.character(at: i + 1) == 0x2E { break }
                        i += 1; continue
                    }
                    break
                }
                out.append(Token(kind: .number, text: ns.substring(with: NSRange(location: startLoc, length: i - startLoc)) as String, location: startLoc))
                continue
            }
            // symbol
            var len = 1
            if i + 2 < end {
                let three = ns.substring(with: NSRange(location: i, length: 3)) as String
                if three == "..." || three == "..<" { len = 3 }
            }
            if len == 1 && i + 1 < end {
                let two = ns.substring(with: NSRange(location: i, length: 2)) as String
                if ["&&", "||", "==", "!=", "<=", ">=", "+=", "-=", "*=", "/=",
                    "<<", ">>", "++", "--", "->", "::"].contains(two) {
                    len = 2
                }
            }
            out.append(Token(kind: .symbol, text: ns.substring(with: NSRange(location: i, length: len)) as String, location: i))
            i += len
        }
        return out
    }

    private func isIdentStart(_ c: unichar) -> Bool {
        (c >= 0x41 && c <= 0x5A) || (c >= 0x61 && c <= 0x7A) || c == 0x5F
    }
    private func isIdent(_ c: unichar) -> Bool { isIdentStart(c) || (c >= 0x30 && c <= 0x39) }
}

// MARK: - Structured CFG builder

private final class Builder {
    private let tokens: [FlowTokenizer.Token]
    private var nodes: [ControlFlowParser.Node] = []
    private var edges: [ControlFlowParser.Edge] = []
    private(set) var decisionCount = 0
    private(set) var logicalOperatorCount = 0
    private var nextID = 0
    private var idx = 0
    private let logicalOps: Set<String> = ["&&", "||"]
    private let bodyOpenIndex: Int
    /// Newline-terminated language (Swift): `\n` tokens mark statement ends.
    private let newlineTerminators: Bool

    init(tokens: [FlowTokenizer.Token], bodyOpenIndex: Int, newlineTerminators: Bool = false) {
        self.tokens = tokens
        self.bodyOpenIndex = bodyOpenIndex
        self.newlineTerminators = newlineTerminators
    }

    typealias Fragment = (entry: Int, exit: Int)
    typealias Node = ControlFlowParser.Node
    typealias Edge = ControlFlowParser.Edge

    // MARK: building

    func build() -> (nodes: [Node], edges: [Edge], decisionCount: Int, logicalOperatorCount: Int) {
        let entry = make(.entry)
        let exit = make(.exit)
        // Start at the body's opening '{', consume it, then parse inner flow.
        idx = bodyOpenIndex
        let (s, e) = parseBlockToken()
        connect(entry, s)
        connect(e, exit)
        return (nodes, edges, decisionCount, logicalOperatorCount)
    }

    private func make(_ kind: Node.Kind, at loc: Int? = nil) -> Int {
        let id = nextID; nextID += 1
        nodes.append(Node(id: id, kind: kind, loc: loc))
        return id
    }

    /// Body-relative UTF-16 offset of the first token of the statement that
    /// starts at `tokenIdx` (nil when the token index is out of bounds).
    private func locAt(_ tokenIdx: Int) -> Int? {
        guard tokenIdx >= 0, tokenIdx < tokens.count else { return nil }
        return tokens[tokenIdx].location
    }

    private func connect(_ from: Int, _ to: Int, branch: String? = nil, back: Bool = false) {
        edges.append(Edge(from: from, to: to, branch: branch, isBackEdge: back))
        if branch == nil { countLogicalOps(between: from, to: to) }
    }

    // Count && / || that appear in a decision condition contributed by node's label.
    // Simpler: we count them during label creation via the header scanner instead.
    private func countLogicalOps(between a: Int, to b: Int) {}

    // MARK: statement parsing

    private func parseStatements() -> Fragment {
        var first: Int? = nil
        var last: Int? = nil
        while idx < tokens.count {
            // Skip empty statements and treat a '}' as the end of our scope.
            let t = tokens[idx]
            if t.kind == .symbol {
                if t.text == "}" { break }
                if t.text == ";" { idx += 1; continue }
                if newlineTerminators && t.text == "\n" { idx += 1; continue }
            }
            // A top-level 'case'/'default' starts the next switch arm -> stop.
            if t.kind == .identifier && (t.text == "case" || t.text == "default") {
                break
            }
            guard let f = parseStatement() else { break }
            if first == nil { first = f.entry }
            if let l = last { connect(l, f.entry) }
            last = f.exit
        }
        if first == nil {
            let n = make(.block("·"))
            return (n, n)
        }
        return (first!, last!)
    }

    private func parseStatement() -> Fragment? {
        // Peek past any stray '{' handled by parseBlock path; here decide by token.
        guard idx < tokens.count else { return nil }
        let t = tokens[idx]
        if t.kind == .identifier {
            switch t.text {
            case "if": return parseIf()
            case "while": return parseLoop("while")
            case "for":
                // Check for for...of / for...in
                if let nextIdx = peekNextNonWhitespace(idx + 1), nextIdx < tokens.count {
                    let nextToken = tokens[nextIdx]
                    if nextToken.kind == .identifier && (nextToken.text == "of" || nextToken.text == "in") {
                        return parseLoop("for")
                    }
                }
                return parseLoop("for")
            case "foreach": return parseLoop("foreach")
            case "switch": return parseSwitch()
            case "else": idx += 1; return parseBlockToken()
            case "try": return parseTryCatch()
            case "catch": idx += 1; return parseBlockToken()
            case "finally": idx += 1; return parseBlockToken()
            case "return", "break", "continue", "goto":
                return parseTerminator()
            case "guard":
                // Swift-only keyword: an early-exit condition. Gated on the
                // newline mode so a C/Java identifier named `guard` is untouched.
                if newlineTerminators { return parseGuard() }
                return parsePlain()
            default:
                return parsePlain()
            }
        }
        if t.kind == .symbol && t.text == "{" { return parseBlockToken() }
        return parsePlain()
    }

    private func parseTryCatch() -> Fragment {
        idx += 1 // consume "try"
        let tryBody = parseBlockToken()
        // Look for catch/finally
        while idx < tokens.count {
            let t = tokens[idx]
            if t.kind == .identifier && t.text == "catch" {
                idx += 1
                _ = parseBlockToken() // catch block
            } else if t.kind == .identifier && t.text == "finally" {
                idx += 1
                _ = parseBlockToken() // finally block
            } else {
                break
            }
        }
        return tryBody
    }

    private func peekNextNonWhitespace(_ from: Int) -> Int? {
        var i = from
        while i < tokens.count {
            if tokens[i].kind != .symbol || tokens[i].text != ";" {
                return i
            }
            i += 1
        }
        return nil
    }

    private func emptyFragment() -> Fragment {
        let n = make(.block("·"))
        return (n, n)
    }

    private func parsePlain() -> Fragment {
        // Consume tokens until a top-level ';' (or, for newline-terminated
        // languages, a top-level line break) or a '}' (nested braces handled).
        var depth = 0
        var parenDepth = 0
        let labelStart = idx
        var endIdx = idx
        while idx < tokens.count {
            let t = tokens[idx]
            if t.kind == .symbol {
                if t.text == "{" { depth += 1 }
                else if t.text == "}" {
                    if depth == 0 { break }
                    depth -= 1
                } else if t.text == "(" || t.text == "[" { parenDepth += 1 }
                else if t.text == ")" || t.text == "]" { parenDepth = max(0, parenDepth - 1) }
                else if t.text == ";" && depth == 0 {
                    idx += 1
                    endIdx = idx
                    break
                } else if newlineTerminators && t.text == "\n" {
                    if depth == 0 && parenDepth == 0 {
                        endIdx = idx
                        idx += 1
                        break
                    }
                    idx += 1
                    continue
                }
            }
            if depth == 0 && isStatementEnd(t) { break }
            idx += 1
            endIdx = idx
        }
        let label = flowLabel(from: labelStart, to: endIdx)
        if label.trimmingCharacters(in: .whitespaces).isEmpty {
            let n = make(.block("·"))
            return (n, n)
        }
        let n = make(.block(truncate(label)), at: locAt(labelStart))
        return (n, n)
    }

    /// Joins tokens [start..<end) into a statement label, dropping the newline
    /// markers (they sit inside the range but are not part of the statement text).
    private func flowLabel(from start: Int, to end: Int) -> String {
        tokens[start..<max(start, end)]
            .filter { !(newlineTerminators && $0.kind == .symbol && $0.text == "\n") }
            .map { $0.text }
            .joined(separator: " ")
    }

    private func isStatementEnd(_ t: FlowTokenizer.Token) -> Bool {
        // A '}' at depth 0 ends the covering block.
        return false
    }

    private func parseBlockToken() -> Fragment {
        // tokens[idx] == '{'
        idx += 1
        let f = parseStatements()
        if idx < tokens.count, tokens[idx].kind == .symbol, tokens[idx].text == "}" { idx += 1 }
        return f
    }

    private func parseTerminator() -> Fragment {
        // return / break / continue / goto
        let labelStart = idx
        var depth = 0
        var parenDepth = 0
        idx += 1
        var endIdx = idx
        while idx < tokens.count {
            let t = tokens[idx]
            if t.kind == .symbol {
                if t.text == "{" { depth += 1 }
                else if t.text == "}" { if depth == 0 { break }; depth -= 1 }
                else if t.text == "(" || t.text == "[" { parenDepth += 1 }
                else if t.text == ")" || t.text == "]" { parenDepth = max(0, parenDepth - 1) }
                else if t.text == ";" && depth == 0 { idx += 1; endIdx = idx; break }
                else if newlineTerminators && t.text == "\n" {
                    if depth == 0 && parenDepth == 0 {
                        endIdx = idx
                        idx += 1
                        break
                    }
                    idx += 1
                    continue
                }
            }
            idx += 1; endIdx = idx
        }
        let text = flowLabel(from: labelStart, to: endIdx)
        let n = make(.block(truncate(text)), at: locAt(labelStart))
        return (n, n)
    }

    // MARK: if / else

    private func parseIf() -> Fragment {
        let kwIdx = idx
        idx += 1 // 'if'
        let cond = eatCondition()
        decisionCount += 1
        decisionCount += logicalOpsCount(in: cond)
        let dec = make(.decision("if \(cond)"), at: locAt(kwIdx))

        guard let thenF = parseStatement() else {
            let join = make(.join)
            connect(dec, join, branch: "F")
            return (dec, join)
        }
        connect(dec, thenF.entry, branch: "T")

        var elseF: Fragment? = nil
        if newlineTerminators { skipNewlines() }
        if idx < tokens.count, tokens[idx].kind == .identifier, tokens[idx].text == "else" {
            idx += 1
            if newlineTerminators { skipNewlines() }
            if let f = parseStatement() { elseF = f }
        }

        let join = make(.join)
        connect(thenF.exit, join)
        if let ef = elseF {
            connect(dec, ef.entry, branch: "F")
            connect(ef.exit, join)
        } else {
            connect(dec, join, branch: "F")
        }
        return (dec, join)
    }

    private func parseLoop(_ kw: String) -> Fragment {
        let kwIdx = idx
        idx += 1 // while / for
        let cond = eatCondition()
        decisionCount += 1
        decisionCount += logicalOpsCount(in: cond)
        let dec = make(.decision("\(kw) \(cond)"), at: locAt(kwIdx))

        guard let bodyF = parseStatement() else {
            let join = make(.join)
            connect(dec, join, branch: "F")
            return (dec, join)
        }
        connect(dec, bodyF.entry, branch: "T")
        connect(bodyF.exit, dec, back: true)  // loop back-edge
        let join = make(.join)
        connect(dec, join, branch: "F")
        return (dec, join)
    }

    private func parseSwitch() -> Fragment {
        let kwIdx = idx
        idx += 1 // 'switch'
        // Parenthesized header (C/Java/C#) or bare header before `{` (Swift).
        let cond = eatCondition()
        let dec = make(.decision("switch \(cond)"), at: locAt(kwIdx))

        // Expect '{'.
        if idx < tokens.count, tokens[idx].kind == .symbol, tokens[idx].text == "{" {
            idx += 1
        }

        var arms: [(label: String, startIdx: Int)] = []
        var depth = 0
        var i = idx
        while i < tokens.count {
            let t = tokens[i]
            if t.kind == .symbol {
                if t.text == "{" { depth += 1 }
                else if t.text == "}" {
                    if depth == 0 { break }
                    depth -= 1
                }
            } else if t.kind == .identifier && depth == 0 && (t.text == "case" || t.text == "default") {
                arms.append((label: extractCaseLabel(from: i), startIdx: i))
            }
            i += 1
        }

        let endIdx = i // '}' index

        let join = make(.join)
        if arms.isEmpty {
            connect(dec, join, branch: "case")
            idx = min(endIdx + 1, tokens.count)
            return (dec, join)
        }

        // += number of cases (each case label is a decision point).
        let caseCount = arms.filter { labels.isCase($0.label) }.count
        decisionCount += max(caseCount, 1)
        let hasDefault = arms.contains { !labels.isCase($0.label) }

        for (n, arm) in arms.enumerated() {
            let caseNode = make(.switchCase(arm.label), at: locAt(arm.startIdx))
            connect(dec, caseNode, branch: "case \(n + 1)")
            idx = arm.startIdx
            // consume 'case'/'default' + following value/':' and then its body
            skipCaseLabel()  // consumes through the ':'
            let bodyF = parseStatements()
            connect(caseNode, bodyF.entry)
            connect(bodyF.exit, join)
        }
        if !hasDefault {
            connect(dec, join, branch: "default")
        }
        idx = min(endIdx + 1, tokens.count)
        return (dec, join)
    }

    private let labels = CaseLabelHelper()

    struct CaseLabelHelper {
        func isCase(_ l: String) -> Bool {
            l.hasPrefix("case ")
        }
    }

    private func extractCaseLabel(from startIdx: Int) -> String {
        // tokens[startIdx] is 'case' or 'default'; read until ':' or '{'
        var out: [String] = []
        var i = startIdx
        while i < tokens.count {
            let t = tokens[i]
            if t.kind == .symbol && (t.text == ":" || t.text == "{") { break }
            out.append(t.text)
            i += 1
        }
        let joined = out.joined(separator: " ")
        return joined.trimmingCharacters(in: .whitespaces)
    }

    private func skipCaseLabel() {
        // tokens[idx] is 'case'/'default'; consume until ':' or '{'.
        while idx < tokens.count {
            let t = tokens[idx]
            if t.kind == .symbol && t.text == ":" { idx += 1; break }
            if t.kind == .symbol && t.text == "{" { break }
            idx += 1
        }
        // If a block follows, parseStatements will handle it; else fall through.
    }

    // MARK: guard (Swift early exit)

    /// Parses `guard <cond> else { <exit body> }`. The condition body is the
    /// happy path; the else block is the early-exit branch.
    private func parseGuard() -> Fragment {
        let kwIdx = idx
        idx += 1 // 'guard'
        let cond = eatGuardHeader()
        if idx < tokens.count, tokens[idx].kind == .identifier, tokens[idx].text == "else" {
            idx += 1
        }
        decisionCount += 1
        decisionCount += logicalOpsCount(in: cond)
        let dec = make(.decision("guard \(cond)"), at: locAt(kwIdx))

        let join = make(.join)
        if let elseF = parseStatement() {
            connect(dec, elseF.entry, branch: "F")
            connect(elseF.exit, join)
        } else {
            connect(dec, join, branch: "F")
        }
        connect(dec, join, branch: "T")
        return (dec, join)
    }

    /// Consumes the guard condition text: tokens up to the `else` keyword at
    /// paren depth 0 (newlines inside the condition list are folded away).
    private func eatGuardHeader() -> String {
        var out: [String] = []
        var depth = 0
        while idx < tokens.count {
            let t = tokens[idx]
            if t.kind == .identifier && t.text == "else" && depth == 0 { break }
            if t.kind == .symbol {
                if t.text == "(" || t.text == "[" { depth += 1 }
                else if t.text == ")" || t.text == "]" { depth = max(0, depth - 1) }
                else if newlineTerminators && t.text == "\n" { idx += 1; continue }
                else if t.text == "{" && depth == 0 { break }
            }
            out.append(t.text)
            idx += 1
        }
        return out.joined(separator: " ")
    }

    private func skipNewlines() {
        while idx < tokens.count, newlineTerminators,
              tokens[idx].kind == .symbol, tokens[idx].text == "\n" {
            idx += 1
        }
    }

    // MARK: helpers

    private func eatBalanced(_ open: String, _ close: String) -> String {
        // Consume tokens up to and including the matching close; return inner text.
        var out: [String] = []
        var depth = 0
        var started = false
        while idx < tokens.count {
            let t = tokens[idx]
            if newlineTerminators && t.kind == .symbol && t.text == "\n" { idx += 1; continue }
            if t.text == open {
                depth += 1
                started = true
                idx += 1
                continue
            }
            if started && t.text == close {
                depth -= 1
                idx += 1
                if depth == 0 { break }
                continue
            }
            if started { out.append(t.text) }
            idx += 1
        }
        return out.joined(separator: " ")
    }

    /// Reads a condition header for `if`/`while`/`for`. When the next token is a
    /// `(`, consumes a balanced group (C/Java/C#/Kotlin style). Otherwise scans
    /// forward to the `{` that opens the body, leaving the cursor ON the `{`
    /// (Go/Rust style `if x {` and Python/Ruby-normalized headers).
    private func eatCondition() -> String {
        if idx < tokens.count, tokens[idx].kind == .symbol, tokens[idx].text == "(" {
            return eatBalanced("(", ")")
        }
        var out: [String] = []
        var depth = 0
        while idx < tokens.count {
            let t = tokens[idx]
            if t.kind == .symbol {
                if t.text == "{" && depth == 0 { break }
                if newlineTerminators && t.text == "\n" { idx += 1; continue }
                if t.text == "(" || t.text == "[" { depth += 1 }
                else if t.text == ")" || t.text == "]" {
                    depth = max(0, depth - 1)
                } else if t.text == "}" && depth == 0 {
                    break
                }
            }
            out.append(t.text)
            idx += 1
        }
        return out.joined(separator: " ")
    }

    private func logicalOpsCount(in s: String) -> Int {
        // Count '&&' and '||' occurrences in the condition text.
        let lower = s as NSString
        var count = 0
        var i = 0
        while i < lower.length - 1 {
            let two = lower.substring(with: NSRange(location: i, length: 2)) as String
            if logicalOps.contains(two) { count += 1; i += 2 } else { i += 1 }
        }
        return count
    }

    private func truncate(_ s: String, limit: Int = 48) -> String {
        if s.count <= limit { return s }
        let end = s.index(s.startIndex, offsetBy: limit)
        return String(s[..<end]) + "…"
    }
}

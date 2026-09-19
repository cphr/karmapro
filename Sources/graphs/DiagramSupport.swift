// by cipher.org.uk
import Foundation

/// Language-aware helpers shared by the source viewer's clickable function names,
/// the flowchart panel, and the dataflow diagrams. Each language resolves its
/// function/method definitions from the right parser, and Python/Ruby bodies are
/// normalized into brace + semicolon form so the existing C-like control-flow
/// builder can render their flowcharts.
enum DiagramLanguage: Equatable {
    case c, objc, java, csharp, kotlin, python, ruby, go, rust, php, solidity, javascript, swift

    static func from(ext: String) -> DiagramLanguage? {
        switch ext.lowercased() {
        case "c", "h", "cpp", "cc", "cxx", "hpp", "hxx", "hh": return .c
        case "m", "mm", "objc": return .objc
        case "java": return .java
        case "cs", "csx": return .csharp
        case "kt", "kts": return .kotlin
        case "py": return .python
        case "rb", "rake", "gemspec": return .ruby
        case "go": return .go
        case "rs": return .rust
        case "php", "phtml": return .php
        case "sol": return .solidity
        case "js", "jsx", "ts", "tsx": return .javascript
        case "swift": return .swift
        default: return nil
        }
    }

    /// True for Python/Ruby, whose bodies are indentation/`end`-based rather than
    /// brace-based, and need normalizing before the flow builder runs.
    var usesIndentation: Bool { self == .python || self == .ruby }

    /// True for languages whose statements are newline-terminated rather than
    /// `;`-terminated. The flow tokenizer emits newline markers for these so the
    /// C-like statement parser knows where each statement ends.
    var usesNewlineTerminators: Bool { self == .swift || self == .go || self == .kotlin || self == .javascript }

    var scriptKind: ScriptLanguage? {
        switch self {
        case .go: return .go
        case .kotlin: return .kotlin
        case .php: return .php
        case .python: return .python
        case .ruby: return .ruby
        case .rust: return .rust
        default: return nil
        }
    }
}

/// Resolves the defined functions/methods in `source` for the file's language,
/// as `CCFunctionParser.FunctionDef`s so all downstream consumers share one shape.
func diagramDefinitions(source: String, ext: String) -> [CCFunctionParser.FunctionDef] {
    guard let lang = DiagramLanguage.from(ext: ext) else { return [] }
    switch lang {
    case .c:
        return CCFunctionParser(source: source).parseDefinitions() + macroDefinitions(source: source)
    case .objc:
        // A Cocoa file (.m/.mm) typically mixes declared C functions with
        // ObjC methods (`-`/`+`), so both must be included. The C parser only
        // sees top-level C functions and the ObjC parser only sees `-`/`+`
        // methods, so unioning the two is non-overlapping.
        var defs = CCFunctionParser(source: source).parseDefinitions()
        defs += macroDefinitions(source: source)
        defs += ObjCMethodParser(source: source).parseDefinitions().map { def in
            CCFunctionParser.FunctionDef(name: def.name,
                                         bodyRange: def.bodyRange,
                                         signatureRange: def.signatureRange,
                                         nameRange: def.nameRange)
        }
        return defs
    case .java:
        return JParser(source: source).parseMethods().map { def in
            CCFunctionParser.FunctionDef(name: def.name,
                                         bodyRange: def.bodyRange,
                                         signatureRange: NSRange(location: def.startOffset,
                                                                  length: max(0, def.bodyOffset - def.startOffset)),
                                         nameRange: NSRange(location: def.startOffset,
                                                            length: (def.name as NSString).length))
        }
    case .csharp:
        return CSharpParser(source: source).parseMethods().map { def in
            CCFunctionParser.FunctionDef(name: def.name,
                                         bodyRange: def.bodyRange,
                                         signatureRange: NSRange(location: def.startOffset,
                                                                  length: max(0, def.bodyOffset - def.startOffset)),
                                         nameRange: NSRange(location: def.startOffset,
                                                            length: (def.name as NSString).length))
        }
    case .solidity:
        return SolidityParser(source: source).parseMethods().map { def in
            CCFunctionParser.FunctionDef(name: def.name,
                                         bodyRange: def.bodyRange,
                                         signatureRange: NSRange(location: def.startOffset,
                                                                  length: max(0, def.bodyOffset - def.startOffset)),
                                         nameRange: NSRange(location: def.startOffset,
                                                            length: (def.name as NSString).length))
        }
    case .kotlin, .php, .python, .ruby, .go, .rust:
        guard let kind = lang.scriptKind else { return [] }
        return ScriptMethodParser(language: kind, source: source).parseMethods().map { def in
            CCFunctionParser.FunctionDef(name: def.name,
                                          bodyRange: def.bodyRange,
                                          signatureRange: NSRange(location: def.startOffset,
                                                                   length: max(0, def.bodyOffset - def.startOffset)),
                                          nameRange: NSRange(location: def.nameOffset,
                                                             length: (def.name as NSString).length))
        }
    case .javascript:
        return JSParser(source: source).parseDefinitions().map { d in
            CCFunctionParser.FunctionDef(name: d.name,
                                          bodyRange: d.bodyRange,
                                          signatureRange: d.signatureRange,
                                          nameRange: d.nameRange)
        }
    case .swift:
        return SwiftParser(source: source).parseDefinitions().map { d in
            CCFunctionParser.FunctionDef(name: d.name,
                                          bodyRange: d.bodyRange,
                                          signatureRange: d.signatureRange,
                                          nameRange: d.nameRange)
        }
    }
}

/// Function-like `#define NAME(...)` macro definitions for the C family.
///
/// A function-like macro (`#define locomo_readl(addr) (*(volatile u16 *)(addr))`)
/// is called exactly like a function, so call sites must resolve to the
/// `#define` just as they do for a real function. Object-like macros
/// (`#define FOO bar`) are not call targets and are excluded — a function-like
/// macro has *no* whitespace between the name and the opening parenthesis.
func macroDefinitions(source: String) -> [CCFunctionParser.FunctionDef] {
    let ns = source as NSString
    let regex = try? NSRegularExpression(
        pattern: #"^[ \t]*#[ \t]*define[ \t]+([A-Za-z_][A-Za-z0-9_]*)\("#,
        options: [.anchorsMatchLines])
    guard let re = regex else { return [] }
    var defs: [CCFunctionParser.FunctionDef] = []
    re.enumerateMatches(in: source, options: [], range: NSRange(location: 0, length: ns.length)) { match, _, _ in
        guard let match = match, match.numberOfRanges > 1 else { return }
        let nameRange = match.range(at: 1)
        guard nameRange.location != NSNotFound, nameRange.length > 0 else { return }
        // Body extends through backslash-continued lines (end of each line
        // scanned; a trailing `\` pulls in the next line).
        var end = match.range.location
        while end < ns.length, ns.character(at: end) != 0x0A { end += 1 }
        while end > 0, ns.character(at: end - 1) == 0x5C {
            var next = min(end + 1, ns.length)
            while next < ns.length, ns.character(at: next) != 0x0A { next += 1 }
            end = next
        }
        let body = NSRange(location: match.range.location, length: end - match.range.location)
        defs.append(CCFunctionParser.FunctionDef(name: ns.substring(with: nameRange),
                                                 bodyRange: body,
                                                 signatureRange: body,
                                                 nameRange: nameRange))
    }
    return defs
}

/// Generic intra-file call/data edges: for every defined function, an identifier
/// followed by `(` inside its body that names another defined function is a call
/// (and data flows caller -> callee). Language-neutral, so it serves C, ObjC,
/// Java, C#, Kotlin, Python, Ruby, Go and Rust alike.
func diagramCallGraph(source: String, definitions: [CCFunctionParser.FunctionDef]) ->
    (calls: [(from: String, to: String)], data: [(from: String, to: String)]) {
    let ns = source as NSString
    let names = Set(definitions.map { $0.name })

    var calls: [(String, String)] = []
    var data: [(String, String)] = []

    for def in definitions {
        let body = def.bodyRange
        let start = min(max(body.location, 0), ns.length)
        let end = min(body.location + body.length, ns.length)
        var i = start
        while i < end {
            let c = ns.character(at: i)
            if isDiagramIdentStart(c) {
                let s = i
                while i < end && isDiagramIdentChar(ns.character(at: i)) { i += 1 }
                let ident = ns.substring(with: NSRange(location: s, length: i - s))
                var j = i
                while j < end && isDiagramWs(ns.character(at: j)) { j += 1 }
                if j < end && ns.character(at: j) == 0x28 && names.contains(ident) {
                    if ident != def.name {
                        calls.append((def.name, ident))
                        data.append((def.name, ident))
                    }
                    i = j + 1
                    continue
                }
            }
            i += 1
        }
    }
    return (dedupePairs(calls), dedupePairs(data))
}

private func dedupePairs(_ pairs: [(String, String)]) -> [(String, String)] {
    var seen = Set<String>()
    var result: [(String, String)] = []
    for p in pairs {
        let key = p.0 + "\u{1}" + p.1
        if seen.insert(key).inserted { result.append(p) }
    }
    return result
}

private func isDiagramIdentStart(_ c: unichar) -> Bool {
    (c >= 0x41 && c <= 0x5A) || (c >= 0x61 && c <= 0x7A) || c == 0x5F
}
private func isDiagramIdentChar(_ c: unichar) -> Bool {
    isDiagramIdentStart(c) || (c >= 0x30 && c <= 0x39)
}
private func isDiagramWs(_ c: unichar) -> Bool {
    c == 0x20 || c == 0x09 || c == 0x0A || c == 0x0D || c == 0x0B || c == 0x0C
}

// MARK: - Python / Ruby brace normalization

/// A normalized body plus the mapping needed to recover original source lines:
/// `lineMap[i]` is the 1-based line number (within the input `body`) that output
/// line `i` was derived from. Several output lines may share a source line (e.g.
/// Ruby's `} else {`), and synthetic closing braces reuse the line that follows.
struct BracedBody {
    let text: String
    let lineMap: [Int]
}

/// Normalizes an indentation-based Python/Ruby function body into C-like
/// brace + semicolon source text that `ControlFlowParser`'s builder can consume.
func diagramBodyToBraced(_ body: String, language: DiagramLanguage) -> BracedBody? {
    switch language {
    case .python: return pythonBodyToBraced(body)
    case .ruby: return rubyBodyToBraced(body)
    default:
        let count = body.components(separatedBy: "\n").count
        return BracedBody(text: body, lineMap: Array(1...max(count, 1)))
    }
}

/// Strips `#` comments (Ruby & Python) without breaking string literals.
private func stripHashComment(_ line: String) -> String {
    var inQuote: Character?
    var escaped = false
    var out = ""
    for c in line {
        if escaped {
            out.append(c); escaped = false; continue
        }
        if let q = inQuote {
            out.append(c)
            if c == "\\" { escaped = true }
            else if c == q { inQuote = nil }
            continue
        }
        if c == "\"" || c == "'" || c == "`" {
            inQuote = c; out.append(c); continue
        }
        if c == "#" { break }
        out.append(c)
    }
    return out
}

private func substLogical(_ s: String) -> String {
    var t = s.replacingOccurrences(of: " and ", with: " && ")
    t = t.replacingOccurrences(of: " or ", with: " || ")
    t = t.replacingOccurrences(of: " not ", with: " ! ")
    return t
}

// MARK: Python

private func pythonBodyToBraced(_ body: String) -> BracedBody? {
    struct L {
        let indent: Int
        let text: String
        let srcLine: Int
    }
    var lines: [L] = []
    for (rawIdx, raw) in body.components(separatedBy: "\n").enumerated() {
        let cleaned = stripHashComment(raw)
        var indent = 0
        var i = cleaned.startIndex
        while i < cleaned.endIndex {
            let c = cleaned[i]
            if c == " " { indent += 1 }
            else if c == "\t" { indent += 8 }
            else { break }
            i = cleaned.index(after: i)
        }
        let text = String(cleaned[i...]).trimmingCharacters(in: .whitespaces)
        guard !text.isEmpty else { continue }
        lines.append(L(indent: indent, text: text, srcLine: rawIdx + 1))
    }
    guard !lines.isEmpty else { return nil }

    let root = lines[0].indent
    var stack: [Int] = [root]
    var out: [String] = []
    var lineMap: [Int] = []

    func emit(_ s: String, _ srcLine: Int) {
        out.append(s)
        lineMap.append(srcLine)
    }

    func nextBodyIndent(after idx: Int, minIndent: Int) -> Int? {
        var j = idx + 1
        while j < lines.count {
            if lines[j].indent > minIndent { return lines[j].indent }
            if lines[j].indent <= minIndent { return nil }
            j += 1
        }
        return nil
    }

    for (idx, l) in lines.enumerated() {
        while stack.count > 1 && l.indent < stack.last! {
            emit("}", l.srcLine)
            stack.removeLast()
        }
        if l.text.hasSuffix(":") {
            let head = String(l.text.dropLast())
            if let ni = nextBodyIndent(after: idx, minIndent: l.indent), ni > l.indent {
                emit(pythonHeaderLine(head) + " {", l.srcLine)
                stack.append(ni)
            } else {
                emit(pythonHeaderLine(head) + ";", l.srcLine)
            }
        } else {
            emit(l.text + ";", l.srcLine)
        }
    }
    while stack.count > 1 {
        emit("}", lines.last!.srcLine)
        stack.removeLast()
    }
    return BracedBody(text: out.joined(separator: "\n"), lineMap: lineMap)
}

/// Translates the body of a Python line (its text minus the trailing ':') into a
/// C-like flow header. The caller decides whether to append ` {` or `;`.
private func pythonHeaderLine(_ line: String) -> String {
    var s = line.trimmingCharacters(in: .whitespaces)
    s = substLogical(s)

    if s == "def" || s.hasPrefix("def ") || s == "async def" || s.hasPrefix("async def ") {
        return ""
    }
    if s == "try" { return "try" }
    if s == "finally" { return "finally" }
    if s == "except" { return "catch ()" }
    if s == "else" { return "else" }
    if s.hasPrefix("elif ") { return "else if (" + String(s.dropFirst(5)) + ")" }
    if s.hasPrefix("elif\t") { return "else if (" + String(s.dropFirst(5)) + ")" }
    if s.hasPrefix("if ") { return "if (" + String(s.dropFirst(3)) + ")" }
    if s.hasPrefix("while ") { return "while (" + String(s.dropFirst(6)) + ")" }
    if s.hasPrefix("for ") { return "for (" + String(s.dropFirst(4)) + ")" }
    if s.hasPrefix("except ") { return "catch (" + String(s.dropFirst(7)) + ")" }
    if s.hasPrefix("with ") { return "with (" + String(s.dropFirst(5)) + ")" }
    if s.hasPrefix("class ") { return "class (" + String(s.dropFirst(6)) + ")" }
    if s.hasPrefix("match ") { return "switch (" + String(s.dropFirst(6)) + ")" }
    if s.hasPrefix("case ") { return "case (" + String(s.dropFirst(5)) + "):" }
    if s == "async" { return "{" }
    return s + ":"
}

// MARK: Ruby

private func rubyBodyToBraced(_ body: String) -> BracedBody? {
    struct L {
        let text: String
        let srcLine: Int
    }
    var lines: [L] = []
    for (rawIdx, raw) in body.components(separatedBy: "\n").enumerated() {
        let line = stripHashComment(raw).trimmingCharacters(in: .whitespaces)
        guard !line.isEmpty else { continue }
        lines.append(L(text: line, srcLine: rawIdx + 1))
    }
    guard !lines.isEmpty else { return nil }

    var out: [String] = []
    var lineMap: [Int] = []
    func emit(_ s: String, _ srcLine: Int) {
        out.append(s)
        lineMap.append(srcLine)
    }
    // The body range starts at the method *name* (e.g. `process(x)`), not at the
    // `def` keyword. Treat the first line as the signature of the analyzed method
    // and open its body with an explicit brace; the trailing `end` closes it.
    emit("{", lines[0].srcLine)
    for l in lines.dropFirst() {
        let line = l.text
        // A nested `def` starts a block whose own `end` closes it.
        if line.hasPrefix("def ") {
            emit("def (" + String(line.dropFirst(4)) + ") {", l.srcLine)
            continue
        }

        if line == "end" { emit("}", l.srcLine); continue }
        // Ruby's `if/elsif/else` share a single `end`, so each branch must close
        // the previous brace and open its own: `} else {`, `} else if (...) {`.
        if line == "else" { emit("} else {", l.srcLine); continue }
        if line == "begin" { emit("{", l.srcLine); continue }
        if line == "do" || line.hasPrefix("do ") { emit("{", l.srcLine); continue }

        if line.hasPrefix("elsif") { emit("} else if (" + rubyCond(String(line.dropFirst(5))) + ") {", l.srcLine); continue }
        if line.hasPrefix("if ") || line == "if" { emit("if (" + rubyCond(String(line.dropFirst(3))) + ") {", l.srcLine); continue }
        if line.hasPrefix("unless ") { emit("if (!(" + rubyCond(String(line.dropFirst(7))) + ")) {", l.srcLine); continue }
        if line.hasPrefix("while ") { emit("while (" + rubyCond(String(line.dropFirst(6))) + ") {", l.srcLine); continue }
        if line.hasPrefix("until ") { emit("while (!(" + rubyCond(String(line.dropFirst(6))) + ")) {", l.srcLine); continue }
        if line.hasPrefix("for ") { emit("for (" + rubyCond(String(line.dropFirst(4))) + ") {", l.srcLine); continue }
        if line.hasPrefix("case ") { emit("switch (" + rubyCond(String(line.dropFirst(5))) + ") {", l.srcLine); continue }
        if line.hasPrefix("when ") { emit("case (" + rubyCond(String(line.dropFirst(5))) + "):", l.srcLine); continue }

        emit(line + ";", l.srcLine)
    }
    return BracedBody(text: out.joined(separator: "\n"), lineMap: lineMap)
}

/// Extracts a Ruby condition body, dropping a trailing `then`, and normalizing
/// `and`/`or`/`not` to C-style operators.
private func rubyCond(_ body: String) -> String {
    var s = body.trimmingCharacters(in: .whitespaces)
    if s.hasSuffix(" then") { s = String(s.dropLast(5)) }
    else if s.hasSuffix("\tthen") { s = String(s.dropLast(5)) }
    return substLogical(s)
}
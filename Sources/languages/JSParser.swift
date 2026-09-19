// by cipher.org.uk
import Foundation

/// Fresh JavaScript/TypeScript frontend (replaces the previous JSFunctionParser
/// approach). A dedicated tokenizer emits template literals and regex literals
/// as single string tokens, so brace matching — and the shared `CParser` block
/// bridge used for the 3-walk AST layer — is brace-correct on real-world JS.

public struct JSDef {
    public enum Kind { case function, method, arrow }
    public let name: String
    public let nameOffset: Int
    public let kind: Kind
    public let isAsync: Bool
    public let isGenerator: Bool
    public let startOffset: Int       // `async`/`function`/receiver/LHS start
    public let params: [CAParam]
    public let bodyOpenOffset: Int    // offset of `{` for brace bodies
    public let bodyEndOffset: Int     // inclusive (closing `}` or last expr token)
    public let hasBraceBody: Bool

    public var bodyRange: NSRange {
        let start = hasBraceBody ? bodyOpenOffset : bodyOpenOffset
        return NSRange(location: start, length: max(0, bodyEndOffset - start + 1))
    }
    public var signatureRange: NSRange {
        let end = max(startOffset, bodyOpenOffset)
        return NSRange(location: startOffset, length: max(0, end - startOffset))
    }
    public var nameRange: NSRange {
        NSRange(location: nameOffset, length: (name as NSString).length)
    }
}

/// JS keywords beyond the C/Java set in `CAstToken.classify`.
let jsKeywords: Set<String> = [
    "function", "const", "let", "var", "async", "await", "yield", "of", "export",
    "import", "from", "as", "typeof", "undefined", "null", "true", "false",
    "get", "set", "static", "constructor", "extends", "super", "this", "new",
    "delete", "void", "in", "instanceof", "class", "default", "debugger",
    "with", "arguments", "eval"
]

/// C/C++/Java-only keywords that are ordinary identifiers in JavaScript.
/// `CAstToken.classify` marks them `.keyword`, which would break parameter
/// extraction and taint seeding for names like `template` or `boolean`.
let cOnlyKeywords: Set<String> = [
    "int", "char", "short", "long", "float", "double", "signed", "unsigned",
    "bool", "struct", "union", "enum", "typename", "volatile", "extern",
    "register", "auto", "inline", "typedef", "constexpr", "restrict",
    "mutable", "explicit", "virtual", "override", "final", "friend",
    "namespace", "using", "template", "operator", "sizeof", "nullptr",
    "NULL", "alignas", "alignof", "decltype", "static_assert", "thread_local",
    "noexcept", "wchar_t", "char16_t", "char32_t", "package", "interface",
    "implements", "abstract", "synchronized", "transient", "throws",
    "assert", "strictfp", "native", "boolean", "byte", "goto", "and", "or", "not"
]

let jsMultiCharOperators: Set<String> = [
    ">>>=", "===", "!==", "**=", "<<=", ">>=", "&&=", "||=", "??=",
    "...", "=>", "==", "!=", "<=", ">=", "&&", "||", "??", "?.", "++", "--",
    "+=", "-=", "*=", "/=", "%=", "&=", "|=", "^=", "**", "<<", ">>", ">>>",
    "->"
]

public final class JSTokenizer {
    private let source: String
    private let ns: NSString
    private let length: Int
    private var line = 1
    private var column = 1

    public init(source: String) {
        self.source = source
        self.ns = source as NSString
        self.length = ns.length
    }

    /// Tokenizes JS source into `CAstToken`s. Template literals, regex
    /// literals and strings become single `.string` tokens.
    public func tokenize() -> [CAstToken] {
        var tokens: [CAstToken] = []
        var prevSignificant: CAstToken? = nil
        var i = 0

        func emit(_ kind: CAstToken.Kind, _ text: String, _ offset: Int) {
            tokens.append(CAstToken(kind: kind, text: text, line: line, column: column, offset: offset))
        }

        func advance(_ count: Int) {
            let end = min(i + count, length)
            while i < end {
                if ns.character(at: i) == 0x0A { line += 1; column = 1 } else { column += 1 }
                i += 1
            }
        }

        while i < length {
            let ch = ns.character(at: i)

            // Whitespace
            if ch == 0x20 || ch == 0x09 || ch == 0x0D { advance(1); continue }
            if ch == 0x0A { advance(1); continue }

            // Comments
            if ch == 0x2F && i + 1 < length {
                let next = ns.character(at: i + 1)
                if next == 0x2F {
                    var j = i
                    while j < length && ns.character(at: j) != 0x0A { j += 1 }
                    advance(j - i)
                    continue
                }
                if next == 0x2A {
                    var j = i + 2
                    while j + 1 < length && !(ns.character(at: j) == 0x2A && ns.character(at: j + 1) == 0x2F) {
                        if ns.character(at: j) == 0x0A { line += 1; column = 1 } else { column += 1 }
                        j += 1
                    }
                    advance(min(j + 2, length) - i)
                    continue
                }
                // Regex vs division: a `/` after a value-ending token is division.
                if let p = prevSignificant {
                    let valueEnding = p.kind == .identifier || p.kind == .number || p.kind == .string
                        || p.text == ")" || p.text == "]" || p.text == "++" || p.text == "--"
                    if valueEnding {
                        emit(.operator, "/", i); advance(1)
                        prevSignificant = tokens.last
                        continue
                    }
                }
                // Regex literal
                let start = i
                var j = i + 1
                var inClass = false
                while j < length {
                    let c = ns.character(at: j)
                    if c == 0x5C { j += 2; continue }
                    if c == 0x0A { break }
                    if c == 0x5B { inClass = true }
                    else if c == 0x5D { inClass = false }
                    else if c == 0x2F && !inClass { j += 1; break }
                    j += 1
                }
                while j < length, isIdentChar(ns.character(at: j)) { j += 1 } // flags
                let text = ns.substring(with: NSRange(location: start, length: min(j, length) - start))
                advance(j - start)
                emit(.string, text, start)
                prevSignificant = tokens.last
                continue
            }

            // Strings & template literals (single token, incl. ${...} nesting)
            if ch == 0x22 || ch == 0x27 || ch == 0x60 {
                let start = i
                let j = scanString(from: i)
                let text = ns.substring(with: NSRange(location: start, length: min(j, length) - start))
                advance(j - start)
                emit(.string, text, start)
                prevSignificant = tokens.last
                continue
            }

            // Numbers
            if isDigit(ch) || (ch == 0x2E && i + 1 < length && isDigit(ns.character(at: i + 1))) {
                let start = i
                var j = i
                if ch == 0x30 && j + 1 < length {
                    let nch = ns.character(at: j + 1)
                    if nch == 0x78 || nch == 0x58 || nch == 0x62 || nch == 0x42 || nch == 0x6F || nch == 0x4F {
                        j += 2
                        while j < length && isIdentChar(ns.character(at: j)) { j += 1 }
                    }
                }
                if j == start {
                    while j < length {
                        let c = ns.character(at: j)
                        if isDigit(c) || c == 0x5F { j += 1; continue }
                        if c == 0x2E && j + 1 < length && isDigit(ns.character(at: j + 1)) { j += 1; continue }
                        break
                    }
                    if j < length && (ns.character(at: j) == 0x65 || ns.character(at: j) == 0x45) {
                        var k = j + 1
                        if k < length && (ns.character(at: k) == 0x2B || ns.character(at: k) == 0x2D) { k += 1 }
                        if k < length && isDigit(ns.character(at: k)) {
                            j = k
                            while j < length && isDigit(ns.character(at: j)) { j += 1 }
                        }
                    }
                }
                if j < length && ns.character(at: j) == 0x6E { j += 1 } // bigint
                let text = ns.substring(with: NSRange(location: start, length: j - start))
                advance(j - start)
                emit(.number, text, start)
                prevSignificant = tokens.last
                continue
            }

            // Identifiers / keywords
            if isIdentStart(ch) || ch >= 0x80 {
                let start = i
                var j = i
                while j < length && (isIdentChar(ns.character(at: j)) || ns.character(at: j) >= 0x80) { j += 1 }
                let text = ns.substring(with: NSRange(location: start, length: j - start))
                advance(j - start)
                let kind: CAstToken.Kind
                if jsKeywords.contains(text) {
                    kind = .keyword
                } else if cOnlyKeywords.contains(text) {
                    kind = .identifier
                } else {
                    kind = CAstToken.classify(text)
                }
                emit(kind, text, start)
                prevSignificant = tokens.last
                continue
            }

            // Multi-char operators (longest match first)
            var matched: String? = nil
            for l in stride(from: 4, through: 2, by: -1) where i + l <= length {
                let s = ns.substring(with: NSRange(location: i, length: l))
                if jsMultiCharOperators.contains(s) { matched = s; break }
            }
            if let op = matched {
                emit(.operator, op, i)
                advance((op as NSString).length)
                prevSignificant = tokens.last
                continue
            }

            // Punctuation vs single-char operators. Comparison/assignment/
            // arithmetic characters must be `.operator` so the expression
            // parser's precedence engine recognizes them; grouping and
            // terminator characters stay `.punct`.
            let single = String(Character(UnicodeScalar(ch)!))
            let operatorChars = Set("<>+-*/%&|^!~?:=")
            if operatorChars.contains(Character(UnicodeScalar(ch)!)) {
                emit(.operator, single, i)
            } else {
                emit(.punct, single, i)
            }
            advance(1)
            prevSignificant = tokens.last
        }
        tokens.append(CAstToken(kind: .eof, text: "", line: line, column: column, offset: length))
        return tokens
    }

    /// Scans a `'...'` / `"..."` / `` `...` `` literal as one unit, handling
    /// escapes and nested `${ ... }` template interpolation.
    private func scanString(from start: Int) -> Int {
        let quote = ns.character(at: start)
        var i = start + 1
        while i < length {
            let c = ns.character(at: i)
            if c == 0x5C { i += 2; continue }
            if quote != 0x60 {
                if c == quote { return min(i + 1, length) }
                if c == 0x0A { return min(i, length) }
                i += 1
                continue
            }
            if c == quote { return min(i + 1, length) }
            if c == 0x24 && i + 1 < length && ns.character(at: i + 1) == 0x7B {
                i = scanInterpolation(from: i + 2)
                continue
            }
            i += 1
        }
        return min(i, length)
    }

    /// Scans a `${ ... }` interpolation body, honoring nested braces, strings
    /// and nested templates.
    private func scanInterpolation(from start: Int) -> Int {
        var depth = 1
        var i = start
        while i < length && depth > 0 {
            let c = ns.character(at: i)
            if c == 0x5C { i += 2; continue }
            if c == 0x22 || c == 0x27 || c == 0x60 {
                i = scanString(from: i)
                continue
            }
            if c == 0x7B { depth += 1 }
            else if c == 0x7D {
                depth -= 1
                if depth == 0 { return min(i + 1, length) }
            }
            i += 1
        }
        return min(i, length)
    }

    private func isDigit(_ c: unichar) -> Bool { c >= 0x30 && c <= 0x39 }
    private func isIdentStart(_ c: unichar) -> Bool {
        (c >= 0x41 && c <= 0x5A) || (c >= 0x61 && c <= 0x7A) || c == 0x5F || c == 0x24
    }
    private func isIdentChar(_ c: unichar) -> Bool {
        isIdentStart(c) || isDigit(c)
    }
}

/// Extracts named function/method/arrow definitions with exact body ranges.
public final class JSParser {

    /// Arrow `=>` tokens already consumed by `NAME =` / `NAME:` / class-method
    /// parsing, so the anonymous-callback pass does not re-derive them.
    private var consumedArrowOffsets = Set<Int>()

    private enum ScopeKind { case block, object, klass }
    private struct Scope {
        let kind: ScopeKind
        let closer: String
        let openIndex: Int
    }

    private let source: String
    private let ns: NSString
    private let tokens: [CAstToken]

    public init(source: String, tokens: [CAstToken]? = nil) {
        self.source = source
        self.ns = source as NSString
        self.tokens = tokens ?? JSTokenizer(source: source).tokenize()
    }

    public func allTokens() -> [CAstToken] { tokens }

    // MARK: - Definition extraction

    public func parseDefinitions() -> [JSDef] {
        var defs: [JSDef] = []
        var scopes: [Scope] = []
        var pendingClass = false
        var seen = Set<String>()
        let n = tokens.count
        var i = 0

        func record(_ def: JSDef) {
            let key = "\(def.name)\u{1}\(def.startOffset)"
            if seen.insert(key).inserted { defs.append(def) }
        }

        while i < n {
            let t = tokens[i]
            if t.kind == .eof { break }

            if t.text == "(" {
                // Method shorthand inside class bodies / object literals.
                if let def = parseMethodCall(parenIndex: i, scopes: scopes) {
                    record(def)
                    // Resume inside the body so nested definitions are found.
                    i = bodyOpenTokenIndex(of: def) ?? (i + 1)
                    continue
                }
                scopes.append(Scope(kind: .block, closer: ")", openIndex: i))
                i += 1
                continue
            }
            if t.text == "[" {
                scopes.append(Scope(kind: .block, closer: "]", openIndex: i))
                i += 1
                continue
            }
            if t.text == "{" {
                let kind = classifyBrace(at: i, pendingClass: pendingClass)
                pendingClass = false
                scopes.append(Scope(kind: kind, closer: "}", openIndex: i))
                i += 1
                continue
            }
            if t.text == "}" {
                if !scopes.isEmpty { scopes.removeLast() }
                i += 1
                continue
            }
            if t.kind == .keyword && t.text == "class" {
                pendingClass = true
                i += 1
                continue
            }

            // Named function declaration: [async] function [*] name ( ... ) { }
            if t.text == "function" {
                if let def = parseFunctionDecl(from: i) {
                    record(def)
                    i = bodyOpenTokenIndex(of: def) ?? (i + 1)
                    continue
                }
                i += 1
                continue
            }

            // NAME = <arrow|function-expr>, NAME: <arrow|function-expr> in objects
            if t.kind == .identifier || t.kind == .keyword {
                if i + 1 < n, tokens[i + 1].text == "=" {
                    if let def = parseAssignedFunction(name: t.text, nameOffset: t.offset, eqIndex: i + 1) {
                        record(def)
                        i = bodyOpenTokenIndex(of: def) ?? (i + 1)
                        continue
                    }
                }
                if let def = parsePropertyArrow(at: i, scopes: scopes) {
                    record(def)
                    i = bodyOpenTokenIndex(of: def) ?? (i + 1)
                    continue
                }
            }

            // Anonymous arrow callback: `app.get(url, (req, res) => { … })`,
            // `arr.map(x => …)`, `(a, b) => …` passed as a call argument. These
            // have no `NAME =` binding, so the def must be synthesized here or
            // sinks inside the body stay invisible to the security analysis.
            // (Arrows already claimed by `parseAssignedFunction`/`parsePropertyArrow`
            // are recorded in `consumedArrowOffsets` and skipped.)
            if t.text == "=>", !consumedArrowOffsets.contains(t.offset) {
                if let def = parseCallbackArrow(at: i) {
                    record(def)
                    i = bodyOpenTokenIndex(of: def) ?? (i + 1)
                    continue
                }
            }

            i += 1
        }
        return defs
    }

    /// Anonymous arrow callback used as a call argument: `(params) => body`
    /// or `param => body`, with a synthesized name derived from the enclosing
    /// call receiver. Dedup with `NAME =`/`NAME:`-bound arrows is handled by
    /// `consumedArrowOffsets` (recorded inside `parseArrowBody`).
    private func parseCallbackArrow(at arrowIdx: Int) -> JSDef? {
        guard arrowIdx > 0, arrowIdx + 1 < tokens.count, tokens[arrowIdx].text == "=>" else { return nil }

        let prev = tokens[arrowIdx - 1]
        var params: [CAParam] = []
        var isAsync = false
        var nameOffset = tokens[arrowIdx].offset
        var startOffset = tokens[arrowIdx].offset
        var sigStartIdx = arrowIdx

        if prev.text == ")" {
            // `(params) =>` — find the matching `(` that opened the param list.
            var depth = 0
            var j = arrowIdx - 1
            var openIdx: Int? = nil
            while j >= 0 {
                let t = tokens[j]
                if t.text == ")" { depth += 1 }
                else if t.text == "(" {
                    depth -= 1
                    if depth == 0 { openIdx = j; break }
                }
                j -= 1
            }
            guard let open = openIdx else { return nil }
            guard let (p, _) = parseParamList(openIndex: open) else { return nil }
            params = p
            nameOffset = tokens[open].offset
            startOffset = tokens[open].offset
            sigStartIdx = open
            if open > 0, isAsyncToken(at: open - 1) { isAsync = true }
        } else if prev.kind == .identifier || prev.kind == .keyword {
            // `param => body` (no parens).
            guard !jsKeywords.contains(prev.text) || prev.text == "this" else { return nil }
            params = [CAParam(type: nil, name: prev.text, offset: prev.offset)]
            nameOffset = prev.offset
            startOffset = prev.offset
            sigStartIdx = arrowIdx - 1
            if arrowIdx > 1, isAsyncToken(at: arrowIdx - 2) { isAsync = true }
        } else {
            return nil
        }

        let name = callbackName(before: sigStartIdx) ?? "callback"
        return parseArrowBody(name: name, nameOffset: nameOffset, params: params,
                              isAsync: isAsync, isGenerator: false,
                              startOffset: startOffset, arrowIndex: arrowIdx)
    }

    /// Derives a readable name for an anonymous callback from the enclosing
    /// call, e.g. `app.get` for `app.get('/x', (req, res) => …)` or `arr.map`
    /// for `arr.map(x => …)`. Falls back to the nearest function-ish identifier.
    private func callbackName(before sigStartIdx: Int) -> String? {
        guard sigStartIdx > 0 else { return nil }
        var j = sigStartIdx - 1
        var depth = 0
        var leaf: String? = nil
        while j >= 0 {
            let t = tokens[j]
            if t.kind == .eof { break }
            if t.text == ")" || t.text == "]" { depth += 1; j -= 1; continue }
            if t.text == "(" || t.text == "[" {
                if depth == 0 {
                    // Enclosing call open paren found; the callee chain is
                    // the identifiers directly before it.
                    j -= 1
                    break
                }
                depth -= 1
                j -= 1
                continue
            }
            if depth == 0 {
                if t.text == "," || t.text == ";" || t.text == "{" || t.text == "}" || t.text == "=" {
                    break
                }
                if t.kind == .identifier || t.kind == .keyword {
                    if !jsKeywords.contains(t.text) || t.text == "this" {
                        leaf = t.text
                        j -= 1
                        continue
                    }
                }
            }
            j -= 1
        }
        guard var name = leaf else { return nil }
        // Walk the receiver/property chain (`app.get` ← `get`, `.`, `app`).
        var parts = [name]
        while j >= 0 {
            let t = tokens[j]
            if t.text == "." { j -= 1; continue }
            if t.kind == .identifier && !jsKeywords.contains(t.text) {
                parts.append(t.text)
                j -= 1
                continue
            }
            break
        }
        name = parts.reversed().joined(separator: ".")
        return name.isEmpty ? nil : name
    }

    private func bodyOpenTokenIndex(of def: JSDef) -> Int? {
        guard def.hasBraceBody else { return nil }
        // The `{` offset equals def.bodyOpenOffset; find its token index.
        var lo = 0, hi = tokens.count - 1
        while lo <= hi {
            let mid = (lo + hi) / 2
            if tokens[mid].offset < def.bodyOpenOffset { lo = mid + 1 }
            else if tokens[mid].offset > def.bodyOpenOffset { hi = mid - 1 }
            else {
                var idx = mid
                while idx > 0, tokens[idx - 1].offset == def.bodyOpenOffset { idx -= 1 }
                return idx
            }
        }
        return nil
    }

    // MARK: - Pattern matchers

    private func parseFunctionDecl(from fi: Int) -> JSDef? {
        var i = fi + 1
        let isAsync = fi > 0 && tokens[fi - 1].kind == .identifier && tokens[fi - 1].text == "async"
        let startOffset = isAsync ? tokens[fi - 1].offset : tokens[fi].offset

        var isGenerator = false
        if i < tokens.count, tokens[i].text == "*" { isGenerator = true; i += 1 }

        guard i < tokens.count, tokens[i].kind == .identifier || (tokens[i].kind == .keyword && tokens[i].text != "(") else { return nil }
        guard !(tokens[i].kind == .keyword && tokens[i].text == "(") else { return nil }
        let name = tokens[i].text
        let nameOffset = tokens[i].offset
        i += 1
        guard i < tokens.count, tokens[i].text == "(" else { return nil }
        guard let (params, closeIdx) = parseParamList(openIndex: i) else { return nil }
        guard let k = bodyMarkerIndex(after: closeIdx), tokens[k].text == "{",
              let closeBrace = matchingBrace(openIndex: k) else { return nil }
        return JSDef(name: name,
                     nameOffset: nameOffset,
                     kind: .function,
                     isAsync: isAsync,
                     isGenerator: isGenerator,
                     startOffset: startOffset,
                     params: params,
                     bodyOpenOffset: tokens[k].offset,
                     bodyEndOffset: tokens[closeBrace].offset + tokens[closeBrace].text.count - 1,
                     hasBraceBody: true)
    }

    /// NAME = [async] (function [*] [name] (…) { } | (…) => body | ident => body)
    private func parseAssignedFunction(name: String, nameOffset: Int, eqIndex: Int) -> JSDef? {
        var i = eqIndex + 1
        var isAsync = false
        if i < tokens.count, isAsyncToken(at: i) {
            let nxt = i + 1 < tokens.count ? tokens[i + 1].text : ""
            if nxt == "function" || nxt == "(" || nxt == "*" || (i + 1 < tokens.count && tokens[i + 1].kind == .identifier) {
                isAsync = true
                i += 1
            }
        }
        let startOffset = nameOffset

        if i < tokens.count, tokens[i].text == "function" {
            return parseFunctionExpr(from: i, name: name, nameOffset: nameOffset,
                                     isAsync: isAsync, startOffset: startOffset)
        }

        if i < tokens.count, tokens[i].text == "(" {
            guard let (params, closeIdx) = parseParamList(openIndex: i) else { return nil }
            guard let k = bodyMarkerIndex(after: closeIdx), tokens[k].text == "=>" else { return nil }
            return parseArrowBody(name: name, nameOffset: nameOffset, params: params,
                                  isAsync: isAsync, isGenerator: false, startOffset: startOffset,
                                  arrowIndex: k)
        }

        if i < tokens.count, tokens[i].kind == .identifier,
           i + 1 < tokens.count, tokens[i + 1].text == "=>" {
            let params = [CAParam(type: nil, name: tokens[i].text, offset: tokens[i].offset)]
            return parseArrowBody(name: name, nameOffset: nameOffset, params: params,
                                  isAsync: isAsync, isGenerator: false, startOffset: startOffset,
                                  arrowIndex: i + 1)
        }
        return nil
    }

    /// `function [*] [name] ( ... ) { ... }` starting at the `function` token.
    private func parseFunctionExpr(from fi: Int, name: String, nameOffset: Int,
                                   isAsync: Bool, startOffset: Int) -> JSDef? {
        var i = fi + 1
        var isGenerator = false
        if i < tokens.count, tokens[i].text == "*" { isGenerator = true; i += 1 }
        if i < tokens.count, tokens[i].kind == .identifier { i += 1 } // optional inner name
        guard i < tokens.count, tokens[i].text == "(",
              let (params, closeIdx) = parseParamList(openIndex: i) else { return nil }
        guard let k = bodyMarkerIndex(after: closeIdx), tokens[k].text == "{",
              let closeBrace = matchingBrace(openIndex: k) else { return nil }
        return JSDef(name: name,
                     nameOffset: nameOffset,
                     kind: .function,
                     isAsync: isAsync,
                     isGenerator: isGenerator,
                     startOffset: startOffset,
                     params: params,
                     bodyOpenOffset: tokens[k].offset,
                     bodyEndOffset: tokens[closeBrace].offset + tokens[closeBrace].text.count - 1,
                     hasBraceBody: true)
    }

    private func parseArrowBody(name: String, nameOffset: Int, params: [CAParam],
                                isAsync: Bool, isGenerator: Bool, startOffset: Int,
                                arrowIndex: Int) -> JSDef? {
        consumedArrowOffsets.insert(tokens[arrowIndex].offset)
        let i = arrowIndex + 1
        guard i < tokens.count, tokens[i].kind != .eof else { return nil }
        if tokens[i].text == "{", let closeBrace = matchingBrace(openIndex: i) {
            return JSDef(name: name,
                         nameOffset: nameOffset,
                         kind: .arrow,
                         isAsync: isAsync,
                         isGenerator: isGenerator,
                         startOffset: startOffset,
                         params: params,
                         bodyOpenOffset: tokens[i].offset,
                         bodyEndOffset: tokens[closeBrace].offset + tokens[closeBrace].text.count - 1,
                         hasBraceBody: true)
        }
        let (endToken, _) = expressionBodyRange(from: i)
        return JSDef(name: name,
                     nameOffset: nameOffset,
                     kind: .arrow,
                     isAsync: isAsync,
                     isGenerator: isGenerator,
                     startOffset: startOffset,
                     params: params,
                     bodyOpenOffset: tokens[i].offset,
                     bodyEndOffset: tokens[endToken].offset + tokens[endToken].text.count - 1,
                     hasBraceBody: false)
    }

    private func expressionBodyRange(from start: Int) -> (Int, Int) {
        var depth = 0
        var i = start
        while i < tokens.count {
            let t = tokens[i]
            if t.kind == .eof { return (max(start, i - 1), i) }
            if t.text == "(" || t.text == "[" || t.text == "{" { depth += 1; i += 1; continue }
            if t.text == ")" || t.text == "]" || t.text == "}" {
                if depth == 0 { return (max(start, i - 1), i) }
                depth -= 1; i += 1; continue
            }
            if depth == 0 {
                if t.text == ";" || t.text == "," { return (max(start, i - 1), i) }
                if t.kind == .keyword,
                   ["const", "let", "var", "function", "class", "return", "if", "for",
                    "while", "switch", "try", "throw", "break", "continue"].contains(t.text) {
                    return (max(start, i - 1), i)
                }
            }
            i += 1
        }
        let end = max(start, tokens.count - 2)
        return (end, tokens.count - 1)
    }

    /// Method shorthand inside class bodies / object literals, invoked at the
    /// `(` token: NAME ( ... ) { }, with optional async/get/set/* prefixes.
    private func parseMethodCall(parenIndex: Int, scopes: [Scope]) -> JSDef? {
        guard let nearestBrace = scopes.last(where: { $0.closer == "}" }) else { return nil }
        guard nearestBrace.kind == .klass || nearestBrace.kind == .object else { return nil }
        guard parenIndex > 0 else { return nil }
        let prev = tokens[parenIndex - 1]
        guard prev.kind == .identifier || prev.kind == .keyword else { return nil }
        guard !methodNonNameKeywords.contains(prev.text) else { return nil }

        let name = prev.text
        let nameOffset = prev.offset
        var isAsync = false
        var isGenerator = false
        var startIdx = parenIndex - 1
        if startIdx > 0, tokens[startIdx - 1].kind == .operator, tokens[startIdx - 1].text == "*" {
            isGenerator = true
            startIdx -= 1
        }
        if startIdx > 0, tokens[startIdx - 1].kind == .identifier, tokens[startIdx - 1].text == "async" {
            isAsync = true
            startIdx -= 1
        }
        if startIdx > 0, tokens[startIdx - 1].kind == .keyword,
           ["static", "get", "set"].contains(tokens[startIdx - 1].text) {
            startIdx -= 1
            if startIdx > 0, tokens[startIdx - 1].kind == .identifier,
               tokens[startIdx - 1].text == "async" {
                isAsync = true
                startIdx -= 1
            }
        }
        let startOffset = tokens[startIdx].offset

        guard let (params, closeIdx) = parseParamList(openIndex: parenIndex) else { return nil }
        guard let k = bodyMarkerIndex(after: closeIdx), tokens[k].text == "{",
              let closeBrace = matchingBrace(openIndex: k) else { return nil }
        return JSDef(name: name,
                     nameOffset: nameOffset,
                     kind: .method,
                     isAsync: isAsync,
                     isGenerator: isGenerator,
                     startOffset: startOffset,
                     params: params,
                     bodyOpenOffset: tokens[k].offset,
                     bodyEndOffset: tokens[closeBrace].offset + tokens[closeBrace].text.count - 1,
                     hasBraceBody: true)
    }

    private let methodNonNameKeywords: Set<String> = [
        "if", "for", "while", "switch", "catch", "return", "function", "typeof",
        "new", "case", "in", "of", "await", "yield", "delete", "void", "throw",
        "else", "do", "try", "finally", "with", "super", "import", "export"
    ]

    /// Object property values: NAME: [async] (…) => body | NAME: [async] ident => body
    /// | NAME: [async] function (…) { }
    private func parsePropertyArrow(at index: Int, scopes: [Scope]) -> JSDef? {
        guard index + 1 < tokens.count, tokens[index + 1].text == ":" else { return nil }
        guard let nearestBrace = scopes.last(where: { $0.closer == "}" }),
              nearestBrace.kind == .object else { return nil }
        let name = tokens[index].text
        let nameOffset = tokens[index].offset
        var i = index + 2
        var isAsync = false
        if i < tokens.count, isAsyncToken(at: i) { isAsync = true; i += 1 }

        if i < tokens.count, tokens[i].text == "function" {
            return parseFunctionExpr(from: i, name: name, nameOffset: nameOffset,
                                     isAsync: isAsync, startOffset: nameOffset)
        }
        if i < tokens.count, tokens[i].text == "(" {
            guard let (params, closeIdx) = parseParamList(openIndex: i) else { return nil }
            guard let k = bodyMarkerIndex(after: closeIdx), tokens[k].text == "=>" else { return nil }
            return parseArrowBody(name: name, nameOffset: nameOffset, params: params,
                                  isAsync: isAsync, isGenerator: false,
                                  startOffset: nameOffset, arrowIndex: k)
        }
        if i < tokens.count, tokens[i].kind == .identifier,
           i + 1 < tokens.count, tokens[i + 1].text == "=>" {
            let params = [CAParam(type: nil, name: tokens[i].text, offset: tokens[i].offset)]
            return parseArrowBody(name: name, nameOffset: nameOffset, params: params,
                                  isAsync: isAsync, isGenerator: false,
                                  startOffset: nameOffset, arrowIndex: i + 1)
        }
        return nil
    }

    // MARK: - Shared helpers

    private func isAsyncToken(at index: Int) -> Bool {
        guard index < tokens.count else { return false }
        let t = tokens[index]
        return t.text == "async" && (t.kind == .identifier || t.kind == .keyword)
    }

    private func classifyBrace(at index: Int, pendingClass: Bool) -> ScopeKind {
        if pendingClass { return .klass }
        guard index > 0 else { return .object }
        let prev = tokens[index - 1]
        switch prev.text {
        case "=", "(", ",", "[", ":", "?", "case", "of", "in", "yield", "await":
            return .object
        default:
            return .block
        }
    }

    private func matchingBrace(openIndex: Int) -> Int? {
        var depth = 0
        var i = openIndex
        while i < tokens.count {
            let t = tokens[i]
            if t.kind == .eof { return nil }
            if t.text == "{" { depth += 1 }
            else if t.text == "}" {
                depth -= 1
                if depth == 0 { return i }
            }
            i += 1
        }
        return nil
    }

    /// Parses `( ... )` starting at `openIndex` into a parameter list,
    /// splitting on top-level commas. Destructuring groups contribute their
    /// bound identifiers; defaults/rest are reduced to the bound name.
    private func parseParamList(openIndex: Int) -> ([CAParam], Int)? {
        guard openIndex < tokens.count, tokens[openIndex].text == "(" else { return nil }
        var depth = 0
        var i = openIndex
        var groups: [[CAstToken]] = []
        var current: [CAstToken] = []
        while i < tokens.count {
            let t = tokens[i]
            if t.kind == .eof { return nil }
            if t.text == "(" || t.text == "[" || t.text == "{" {
                depth += 1
                if depth > 1 { current.append(t) }
                i += 1
                continue
            }
            if t.text == ")" || t.text == "]" || t.text == "}" {
                depth -= 1
                if depth == 0 {
                    groups.append(current)
                    return (groups.flatMap(paramNames(from:)), i)
                }
                current.append(t)
                i += 1
                continue
            }
            if t.text == "," && depth == 1 {
                groups.append(current)
                current = []
                i += 1
                continue
            }
            if depth >= 1 { current.append(t) }
            i += 1
        }
        return nil
    }

    /// TypeScript puts an optional `: ReturnType` annotation (possibly with
    /// generics like `Promise<string>[]`) between the parameter list and the
    /// body `{` / `=>`. Returning the index of the true body marker so
    /// definition extraction still works on annotated TS signatures.
    private func bodyMarkerIndex(after closeIdx: Int) -> Int? {
        var i = closeIdx + 1
        guard i < tokens.count else { return nil }
        if tokens[i].text == ":" {
            var depth = 0
            i += 1
            while i < tokens.count {
                let t = tokens[i]
                if t.kind == .eof { return nil }
                if t.text == "<" { depth += 1; i += 1; continue }
                if t.text == ">" {
                    depth = max(0, depth - 1)
                    i += 1
                    continue
                }
                if depth == 0 && (t.text == "{" || t.text == "=>") { return i }
                if depth == 0 && (t.text == "(" || t.text == "," || t.text == "=" || t.text == ";") {
                    return nil
                }
                i += 1
            }
            return nil
        }
        if tokens[i].text == "{" || tokens[i].text == "=>" { return i }
        return nil
    }

    private func paramNames(from group: [CAstToken]) -> [CAParam] {
        guard !group.isEmpty else { return [] }
        if group.count >= 2, group[0].text == "..." || group[0].text == "." {
            let idents = group.filter { $0.kind == .identifier }
            if let last = idents.last {
                return [CAParam(type: nil, name: last.text, offset: last.offset)]
            }
        }
        if group.first?.text == "{" || group.first?.text == "[" {
            let idents = group.filter { $0.kind == .identifier && !jsKeywords.contains($0.text) }
            return idents.map { CAParam(type: nil, name: $0.text, offset: $0.offset) }
        }
        if let eq = group.firstIndex(where: { $0.text == "=" }) {
            let head = group[..<eq]
            if let first = head.first(where: { $0.kind == .identifier && !jsKeywords.contains($0.text) }) {
                return [CAParam(type: nil, name: first.text, offset: first.offset)]
            }
        }
        if let first = group.first(where: { $0.kind == .identifier && !jsKeywords.contains($0.text) }) {
            return [CAParam(type: nil, name: first.text, offset: first.offset)]
        }
        return []
    }
}

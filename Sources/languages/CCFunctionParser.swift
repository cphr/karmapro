// by cipher.org.uk
import Foundation

/// A lightweight C/C++ parser that extracts function definitions and the
/// call/data relationships between them. It is a pragmatic tokenizer, not a
/// full compiler front-end: it handles common, well-formed C/C++ reasonably
/// while tolerating preprocessor lines, comments, and strings.
public final class CCFunctionParser {

    /// A located function definition.
    public struct FunctionDef {
        public let name: String
        public let bodyRange: NSRange      // entire definition text range
        public let signatureRange: NSRange // return type .. closing ')' of params
        public let nameRange: NSRange      // exact range of the function name token
    }

    private let source: String
    private let ns: NSString
    private let length: Int

    public init(source: String) {
        self.source = source
        self.ns = source as NSString
        self.length = ns.length
    }

    /// Returns the parsed function/method definitions. Works for both C/C++ file-scope
    /// functions and Java methods nested inside class/interface/record bodies. A
    /// definition is recognized as `name ( params ) { body }` at any brace depth, so
    /// the same logic covers all cases while plain calls (`foo()`) are discarded because
    /// they are followed by `;` rather than a body `{`.
    public func parseDefinitions() -> [FunctionDef] {
        var defs: [FunctionDef] = []

        // Strip comments/preprocessor and tokenize with brace tracking.
        var i = 0
        var depth = 0
        var lastToken: String? = nil       // token before the current '('
        var prevToken: String? = nil       // token before lastToken
        var candidate: (name: String, start: Int, nameRange: NSRange, level: Int)? = nil
        var parenDepth = 0
        // Functions whose body has opened but not yet closed. Stores the signature
        // info, the opening '{' index, and the brace depth at which the body opened so
        // nested methods (e.g. inside Java classes) can be finalized correctly.
        var pending: [(name: String, start: Int, nameRange: NSRange, bodyOpen: Int, level: Int)] = []

        while i < length {
            let ch = ns.character(at: i)
            let next = i + 1 < length ? ns.character(at: i + 1) : 0

            // skip whitespace
            if isWhitespace(ch) { i += 1; continue }

            // skip line comments
            if ch == 0x2F && next == 0x2F { // //
                i = skipToLineEnd(i); continue
            }
            // skip block comments
            if ch == 0x2F && next == 0x2A { // /*
                i = skipBlockComment(i); continue
            }
            // skip preprocessor / #include etc (rest of line)
            if ch == 0x23 { // #
                i = skipToLineEnd(i); continue
            }
            // skip string literals (and Java text blocks / char literals)
            if ch == 0x22 || ch == 0x27 { // " '
                i = skipString(i, quote: ch); continue
            }

            // braces change scope depth
            if ch == 0x7B { // {
                // If a signature candidate is still open at this brace depth, this '{'
                // opens its body: register a pending definition.
                if let cand = candidate, cand.level == depth {
                    pending.append((name: cand.name, start: cand.start, nameRange: cand.nameRange, bodyOpen: i, level: depth))
                    candidate = nil
                } else {
                    candidate = nil
                }
                depth += 1
                prevToken = nil
                lastToken = nil
                i += 1
                continue
            }
            if ch == 0x7D { // }
                depth -= 1
                // If a method body closes here (deepest pending def opened at this depth),
                // finalize it.
                if let last = pending.last, last.level == depth {
                    _ = pending.popLast()
                    defs.append(FunctionDef(
                        name: last.name,
                        bodyRange: NSRange(location: last.start, length: i + 1 - last.start),
                        signatureRange: NSRange(location: last.start, length: last.bodyOpen - last.start),
                        nameRange: last.nameRange
                    ))
                }
                candidate = nil
                prevToken = nil
                lastToken = nil
                i += 1
                continue
            }

            // parentheses
            if ch == 0x28 { // (
                parenDepth += 1
                if parenDepth == 1 && candidate == nil,
                   let name = lastToken,
                   looksLikeFunctionName(name),
                   !isMemberAccessContext(prevToken) {
                    let start = findTokenStart(i, lastToken: name)
                    let nameRange = findNameStart(i)
                    candidate = (name, start, nameRange, depth)
                }
                lastToken = nil
                i += 1
                continue
            }
            if ch == 0x29 { // )
                parenDepth = max(0, parenDepth - 1)
                lastToken = ")"
                i += 1
                continue
            }

            // Generic-arity group `Name<T>(`: if this '<' is matched by a '>' that is
            // immediately followed by '(', skip the whole `<...>` so `lastToken` keeps
            // the method name and the '(' still creates a candidate. Handles C#/C++/
            // Java generic methods (`Foo<T>(`, `Foo<T, U>(`). Also skip lone generic
            // usage that isn't a definition header by falling through to the reset.
            if ch == 0x3C { // <
                if let close = genericCloseIndex(i), isParenAfter(close) {
                    i = close + 1
                    continue
                }
                i += 1
                continue
            }

            if isIdentifierChar(ch) {
                let start = i
                while i < length && isIdentifierChar(ns.character(at: i)) { i += 1 }
                let tok = ns.substring(with: NSRange(location: start, length: i - start))
                prevToken = lastToken
                lastToken = tok
                continue
            }

            // ';' means a declaration/call, not a definition: drop any open candidate.
            if ch == 0x3B { // ;
                candidate = nil
            }

            // Any other symbol resets the pending candidate chain unless it's part of
            // a name (e.g. '::' or '*' in return type). We simply clear on operators.
            prevToken = nil
            lastToken = nil
            i += 1
        }

        // Deduplicate by name, keep first (definition) occurrence.
        var seen = Set<String>()
        var result: [FunctionDef] = []
        for def in defs {
            if !seen.contains(def.name) {
                seen.insert(def.name)
                result.append(def)
            }
        }
        return result
    }

    /// Returns the name ranges of class-like declarations (`class`, `interface`,
    /// `enum`, `record`, `@interface` in Java). The name is the identifier that
    /// directly follows the keyword, i.e. the type being defined.
    public func parseClassNames() -> [(name: String, range: NSRange)] {
        var result: [(String, NSRange)] = []

        var i = 0
        var lastIdent: String? = nil
        let classKeywords: Set<String> = ["class", "interface", "enum", "record", "@interface", "struct"]

        while i < length {
            let ch = ns.character(at: i)
            let next = i + 1 < length ? ns.character(at: i + 1) : 0

            if isWhitespace(ch) { i += 1; continue }
            if ch == 0x2F && next == 0x2F { i = skipToLineEnd(i); continue }
            if ch == 0x2F && next == 0x2A { i = skipBlockComment(i); continue }
            if ch == 0x23 { i = skipToLineEnd(i); continue }
            if ch == 0x22 || ch == 0x27 { i = skipString(i, quote: ch); continue }

            // `@interface` — treat the '@' + keyword together. Detect the keyword but
            // ignore a bare `@` so function annotation `@Override` isn't misread.
            if ch == 0x40 && next != 0 && isClassKeywordStart(next) {
                // Consume '@' then continue; next identifiers will pick up "interface".
                lastIdent = nil
                i += 1
                continue
            }

            if isIdentifierChar(ch) {
                let start = i
                while i < length && isIdentifierChar(ns.character(at: i)) { i += 1 }
                let ident = ns.substring(with: NSRange(location: start, length: i - start))
                // If the previous identifier was a class keyword, this is a class name.
                if let kw = lastIdent, classKeywords.contains(kw),
                   !isReservedWord(ident), !isClassKeyword(ident) {
                    result.append((ident, NSRange(location: start, length: i - start)))
                }
                lastIdent = ident
                continue
            }

            // A '.' could be a qualified name (e.g. `Outer.Inner`); keep the last
            // identifier so the name after the keyword is still captured across dots.
            if ch == 0x2E {
                i += 1
                continue
            }
            // Any other symbol breaks the keyword->name adjacency.
            lastIdent = nil
            i += 1
        }

        return result
    }

    private func isClassKeywordStart(_ c: unichar) -> Bool {
        (c >= 0x41 && c <= 0x5A) || (c >= 0x61 && c <= 0x7A) || c == 0x5F
    }

    private func isClassKeyword(_ t: String) -> Bool {
        ["class", "interface", "enum", "record", "@interface", "struct"].contains(t)
    }

    /// Returns the call/dependency edges among the given functions.
    /// Builds call edges (caller -> callee) and data edges (caller -> callee).
    public func buildGraph() -> (calls: [(from: String, to: String)], data: [(from: String, to: String)]) {
        let defs = parseDefinitions()
        let definedNames = Set(defs.map { $0.name })

        var calls: [(String, String)] = []
        var data: [(String, String)] = []

        for def in defs {
            let bodyStart = def.bodyRange.location
            let bodyEnd = def.bodyRange.location + def.bodyRange.length
            guard bodyStart >= 0, bodyEnd <= length else { continue }

            // Find function calls within the body: identifier '(' where identifier is a defined function.
            var i = bodyStart
            let end = bodyEnd
            while i < end {
                let ch = ns.character(at: i)
                if isIdentifierChar(ch) {
                    let start = i
                    while i < end && isIdentifierChar(ns.character(at: i)) { i += 1 }
                    let ident = ns.substring(with: NSRange(location: start, length: i - start))
                    // Look ahead for '(' ignoring spaces
                    var j = i
                    while j < end && isWhitespace(ns.character(at: j)) { j += 1 }
                    if j < end && ns.character(at: j) == 0x28 && definedNames.contains(ident) {
                        // It's a call to a defined function.
                        if ident != def.name {
                            calls.append((def.name, ident))
                            data.append((def.name, ident)) // arguments flow into callee
                        }
                        i = j + 1
                        continue
                    }
                }
                i += 1
            }
        }

        // Deduplicate
        calls = dedupe(calls)
        data = dedupe(data)
        return (calls, data)
    }

    private func dedupe(_ pairs: [(String, String)]) -> [(String, String)] {
        var seen = Set<String>()
        var result: [(String, String)] = []
        for p in pairs {
            let key = p.0 + "\u{1}" + p.1
            if !seen.contains(key) {
                seen.insert(key)
                result.append(p)
            }
        }
        return result
    }

    // MARK: - Helpers

    private func isWhitespace(_ c: unichar) -> Bool {
        return c == 0x20 || c == 0x09 || c == 0x0A || c == 0x0D
    }

    private func isIdentifierChar(_ c: unichar) -> Bool {
        return (c >= 0x41 && c <= 0x5A) || (c >= 0x61 && c <= 0x7A) ||
               (c >= 0x30 && c <= 0x39) || c == 0x5F
    }

    /// If the character at `i` ('<') opens a balanced `<...>` group that is not
    /// itself inside parentheses, returns the index of the matching '>'; nil if none.
    private func genericCloseIndex(_ i: Int) -> Int? {
        var depth = 0
        var j = i
        while j < length {
            let ch = ns.character(at: j)
            if ch == 0x3C { depth += 1 }          // <
            else if ch == 0x3E {                  // >
                depth -= 1
                if depth == 0 { return j }
            }
            else if ch == 0x28 || ch == 0x29 || j - i > 4096 { return nil } // '(' changed context
            j += 1
        }
        return nil
    }

    /// True if a whitespace-skipping scan from index `i` lands on '('. Used to detect
    /// a generic method header `Name<T>(`.
    private func isParenAfter(_ i: Int) -> Bool {
        var j = i + 1
        while j < length && isWhitespace(ns.character(at: j)) { j += 1 }
        return j < length && ns.character(at: j) == 0x28
    }

    private func skipToLineEnd(_ i: Int) -> Int {
        var j = i
        while j < length && ns.character(at: j) != 0x0A { j += 1 }
        return j
    }

    private func skipBlockComment(_ i: Int) -> Int {
        var j = i + 2
        while j + 1 < length && !(ns.character(at: j) == 0x2A && ns.character(at: j + 1) == 0x2F) {
            j += 1
        }
        return min(j + 2, length)
    }

    private func skipString(_ i: Int, quote: unichar) -> Int {
        var j = i + 1
        while j < length {
            if ns.character(at: j) == 0x5C { j += 2; continue } // backslash escape
            if ns.character(at: j) == quote { return j + 1 }
            j += 1
        }
        return length
    }

    /// Returns true if a token could be a C/C++/Java function name (not a keyword/known storage specifier).
    private func looksLikeFunctionName(_ token: String) -> Bool {
        if isReservedWord(token) { return false }
        return true
    }

    /// True if `t` is a token indicating a member call / construction rather than a
    /// definition name (e.g. `obj.foo(`, `ptr->foo(`, `new Foo(`).
    private func isMemberAccessContext(_ t: String?) -> Bool {
        guard let t = t else { return false }
        return t == "." || t == "->" || t == "new"
    }

    private func isReservedWord(_ t: String) -> Bool {
        let reserved: Set<String> = [
            "int", "char", "float", "double", "void", "long", "short", "unsigned",
            "signed", "struct", "union", "enum", "typedef", "const", "static",
            "extern", "volatile", "return", "if", "else", "for", "while", "do",
            "switch", "case", "default", "break", "continue", "goto", "sizeof",
            "class", "public", "private", "protected", "template", "typename",
            "namespace", "using", "virtual", "operator", "new", "delete", "this",
            "try", "catch", "throw", "inline", "friend", "explicit", "override",
            "final", "constexpr", "auto", "register",
            // Java
            "interface", "record", "extends", "implements", "instanceof",
            "synchronized", "boolean", "byte", "import", "package", "abstract",
            "native", "strictfp", "super", "transient", "yield", "var", "assert",
            "finally", "sealed", "permits", "module", "exports", "opens", "requires",
            "uses", "provides", "non-sealed", "default"
        ]
        return reserved.contains(t)
    }

    /// Finds the starting index of the token that immediately precedes position `i`,
    /// treating the identifier as the candidate name. We reconstruct the earliest
    /// plausible definition start by scanning back over the return-type tokens
    /// (identifiers, '*', '&', '::', '<','>') until a top-level delimiter.
    private func findTokenStart(_ i: Int, lastToken: String) -> Int {        // `i` is index of '('; lastToken is the name just before it.
        // Walk back to find the definition's start.
        var j = i
        var start = i
        while j > 0 {
            // j currently points after previous token; find token end
            var k = j - 1
            // skip whitespace
            while k > 0 && isWhitespace(ns.character(at: k)) { k -= 1 }
            if k <= 0 { start = 0; break }
            // read a token backwards: skip identifier/operator chars
            let tokenEnd = k + 1
            var tokenStart = k
            if isIdentifierChar(ns.character(at: k)) {
                while tokenStart > 0 && isIdentifierChar(ns.character(at: tokenStart - 1)) { tokenStart -= 1 }
            } else {
                // single-char operator
                tokenStart = k
            }
            let tok = ns.substring(with: NSRange(location: tokenStart, length: tokenEnd - tokenStart))
            // Stop at structural delimiters
            if tok == ";" || tok == "{" || tok == "}" || tok == ")" || tok == "," {
                start = tokenEnd
                break
            }
            if tok == "*" || tok == "&" || tok == "::" || tok == ">" || tok == "<" {
                j = tokenStart
                continue
            }
            if isReservedWordForReturnType(tok) {
                start = tokenStart
                j = tokenStart
                continue
            }
            // identifiers in return type (e.g. 'unsigned int', 'MyType')
            start = tokenStart
            j = tokenStart
        }
        return start
    }

    /// Finds the exact range of the identifier token immediately preceding `i` (the '(').
    private func findNameStart(_ i: Int) -> NSRange {
        var end = i
        // Skip whitespace backwards
        while end > 0 && isWhitespace(ns.character(at: end - 1)) { end -= 1 }
        var start = end
        while start > 0 && isIdentifierChar(ns.character(at: start - 1)) { start -= 1 }
        return NSRange(location: start, length: end - start)
    }

    private func isReservedWordForReturnType(_ t: String) -> Bool {
        let set: Set<String> = ["int","char","float","double","void","long","short","unsigned",
            "signed","struct","union","enum","const","static","extern","typedef","volatile",
            "class","bool","size_t","int8_t","uint8_t","int16_t","uint16_t","int32_t",
            "uint32_t","int64_t","uint64_t","auto","constexpr",
            // Java types / modifiers
            "public","private","protected","final","abstract","native","synchronized",
            "strictfp","boolean","byte","String","Object","Integer","Character","Double",
            "Float","Long","Short","Boolean"]
        return set.contains(t)
    }
}

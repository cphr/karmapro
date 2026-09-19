// by cipher.org.uk
import Foundation

/// A real C/C++ tokenizer producing a precise typed token stream with source
/// positions. Handles comments, string/char literals (incl. escapes and
/// prefixes), numeric literals, operators, and preprocessor lines.
public struct CTokenizer {
    private let ns: NSString
    private let length: Int

    public init(source: String) {
        self.ns = source as NSString
        self.length = ns.length
    }

    public func tokenize() -> [CAstToken] {
        var tokens: [CAstToken] = []
        var i = 0
        var line = 1
        var lineStart = 0

        func col(_ offset: Int) -> Int { offset - lineStart + 1 }
        func isWS(_ c: unichar) -> Bool { c == 0x20 || c == 0x09 || c == 0x0A || c == 0x0D }

        while i < length {
            let c = ns.character(at: i)
            let next = i + 1 < length ? ns.character(at: i + 1) : 0

            if c == 0x0A { line += 1; i += 1; lineStart = i; continue }
            if isWS(c) { i += 1; continue }

            // Preprocessor line: skip to end of line.
            if c == 0x23 {
                while i < length && ns.character(at: i) != 0x0A { i += 1 }
                continue
            }

            // line comment //
            if c == 0x2F && next == 0x2F {
                while i < length && ns.character(at: i) != 0x0A { i += 1 }
                continue
            }
            // block comment /* */
            if c == 0x2F && next == 0x2A {
                i += 2
                while i + 1 < length {
                    if ns.character(at: i) == 0x2A && ns.character(at: i + 1) == 0x2F { i += 2; break }
                    if ns.character(at: i) == 0x0A { line += 1; lineStart = i + 1 }
                    i += 1
                }
                continue
            }

            // String / char literals, optionally with a prefix: L" " u" " U" " u8" " R"( )"
            let isQuoteStart = c == 0x22 || c == 0x27
            if isQuoteStart || isStringPrefixAt(i) {
                let startOff = i, startLine = line, startCol = col(i)
                var j = i
                // Skip an optional prefix that immediately precedes the quote.
                var quote = c
                if !isQuoteStart {
                    var p = j
                    if ns.character(at: p) == 0x75 && p + 1 < length && ns.character(at: p + 1) == 0x38 { p += 2 } // u8
                    else if ns.character(at: p) == 0x4C || ns.character(at: p) == 0x75 || ns.character(at: p) == 0x55 { p += 1 } // L/u/U
                    else if ns.character(at: p) == 0x52 { p += 1 } // R raw
                    j = p
                    if j < length { quote = ns.character(at: j) } else { quote = 0 }
                } else {
                    quote = c
                    j = i // quote at start
                }

                if quote == 0x22 || quote == 0x27 {
                    let isRaw = (j > i) && (ns.character(at: j - 1) == 0x52 || ns.character(at: j - 1) == 0x72)
                    var k = j + 1
                    var closed = false
                    if isRaw {
                        // R"delim(...)delim" — find closing via ( and )delim"
                        // Best-effort: find the next unmatched . We handle the simple R"(...)" form.
                        if k < length && ns.character(at: k) == 0x28 {
                            var depth = 1
                            k += 1
                            while k < length {
                                if ns.character(at: k) == 0x28 { depth += 1 }
                                else if ns.character(at: k) == 0x29 {
                                    depth -= 1
                                    if depth == 0 {
                                        if k + 1 < length && ns.character(at: k + 1) == 0x22 { k += 2; closed = true; break }
                                    }
                                }
                                if ns.character(at: k) == 0x0A { line += 1; lineStart = k + 1 }
                                k += 1
                            }
                        } else {
                            while k < length {
                                if ns.character(at: k) == 0x22 { k += 1; closed = true; break }
                                if ns.character(at: k) == 0x0A { line += 1; lineStart = k + 1 }
                                k += 1
                            }
                        }
                    } else {
                        while k < length {
                            if ns.character(at: k) == 0x5C && k + 1 < length { k += 2; continue }
                            if ns.character(at: k) == quote { k += 1; closed = true; break }
                            if ns.character(at: k) == 0x0A { line += 1; lineStart = k + 1 }
                            k += 1
                        }
                    }
                    tokens.append(CAstToken(kind: quote == 0x22 ? .string : .character,
                                            text: ns.substring(with: NSRange(location: startOff, length: k - startOff)),
                                            line: startLine, column: startCol, offset: startOff))
                    i = k
                    _ = closed
                    continue
                }
                // Prefix present but no quote: fall through to identifier handling below.
            }

            // Numbers.
            if isDigit(c) || (c == 0x2E && nextIsDigit(i)) {
                let startOff = i, startLine = line, startCol = col(i)
                var j = i
                while j < length {
                    let ch = ns.character(at: j)
                    if isHexDigit(ch) { j += 1; continue }
                    if ch == 0x78 || ch == 0x58 { j += 1; continue }        // 0x
                    if ch == 0x2E {
                        // Do not swallow the `.` when it starts a Swift range
                        // operator (`0...n`, `0..<n`); leave it for the
                        // operator/punctuation scanner.
                        if j + 3 <= length {
                            let three = ns.substring(with: NSRange(location: j, length: 3))
                            if three == "..." || three == "..<" { break }
                        }
                        j += 1
                        continue
                    }
                    if ch == 0x65 || ch == 0x45 || ch == 0x70 || ch == 0x50 { // exponent
                        j += 1
                        if j < length && (ns.character(at: j) == 0x2B || ns.character(at: j) == 0x2D) { j += 1 }
                        continue
                    }
                    break
                }
                tokens.append(CAstToken(kind: .number, text: ns.substring(with: NSRange(location: startOff, length: j - startOff)),
                                        line: startLine, column: startCol, offset: startOff))
                i = j
                continue
            }

            // Identifiers / keywords.
            // PHP variable sigil: skip `$` when it immediately precedes an
            // identifier so `$foo` is tokenized as `foo` (same as the heuristic
            // tokenizer).  Without this the parser treats `$` as a unary prefix
            // operator and every PHP expression is mis-parsed.
            if c == 0x24 && next != 0 && isIdentStart(next) { i += 1; continue }
            if isIdentStart(c) {
                let startOff = i, startLine = line, startCol = col(i)
                var j = i
                while j < length && isIdentPart(ns.character(at: j)) { j += 1 }
                let text = ns.substring(with: NSRange(location: startOff, length: j - startOff))
                tokens.append(CAstToken(kind: CAstToken.classify(text), text: text, line: startLine, column: startCol, offset: startOff))
                i = j
                continue
            }

            // Operators/punctuation (longest match first).
            let startOff = i, startLine = line, startCol = col(i)
            var matched: String? = nil
            var matchedLen = 0
            for len in [3, 2, 1] {
                guard i + len <= length, len > 0 else { continue }
                let t = ns.substring(with: NSRange(location: i, length: len))
                if cMultiCharOperators.contains(t) {
                    matched = t
                    matchedLen = len
                    break
                }
            }
            guard let m = matched else { i += 1; continue }
            let isPunct = m.count == 1 && "()[]{};,.?:#".contains(m)
            tokens.append(CAstToken(kind: isPunct ? .punct : .operator,
                                    text: m, line: startLine, column: startCol, offset: startOff))
            i += matchedLen
        }

        tokens.append(CAstToken(kind: .eof, text: "", line: line, column: col(i), offset: i))
        return tokens
    }

    private func isStringPrefixAt(_ i: Int) -> Bool {
        guard i < length else { return false }
        let c = ns.character(at: i)
        if c == 0x4C || c == 0x55 || c == 0x52 { // L U R
            return i + 1 < length && (ns.character(at: i + 1) == 0x22 || ns.character(at: i + 1) == 0x27)
        }
        if c == 0x75 { // u or u8
            if i + 1 < length && ns.character(at: i + 1) == 0x38 {
                return i + 2 < length && (ns.character(at: i + 2) == 0x22 || ns.character(at: i + 2) == 0x27)
            }
            return i + 1 < length && (ns.character(at: i + 1) == 0x22 || ns.character(at: i + 1) == 0x27)
        }
        if c == 0x72 { // r raw lowercase
            return i + 1 < length && ns.character(at: i + 1) == 0x22
        }
        return false
    }

    private func nextIsDigit(_ i: Int) -> Bool {
        i + 1 < length && isDigit(ns.character(at: i + 1))
    }
    private func isDigit(_ c: unichar) -> Bool { c >= 0x30 && c <= 0x39 }
    private func isHexDigit(_ c: unichar) -> Bool {
        (c >= 0x30 && c <= 0x39) || (c >= 0x41 && c <= 0x46) || (c >= 0x61 && c <= 0x66)
    }
    private func isIdentStart(_ c: unichar) -> Bool {
        (c >= 0x41 && c <= 0x5A) || (c >= 0x61 && c <= 0x7A) || c == 0x5F
    }
    private func isIdentPart(_ c: unichar) -> Bool {
        isIdentStart(c) || isDigit(c)
    }
}

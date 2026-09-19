// by cipher.org.uk
import Foundation

public enum ScriptLanguage {
    case go
    case kotlin
    case php
    case python
    case ruby
    case rust
}

/// A located Go `func` / Kotlin `fun` / Python & Ruby `def` / Rust `fn`
/// definition with precise UTF-16 offsets, mirroring `JMethodDef` for Java.
/// Offsets are derived from the token stream so the body range is exact, which
/// is essential for correct token slicing.
public struct ScriptMethodDef {
    public let name: String
    public let params: [CAParam]
    public let bodyRange: NSRange      // signature name start .. body end (inclusive)
    public let bodyOffset: Int         // offset of the opening '{' (or first body token)
    public let startOffset: Int        // offset of the function name token
    public let nameOffset: Int         // offset of the displayed method name token
    public let syntheticBraces: Bool   // true for indentation-based bodies (Python/Ruby)
    public let language: ScriptLanguage
}

/// Recursive-descent parser for Go `func`, Kotlin `fun`, Python / Ruby `def`
/// and Rust `fn` definitions. It reuses `CTokenizer`/`CAstToken` for
/// tokenization and detects definitions that have a real `{ }` body (Go
/// top-level funcs/methods, Kotlin funs, Rust fns) or an indentation-based
/// body (Python/Ruby `def`), producing exact source ranges.
public final class ScriptMethodParser {
    private let language: ScriptLanguage
    private let tokens: [CAstToken]

    init(language: ScriptLanguage, source: String) {
        self.language = language
        // Strip PHP tags for PHP to keep offsets aligned with ScriptAnalyzer
        let strippedSource = language == .php ? Self.stripPHPTags(source) : source
        self.tokens = CTokenizer(source: strippedSource).tokenize()
    }

    private static func stripPHPTags(_ source: String) -> String {
        // Replace PHP tags with spaces to preserve source offsets for line attribution
        var result = source
        result = result.replacingOccurrences(of: "<?php", with: "     ")
        result = result.replacingOccurrences(of: "<?=", with: "   ")
        result = result.replacingOccurrences(of: "<?", with: "  ")
        result = result.replacingOccurrences(of: "?>", with: "   ")
        return result
    }

    private var defKeyword: String {
        switch language {
        case .go: return "func"
        case .kotlin: return "fun"
        case .php: return "function"
        case .python, .ruby: return "def"
        case .rust: return "fn"
        }
    }

    public func parseMethods() -> [ScriptMethodDef] {
        var defs: [ScriptMethodDef] = []
        let n = tokens.count
        var i = 0
        while i < n {
            let tk = tokens[i]
            if tk.kind == .eof { break }

            if tk.kind == .identifier && tk.text == defKeyword {
                // Skip a member access like `obj.fun` (identifier '.' before the keyword).
                let prevIsDot = i > 0 && tokens[i - 1].kind == .punct && tokens[i - 1].text == "."
                if !prevIsDot, let m = parseMethodDef(keywordIndex: i) {
                    defs.append(m)
                }
            }
            i += 1
        }

        // If no methods were found (e.g. procedural script like ping.php with no
        // function definitions), synthesise a whole-file "main" method definition
        // spanning all tokens so script analysis covers top-level procedural code.
        if defs.isEmpty, !tokens.isEmpty {
            let startOff = tokens[0].offset
            let lastTok = tokens[tokens.count - 1]
            let endOff = lastTok.offset + lastTok.text.count
            let bodyRange = NSRange(location: startOff, length: max(0, endOff - startOff))
            // PHP, Python, Ruby use synthetic braces (indentation-based or tag-based)
            let needsSyntheticBraces = language == .php || language == .python || language == .ruby
            defs.append(ScriptMethodDef(name: "main", params: [], bodyRange: bodyRange,
                                        bodyOffset: startOff, startOffset: startOff,
                                        nameOffset: startOff, syntheticBraces: needsSyntheticBraces,
                                        language: language))
        }

        // Deduplicate by name, keeping the first (body-bearing) definition so
        // overloads / local shadowed funs do not produce duplicate findings.
        var seen = Set<String>()
        var result: [ScriptMethodDef] = []
        for d in defs where !seen.contains(d.name) {
            seen.insert(d.name)
            result.append(d)
        }
        return result
    }

    private func isPunct(_ tk: CAstToken, _ text: String) -> Bool {
        tk.kind == .punct && tk.text == text
    }

    /// Parses a candidate definition starting at the `func`/`fun`/`def`/`fn` keyword.
    /// Returns nil if the signature is not followed by a real body.
    private func parseMethodDef(keywordIndex: Int) -> ScriptMethodDef? {
        var j = keywordIndex + 1

        // Go methods can have a receiver group before the name: `func (r *T) name(`.
        // A function-typed parameter (`cb func(x int)`) is rejected below because
        // after the balanced group we require name + '('.
        if language == .go, j < tokens.count, isPunct(tokens[j], "(") {
            guard let close = matchingClose(open: j, openText: "(", closeText: ")") else { return nil }
            j = close + 1
        }

        // PHP can declare a by-reference return: `function &name(...) { ... }`.
        // Skip the leading `&` so the following identifier is the method name.
        if language == .php, j < tokens.count, tokens[j].kind == .operator, tokens[j].text == "&" {
            j += 1
        }

        guard j < tokens.count, tokens[j].kind == .identifier else { return nil }
        let nameTok = tokens[j]
        var name = nameTok.text
        var nameTokForRange = nameTok

        // Ruby singleton methods (`def self.foo`, `def Klass.foo`): skip the
        // receiver and the dot to reach the actual method name.
        if language == .ruby {
            let k = j + 1
            if k + 1 < tokens.count, isPunct(tokens[k], "."), tokens[k + 1].kind == .identifier {
                name = tokens[k + 1].text
                nameTokForRange = tokens[k + 1]
                j = k + 1
            }
        }

        // Ruby allows omitting parens entirely (`def main`). Python always has
        // them (`def main():`). If the next token after the name is not '(' and
        // this is Ruby, treat it as a zero-parameter method.
        let hasParens = j + 1 < tokens.count && isPunct(tokens[j + 1], "(")
        if !hasParens && language != .ruby {
            return nil
        }

        let openParen: Int
        let closeParen: Int
        let params: [CAParam]
        var signatureEndLine = tokens[j].line
        if hasParens {
            openParen = j + 1
            guard let close = matchingClose(open: openParen, openText: "(", closeText: ")") else { return nil }
            closeParen = close
            params = parseParams(openParen: openParen, closeParen: closeParen)
            signatureEndLine = tokens[closeParen].line
        } else {
            openParen = j + 1
            closeParen = j + 1
            params = []
            signatureEndLine = tokens[j].line
        }

        // Python/Ruby bodies are indentation-based: the body runs from the first
        // line after the signature that is more indented than the `def` keyword.
        if language == .python || language == .ruby {
            return computeIndentedBody(keywordIndex: keywordIndex, nameTok: nameTok, name: name,
                                       nameTokForRange: nameTokForRange, params: params,
                                       signatureEndLine: signatureEndLine)
        }

        // After ')', scan forward (tracking paren depth for Go return tuples like
        // `(int, error)`, Rust `-> Ret` and Kotlin `: ReturnType`) to the first '{'.
        var pd = 0
        var bodyOpen: Int? = nil
        var k = closeParen + 1
        while k < tokens.count {
            let t = tokens[k]
            if t.kind == .punct {
                if t.text == "(" { pd += 1 }
                else if t.text == ")" { pd = max(0, pd - 1) }
                else if t.text == "{" && pd == 0 { bodyOpen = k; break }
                else if t.text == ";" && pd == 0 { return nil }
            }
            k += 1
        }
        guard let open = bodyOpen, open < tokens.count else { return nil }
        let bodyOpenOffset = tokens[open].offset

        // Find the matching '}' of the body.
        var depth = 1
        var b = open + 1
        while b < tokens.count, depth > 0 {
            let t = tokens[b]
            if t.kind == .punct {
                if t.text == "{" { depth += 1 }
                else if t.text == "}" {
                    depth -= 1
                    if depth == 0 { break }
                }
            }
            b += 1
        }
        guard b < tokens.count, depth == 0 else { return nil }
        let bodyClose = tokens[b]
        let endOffset = bodyClose.offset + bodyClose.text.count

        let bodyRange = NSRange(location: nameTok.offset, length: endOffset - nameTok.offset)
        return ScriptMethodDef(name: name, params: params, bodyRange: bodyRange,
                               bodyOffset: bodyOpenOffset, startOffset: nameTok.offset,
                               nameOffset: nameTokForRange.offset,
                               syntheticBraces: false, language: language)
    }

    /// Computes an indentation-defined body (Python/Ruby) from the line/column
    /// information on the token stream: it starts at the first token more
    /// indented than the `def` keyword and ends at the last token before a
    /// line that is not more indented (a dedent or the next top-level def).
    private func computeIndentedBody(keywordIndex: Int, nameTok: CAstToken, name: String,
                                     nameTokForRange: CAstToken, params: [CAParam],
                                     signatureEndLine: Int) -> ScriptMethodDef? {
        let defLine = tokens[keywordIndex].line
        let indentCol = tokens[keywordIndex].column

        var bodyStart: Int? = nil
        let n = tokens.count
        var i = keywordIndex + 1
        while i < n {
            let t = tokens[i]
            if t.kind == .eof { break }
            if t.line > signatureEndLine && t.column > indentCol {
                bodyStart = i
                break
            }
            i += 1
        }
        guard let bs = bodyStart else { return nil }

        var bodyEnd = bs
        while i < n {
            let t = tokens[i]
            if t.kind == .eof { break }
            if t.line <= signatureEndLine { i += 1; continue }
            if t.column > indentCol && defLine != t.line {
                bodyEnd = i
                i += 1
                continue
            }
            break
        }
        guard tokens[bodyEnd].kind != .eof else { return nil }

        let bodyStartOffset = tokens[bs].offset
        let endOffset = tokens[bodyEnd].offset + tokens[bodyEnd].text.count
        let bodyRange = NSRange(location: nameTok.offset, length: endOffset - nameTok.offset)
        return ScriptMethodDef(name: name, params: params, bodyRange: bodyRange,
                               bodyOffset: bodyStartOffset, startOffset: nameTok.offset,
                               nameOffset: nameTokForRange.offset,
                               syntheticBraces: true, language: language)
    }

    private func matchingClose(open: Int, openText: String, closeText: String) -> Int? {
        var depth = 1
        var i = open + 1
        while i < tokens.count, depth > 0 {
            let t = tokens[i]
            if t.kind == .punct {
                if t.text == openText { depth += 1 }
                else if t.text == closeText {
                    depth -= 1
                    if depth == 0 { break }
                }
            }
            i += 1
        }
        guard i < tokens.count, depth == 0 else { return nil }
        return i
    }

    /// Parses the comma-separated parameter list between the parameter parens.
    private func parseParams(openParen: Int, closeParen: Int) -> [CAParam] {
        var results: [CAParam] = []
        var group: [CAstToken] = []
        var depth = 0
        var j = openParen + 1
        while j < closeParen {
            let t = tokens[j]
            if t.kind == .punct {
                if t.text == "(" || t.text == "<" || t.text == "[" { depth += 1 }
                else if t.text == ")" || t.text == ">" || t.text == "]" { depth = max(0, depth - 1) }
                else if t.text == "," && depth == 0 {
                    if let p = paramFrom(group) { results.append(p) }
                    group = []
                    j += 1
                    continue
                }
            }
            group.append(t)
            j += 1
        }
        if !group.isEmpty, let p = paramFrom(group) { results.append(p) }
        return results
    }

    /// Extracts the parameter name from a single comma-separated group.
    /// - Go: `a0 string`, `db *sql.DB`, `key []byte` -> the first identifier.
    /// - Kotlin/Rust: `cmd: String`, `u: &str` -> the identifier before the ':'.
    /// - Python/Ruby: `user_path`, `(db, user_id)` -> the first identifier.
    private func paramFrom(_ group: [CAstToken]) -> CAParam? {
        guard !group.isEmpty else { return nil }
        switch language {
        case .go, .python, .ruby:
            guard let first = group.first(where: { $0.kind == .identifier }) else { return nil }
            return CAParam(type: nil, name: first.text, offset: first.offset)
        case .php:
            // PHP params are `type $name` (or just `$name`); the `$` is dropped by
            // the tokenizer so the variable name is the LAST identifier in the
            // group (before any `= default` expression). Types like `?string` and
            // defaults like `null`/`[]` are excluded by keeping only identifiers.
            guard let name = group.reversed().first(where: { $0.kind == .identifier }) else { return nil }
            return CAParam(type: nil, name: name.text, offset: name.offset)
        case .kotlin, .rust:
            var depth = 0
            var name: (String, Int)? = nil
            var lastIdent: (String, Int)? = nil
            var j = 0
            while j < group.count {
                let t = group[j]
                if t.kind == .punct {
                    if t.text == "(" || t.text == "<" || t.text == "[" { depth += 1 }
                    else if t.text == ")" || t.text == ">" || t.text == "]" { depth = max(0, depth - 1) }
                    else if t.text == ":" && depth == 0 {
                        // nearest preceding identifier is the parameter name.
                        name = lastIdent
                        break
                    }
                }
                if t.kind == .identifier { lastIdent = (t.text, t.offset) }
                j += 1
            }
            if name == nil { name = lastIdent }
            guard let n = name else { return nil }
            return CAParam(type: nil, name: n.0, offset: n.1)
        }
    }
}
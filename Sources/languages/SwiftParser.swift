// by cipher.org.uk
import Foundation

/// A located Swift function-like definition (function / method / initializer /
/// deinitializer / subscript) with precise UTF-16 byte offsets.
/// Structurally mirrors `SolidityMethodDef` + `JSDef` so downstream consumers
/// (scan definitions, diagram call graphs, the three-walk security detector)
/// can share one shape.
public struct SwiftDef {
    public enum Kind: Equatable {
        case function, initializer, deinitializer, `subscript`
    }

    public let name: String
    public let nameOffset: Int
    public let kind: Kind
    public let startOffset: Int        // `func` / `init` / `deinit` / `subscript` token
    public let params: [CAParam]
    public let bodyOpenOffset: Int     // offset of the opening `{`
    public let bodyEndOffset: Int      // offset of the closing `}` (inclusive)
    public let qualifiers: Set<String>
    public let isAsync: Bool
    public let throwsClause: Bool

    public var bodyRange: NSRange {
        NSRange(location: bodyOpenOffset,
                length: max(0, bodyEndOffset - bodyOpenOffset + 1))
    }
    public var signatureRange: NSRange {
        let end = max(startOffset, bodyOpenOffset)
        return NSRange(location: startOffset, length: max(0, end - startOffset))
    }
    public var nameRange: NSRange {
        NSRange(location: nameOffset, length: (name as NSString).length)
    }
    /// Offset just past the `{` (where real statements begin).
    public var bodyStart: Int { bodyOpenOffset + 1 }

    /// Token index of the body's closing `}` (parser bookkeeping so the outer
    /// walk can skip the whole body).
    public var bodyEndTokenIndex: Int = -1

    func settingBodyEndTokenIndex(_ idx: Int) -> SwiftDef {
        var d = self
        d.bodyEndTokenIndex = idx
        return d
    }

    public var isDefinition: Bool { true }
}

/// Recursive-descent parser for Swift function/method/init/deinit/subscript
/// definitions. Reuses `CTokenizer`/`CAstToken` for tokenization and detects
/// the constructs that carry a real `{ }` body:
///  - `func name(...) -> Ret { ... }`   (incl. `mutating`/`static`/`async
///    throws`/`where` clauses / generic `<T: X>` heads)
///  - `init(...) { ... }` / `init?` / `init!` and `deinit { ... }`
///  - `subscript(...) -> T { ... }`
/// Call sites (obj.method(...)) are never scanned because the walk only
/// starts at a declaration keyword.
public final class SwiftParser {
    private let source: String
    private let tokens: [CAstToken]

    public init(source: String) {
        self.source = source
        self.tokens = CTokenizer(source: source).tokenize()
    }

    private static let headKeywords: Set<String> =
        ["func", "init", "deinit", "subscript"]

    private static let accessModifiers: Set<String> = [
        "public", "private", "internal", "fileprivate", "open",
    ]

    public func parseDefinitions() -> [SwiftDef] {
        var defs: [SwiftDef] = []
        let n = tokens.count
        var i = 0
        while i < n {
            let t = tokens[i]
            if t.kind == .eof { break }

            // Only `func`/`init`/`deinit`/`subscript` at a *statement* position
            // start a definition. Skip `self.func(...)`-shaped member call sites:
            // those appear as `.` `func`? Never — `func` is a reserved word in
            // Swift, so any occurrence at token level is a declaration head, EXCEPT
            // inside strings/comments which the tokenizer already removed.
            if t.kind == .identifier, Self.headKeywords.contains(t.text) {
                // A head directly preceded by `.` is a member CARRIED by the
                // tokenizer? In Swift a member is always written `.method(...)`
                // where the head word can't be `func`. It can't happen; still,
                // guard against `obj.subscript` (rare) by checking the previous
                // significant token for `.`.
                if let prev = prevSignificant(before: i), prev.text == "." {
                    i += 1
                    continue
                }
                // `#if`-wrapped and attribute-marked heads (`@MainActor func`)
                // are handled: we only require the head keyword here.
                if let def = parseHead(keywordIndex: i) {
                    defs.append(def)
                    i = skipToBodyEnd(from: def.bodyEndTokenIndex, limit: n)
                    continue
                }
            }
            i += 1
        }

        // Overloads: keep the first definition of each name so the taint maps /
        // definition tables stay unambiguous (mirrors Solidity/JS behavior).
        var seen = Set<String>()
        var result: [SwiftDef] = []
        for d in defs where !seen.contains(d.name) {
            seen.insert(d.name)
            result.append(d)
        }
        return result
    }

    private func prevSignificant(before i: Int) -> CAstToken? {
        var j = i - 1
        while j >= 0 {
            if tokens[j].kind != .eof { return tokens[j] }
            j -= 1
        }
        return nil
    }

    private func parseHead(keywordIndex: Int) -> SwiftDef? {
        let kwTok = tokens[keywordIndex]
        let n = tokens.count

        // Resolve the head kind and (for `func`) the trailing name token.
        var kind: SwiftDef.Kind = .function
        var name = ""
        var nameIndex = keywordIndex
        var scanFrom = keywordIndex + 1

        switch kwTok.text {
        case "func":
            // `func <name> ...`
            guard keywordIndex + 1 < n, tokens[keywordIndex + 1].kind == .identifier else { return nil }
            let nTok = tokens[keywordIndex + 1]
            name = nTok.text
            nameIndex = keywordIndex + 1
            scanFrom = nameIndex + 1
        case "init":
            kind = .initializer
            name = "init"
            nameIndex = keywordIndex
            scanFrom = keywordIndex + 1
            // `init?` / `init!`
            if scanFrom < n, tokens[scanFrom].kind == .operator,
               (tokens[scanFrom].text == "?" || tokens[scanFrom].text == "!") {
                scanFrom += 1
            }
        case "deinit":
            kind = .deinitializer
            name = "deinit"
            nameIndex = keywordIndex
            scanFrom = keywordIndex + 1
        case "subscript":
            kind = .subscript
            name = "subscript"
            nameIndex = keywordIndex
            scanFrom = keywordIndex + 1
        default:
            return nil
        }

        // For `func`, skip a generic parameter clause `<T: X, U: Y>` between the
        // name and the parameter list. (Not needed for init/subscript, but safe.)
        var sigStart = scanFrom
        if kind == .function, sigStart < n, tokens[sigStart].kind == .punct, tokens[sigStart].text == "<" {
            var depth = 0
            var j = sigStart
            while j < n {
                let t = tokens[j]
                if t.kind == .punct {
                    if t.text == "<" { depth += 1 }
                    else if t.text == ">" { depth -= 1; if depth == 0 { j += 1; break } }
                }
                j += 1
            }
            sigStart = j
        }

        // Parameter list: the first `(` after the head (balanced).
        var openParen = -1
        var j = sigStart
        while j < n {
            if tokens[j].kind == .punct && tokens[j].text == "(" { openParen = j; break }
            j += 1
        }
        guard openParen >= 0 else { return nil }
        var closeParen = -1
        var depth = 0
        var k = openParen
        while k < n {
            let t = tokens[k]
            if t.kind == .punct {
                if t.text == "(" || t.text == "[" || t.text == "{" { depth += 1 }
                else if t.text == ")" || t.text == "]" || t.text == "}" {
                    depth -= 1
                    if depth == 0 && t.text == ")" { closeParen = k; break }
                }
            }
            k += 1
        }
        guard closeParen >= 0 else { return nil }
        let params = closeParen > openParen + 1
            ? parseParams(openParen: openParen, closeParen: closeParen)
            : []

        // Scan for the body `{` past the return type / throws / async / where.
        var bodyIndex = -1
        var m = closeParen + 1
        while m < n {
            let t = tokens[m]
            if t.kind == .punct {
                // A declaration with no body: skip a trailing `{` that begins a
                // *nested block unrelated to this head* — impossible here because
                // the head MUST be followed by its own body; but `->` return type
                // may contain `{`? It can't in Swift. So the first `{` is the body.
                if t.text == "{" { bodyIndex = m; break }
                if t.text == "}" || t.text == ";" { return nil } // no body (protocol stub / abstract)
            }
            m += 1
        }
        guard bodyIndex >= 0, tokens[bodyIndex].kind == .punct, tokens[bodyIndex].text == "{" else { return nil }
        let bodyOpen = tokens[bodyIndex].offset

        // Match the closing `}` of the body.
        var bdepth = 1
        var b = bodyIndex + 1
        var bodyEndIndex = bodyIndex
        var bodyEndOffset = bodyOpen
        while b < n, bdepth > 0 {
            let t = tokens[b]
            if t.kind == .punct {
                if t.text == "{" { bdepth += 1 }
                else if t.text == "}" {
                    bdepth -= 1
                    if bdepth == 0 {
                        bodyEndIndex = b
                        bodyEndOffset = tokens[b].offset
                        break
                    }
                }
            }
            b += 1
        }
        guard bdepth == 0, bodyEndIndex >= 0 else { return nil }

        let qualifiers = collectQualifiers(keywordIndex: keywordIndex, bodyIndex: bodyIndex)
        let isAsync = qualifiers.contains("async")
        let throwsClause = qualifiers.contains("throws") || qualifiers.contains("rethrows")

        return SwiftDef(name: name,
                        nameOffset: tokens[nameIndex].offset,
                        kind: kind,
                        startOffset: kwTok.offset,
                        params: params,
                        bodyOpenOffset: bodyOpen,
                        bodyEndOffset: bodyEndOffset,
                        qualifiers: qualifiers,
                        isAsync: isAsync,
                        throwsClause: throwsClause)
                        .settingBodyEndTokenIndex(bodyEndIndex)
    }

    /// Tracks the token index of each definition's closing `}` so the outer walk
    /// can skip over it (nested definitions are never re-scanned).
    private func skipToBodyEnd(from endIndex: Int, limit: Int) -> Int {
        min(max(endIndex, 0), limit)
    }

    private func collectQualifiers(keywordIndex: Int, bodyIndex: Int) -> Set<String> {
        // Collect descriptor tokens between the head and the body brace that have
        // control-flow / concurrency semantics: `async`, `throws`, `rethrows`,
        // `mutating`, `nonisolated`, `final`, `override`, `static`, `convenience`.
        var q: Set<String> = []
        let interesting: Set<String> = [
            "async", "throws", "rethrows", "mutating", "nonisolated",
            "final", "override", "static", "class", "convenience", "required",
        ]
        var j = keywordIndex + 1
        while j < bodyIndex {
            let t = tokens[j]
            if t.kind == .identifier && interesting.contains(t.text) { q.insert(t.text) }
            j += 1
        }
        return q
    }

    /// Parses the comma-separated parameter list between the two parens.
    /// Swift parameters are `label name: Type`, `_ name: Type`, or `name: Type`;
    /// the variable name is the identifier immediately before the last top-level `:`.
    private func parseParams(openParen: Int, closeParen: Int) -> [CAParam] {
        var results: [CAParam] = []
        var group: [CAstToken] = []
        var depth = 0
        var j = openParen + 1
        while j < closeParen {
            let t = tokens[j]
            if t.kind == .punct {
                if t.text == "(" || t.text == "[" || t.text == "<" { depth += 1 }
                else if t.text == ")" || t.text == "]" || t.text == ">" { depth = max(0, depth - 1) }
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

    private func paramFrom(_ group: [CAstToken]) -> CAParam? {
        guard !group.isEmpty else { return nil }
        // Find the last top-level `:` inside the group (the type separator).
        var topLevelColon = -1
        var depth = 0
        for (idx, t) in group.enumerated() {
            switch t.kind {
            case .punct:
                if t.text == "(" || t.text == "[" || t.text == "<" { depth += 1 }
                else if t.text == ")" || t.text == "]" || t.text == ">" { depth = max(0, depth - 1) }
                else if t.text == ":" && depth == 0 { topLevelColon = idx }
            case .operator:
                // `->` inside a closure-typed parameter is not a param separator.
                break
            default:
                break
            }
        }
        var name: String? = nil
        var nameOffset = group[0].offset
        if topLevelColon >= 0 {
            // The name is the identifier immediately before the colon.
            var p = topLevelColon - 1
            while p >= 0 {
                let t = group[p]
                if t.kind == .identifier {
                    name = t.text
                    nameOffset = t.offset
                    break
                }
                // Skip `_` / trailing whitespace tokens (whitespace isn't tokenized).
                p -= 1
            }
        } else {
            // No type annotation: `func f(_ handler)` — find the last identifier
            // (often the only one) as the param name.
            for t in group.reversed() where t.kind == .identifier {
                name = t.text
                nameOffset = t.offset
                break
            }
        }
        guard let n = name, !n.isEmpty, n != "_" else { return nil }
        return CAParam(type: nil, name: n, offset: nameOffset)
    }
}
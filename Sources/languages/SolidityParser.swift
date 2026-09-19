// by cipher.org.uk
import Foundation

/// A located Solidity function-like definition (function / modifier /
/// constructor / fallback / receive) with precise byte offsets (UTF-16).
/// Structurally mirrors `CSharpMethodDef` so the shared AST frontend can slice
/// each body and parse it with `CParser`.
public struct SolidityMethodDef {
    public let name: String
    public let params: [CAParam]
    public let bodyRange: NSRange      // signature start .. closing '}' (inclusive)
    public let bodyOffset: Int         // offset of the opening '{'
    public let startOffset: Int        // offset of the name token
    public let isDefinition: Bool
    public let qualifiers: Set<String>
    public let isConstructor: Bool
    public let isModifier: Bool
}

/// Recursive-descent parser for Solidity function/method definitions. It reuses
/// `CTokenizer`/`CAstToken` for tokenization and detects the constructs that
/// carry a real `{ }` body:
///  - `contract C { ... }`, `interface`, `library`, `abstract contract`
///  - `function foo(...) visibility ... returns (...) { ... }`
///  - `modifier mod(...) { ... }`
///  - `constructor(...) { ... }`, `fallback() external { ... }`, `receive() external payable { ... }`
/// Call-sites (`obj.foo(...)`) and assignments are skipped, exactly like the
/// C# parser.
public final class SolidityParser {
    private let source: String
    private let tokens: [CAstToken]

    public init(source: String) {
        self.source = source
        self.tokens = CTokenizer(source: source).tokenize()
    }

    private static let containerKeywords: Set<String> = ["contract", "interface", "library", "struct", "enum"]
    private static let nonBodyKeywords: Set<String> = ["if", "for", "while", "else", "switch", "try", "catch", "do"]

    public func parseMethods() -> [SolidityMethodDef] {
        var defs: [SolidityMethodDef] = []
        let n = tokens.count
        var braceDepth = 0
        var containerDepth: [Int] = []

        var i = 0
        while i < n {
            let tk = tokens[i]
            if tk.kind == .eof { break }

            if tk.kind == .punct && tk.text == "{" {
                braceDepth += 1
                i += 1
                continue
            }
            if tk.kind == .punct && tk.text == "}" {
                if let last = containerDepth.last, last == braceDepth {
                    containerDepth.removeLast()
                }
                braceDepth = max(0, braceDepth - 1)
                i += 1
                continue
            }

            // Container keyword: merge `abstract contract`, `interface`, etc.
            if tk.kind == .keyword || (tk.kind == .identifier && Self.containerKeywords.contains(tk.text)) {
                if Self.containerKeywords.contains(tk.text) {
                    if let open = findTypeBodyOpen(after: i) {
                        containerDepth.append(braceDepth + 1)
                        braceDepth += 1
                        i = open + 1
                        continue
                    }
                    i += 1
                    continue
                }
            }

            // Function-like head keywords (matched by text; they tokenize as
            // identifiers in the shared C tokenizer).
            let headKind: HeadKind? =
                tk.text == "function" ? .function :
                tk.text == "modifier" ? .modifier :
                tk.text == "constructor" ? .constructor :
                tk.text == "fallback" ? .fallback :
                tk.text == "receive" ? .receive : nil

            if let hk = headKind {
                // Fallback/receive have no name; `constructor` name == "constructor".
                if let m = parseHead(kind: hk, keywordIndex: i, enclosing: containerDepth.last) {
                    defs.append(m)
                    i = skipToBodyEnd(from: i)
                    continue
                }
            }
            i += 1
        }

        // Dedupe by name (last definition wins for overloads; keep first).
        var seen = Set<String>()
        var result: [SolidityMethodDef] = []
        for d in defs where !seen.contains(d.name) {
            seen.insert(d.name)
            result.append(d)
        }
        return result
    }

    private enum HeadKind {
        case function, modifier, constructor, fallback, receive
    }

    private func skipToBodyEnd(from start: Int) -> Int {
        // Advance past the body we just parsed so nested contents aren't
        // re-scanned as new head candidates.
        var i = start
        let n = tokens.count
        var depth = 0
        while i < n {
            let t = tokens[i]
            if t.kind == .punct {
                if t.text == "{" { depth += 1 }
                else if t.text == "}" {
                    depth -= 1
                    if depth == 0 { return i + 1 }
                }
            }
            i += 1
        }
        return n
    }

    private func findTypeBodyOpen(after kwIndex: Int) -> Int? {
        var j = kwIndex + 1
        var paren = 0
        while j < tokens.count {
            let t = tokens[j]
            if t.kind == .punct {
                if t.text == "(" { paren += 1 }
                else if t.text == ")" { paren = max(0, paren - 1) }
                else if t.text == "{" && paren == 0 { return j }
                else if t.text == ";" && paren == 0 { return nil }
            } else if t.kind == .keyword, t.text == "is" || t.text == "abstract" {
                // `contract C is Base` — keep walking.
            }
            j += 1
        }
        return nil
    }

    private func parseHead(kind: HeadKind, keywordIndex: Int, enclosing: Int?) -> SolidityMethodDef? {
        let keywordTok = tokens[keywordIndex]

        // Determine the name token(s).
        var nameTok: CAstToken? = nil
        var name = ""
        var nameIndex = keywordIndex
        var scanFrom = keywordIndex + 1

        switch kind {
        case .function:
            // function <name> ( ...
            guard keywordIndex + 1 < tokens.count,
                  tokens[keywordIndex + 1].kind == .identifier else { return nil }
            let ntok = tokens[keywordIndex + 1]
            // A function head must eventually be followed by '(' and '{'.
            name = ntok.text
            nameTok = ntok
            nameIndex = keywordIndex + 1
            scanFrom = nameIndex + 1
        case .modifier:
            // modifier <name> ( ... ) { ... }  or  modifier <name> { ... }
            guard keywordIndex + 1 < tokens.count,
                  tokens[keywordIndex + 1].kind == .identifier else { return nil }
            let ntok = tokens[keywordIndex + 1]
            name = ntok.text
            nameTok = ntok
            nameIndex = keywordIndex + 1
            scanFrom = nameIndex + 1
        case .constructor:
            name = "constructor"
            nameTok = keywordTok
            scanFrom = keywordIndex + 1
        case .fallback:
            name = "fallback"
            nameTok = keywordTok
            scanFrom = keywordIndex + 1
        case .receive:
            name = "receive"
            nameTok = keywordTok
            scanFrom = keywordIndex + 1
        }

        // Optional parameter list: `(` ... `)`.
        var parenDepth = 0
        var closeParen = scanFrom
        var openParen: Int? = nil
        while closeParen < tokens.count {
            let t = tokens[closeParen]
            if t.kind == .punct {
                if t.text == "(" { parenDepth += 1; if openParen == nil { openParen = closeParen } }
                else if t.text == ")" {
                    parenDepth -= 1
                    if parenDepth == 0 { break }
                }
            }
            closeParen += 1
        }
        let hasParams = openParen != nil && parenDepth == 0
        let params = hasParams ? parseParams(openParen: openParen!, closeParen: closeParen) : []

        // Find the body `{` after the signature. Skip visibility / mutability /
        // modifiers / `returns (...)`, `override`, `virtual`, custom modifiers.
        var j = hasParams ? closeParen + 1 : scanFrom
        let n = tokens.count
        while j < n {
            let t = tokens[j]
            if t.kind == .punct {
                if t.text == "{" { break }
                if t.text == ";" { return nil }        // no body (abstract / interface)
                if t.text == "}" { return nil }
            }
            if t.kind == .keyword, t.text == "returns" {
                // skip the following `(type, ...)` return list.
                j += 1
                var d = 0
                while j < n {
                    let r = tokens[j]
                    if r.kind == .punct {
                        if r.text == "(" { d += 1 }
                        else if r.text == ")" { d -= 1; if d == 0 { j += 1; break } }
                    }
                    j += 1
                }
                continue
            }
            j += 1
        }
        guard j < n, tokens[j].kind == .punct, tokens[j].text == "{" else { return nil }

        let bodyOpen = tokens[j].offset

        // Find the matching '}' of the body.
        var depth = 1
        var k = j + 1
        while k < n, depth > 0 {
            let t = tokens[k]
            if t.kind == .punct {
                if t.text == "{" { depth += 1 }
                else if t.text == "}" {
                    depth -= 1
                    if depth == 0 { break }
                }
            }
            k += 1
        }
        guard k < n, depth == 0 else { return nil }
        let bodyClose = tokens[k]
        let endOffset = bodyClose.offset + bodyClose.text.count

        // Body range starts at the signature keyword (so downstream consumers can
        // attribute the whole definition), not just the name token.
        let bodyRange = NSRange(location: keywordTok.offset, length: endOffset - keywordTok.offset)
        let qualifiers = collectQualifiers(kind: kind, nameIndex: nameIndex)

        return SolidityMethodDef(name: name,
                                 params: params,
                                 bodyRange: bodyRange,
                                 bodyOffset: bodyOpen,
                                 startOffset: nameTok?.offset ?? keywordTok.offset,
                                 isDefinition: true,
                                 qualifiers: qualifiers,
                                 isConstructor: kind == .constructor,
                                 isModifier: kind == .modifier)
    }

    private func collectQualifiers(kind: HeadKind, nameIndex: Int) -> Set<String> {
        // Collect trailing descriptors between the name and the body brace:
        // visibility (`public`/`private`/`internal`/`external`), mutability
        // (`view`/`pure`/`payable`/`constant`), `override`/`virtual`, and custom
        // modifier names (`onlyOwner`, `nonReentrant`, `whenNotPaused`, ...), any
        // of which may carry security-relevant semantics (e.g. a reentrancy guard).
        var q: Set<String> = []
        let visibility: Set<String> = ["public", "private", "internal", "external"]
        let mutability: Set<String> = ["view", "pure", "payable", "constant", "override", "virtual"]
        var j = nameIndex + 1
        var depth = 0
        while j < tokens.count {
            let t = tokens[j]
            if t.kind == .punct {
                if t.text == "{" || t.text == ";" || t.text == "}" { break }
                if t.text == "(" { depth += 1; j += 1; continue }
                if t.text == ")" { depth = max(0, depth - 1); j += 1; continue }
            }
            if depth == 0 {
                if (t.kind == .keyword || t.kind == .identifier) &&
                    (visibility.contains(t.text) || mutability.contains(t.text)) {
                    q.insert(t.text)
                } else if t.kind == .identifier, t.text != "returns", t.text != "override", t.text != "virtual" {
                    // Custom modifier application (an identifier in the modifier
                    // list), e.g. `nonReentrant`, `onlyOwner`.
                    q.insert(t.text)
                }
            }
            j += 1
        }
        return q
    }

    /// Parses the comma-separated parameter list between the two parens.
    private func parseParams(openParen: Int, closeParen: Int) -> [CAParam] {
        var results: [CAParam] = []
        var group: [CAstToken] = []
        var depth = 0
        var j = openParen + 1
        while j < closeParen {
            let t = tokens[j]
            if t.kind == .punct {
                if t.text == "(" { depth += 1 }
                else if t.text == ")" { depth = max(0, depth - 1) }
                else if t.text == "<" { depth += 1 }
                else if t.text == ">" { depth = max(0, depth - 1) }
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
        var name: String? = nil
        var pendingIdent: (String, Int)? = nil
        var typeParts: [String] = []
        for t in group {
            switch t.kind {
            case .identifier:
                pendingIdent = (t.text, t.offset)
                typeParts.append(t.text)
            case .keyword:
                typeParts.append(t.text)
            case .operator:
                if t.text == "[]" || t.text == "*" || t.text == "[" || t.text == "]" {
                    typeParts.append(t.text)
                } else if t.text == "=" {
                    break
                }
            default:
                break
            }
        }
        if let pid = pendingIdent { name = pid.0 }
        guard let n = name, !n.isEmpty else { return nil }
        return CAParam(type: typeParts.joined(separator: " "), name: n, offset: pendingIdent?.1 ?? group[0].offset)
    }
}

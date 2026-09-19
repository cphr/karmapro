// by cipher.org.uk
import Foundation

/// A located C# method definition with precise byte offsets (UTF-16), used by
/// the C# AST frontend. Mirrors `JMethodDef` for Java.
public struct CSharpMethodDef {
    public let name: String
    public let params: [CAParam]
    public let bodyRange: NSRange      // signature start .. closing '}' (inclusive)
    public let bodyOffset: Int         // offset of the opening '{'
    public let startOffset: Int        // offset of the method name token
    public let isDefinition: Bool
    public let qualifiers: Set<String>
}

/// Recursive-descent parser for C# method definitions. It reuses
/// `CTokenizer`/`CAstToken` for tokenization and detects methods that have a
/// real `{ }` body, producing exact source ranges. It is structurally analogous
/// to `JParser` (C# shares the C-like declaration grammar): a method is a name
/// followed by `( params )` and a `{ body }`. Calls (`obj.Method(...)`),
/// constructor calls (`new Type(...)`) and property declarations (name followed
/// by `{ ... }` without a parameter list) are skipped.
public final class CSharpParser {
    private let source: String
    private let tokens: [CAstToken]

    public init(source: String) {
        self.source = source
        self.tokens = CTokenizer(source: source).tokenize()
    }

    private static let typeKeywords: Set<String> = ["class", "interface", "struct", "enum", "record", "namespace"]
    private static let methodModifiers: Set<String> = [
        "public", "private", "protected", "internal", "static", "abstract", "sealed",
        "virtual", "override", "new", "readonly", "async", "unsafe", "extern", "partial", "void"
    ]

    public func parseMethods() -> [CSharpMethodDef] {
        var defs: [CSharpMethodDef] = []
        let n = tokens.count
        var braceDepth = 0
        var typeStack: [(name: String, insideDepth: Int)] = []

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
                if let last = typeStack.last, last.insideDepth == braceDepth {
                    typeStack.removeLast()
                }
                braceDepth = max(0, braceDepth - 1)
                i += 1
                continue
            }

            // Type / namespace body: keyword ... { }
            if tk.kind == .keyword, Self.typeKeywords.contains(tk.text) {
                let typeName = detectTypeName(after: i)
                if let open = findTypeBodyOpen(after: i) {
                    typeStack.append((name: typeName, insideDepth: braceDepth + 1))
                    braceDepth += 1
                    i = open + 1
                    continue
                }
                i += 1
                continue
            }

            // Method/property candidate: identifier directly followed by '(' or '{'.
            if tk.kind == .identifier {
                if i > 0 {
                    let prev = tokens[i - 1]
                    if prev.kind == .operator, prev.text == "." || prev.text == "->" || prev.text == "new" {
                        i += 1
                        continue
                    }
                }
                if i + 1 < n, tokens[i + 1].kind == .punct, tokens[i + 1].text == "(" {
                    if let m = parseMethodDef(nameIndex: i, enclosing: typeStack.last?.name) {
                        defs.append(m)
                    }
                }
            }
            i += 1
        }

        var seen = Set<String>()
        var result: [CSharpMethodDef] = []
        for d in defs where !seen.contains(d.name) {
            seen.insert(d.name)
            result.append(d)
        }
        return result
    }

    private func detectTypeName(after kwIndex: Int) -> String {
        var j = kwIndex + 1
        while j < tokens.count {
            let t = tokens[j]
            if t.kind == .identifier { return t.text }
            if t.kind == .punct, t.text == "{" || t.text == ";" || t.text == "(" { break }
            j += 1
        }
        return ""
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
            }
            j += 1
        }
        return nil
    }

    private func parseMethodDef(nameIndex: Int, enclosing: String?) -> CSharpMethodDef? {
        let nameTok = tokens[nameIndex]
        let name = nameTok.text
        let openParen = nameIndex + 1
        guard openParen + 1 < tokens.count else { return nil }

        var parenDepth = 1
        var closeParen = openParen + 1
        while closeParen < tokens.count, parenDepth > 0 {
            let t = tokens[closeParen]
            if t.kind == .punct {
                if t.text == "(" { parenDepth += 1 }
                else if t.text == ")" {
                    parenDepth -= 1
                    if parenDepth == 0 { break }
                }
            }
            closeParen += 1
        }
        guard closeParen < tokens.count, parenDepth == 0 else { return nil }
        let params = parseParams(openParen: openParen, closeParen: closeParen)

        // After ')', allow C# modifiers/attributes then require '{'. C# expression
        // bodies (`=>`) and property/accessor bodies without a method body are
        // skipped.
        var j = closeParen + 1
        while j < tokens.count {
            let t = tokens[j]
            if t.kind == .operator, t.text == "@" {
                j += 1
                while j < tokens.count, tokens[j].kind == .identifier { j += 1 }
                continue
            }
            if t.kind == .identifier, t.text == "where" {
                // generic constraint clause; skip to '{' or ';'
                while j < tokens.count {
                    if tokens[j].kind == .punct, tokens[j].text == "{" { break }
                    if tokens[j].kind == .punct, tokens[j].text == ";" { return nil }
                    j += 1
                }
                continue
            }
            if t.kind == .keyword, Self.methodModifiers.contains(t.text) {
                j += 1
                continue
            }
            if t.kind == .punct, t.text == "{" { break }
            if t.kind == .punct, t.text == ";" { return nil }
            if t.kind == .operator, t.text == "=>" { return nil } // expression-bodied
            if t.kind == .operator, t.text == "(" { return nil } // call, not method
            break
        }
        guard j < tokens.count, tokens[j].kind == .punct, tokens[j].text == "{" else { return nil }

        let bodyOpen = tokens[j].offset

        // Find the matching '}' of the body.
        var depth = 1
        var k = j + 1
        while k < tokens.count, depth > 0 {
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
        guard k < tokens.count, depth == 0 else { return nil }
        let bodyClose = tokens[k]
        let endOffset = bodyClose.offset + bodyClose.text.count

        let bodyRange = NSRange(location: nameTok.offset, length: endOffset - nameTok.offset)
        let qualifiers = collectQualifiers(nameIndex: nameIndex)

        return CSharpMethodDef(name: name, params: params, bodyRange: bodyRange,
                               bodyOffset: bodyOpen, startOffset: nameTok.offset,
                               isDefinition: true, qualifiers: qualifiers)
    }

    private func collectQualifiers(nameIndex: Int) -> Set<String> {
        var q: Set<String> = []
        var j = nameIndex - 1
        while j >= 0 {
            let t = tokens[j]
            if (t.kind == .keyword || t.kind == .identifier),
               Self.methodModifiers.contains(t.text) {
                q.insert(t.text)
            } else if t.kind == .identifier, !q.isEmpty {
                break
            } else if t.kind == .punct, t.text == ")" || t.text == "}" || t.text == ";" {
                break
            }
            j -= 1
        }
        return q
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
                if t.text == "[]" || t.text == "*" || t.text == "&" {
                    typeParts.append(t.text)
                } else if t.text == "=" {
                    break
                }
            default:
                break
            }
        }
        if let pid = pendingIdent {
            name = pid.0
        }
        guard let n = name, !n.isEmpty else { return nil }
        return CAParam(type: typeParts.joined(separator: " "), name: n, offset: pendingIdent?.1 ?? group[0].offset)
    }
}

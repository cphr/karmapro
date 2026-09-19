// by cipher.org.uk
import Foundation

/// A located Java method definition with precise byte offsets (UTF-16), used by
/// the Java AST frontend. The offsets are derived from the token stream so the
/// body range is exact, which is essential for correct token slicing.
public struct JMethodDef {
    public let name: String
    public let returnType: String?     // raw return type as written (e.g. "String", "int", "boolean", "void")
    public let params: [CAParam]
    public let bodyRange: NSRange      // signature start .. closing '}' (inclusive)
    public let bodyOffset: Int         // offset of the opening '{'
    public let startOffset: Int        // offset of the method name token
    public let isDefinition: Bool
    public let isConstructor: Bool
    public let qualifiers: Set<String>
}

/// Recursive-descent parser for Java method definitions. It reuses
/// `CTokenizer`/`CAstToken` for tokenization and detects methods that have a
/// real `{ }` body (in top-level and nested class/interface/enum bodies),
/// producing exact source ranges. Interface/abstract method declarations (those
/// ending in `;`) and annotations are skipped.
public final class JParser {
    private let source: String
    private let tokens: [CAstToken]

    public init(source: String) {
        self.source = source
        self.tokens = CTokenizer(source: source).tokenize()
    }

    private static let typeKeywords: Set<String> = ["class", "interface", "enum", "record", "annotation"]
    private static let methodModifiers: Set<String> = [
        "public", "private", "protected", "static", "final", "abstract", "synchronized",
        "native", "strictfp", "default", "transient", "volatile", "void"
    ]

    public func parseMethods() -> [JMethodDef] {
        var defs: [JMethodDef] = []
        let n = tokens.count
        var braceDepth = 0
        // Open type bodies: (name, braceDepth at which the body's '{' opens)
        // Open type bodies: (name, brace depth INSIDE the type body)
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

            // Type declaration: class/interface/enum/record/@interface ... { }
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

            // Method definition candidate: identifier '(' ... ')' 'throws ...' '{'
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

        // Deduplicate by name + parameter arity, keeping the first (body-bearing)
        // definition so that genuinely distinct overloads (e.g. a no-arg and a
        // parameterized constructor that stores its param into a field) are all
        // analyzed instead of collapsing onto the first (mirrors the C path, but
        // the name alone would drop constructors with different arities entirely).
        var seen = Set<String>()
        var result: [JMethodDef] = []
        for d in defs {
            let key = "\(d.name)#\(d.params.count)"
            if !seen.contains(key) {
                seen.insert(key)
                result.append(d)
            }
        }
        return result
    }

    /// Returns the type name (first identifier after the class/interface keyword).
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

    /// Finds the token index of the '{' that opens a type body, scanning forward
    /// from just after the type keyword at paren depth 0.
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

    /// Parses a candidate method starting at the name token. Returns nil if the
    /// signature is not followed by a real body '{' (e.g. it is a call or an
    /// interface/abstract declaration ending in ';').
    private func parseMethodDef(nameIndex: Int, enclosing: String?) -> JMethodDef? {
        let nameTok = tokens[nameIndex]
        let name = nameTok.text
        // '(' at nameIndex+1
        let openParen = nameIndex + 1
        guard openParen + 1 < tokens.count else { return nil }

        // Find the matching ')' of the parameter list.
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

        // Everything between the last modifier/annotation and the method name
        // is the return type. Constructors have no return type.
        let returnType = parseReturnType(before: nameIndex)

        // After ')', skip a 'throws' clause and any annotations, then require '{'.
        var j = closeParen + 1
        while j < tokens.count {
            let t = tokens[j]
            if t.kind == .keyword, t.text == "throws" {
                // skip the exception list (identifiers, dots, commas) until '{' or ';'
                while j < tokens.count {
                    let tt = tokens[j]
                    if tt.kind == .punct, tt.text == "{" { break }
                    if tt.kind == .punct, tt.text == ";" { return nil }
                    if tt.kind == .operator, tt.text == "(" { break }
                    j += 1
                }
                continue
            }
            if t.kind == .operator, t.text == "@" {
                j += 1
                while j < tokens.count, tokens[j].kind == .identifier { j += 1 }
                continue
            }
            if t.kind == .keyword, Self.methodModifiers.contains(t.text) {
                j += 1
                continue
            }
            if t.kind == .punct, t.text == "{" {
                break
            }
            if t.kind == .punct, t.text == ";" { return nil }
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
        let isConstructor = name == (enclosing ?? "")

        return JMethodDef(name: name, returnType: returnType, params: params, bodyRange: bodyRange,
                          bodyOffset: bodyOpen, startOffset: nameTok.offset,
                          isDefinition: true, isConstructor: isConstructor, qualifiers: qualifiers)
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

    /// Extracts the type and name of a single parameter token group. The last
    /// identifier (that isn't itself a nested type token before a generic) is the
    /// parameter name.
    private func paramFrom(_ group: [CAstToken]) -> CAParam? {
        guard !group.isEmpty else { return nil }
        // Find the last identifier before a top-level '=' default or end.
        var name: String? = nil
        var nameOff = group[0].offset
        var typeParts: [String] = []
        var pendingIdent: (String, Int)? = nil

        for t in group {
            switch t.kind {
            case .identifier:
                pendingIdent = (t.text, t.offset)
                typeParts.append(t.text)
            case .keyword:
                typeParts.append(t.text)
            case .operator:
                typeParts.append(t.text)  // '.', '...', '[]', generics <,>
            case .punct:
                typeParts.append(t.text)
            default:
                break
            }
        }
        if let id = pendingIdent {
            name = id.0
            nameOff = id.1
            typeParts = typeParts.filter { $0 != id.0 }
        }
        let type = typeParts.isEmpty ? nil : typeParts.joined(separator: "")
        return CAParam(type: type, name: name, offset: nameOff)
    }

    /// Collects modifier keywords preceding the method name (for race/qualifier use).
    private func collectQualifiers(nameIndex: Int) -> Set<String> {
        var set = Set<String>()
        var j = nameIndex - 1
        while j >= 0 {
            let t = tokens[j]
            if t.kind == .keyword {
                if Self.methodModifiers.contains(t.text) { set.insert(t.text) }
                else if Self.typeKeywords.contains(t.text) { break }
                else if ["extends", "implements", "throws", "return", "if", "else", "while", "for"].contains(t.text) { break }
                j -= 1
                continue
            }
            if t.kind == .identifier || t.kind == .operator {
                j -= 1
                continue
            }
            if t.kind == .punct {
                if t.text == ";" || t.text == "{" || t.text == "}" || t.text == "(" { break }
                j -= 1
                continue
            }
            break
        }
        return set
    }

    /// Returns the raw return type tokens preceding the method name (skipping
    /// modifiers/annotations and generic punctuation). Constructors return nil.
    private func parseReturnType(before nameIndex: Int) -> String? {
        var parts: [String] = []
        var j = nameIndex - 1
        while j >= 0 {
            let t = tokens[j]
            if t.kind == .keyword, Self.methodModifiers.contains(t.text) { break }
            if t.kind == .keyword, t.text == "void" { parts.insert(t.text, at: 0); j -= 1; continue }
            if t.kind == .keyword, t.text == "throws" { break }
            if t.kind == .identifier, Self.typeKeywords.contains(t.text) { break }
            if t.kind == .punct, t.text == "{" || t.text == ";" || t.text == ")" { break }
            if t.kind == .identifier || t.kind == .keyword || t.kind == .operator || t.kind == .punct {
                parts.insert(t.text, at: 0)
            }
            j -= 1
        }
        let joined = parts.joined(separator: " ").trimmingCharacters(in: .whitespaces)
        return joined.isEmpty ? nil : joined
    }
}

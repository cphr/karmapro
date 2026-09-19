// by cipher.org.uk
import Foundation

/// Computes the type of a variable (or the return type of a function / a type name)
/// at a given character offset in a C, C++, or Java source file.
///
/// Scope covered by this lightweight resolver:
///   - Local variable declarations inside function bodies (including pointer,
///     array, and comma-separated declarators, and qualifiers like const/static).
///   - Function and method parameters (mapped from `Type param`).
///   - Struct / class / union fields.
///   - Global (file-scope) variables and typedefs.
///   - Function return types, so hovering a function name reports its return type.
///   - Java fields and primitives.
///
/// Not covered (accepted as out of scope): `auto`/`var` type inference, template /
/// generic substitution, and cross-file resolution.
enum TypeResolver {

    /// The declared type string for a variable, or the return type for a function,
    /// or a description for other identifiers. Returns nil when nothing is known.
    static func type(at charIndex: Int, in source: String, language: Language) -> String? {
        guard charIndex >= 0 && charIndex <= (source as NSString).length else { return nil }

        let lang: LangKind
        if language.name == "C" {
            lang = .c
        } else if language.name == "C++" {
            lang = .cpp
        } else if language.name == "Java" {
            lang = .java
        } else if language.name == "C#" {
            lang = .csharp
        } else {
            return nil
        }

        let parser = Parser(source: source, lang: lang)
        parser.parse()

        // 1) Resolve the identifier whose span contains (or is just left of) offset.
        guard let span = parser.wordSpan(containing: charIndex) else { return nil }
        let word = (source as NSString).substring(with: span)

        // 2) A function definition name at this offset -> return type (and params).
        if let fn = parser.functionName(range: span) {
            return "returns \(fn.returnType)" + (fn.parameters.isEmpty ? "" : paramsString(fn.parameters))
        }

        // 3) A type name itself (e.g. hovering `MyStruct`) -> "type".
        if parser.isKnownTypeName(word) {
            return "type: \(word)"
        }

        // 4) Variable / field lookup, innermost scope first.
        if let type = parser.resolveVariable(named: word, at: charIndex) {
            return "\(normalizedType(type))"
        }

        return nil
    }

    /// Tidies a declared type string for display: removes spaces that sit directly
    /// adjacent to array brackets (`double []` -> `double[]`) while preserving
    /// meaningful spaces in pointer/qualified types (`const Shape *`, `std::string`).
    private static func normalizedType(_ s: String) -> String {
        var out = s.replacingOccurrences(of: " [", with: "[")
        out = out.replacingOccurrences(of: " ]", with: "]")
        out = out.replacingOccurrences(of: "[] ", with: "[]")
        // Collapse spaces that separate `std :: string` into `std::string`.
        out = out.replacingOccurrences(of: " :: ", with: "::")
        out = out.replacingOccurrences(of: ":: ", with: "::")
        out = out.replacingOccurrences(of: " ::", with: "::")
        return out
    }

    private static func paramsString(_ params: [(name: String?, type: String)]) -> String {
        let parts = params.map { p -> String in
            if let n = p.name { return "\(p.type) \(n)" }
            return p.type
        }
        return " (\(parts.joined(separator: ", ")))"
    }

    private enum LangKind { case c, cpp, java, csharp }

    // MARK: - Token model

    private struct Token {
        enum Kind { case ident, number, string, other }
        let kind: Kind
        let text: String
        let location: Int
        let length: Int
    }

    private struct Variable {
        let name: String
        let type: String
        let scopeStart: Int   // offset of the opening brace of the scope that declared it
        let scopeEnd: Int     // offset of the matching closing brace
        let atOrAfter: Int    // declaration offset; only matches if offset >= this
    }

    private struct FunctionInfo {
        let name: String
        let nameRange: NSRange
        let returnType: String
        let parameters: [(name: String?, type: String)]
        let bodyStart: Int
        let bodyEnd: Int
    }

    // MARK: - Parser

    private final class Parser {
        let source: String
        let ns: NSString
        let lang: LangKind

        private var tokens: [Token] = []
        var typeNames: Set<String> = []
        var variables: [Variable] = []
        var functions: [FunctionInfo] = []
        private var bracePairs: [(Int, Int)] = []

        private static let qualifiers: Set<String> = [
            "const", "volatile", "static", "extern", "register", "auto", "restrict",
            "inline", "unsigned", "signed", "long", "short", "typedef", "struct",
            "union", "enum", "class", "constexpr", "final", "abstract", "transient",
            "volatile",
            // C#
            "public", "private", "protected", "internal", "readonly", "sealed",
            "virtual", "override", "abstract", "new", "async", "ref", "out", "in",
            "params", "unsafe", "fixed", "stackalloc",
            // JavaScript/TypeScript
            "let", "var", "const", "function", "async", "await", "yield", "export",
            "import", "default", "extends", "implements", "interface", "type",
            "enum", "namespace", "module", "declare", "abstract", "readonly",
            "private", "protected", "public", "static", "get", "set", "constructor"
        ]

        private static let cPrimitives: Set<String> = [
            "int", "char", "float", "double", "void", "bool", "short", "long",
            "unsigned", "signed", "size_t", "ssize_t", "int8_t", "int16_t", "int32_t",
            "int64_t", "uint8_t", "uint16_t", "uint32_t", "uint64_t", "uintptr_t",
            "intptr_t", "ptrdiff_t", "wchar_t", "char16_t", "char32_t", "FILE", "NULL",
            "uint", "byte", "off_t", "pid_t", "uid_t", "gid_t", "mode_t", "time_t"
        ]

        private static let javaPrimitives: Set<String> = [
            "int", "long", "short", "byte", "char", "float", "double", "boolean",
            "void", "String", "Object", "Integer", "Long", "Short", "Byte", "Character",
            "Double", "Float", "Boolean", "Void", "Class", "Exception", "Throwable",
            "RuntimeException", "Error", "Number", "Boolean"
        ]

        private static let csharpPrimitives: Set<String> = [
            "int", "long", "short", "byte", "sbyte", "uint", "ulong", "ushort",
            "char", "float", "double", "bool", "void", "decimal", "object", "string",
            "char", "DateTime", "Guid", "Task", "IEnumerable", "IEnumerator", "IList",
            "ICollection", "IDictionary", "List", "Dictionary", "Array", "Nullable"
        ]

        init(source: String, lang: LangKind) {
            self.source = source
            self.ns = source as NSString
            self.lang = lang
        }

        func parse() {
            tokenize()
            discoverTypeNames()
            parseBodies()
        }

        // MARK: Tokenizer (skips comments, strings, preprocessor)

        private func tokenize() {
            let length = ns.length
            var i = 0
            while i < length {
                let ch = ns.character(at: i)

                // Preprocessor lines (C/C++/C#): skip to end of line.
                if (lang != .java && lang != .csharp) && ch == 0x23 /* # */ {
                    while i < length && ns.character(at: i) != 0x0A { i += 1 }
                    continue
                }
                // Line comment
                if ch == 0x2F && i + 1 < length && ns.character(at: i + 1) == 0x2F {
                    while i < length && ns.character(at: i) != 0x0A { i += 1 }
                    continue
                }
                // Block comment
                if ch == 0x2F && i + 1 < length && ns.character(at: i + 1) == 0x2A {
                    i += 2
                    while i + 1 < length && !(ns.character(at: i) == 0x2A && ns.character(at: i + 1) == 0x2F) { i += 1 }
                    i += 2
                    continue
                }
                // String / char literal
                if ch == 0x22 || ch == 0x27 || ch == 0x60 { // " ' `
                    let quote = ch
                    let start = i
                    i += 1
                    while i < length {
                        if ns.character(at: i) == 0x5C { i += 2; continue }
                        if ns.character(at: i) == quote { i += 1; break }
                        i += 1
                    }
                    tokens.append(Token(kind: .string, text: ns.substring(with: NSRange(location: start, length: i - start)), location: start, length: i - start))
                    continue
                }
                // Identifier
                if isAlpha(ch) || ch == 0x5F || ch == 0x24 { // $ for jQuery
                    let start = i
                    while i < length && (isAlpha(ns.character(at: i)) || isDigit(ns.character(at: i)) || ns.character(at: i) == 0x5F) { i += 1 }
                    let text = ns.substring(with: NSRange(location: start, length: i - start))
                    tokens.append(Token(kind: .ident, text: text, location: start, length: i - start))
                    continue
                }
                // Number
                if isDigit(ch) {
                    let start = i
                    while i < length && (isDigit(ns.character(at: i)) || ns.character(at: i) == 0x2E) { i += 1 }
                    tokens.append(Token(kind: .number, text: ns.substring(with: NSRange(location: start, length: i - start)), location: start, length: i - start))
                    continue
                }
                // Whitespace: skip (space, tab, newline, CR).
                if ch == 0x20 || ch == 0x09 || ch == 0x0A || ch == 0x0D {
                    i += 1
                    continue
                }
                // C++ scope-resolution operator `::` as a single token.
                if ch == 0x3A && i + 1 < length && ns.character(at: i + 1) == 0x3A {
                    tokens.append(Token(kind: .other, text: "::", location: i, length: 2))
                    i += 2
                    continue
                }
                // Generic punctuation/operator
                tokens.append(Token(kind: .other, text: String(UnicodeScalar(ch) ?? " "), location: i, length: 1))
                i += 1
            }
        }

        // MARK: Type-name discovery

        private func isAlpha(_ c: unichar) -> Bool {
            (c >= 0x41 && c <= 0x5A) || (c >= 0x61 && c <= 0x7A)
        }
        private func isDigit(_ c: unichar) -> Bool {
            c >= 0x30 && c <= 0x39
        }

        private func discoverTypeNames() {
            // Primitives are always valid type names.
            for p in Parser.cPrimitives { typeNames.insert(p) }
            for p in Parser.javaPrimitives { typeNames.insert(p) }
            for p in Parser.csharpPrimitives { typeNames.insert(p) }
            let n = tokens.count
            var i = 0
            while i < n {
                let t = tokens[i]
                if t.kind != .ident { i += 1; continue }

                // struct/union/enum/class NAME
                if (t.text == "struct" || t.text == "union" || t.text == "enum" || t.text == "class" || t.text == "interface")
                    && i + 1 < n, tokens[i + 1].kind == .ident {
                    typeNames.insert(tokens[i + 1].text)
                }
                // C++ `using NAME =` (alias) and Java generic `class NAME<...>`
                if t.text == "using" && i + 1 < n, tokens[i + 1].kind == .ident {
                    if i + 2 < n, tokens[i + 2].text == "=" {
                        typeNames.insert(tokens[i + 1].text)
                    }
                }
                // TypeScript `type NAME =` / `interface NAME`
                if (t.text == "type" || t.text == "interface") && i + 1 < n, tokens[i + 1].kind == .ident {
                    if i + 2 < n && tokens[i + 2].text == "=" {
                        typeNames.insert(tokens[i + 1].text)
                    } else {
                        typeNames.insert(tokens[i + 1].text)
                    }
                }
                // typedef declaration -- the LAST identifier before ';'
                if t.text == "typedef" {
                    var j = i + 1
                    var lastIdent: String?
                    while j < n, tokens[j].text != ";" {
                        if tokens[j].kind == .ident { lastIdent = tokens[j].text }
                        j += 1
                    }
                    if let name = lastIdent { typeNames.insert(name) }
                }
                // C# / Java / JS: capitalized identifier in type position -> type name
                if lang == .java || lang == .csharp {
                    if let first = t.text.first, first.isUppercase {
                        typeNames.insert(t.text)
                    }
                }
                i += 1
            }
        }

        func isKnownTypeName(_ word: String) -> Bool {
            typeNames.contains(word)
        }

        // MARK: Brace pairing

        private func computeBracePairs() {
            guard bracePairs.isEmpty else { return }
            var stack: [(Int, Int)] = [] // location of '{'
            var i = 0
            for t in tokens {
                if t.text == "{" { stack.append((t.location, i)) }
                else if t.text == "}" {
                    if let top = stack.popLast() {
                        bracePairs.append((top.0, t.location))
                    }
                }
                i += 1
            }
        }

        // MARK: Body parsing

        private func parseBodies() {
            computeBracePairs()

            // Identify function-like scopes: `name ( params ) {` where the '{' token
            // is preceded (ignoring qualifiers) by a closing ')', and that ')' belongs
            // to a parameter list whose opening '(' was preceded by an identifier.
            let n = tokens.count
            var i = 0
            var depth = 0
            var braceOffsetToDepth: [Int: Int] = [:]
            var allBraceOpen: [(offset: Int, tokenIndex: Int)] = []

            for (idx, t) in tokens.enumerated() {
                if t.text == "{" {
                    braceOffsetToDepth[t.location] = depth
                    allBraceOpen.append((t.location, idx))
                    depth += 1
                } else if t.text == "}" {
                    depth -= 1
                    braceOffsetToDepth[t.location] = depth
                }
            }

            // First pass: find function definitions so we can parse their params/bodies
            // and treat struct/class bodies as field scopes.
            i = 0
            while i < n {
                let t = tokens[i]
                if t.text == "{" {
                    // Check if this '{' is a function body: preceding token (ignore
                    // qualifiers that may appear between ')' and '{') is ')'.
                    var k = i - 1
                    while k >= 0 && tokens[k].text != ")" && isQualifierToken(k) { k -= 1 }
                    if k >= 0, tokens[k].text == ")" {
                        // Find matching '(' for params
                        if let (paramsOpenIdx, fnNameIdx, returnType) = parameterListInfo(beforeBraceIndex: k, depthAt: t.location) {
                            let bodyEnd = closingBrace(forOpen: t.location) ?? ns.length
                            let fn = FunctionInfo(name: tokens[fnNameIdx].text,
                                                  nameRange: NSRange(location: tokens[fnNameIdx].location, length: tokens[fnNameIdx].length),
                                                  returnType: returnType,
                                                  parameters: parseParameters(openParenIndex: paramsOpenIdx),
                                                  bodyStart: t.location,
                                                  bodyEnd: bodyEnd)
                            functions.append(fn)
                            // Declare parameters in function scope.
                            let scopeStart = t.location
                            let scopeEnd = bodyEnd
                            for param in fn.parameters {
                                if let name = param.name {
                                    variables.append(Variable(name: name, type: param.type, scopeStart: scopeStart, scopeEnd: scopeEnd, atOrAfter: t.location))
                                }
                            }
                            i = indexOfToken(atOrAfter: t.location) + 1 // continue after the body's opening '{'
                            continue
                        }
                    }
                }
                i += 1
            }

            // Second pass: parse struct/class/union bodies for fields.
            parseTypeBodies(allBraceOpen: allBraceOpen, braceOffsetToDepth: braceOffsetToDepth)

            // Third pass: parse simple local variable declarations inside bodies, and
            // global declarations outside any brace scope.
            parseDeclarations(allBraceOpen: allBraceOpen, braceOffsetToDepth: braceOffsetToDepth)
        }

        private func isQualifierToken(_ idx: Int) -> Bool {
            let t = tokens[idx]
            // qualifiers are identifiers/text that are part of the return-type,
            // not a statement. Only treat the specific suffix qualifiers as skip-able.
            return t.kind == .ident && Parser.qualifiers.contains(t.text) ||
                   t.text == "*" || t.text == "&" || t.text == "::" || t.text == "<" ||
                   (t.kind == .number)
        }

        /// Given the ')' that closes a parameter list (token index k), finds the
        /// parameter opening '(' token index, the function-name token index, and the
        /// return type string. Returns nil if not a function-like header.
        private func parameterListInfo(beforeBraceIndex k: Int, depthAt: Int) -> (paramsOpenIdx: Int, fnNameIdx: Int, returnType: String)? {
            // Walk back from k to find matching '('.
            var open = -1
            var p = k - 1
            var pd = 0
            while p >= 0 {
                if tokens[p].text == ")" { pd += 1 }
                else if tokens[p].text == "(" {
                    if pd == 0 { open = p; break }
                    pd -= 1
                }
                p -= 1
            }
            guard open >= 0 else { return nil }
            // The function name is the identifier immediately before '('. Skip
            // template args `name<...>(` by walking past '>' ... '<'.
            var q = open - 1
            while q >= 0 && tokens[q].text == ">" {
                // skip matching <
                var tpl = 0
                var r = q
                while r >= 0 {
                    if tokens[r].text == ">" { tpl += 1 }
                    else if tokens[r].text == "<" {
                        tpl -= 1
                        if tpl == 0 { q = r - 1; break }
                    }
                    r -= 1
                }
            }
            while q >= 0 && (tokens[q].text == "*" || tokens[q].text == "&" || tokens[q].text == "::") { q -= 1 }
            guard q >= 0, tokens[q].kind == .ident else { return nil }

            let fnNameIdx = q
            // Return type = identifiers/qualifiers from the start of this declaration up
            // to just before the function name.
            var start = fnNameIdx - 1
            while start >= 0 && (tokens[start].text != ";" && tokens[start].text != "{" && tokens[start].text != "}") {
                start -= 1
            }
            start += 1
            let retEnd = fnNameIdx
            var parts: [String] = []
            if start < retEnd {
                for idx in start..<retEnd {
                    let tt = tokens[idx]
                    if tt.text == "(" || tt.text == ")" { break }
                    parts.append(tt.text)
                }
            }
            let returnType = parts.joined(separator: " ").trimmingCharacters(in: .whitespaces)
            return (open, fnNameIdx, returnType.isEmpty ? "void" : returnType)
        }

        private func parseParameters(openParenIndex: Int) -> [(name: String?, type: String)] {
            var result: [(name: String?, type: String)] = []
            var pd = 0
            var j = openParenIndex + 1
            let n = tokens.count
            var typeWords: [String] = []
            var paramName: String? = nil
            while j < n {
                let t = tokens[j]
                if t.text == "(" { pd += 1 }
                else if t.text == ")" {
                    if pd == 0 { break }
                    pd -= 1
                }
                if t.text == "," && pd == 0 {
                    result.append((paramName, typeWords.joined(separator: " ")))
                    typeWords = []; paramName = nil
                    j += 1
                    continue
                }
                if pd == 0 {
                    if t.kind == .ident {
                        if isTypeTokenName(t.text) || Parser.qualifiers.contains(t.text) {
                            typeWords.append(t.text)
                        } else if paramName == nil {
                            // First non-type identifier is the parameter name, but a
                            // pointer follows may be part of a `Type* name` — still the
                            // pointer after the name is part of the *type* of future
                            // usage. We treat the first non-type ident as the name.
                            paramName = t.text
                        } else {
                            // secondary identifier (shouldn't happen in simple decls)
                            typeWords.append(t.text)
                        }
                    } else if t.text == "*" || t.text == "&" || t.text == "&&" || t.text == "::" || t.text == "<" || t.text == ">" || t.text == "," {
                        if t.text != "," { typeWords.append(t.text) }
                    }
                }
                j += 1
            }
            result.append((paramName, typeWords.joined(separator: " ")))
            return result
        }

        private func isTypeTokenName(_ w: String) -> Bool {
            typeNames.contains(w)
        }

        // MARK: closing-brace lookup

        private func closingBrace(forOpen openOffset: Int) -> Int? {
            // recompute matching from bracePairs
            for pair in bracePairs where pair.0 == openOffset {
                return pair.1
            }
            return nil
        }

        private func indexOfToken(atOrAfter offset: Int) -> Int {
            for (idx, t) in tokens.enumerated() where t.location >= offset {
                return idx
            }
            return tokens.count
        }

        // MARK: Struct/class field bodies

        private func parseTypeBodies(allBraceOpen: [(offset: Int, tokenIndex: Int)], braceOffsetToDepth: [Int: Int]) {
            // A body is a "type body" if it is immediately preceded (ignoring
            // qualifiers) by `class/struct/union/enum NAME` OR in Java by
            // `CLASSNAME` header ending in `{`.
            for open in allBraceOpen {
                let bodyStart = open.offset
                var k = open.tokenIndex - 1
                while k >= 0 && (tokens[k].text == "{" || tokens[k].text == "}" || tokens[k].text == ";" || tokens[k].text == ":") { k -= 1 }
                // Determine if preceded by struct/class/union/enum name
                var isTypeBody = false
                if k >= 1, tokens[k].kind == .ident,
                   (tokens[k-1].text == "struct" || tokens[k-1].text == "union" || tokens[k-1].text == "class" || tokens[k-1].text == "enum") {
                    isTypeBody = true
                } else if lang == .java, k >= 0, tokens[k].kind == .ident {
                    // Java: `class Name {` / `interface Name {`/`record`, or a class with
                    // generic header `class Name<...> {`. Heuristic: previous ident is a
                    // type name and there's a class/interface/record token within the last 4.
                    var m = k
                    var count = 0
                    var isClass = false
                    while m >= 0 && count < 4 {
                        if tokens[m].text == "class" || tokens[m].text == "interface" || tokens[m].text == "record" || tokens[m].text == "@interface" {
                            isClass = true; break
                        }
                        if tokens[m].text == ";" || tokens[m].text == "{" || tokens[m].text == "}" { break }
                        m -= 1; count += 1
                    }
                    isTypeBody = isClass
                } else if k >= 3, tokens[k].kind == .ident, tokens[k-1].text == "::" {
                    // C++ out-of-class member definitions are methods, not field bodies;
                    // handled by function detection instead.
                    isTypeBody = false
                }

                if isTypeBody {
                    let bodyEnd = closingBrace(forOpen: bodyStart) ?? open.offset
                    let depth = braceOffsetToDepth[bodyStart] ?? 0
                    parseFields(in: (bodyStart, bodyEnd), depth: depth, tokenStart: open.tokenIndex + 1)
                }
            }
        }

        private func parseFields(in range: (Int, Int), depth: Int, tokenStart: Int) {
            // Iterate tokens within the body (top-level only, don't descend into nested
            // braces) splitting on ';' and skipping access specifiers & methods.
            var i = tokenStart
            let n = tokens.count
            var braceDepth = 0
            var current: [String] = []
            let consumedUntil = range.1
            while i < n {
                let t = tokens[i]
                if t.location >= range.1 { break }
                if t.text == "{" { braceDepth += 1; i += 1; continue }
                if t.text == "}" { braceDepth -= 1; i += 1; continue }
                if braceDepth > 0 { i += 1; continue }
                if t.text == ";" {
                    if let field = fieldFromWords(current) {
                        variables.append(Variable(name: field.name, type: field.type, scopeStart: range.0, scopeEnd: range.1, atOrAfter: range.0))
                    }
                    current = []
                    i += 1
                    continue
                }
                if t.text == "(" {
                    // Method declaration/definition inside class -> skip to matching ).
                    var pd = 0
                    var j = i
                    while j < n {
                        if tokens[j].text == "(" { pd += 1 }
                        else if tokens[j].text == ")" {
                            pd -= 1
                            if pd == 0 { i = j; break }
                        }
                        j += 1
                    }
                    i += 1
                    continue
                }
                // access specifiers
                if t.kind == .ident && (t.text == "public" || t.text == "private" || t.text == "protected") {
                    current = []
                    i += 1
                    continue
                }
                if t.kind == .ident {
                    current.append(t.text)
                } else if t.text == "<" || t.text == ">" || t.text == "::" || t.text == "*" || t.text == "&" || t.text == "[" && nextIsArray(tokens, i) {
                    // arrays appended separately below
                }
                i += 1
            }
            _ = consumedUntil
        }

        private func nextIsArray(_ tokens: [Token], _ i: Int) -> Bool { true }

        /// Extracts a field name + type from collected words of a `Type name ...;`
        /// declaration, handling pointers and arrays.
        private func fieldFromWords(_ words: [String]) -> (name: String, type: String)? {
            guard words.count >= 2 else { return nil }
            let name = words[words.count - 1]
            if isTypeTokenName(name) || Parser.qualifiers.contains(name) { return nil }
            let type = words.dropLast().joined(separator: " ")
            return (name, type.isEmpty ? "unknown" : type)
        }

        // MARK: Local & global declarations

        private func parseDeclarations(allBraceOpen: [(offset: Int, tokenIndex: Int)], braceOffsetToDepth: [Int: Int]) {
            let n = tokens.count
            var i = 0
            while i < n {
                let t = tokens[i]

                // A declaration candidate starts at (a) a known type name, (b) a
                // `std::...`-style qualified type head, or (c) a Java array type head
                // like `double[] name`.
                if t.kind == .ident, declarationStartCandidate(at: i) {
                    let (type, nameTokenIndex, next) = consumeDeclaration(from: i)
                    if let ni = nameTokenIndex, ni < n, tokens[ni].kind == .ident,
                       !isTypeTokenName(tokens[ni].text), !parserQualifier(tokens[ni].text) {
                        let name = tokens[ni].text
                        declareIfApplicable(name: name, type: type, at: tokens[i].location)

                        // Handle array suffix that appears after the name (C style):
                        // `int arr[10];`
                        let ai = ni + 1
                        let baseType = type
                        if ai < n, tokens[ai].text == "[" {
                            let (dims, after) = consumeBracketedRange(from: ai)
                            let suffix = dims
                            if let idx = variables.lastIndex(where: { $0.name == name && $0.type == baseType }) {
                                variables[idx] = Variable(name: name, type: variables[idx].type + suffix,
                                                          scopeStart: variables[idx].scopeStart, scopeEnd: variables[idx].scopeEnd,
                                                          atOrAfter: variables[idx].atOrAfter)
                            }
                            i = after
                        } else {
                            i = next > ni ? next : ni + 1
                        }
                        continue
                    } else {
                        i = next > i ? next : i + 1
                        continue
                    }
                }
                i += 1
            }
        }

        /// True if token `i` (an identifier) could begin a declaration: it is a known
        /// type name, or starts a qualified `A::B` chain, or is immediately followed by
        /// `[` (Java `double[] name`) or by a template/pointer that leads to a name
        /// plus a following declarator terminator (`=`, `;`, `[`).
        private func declarationStartCandidate(at i: Int) -> Bool {
            if isTypeTokenName(tokens[i].text) { return true }
            // Qualified head: `std::`
            if i + 1 < tokens.count, tokens[i + 1].text == "::" { return true }
            // Java array head: `double[...] name` where the ident is a known type.
            if i + 1 < tokens.count, tokens[i + 1].text == "[" { return true }
            return false
        }

        /// Consumes a full declaration's type and name starting at token `i` (the type
        /// head). Returns the type string, the token index of the variable name (if
        /// any), and the token index to resume scanning after the declarator.
        private func consumeDeclaration(from start: Int) -> (type: String, nameIndex: Int?, next: Int) {
            let n = tokens.count
            var ti = start
            var typeWords: [String] = []
            let bracketDepth = 0
            var templateDepth = 0
            var nameIndex: Int? = nil

            while ti < n {
                let tok = tokens[ti]
                let text = tok.text

                // Statement terminators -> stop.
                if text == ";" || text == "=" || text == "(" { break }
                if text == "{" { break } // a control-flow block, not a declaration here

                if text == "[" {
                    // Brackets: if a name hasn't been found yet, these are part of the
                    // type (Java `double[] name`). If a name was found, they are the
                    // C-style array suffix `name[N]` (handled by caller). We consume
                    // type-level brackets into the type.
                    if nameIndex == nil {
                        let (dims, after) = consumeBracketedRange(from: ti)
                        typeWords.append(dims)
                        ti = after
                        continue
                    } else {
                        break
                    }
                }
                if text == ">" && templateDepth > 0 { templateDepth -= 1; typeWords.append(text); ti += 1; continue }
                if text == "<" { templateDepth += 1; typeWords.append(text); ti += 1; continue }

                if tok.kind == .ident {
                    let precededByColon = ti > 0 && tokens[ti - 1].text == "::"
                    let followedByColon = ti + 1 < n && tokens[ti + 1].text == "::"
                    if nameIndex == nil && !isTypeTokenName(text) && !Parser.qualifiers.contains(text) {
                        if precededByColon || followedByColon {
                            // Qualified-name component (e.g. `std::string`): belongs to
                            // the type.
                            typeWords.append(text)
                        } else {
                            // First non-type identifier not part of a `::` chain => the
                            // variable name.
                            nameIndex = ti
                            break
                        }
                    } else {
                        typeWords.append(text)
                    }
                } else if text == "*" || text == "&" || text == "::" || text == "..." {
                    typeWords.append(text)
                }
                ti += 1
            }
            _ = bracketDepth
            return (typeWords.joined(separator: " "), nameIndex, ti)
        }

        /// Consumes `[...]` nesting starting at token index `start` (the opening `[`
        /// token). Returns the textual `[ ... ]` and the index past the closing `]`.
        private func consumeBracketedRange(from start: Int) -> (String, Int) {
            let n = tokens.count
            var out: [String] = []
            var depth = 0
            var ti = start
            while ti < n {
                let t = tokens[ti].text
                if t == "[" {
                    if depth == 0 { out.append("[") }
                    else { out.append(t) }
                    depth += 1
                    ti += 1
                } else if t == "]" {
                    out.append("]")
                    depth -= 1
                    ti += 1
                    if depth == 0 { break }
                } else if t == ";" || t == "=" || t == "(" {
                    break
                } else {
                    out.append(t)
                    ti += 1
                }
            }
            return (out.joined(separator: ""), ti)
        }

        private func parserQualifier(_ w: String) -> Bool {
            Parser.qualifiers.contains(w)
        }

        private func declareIfApplicable(name: String, type: String, at offset: Int) {
            let scope = enclosingBraceScope(at: offset)
            variables.append(Variable(name: name, type: type, scopeStart: scope.0, scopeEnd: scope.1, atOrAfter: offset))
        }

        private func enclosingBraceScope(at offset: Int) -> (Int, Int) {
            // Find the innermost brace-pair containing offset.
            var best: (Int, Int) = (0, ns.length)
            for pair in bracePairs where pair.0 <= offset && offset <= pair.1 {
                if pair.0 >= best.0 { best = pair }
            }
            return best
        }

        // MARK: word-span / hit testing

        func wordSpan(containing offset: Int) -> NSRange? {
            // Prefer an identifier token that spans the offset (or starts at it, if we
            // are at the very first char of the word).
            for t in tokens where t.kind == .ident {
                if offset >= t.location && offset <= t.location + t.length {
                    if offset == t.location + t.length {
                        // allow if not the next token's start
                    }
                    return NSRange(location: t.location, length: t.length)
                }
            }
            return nil
        }

        func resolveVariable(named word: String, at offset: Int) -> String? {
            var best: Variable?
            for v in variables where v.name == word && offset >= v.atOrAfter && offset >= v.scopeStart && offset <= v.scopeEnd {
                if best == nil || v.scopeStart > best!.scopeStart {
                    best = v
                }
            }
            return best?.type
        }

        func functionContaining(_ offset: Int) -> FunctionInfo? {
            var best: FunctionInfo?
            for f in functions where offset >= f.bodyStart && offset <= f.bodyEnd {
                if best == nil || f.bodyStart > best!.bodyStart {
                    best = f
                }
            }
            return best
        }

        func functionName(range: NSRange) -> FunctionInfo? {
            for f in functions {
                if f.nameRange.location == range.location && f.nameRange.length >= 1 {
                    return f
                }
            }
            return nil
        }
    }
}

// by cipher.org.uk
import Foundation

/// Recursive-descent parser for C/C++ producing the AST in CAstNode.swift.
///
/// This is a practical parser tuned for real-world source rather than a fully
/// conforming C++ grammar front-end. It handles the mainstream constructs used
/// in security-sensitive code (functions, control flow, expressions, pointer
/// arithmetic, casts, member access, initializer lists) with source positions.
/// Where the grammar is ambiguous (notably declaration-vs-expression), it uses
/// bounded lookahead heuristics and favors the more common meaning.
public final class CParser {
    private let tokens: [CAstToken]
    private var pos = 0
    private let isPHP: Bool
    private let isGo: Bool

    public init(tokens: [CAstToken], isPHP: Bool = false, isGo: Bool = false) {
        self.tokens = tokens
        self.isPHP = isPHP
        self.isGo = isGo
    }

    // MARK: - Token helpers

    private var current: CAstToken { tokens[pos] }
    private var peek: CAstToken { pos + 1 < tokens.count ? tokens[pos + 1] : tokens[tokens.count - 1] }
    private func peekAheadIsOp(_ ahead: Int, _ text: String) -> Bool {
        let idx = pos + ahead
        return idx < tokens.count && tokens[idx].kind == .operator && tokens[idx].text == text
    }

    private func isKeyword(_ text: String) -> Bool { current.kind == .keyword && current.text == text }
    private func isPunct(_ text: String) -> Bool { current.kind == .punct && current.text == text }
    private func isOp(_ text: String) -> Bool { current.kind == .operator && current.text == text }

    private func advance() { if pos < tokens.count - 1 { pos += 1 } }

    private func match(_ text: String) -> Bool {
        if isPunct(text) || isOp(text) || (current.text == text && (current.kind == .punct || current.kind == .operator)) {
            if current.text == text { advance(); return true }
        }
        return false
    }

    private func matchKeyword(_ text: String) -> Bool {
        if isKeyword(text) { advance(); return true }
        return false
    }

    private func expect(_ text: String) -> Bool {
        if current.text == text { advance(); return true }
        return false
    }

    // MARK: - Top level

    public func parseTranslationUnit() -> CTranslationUnit {
        var funcs: [CFunctionDef] = []
        var structs: [CStructDef] = []
        var typedefs: [String] = []
        var globals: [String] = []
        var namespaces: [String] = []

        while current.kind != .eof {
            parseTopLevel(&funcs, &structs, &typedefs, &globals, &namespaces)
        }
        return CTranslationUnit(functions: funcs, structs: structs, typedefs: typedefs, globalVariables: globals, namespaces: namespaces)
    }

    private func parseTopLevel(_ funcs: inout [CFunctionDef], _ structs: inout [CStructDef],
                               _ typedefs: inout [String], _ globals: inout [String], _ namespaces: inout [String]) {
        // Skip stray semicolons.
        if match(";") { return }

        // namespace X { ... }
        if isKeyword("namespace") {
            advance()
            let name = current.kind == .identifier ? current.text : ""
            if current.kind == .identifier { advance() } else if current.kind == .operator { advance() }
            namespaces.append(name)
            if match("{") {
                // parse its contents (recursively)
                while !isPunct("}") && current.kind != .eof {
                    parseTopLevel(&funcs, &structs, &typedefs, &globals, &namespaces)
                }
                _ = match("}")
            }
            return
        }

        // using directive / using X = Y ;
        if isKeyword("using") {
            advance()
            // Skip until ';' or end of scope (a `using` inside a function is handled by stmt parser).
            while current.kind != .eof && !isPunct(";") {
                if isPunct("{") { break }
                advance()
            }
            _ = match(";")
            return
        }

        // typedef ... ;  -> capture the last identifier as a type alias
        if isKeyword("typedef") {
            advance()
            var idents: [String] = []
            while current.kind != .eof && !isPunct(";") {
                if current.kind == .identifier { idents.append(current.text) }
                // skip struct/enum body if inline; re-check the token after it
                if isPunct("{") { skipBalanced(); continue }
                advance()
            }
            _ = match(";")
            if let last = idents.last { typedefs.append(last) }
            return
        }

        // enum / struct / union / class declarations
        let aggregate = isKeyword("struct") || isKeyword("union") || isKeyword("class") || isKeyword("enum")
        if aggregate && !isKeyword("enum") {
            let kw = current.text
            advance()
            let name = current.kind == .identifier ? current.text : ""
            if current.kind == .identifier { advance() }
            structs.append(CStructDef(name: name + (kw == "union" ? " (union)" : ""), offset: tokens[pos - 1].offset))
            if isPunct("{") { skipBalanced() }
            // possibly followed by variable declarators before ';'
            if !isPunct(";") { consumeDeclarators(&globals) }
            _ = match(";")
            return
        }
        if isKeyword("enum") {
            advance()
            if current.kind == .identifier { advance() }
            if isPunct("{") { skipBalanced() }
            if !isPunct(";") { consumeDeclarators(&globals) }
            _ = match(";")
            return
        }

        // extern "C" { ... }
        if isKeyword("extern") {
            advance()
            if current.kind == .string {
                advance()
                if match("{") {
                    while !isPunct("}") && current.kind != .eof { parseTopLevel(&funcs, &structs, &typedefs, &globals, &namespaces) }
                    _ = match("}")
                    return
                }
            }
            // extern decl or variable
            parseFunctionOrDecl(&funcs, &globals, allowBody: true)
            return
        }

        // template < ... > decl (skip template clause then parse)
        if isKeyword("template") {
            advance()
            if match("<") {
                var depth = 1
                while depth > 0 && current.kind != .eof {
                    if isPunct("<") { depth += 1 }
                    else if isPunct(">") { depth -= 1 }
                    advance()
                }
            }
            parseFunctionOrDecl(&funcs, &globals, allowBody: true)
            return
        }

        // Otherwise: a declaration or function definition.
        parseFunctionOrDecl(&funcs, &globals, allowBody: true)
    }

    private func parseFunctionOrDecl(_ funcs: inout [CFunctionDef], _ globals: inout [String], allowBody: Bool) {
        // Save position to backtrack to.
        let declStartTokens = pos
        let declStartOffset = current.offset

        // Try to parse as a function definition or declaration.
        if let fn = tryParseFunction(allowBody: allowBody) {
            funcs.append(fn)
            return
        }

        // Not a function: consume as a global variable / other declaration.
        restore(declStartTokens)
        if current.offset == declStartOffset {
            consumeDeclarators(&globals)
            _ = match(";")
        }
    }

    // MARK: - Backup/restore

    private func restore(_ p: Int) { pos = p }

    // MARK: - Function parsing

    /// Attempts to parse a function definition/declaration starting at a type/qualifier.
    /// Returns nil if the token stream is not a function.
    private func tryParseFunction(allowBody: Bool) -> CFunctionDef? {
        let snapshot = pos
        var qualifiers: Set<String> = []
        var returnType: String? = nil

        // Consume leading pure-qualifier keywords first.
        let pureQualifiers: Set<String> = ["static","virtual","inline","extern","constexpr","mutable",
                                           "explicit","friend","register","thread_local","noexcept"]
        while current.kind == .keyword, pureQualifiers.contains(current.text) {
            qualifiers.insert(current.text)
            advance()
        }

        // Scan for the function name = the identifier immediately before '(' (after optional
        // ptr/ref qualifiers / template args). Everything before it is the return type.
        var nameTok: CAstToken? = nil
        var returnParts: [String] = []
        var guardDepth = 0
        while current.kind != .eof, guardDepth < 200 {
            guardDepth += 1
            let t = current
            switch t.kind {
            case .identifier:
                advance()
                // After the identifier, skip template args and ptr/ref qualifiers, then check '('.
                if isPunct("<") { skipBalanced() }
                while isOp("*") || isOp("&") || isOp("&&") { advance() }
                if isPunct("(") {
                    nameTok = t
                    break
                }
                // Otherwise it was part of the (possibly multi-word) return type.
                returnParts.append(t.text)
            case .operator:
                if t.text == "::" || t.text == "*" || t.text == "&" || t.text == "&&" {
                    returnParts.append(t.text)
                    advance()
                } else if t.text == "operator" {
                    // overloaded operator function
                    advance()
                    var opName = "operator"
                    if current.kind == .operator || current.kind == .punct {
                        opName += current.text; advance()
                    } else if current.kind == .identifier {
                        opName += current.text; advance()
                    }
                    nameTok = CAstToken(kind: .identifier, text: opName, line: t.line, column: t.column, offset: t.offset)
                    break
                } else {
                    restore(snapshot)
                    return nil
                }
            case .keyword:
                returnParts.append(t.text)
                advance()
            default:
                restore(snapshot)
                return nil
            }
            if nameTok != nil { break }
        }

        guard let name = nameTok, name.text != "" else {
            restore(snapshot)
            return nil
        }
        let funcName = name.text
        // Everything captured in returnParts (plus pure qualifiers are separate) is the return type.
        if !returnParts.isEmpty {
            returnType = returnParts.joined(separator: " ")
        }
        // The name token's offset may point at a synthesized value for operators; that's fine.

        // Expect '(' (the parameter list opener).
        if !isPunct("(") {
            restore(snapshot)
            return nil
        }
        advance()

        // Parse params.
        var params: [CAParam] = []
        if !isPunct(")") {
            parseParams(&params)
        }
        if !match(")") {
            restore(snapshot)
            return nil
        }

        // Optional const/noexcept/override/-> trailing return.
        while isKeyword("const") || isKeyword("noexcept") || isKeyword("override") || isKeyword("mutable") ||
              isKeyword("final") || isOp("&") || isOp("*") || isOp("&&") || isPunct("<") || isOp("->") {
            if isOp("->") {
                // trailing return type; skip to end of type
                advance()
                skipDeclaratorType()
                break
            }
            if isPunct("<") { skipBalanced(); continue }
            advance()
        }

        // If next is '{' => definition. If ';' => declaration (no body).
        let bodyOffset = current.offset
        if isPunct("{") {
            advance()
            let body = parseBlock()
            // parseBlock consumed the closing '}'; the token before current is that '}'.
            let endOffset = (pos > 0) ? (tokens[pos - 1].offset + tokens[pos - 1].text.count) : bodyOffset
            let fn = CFunctionDef(name: funcName, returnType: returnType,
                                  params: params, body: body,
                                  startOffset: name.offset, bodyOffset: bodyOffset,
                                  endOffset: endOffset,
                                  isDefinition: true,
                                  isMethod: false,
                                  qualifiers: qualifiers)
            _ = match(";") // ignore a trailing ;
            return fn
        }
        if isPunct(";") {
            advance()
            if allowBody {
                return CFunctionDef(name: funcName, returnType: returnType,
                                    params: params, body: .empty,
                                    startOffset: name.offset, bodyOffset: bodyOffset,
                                    endOffset: bodyOffset, isDefinition: false,
                                    isMethod: false, qualifiers: qualifiers)
            }
            restore(snapshot)
            return nil
        }

        // Something else after params: could be a variable with function-pointer type, or a class
        // method definition with a trailing const. Be conservative.
        restore(snapshot)
        return nil
    }

    private func skipDeclaratorType() {
        // Skip a trailing return type like -> int or -> vector<int>.
        while current.kind != .eof && !isPunct("{") && !isPunct(";") {
            if isPunct("(") { break }
            if isPunct("<") { skipBalanced(); continue }
            advance()
        }
    }

    private func peekIsIdentifier() -> Bool {
        peek.kind == .identifier
    }

    private func peekIsPunct(_ text: String) -> Bool {
        peek.kind == .punct && peek.text == text
    }

    private func parseParams(_ params: inout [CAParam]) {
        // Loop over comma-separated params. Each: [type qualifiers] [ptr/ref] name [= default].
        // We collect type tokens; the final identifier before , ) = is the parameter name.
        while current.kind != .eof && !isPunct(")") {
            let startOff = current.offset
            var typeParts: [String] = []
            var name: String? = nil
            var nameOff = startOff
            var lastIdent: (String, Int)? = nil
            var progress = false

            while current.kind != .eof && !isPunct(",") && !isPunct(")") && !isPunct("=") && !isPunct("{") && !isPunct("(") && !isPunct("[") {
                progress = true
                let t = current
                switch t.kind {
                case .keyword, .identifier:
                    if t.kind == .identifier { lastIdent = (t.text, t.offset) }
                    typeParts.append(t.text)
                    advance()
                case .operator:
                    if t.text == "::" || t.text == "*" || t.text == "&" || t.text == "&&" || t.text == "..." {
                        typeParts.append(t.text)
                    }
                    advance()
                default:
                    advance()
                }
            }

            // The last identifier before a terminator is the parameter name.
            // Consume any array brackets `[...]` that may follow the name first.
            while isPunct("[") { skipSquareBalanced() }
            if let id = lastIdent, current.kind == .punct, current.text == "," || current.text == ")" {
                name = id.0
                nameOff = id.1
                if let idx = typeParts.lastIndex(of: id.0) {
                    typeParts.remove(at: idx)
                }
            }

            // Optional default value `= expr`.
            if match("=") {
                var depth = 0
                while current.kind != .eof {
                    if isPunct("(") { depth += 1; advance(); continue }
                    if isPunct(")") { if depth == 0 { break }; depth -= 1; advance(); continue }
                    if isPunct(",") && depth == 0 { break }
                    advance()
                }
            }

            if progress {
                params.append(CAParam(type: typeParts.isEmpty ? nil : typeParts.joined(separator: " "),
                                      name: name, offset: nameOff))
            }

            if !match(",") { break }
        }
    }

    // MARK: - Block / statements

    private func parseBlock() -> CStmt {
        var stmts: [CStmt] = []
        while current.kind != .eof && !isPunct("}") {
            if let s = parseStatement() {
                stmts.append(s)
            } else {
                // Safety: avoid infinite loop.
                if current.kind == .eof { break }
                advance()
            }
        }
        _ = match("}")
        return .block(stmts)
    }

    /// Parses a brace-delimited statement block starting at the current '{' token.
    /// Reused by the Java frontend to parse method bodies into the shared AST.
    public func parseBlockFromCurrent() -> CStmt? {
        guard isPunct("{") else { return nil }
        advance()
        return parseBlock()
    }

    private func parseStatement() -> CStmt? {
        // ';' empty statement
        if match(";") { return .empty }

        if isPunct("{") { advance(); return parseBlock() }

        if isKeyword("return") {
            let off = current.offset
            advance()
            var expr: CExpr? = nil
            if !isPunct(";") {
                expr = parseExpression()
            }
            _ = match(";")
            return .returnStmt(expr, off)
        }

        if isKeyword("break") { let o = current.offset; advance(); _ = match(";"); return .breakStmt(o) }
        if isKeyword("continue") { let o = current.offset; advance(); _ = match(";"); return .continueStmt(o) }

        if isKeyword("if") {
            let off = current.offset
            advance()
            _ = expect("(")
            let cond = parseExpression()
            _ = expect(")")
            let thenB = parseStatement() ?? .empty
            var elseB: CStmt? = nil
            if matchKeyword("else") {
                elseB = parseStatement() ?? .empty
            }
            return .ifStmt(cond: cond, thenBranch: thenB, elseBranch: elseB, off)
        }

        if isKeyword("while") {
            let off = current.offset
            advance()
            _ = expect("(")
            let cond = parseExpression()
            _ = expect(")")
            let body = parseStatement() ?? .empty
            return .whileStmt(cond: cond, body: body, off)
        }

        if isKeyword("do") {
            let off = current.offset
            advance()
            let body = parseStatement() ?? .empty
            _ = matchKeyword("while")
            _ = expect("(")
            let cond = parseExpression()
            _ = expect(")")
            _ = match(";")
            return .doWhileStmt(body: body, cond: cond, off)
        }

        if isKeyword("for") {
            let off = current.offset
            advance()
            _ = expect("(")
            var initStmt: CStmt? = nil
            if !isPunct(";") {
                initStmt = parseForInit()
            }
            // Enhanced-for: `for (Type v : coll)`. The init is a bare
            // declaration and the `:` denotes the collection, which becomes the
            // loop's condition (`forStmt(init: decl(v), cond: coll, ...)`).
            if isPunct(":") {
                advance()
                let coll = parseExpression()
                _ = expect(")")
                let body = parseStatement() ?? .empty
                return .forStmt(init: initStmt, cond: coll, increment: nil, body: body, off)
            }
            _ = match(";")
            var cond: CExpr? = nil
            if !isPunct(";") { cond = parseExpression() }
            _ = match(";")
            var inc: CExpr? = nil
            if !isPunct(")") { inc = parseExpression() }
            _ = expect(")")
            let body = parseStatement() ?? .empty
            return .forStmt(init: initStmt, cond: cond, increment: inc, body: body, off)
        }

        if isKeyword("switch") {
            let off = current.offset
            advance()
            _ = expect("(")
            let cond = parseExpression()
            _ = expect(")")
            _ = match("{")
            var cases: [CSwitchCase] = []
            while current.kind != .eof && !isPunct("}") {
                if isKeyword("case") {
                    advance()
                    var vals: [CExpr] = [parseExpression()]
                    while match(",") { vals.append(parseExpression()) }
                    _ = match(":")
                    var body: [CStmt] = []
                    while current.kind != .eof && !isKeyword("case") && !isKeyword("default") && !isPunct("}") {
                        if let s = parseStatement() { body.append(s) }
                    }
                    cases.append(CSwitchCase(values: vals, isDefault: false, body: body))
                } else if isKeyword("default") {
                    advance()
                    _ = match(":")
                    var body: [CStmt] = []
                    while current.kind != .eof && !isKeyword("case") && !isKeyword("default") && !isPunct("}") {
                        if let s = parseStatement() { body.append(s) }
                    }
                    cases.append(CSwitchCase(values: [], isDefault: true, body: body))
                } else {
                    if current.kind == .eof { break }
                    advance()
                }
            }
            _ = match("}")
            return .switchStmt(expr: cond, cases: cases, off)
        }

        if isKeyword("goto") {
            let off = current.offset
            advance()
            let label = current.kind == .identifier ? current.text : ""
            if current.kind == .identifier { advance() }
            _ = match(";")
            return .gotoStmt(label, off)
        }

        // Labeled statement: identifier ':' (not '::').
        // In Go, `name := expr` is a short-variable declaration, NOT a label
        // followed by `=`. Detect that case (identifier ':' followed by '=')
        // and skip the label branch so `tryParseGoShortDeclaration` can handle it.
        if current.kind == .identifier && peekIsPunct(":") {
            let isGoDecl = isGo && peekAheadIsOp(2, "=")
            if !isGoDecl {
                let label = current.text
                let off = current.offset
                advance()
                _ = match(":")
                let stmt = parseStatement() ?? .empty
                return .labeledStmt(label: label, stmt: stmt, off)
            }
        }

        // try { } catch / else? C++ try-catch.
        if isKeyword("try") {
            advance()
            let body = parseStatement() ?? .empty
            return body
        }
        if isKeyword("catch") {
            advance()
            _ = expect("(")
            _ = skipRoundBalanced()
            _ = expect(")")
            let body = parseStatement() ?? .empty
            return body
        }

        // Python `with expr [as target] [, ...]:` — reduce the clause to its
        // manager expressions (e.g. `open(...)`) as statement expressions so
        // downstream sink-taint analysis still sees the calls. Python bodies
        // are indentation-based (flattened by synthetic braces), so the body
        // statements are parsed separately regardless.
        if current.text == "with" {
            advance()
            var stats: [CStmt] = []
            while true {
                if current.kind == .eof { break }
                if current.text == ":" { advance(); break }
                if current.text == "," { advance(); continue }
                if current.text == "as" {
                    advance()
                    if current.kind == .identifier { advance() }
                    if current.text == ":" { advance(); break }
                    continue
                }
                stats.append(.expr(parseExpression()))
                if current.kind == .eof { break }
            }
            if stats.count == 1 { return stats[0] }
            return .block(stats)
        }

        // Declaration or expression statement.
        return parseDeclOrExprStatement()
    }

    private func parseForInit() -> CStmt? {
        // A for-init can be a declaration (type followed by declarators) or an expression.
        return parseDeclOrExprStatement(allowSemicolonConsumption: false)
    }

    private func parseDeclOrExprStatement(allowSemicolonConsumption: Bool = true) -> CStmt? {
        let snapshot = pos
        // Go short-variable declaration `x := expr` (also `x, y := a, b`).
        // `:=` is tokenized as the punctuation `:` followed by the operator `=`,
        // which the generic expression parser would otherwise mis-parse. Treat
        // it as a variable declaration so downstream taint analysis can track it.
        if isGo, current.kind == .identifier {
            if let decl = tryParseGoShortDeclaration() {
                while isPunct(",") { advance() } // consume trailing declarators
                let _ = match(";")
                return .declaration(decl)
            }
            restore(snapshot)
        }
        // Heuristic declaration detection: a declaration begins with a type-like token.
        if isDeclarationStart() {
            if let decl = tryParseDeclarationStatement() {
                return .declaration(decl)
            }
            restore(snapshot)
        }
        // Expression statement.
        let expr = parseExpression()
        _ = match(";")
        return .expr(expr)
    }

    /// Parses a single Go short-variable declarator `name := expr` when the
    /// cursor sits on the variable `name` directly followed by `:` then `=`.
    private func tryParseGoShortDeclaration() -> CDecl? {
        guard current.kind == .identifier else { return nil }
        let name = current.text
        let nameOff = current.offset
        let save = pos
        advance() // consume name
        // Expect the `:` of `:=` (punct) followed by the `=` operator.
        guard isPunct(":") else { restore2(save); return nil }
        advance()
        guard isOp("=") else { restore2(save); return nil }
        advance()
        let initExpr = parseExpression()
        return CDecl(kind: .variable(typeName: nil, name: name, initExpr: initExpr), offset: nameOff)
    }

    private func isDeclarationStart() -> Bool {
        // Type keywords.
        let typeKw: Set<String> = ["int","char","short","long","float","double","void","bool","unsigned",
                                   "signed","struct","union","class","enum","typename","wchar_t","auto",
                                   "const","volatile","constexpr","static","extern","typedef"]
        if current.kind == .keyword && typeKw.contains(current.text) { return true }
        // Identifier type (e.g. `MyType x = ...`), or `::` (global scope type).
        if current.kind == .identifier {
            // e.g. `Foo bar;` or `Foo bar = ...`
            // But `foo()` or `foo[i]` is an expression. Heuristic: identifier followed by identifier/'*'/'&'/'<' then name.
            // Look ahead one: if next is identifier/*/& or '(' then next-next is identifier or '*' => declaration.
            let n = peek
            if n.kind == .identifier || isOp("*") || isOp("&") || isOp("&&") || isOp("::") {
                // Might be a declaration `Type name`. Check two-ahead.
                // Accept as declaration if after the type identifier we see another identifier (the var name)
                // possibly with a '=' ',' ';' '[' or '(' following the name.
                return looksLikeDeclWithTypeIdent()
            }
            if n.kind == .punct && n.text == "<" { // template type `vector<int> x`
                return looksLikeTemplateTypeDecl()
            }
            return false
        }
        if isOp("::") { return true }  // ::Type x
        return false
    }

    private func looksLikeDeclWithTypeIdent() -> Bool {
        // We are at an identifier that we believe is a type. Look ahead: after the type identifier
        // (plus optional :: and template <> and * &), there should be a name then '=' ',' ';' '[' or '('. 
        let save = pos
        // consume type identifier
        advance()
        // optional ::Qualifier
        while isOp("::") || isPunct("<") {
            if isOp("::") { advance(); if current.kind == .identifier { advance() } else { restore2(save); return false } }
            else if isPunct("<") { skipBalancedProbe(); }
        }
        // optional pointer/ref
        while isOp("*") || isOp("&") || isOp("&&") { advance() }
        // Now expect an identifier (the declarator name).
        if current.kind == .identifier {
            advance()
            // After the name: '=' ',' ';' '[' '(' -> declaration; if ')' maybe a function call of a type-like name -> expression.
            if isPunct("=") || isPunct(";") || isPunct(",") || isPunct("[") { restore2(save); return true }
            // `:` follows an enhanced-for declarator (`for (String s : coll)`,
            // `for (auto& t : vec)`), and also labels `x :` in ObjC — treat as
            // a declaration in the for-init context.
            if isPunct(":") { restore2(save); return true }
            if isPunct("(") { restore2(save); return true }   // `Type x(...)` constructor or function-like
            restore2(save)
            return false
        }
        restore2(save)
        return false
    }

    private func restore2(_ p: Int) { pos = p; }

    private func skipBalancedProbe() {
        // assumes current is '<'
        var depth = 1
        advance()
        while depth > 0 && current.kind != .eof {
            if isPunct("<") { depth += 1 }
            else if isPunct(">") { depth -= 1 }
            advance()
        }
    }
    private func looksLikeTemplateTypeDecl() -> Bool {
        let save = pos
        advance() // '<'
        skipBalancedProbe()
        // optional * &
        while isOp("*") || isOp("&") || isOp("&&") { advance() }
        if isPunct("{") { restore2(save); return false }  // lambda-like
        if current.kind == .identifier {
            advance()
            if isPunct("=") || isPunct(";") || isPunct(",") || isPunct("[") || isPunct("(") {
                restore2(save); return true
            }
        }
        restore2(save)
        return false
    }

    private func isTypeKeyword(_ t: CAstToken) -> Bool {
        let kw: Set<String> = ["int","char","short","long","float","double","void","bool","unsigned","signed",
                               "struct","union","class","enum","typename","const","volatile","constexpr",
                               "static","extern","register","mutable","wchar_t","char16_t","char32_t","auto"]
        return t.kind == .keyword && kw.contains(t.text)
    }

    /// Returns true if the identifier at `current` is a type name (qualified/templated/variable-pointer)
    /// rather than a declarator name, based on the lookahead after it.
    private func identIsTypeName() -> Bool {
        let save = pos
        advance()
        var isType = false
        if isOp("::") || isPunct("<") || isPunct(".") {
            isType = true
        } else if isPunct("*") || isOp("*") || isOp("&") || isOp("&&") {
            isType = true
        } else if current.kind == .identifier || current.kind == .keyword {
            isType = true
        }
        restore2(save)
        return isType
    }

    private func tryParseDeclarationStatement() -> CDecl? {
        let snapshot = pos
        var typeParts: [String] = []
        var decls: [CDecl] = []

        // Phase 1: parse the type specifier (type-keywords + user type identifiers + ptr/ref),
        // stopping right before the first declarator name.
        var guardDepth = 0
        while current.kind != .eof && !isPunct(";"), guardDepth < 200 {
            guardDepth += 1
            let t = current
            if isTypeKeyword(t) {
                typeParts.append(t.text)
                advance()
                continue
            }
            if t.kind == .identifier {
                if identIsTypeName() {
                    typeParts.append(t.text)
                    advance()
                    // Re-parse the qualifying continuation (:: / < > / * &) below via the operator branch.
                    continue
                }
                // It's the first declarator name — stop here.
                break
            }
            if t.kind == .operator, t.text == "*" || t.text == "&" || t.text == "&&" || t.text == "::" {
                typeParts.append(t.text)
                advance()
                if isPunct("<") { skipBalanced(); typeParts.append("<...>") }
                continue
            }
            if isOp("::") {
                typeParts.append("::")
                advance()
                continue
            }
            break
        }

        if typeParts.isEmpty {
            restore(snapshot)
            return nil
        }

        // Phase 2: parse one or more declarators.
        let ok = parseDeclarators(typeParts: typeParts, decls: &decls)
        _ = match(";")
        if ok {
            return decls.first
        }
        restore(snapshot)
        return nil
    }

    private func parseDeclarators(typeParts: [String], decls: inout [CDecl]) -> Bool {
        // Parse: name [= init] [, name [= init]]*
        var parsedAny = false
        while current.kind != .eof && !isPunct(";") {
            // skip leading * & (pointer declarators), and function-pointer parens.
            while isOp("*") || isOp("&") || isOp("&&") { advance() }
            if isPunct("(") {
                // possible function pointer `(*fp)(...)` — consume balanced.
                _ = skipRoundBalanced()
                continue
            }
            guard current.kind == .identifier else {
                if isPunct(",") { advance(); continue }
                if isPunct("=") { break }
                break
            }
            let nameOff = current.offset
            let name = current.text
            advance()
            // skip array brackets `[n]` and `(...)` function-style
            var arraySuffix = ""
            while isPunct("[") || isPunct("(") {
                if isPunct("[") {
                    arraySuffix += skipSquareBalancedText()
                } else { _ = skipRoundBalanced() }
            }
            var initExpr: CExpr? = nil
            if match("=") {
                if isPunct("{") {
                    advance()
                    var elems: [CExpr] = []
                    // Each initializer item is an assignment-expression. Using
                    // parseExpression() here would let the comma-operator
                    // handling swallow the item separator AND the closing `}`
                    // (e.g. `struct X hdr = { .type = FOO, };`), derailing the
                    // rest of the translation unit.
                    while !isPunct("}") && current.kind != .eof {
                        if !isPunct(",") { elems.append(parseAssignment()) }
                        else { advance() }
                    }
                    _ = match("}")
                    initExpr = .arrayInit(elements: elems, nameOff)
                } else {
                    initExpr = parseAssignment()
                }
            }
            let fullType = typeParts.joined(separator: " ") + arraySuffix
            decls.append(CDecl(kind: .variable(typeName: fullType, name: name, initExpr: initExpr),
                               offset: nameOff))
            parsedAny = true
            if !match(",") { break }
        }
        return parsedAny
    }

    private func skipSquareBalanced() {
        var depth = 0
        while current.kind != .eof {
            if isPunct("[") { depth += 1 }
            else if isPunct("]") { depth -= 1; if depth == 0 { advance(); break } }
            advance()
        }
    }

    /// Skips a balanced `[...]` group, returning its source text (`[64]`, `[]`, ...)
    /// so declarators can retain array-dimension information that is otherwise dropped.
    private func skipSquareBalancedText() -> String {
        var depth = 0
        var parts = ""
        var firstOpen = true
        while current.kind != .eof {
            let t = current.text
            if isPunct("[") {
                if firstOpen { parts += t }
                depth += 1
                firstOpen = false
            } else if isPunct("]") {
                depth -= 1
                parts += t
                if depth == 0 { advance(); break }
            } else {
                parts += t
            }
            advance()
        }
        return parts
    }

    private func skipRoundBalanced() -> Bool {
        var depth = 0
        // Defensive cap so a degenerate input can never spin forever, even if the
        // token stream lacks a proper `.eof` sentinel or is malformed.
        var steps = 0
        let maxSteps = tokens.count + 1
        while current.kind != .eof && steps < maxSteps {
            steps += 1
            if isPunct("(") { depth += 1 }
            else if isPunct(")") {
                if depth == 0 { advance(); return true }
                depth -= 1
            }
            advance()
        }
        return false
    }

    private func skipBalanced() {
        // current is the opening of a balanced group ({ < ( [ ).
        // Skips through and including the matching close token.
        let open = current.text
        let close: String
        switch open {
        case "{": close = "}"
        case "<": close = ">"
        case "(": close = ")"
        case "[": close = "]"
        default:
            advance()
            return
        }
        var depth = 0
        while current.kind != .eof {
            if current.text == open { depth += 1 }
            else if current.text == close { depth -= 1; if depth == 0 { advance(); break } }
            advance()
        }
    }

    private func consumeDeclarators(_ globals: inout [String]) {
        while current.kind != .eof && !isPunct(";") {
            if current.kind == .identifier {
                globals.append(current.text)
            }
            if isPunct("{") {
                // Balanced initializer body — skipBalanced already consumes
                // the closing '}', so do NOT advance again (that would eat
                // the ';' — or the next declaration — and derail the parse).
                skipBalanced()
                continue
            }
            advance()
        }
        _ = match(";")
    }

    // MARK: - Expressions (precedence climbing)

    func parseExpression() -> CExpr {
        var e = parseAssignment()
        while true {
            if match(",") {
                let rhs = parseAssignment()
                e = .comma(lhs: e, rhs: rhs, e.offset)
            } else {
                break
            }
        }
        return e
    }

    func parseAssignment() -> CExpr {
        let lhs = parseConditional()
        let assignOps = ["=", "+=", "-=", "*=", "/=", "%=", "&=", "|=", "^=", "<<=", ">>=", "->", ".*"]
        if current.kind == .operator, assignOps.contains(current.text) {
            let op = current.text
            advance()
            let rhs = parseAssignment()
            return .assign(op: op, lhs: lhs, rhs: rhs, lhs.offset)
        }
        return lhs
    }

    private func parseConditional() -> CExpr {
        let cond = parseBinary(0)
        if current.text == "?" && (current.kind == .operator || current.kind == .punct) {
            advance()
            let t = parseExpression()
            _ = match(":")
            let f = parseConditional()
            return .ternary(cond: cond, thenExpr: t, elseExpr: f, cond.offset)
        }
        return cond
    }

    // operator precedence (loosest to tightest)
    private static let precTable: [String: (Int, Bool)] = [
        "||": (1, false),
        "&&": (2, false),
        "|": (3, false),
        "^": (4, false),
        "&": (5, false),
        "==": (6, false), "!=": (6, false),
        "<": (7, false), ">": (7, false), "<=": (7, false), ">=": (7, false),
        "<<": (8, false), ">>": (8, false),
        "+": (9, false), "-": (9, false), ".": (9, false),
        "*": (10, false), "/": (10, false), "%": (10, false),
    ]

    private func parseBinary(_ minPrec: Int) -> CExpr {
        var lhs = parseUnary()
        while true {
            // PHP's `.` is string concatenation and is tokenized as punctuation,
            // unlike C where `.` is member access (handled in parsePostfix).
            let isConcatDot = isPHP && (isPunct(".") || isOp("."))
            guard isConcatDot || current.kind == .operator else { break }
            if isConcatDot, let (p, _) = CParser.precTable["."], p >= minPrec {
                let op = "."
                advance()
                let rhs = parseBinary(p + 1)
                lhs = .binary(op: op, lhs: lhs, rhs: rhs, lhs.offset)
            } else if let (p, _) = current.kind == .operator ? CParser.precTable[current.text] : nil, p >= minPrec {
                let op = current.text
                advance()
                let rhs = parseBinary(p + 1)
                lhs = .binary(op: op, lhs: lhs, rhs: rhs, lhs.offset)
            } else {
                break
            }
        }
        return lhs
    }

    private func parseUnary() -> CExpr {
        let tok = current
        // ++ -- ! ~ - + * & sizeof (cast) new delete
        if tok.kind == .operator || tok.kind == .keyword {
            if tok.kind == .keyword && (tok.text == "sizeof") {
                return parseSizeOf()
            }
            if tok.kind == .keyword && (tok.text == "new") {
                return parseNew()
            }
            if tok.kind == .keyword && (tok.text == "delete") {
                advance()
                _ = match("[]")
                if current.kind == .identifier || isOp("(") {
                    let e = parseUnary()
                    return .unary(op: "delete", operand: e, tok.offset)
                }
                return .unary(op: "delete", operand: .identifier("", tok.offset), tok.offset)
            }
            if tok.kind == .operator {
                switch tok.text {
                case "++", "--", "!", "~", "-", "+", "*", "&":
                    advance()
                    let opnd = parseUnary()
                    return .unary(op: tok.text, operand: opnd, tok.offset)
                case "->", "::":
                    // not a unary prefix
                    break
                default:
                    break
                }
            }
        }

        // Cast: ( Type ) expr  or  Type(expr)  functional cast.
        if isPunct("(") {
            let save = pos
            advance()
            if isCastableTypeStart() {
                // tentative C-style cast: consume type then ')' then unary
                if consumeTypeUntilRParen() {
                    let inner = parseUnary()
                    return .cast(expr: inner, tok.offset)
                }
            }
            // Function call `name(args)` was handled in postfix; here '(' is grouping.
            restore(save)
            advance() // '('
            if isPunct(")") {
                advance()
                return .paren(expr: .identifier("", tok.offset), tok.offset)
            }
            let inner = parseExpression()
            _ = match(")")
            return .paren(expr: inner, tok.offset)
        }

        // Primary / postfix operand.
        let e = parsePrimary()
        return parsePostfix(e)
    }

    private func isCastableTypeStart() -> Bool {
        // After '(' we have a type: keyword or identifier (possibly with ::, *, &, and maybe ')' next).
        if current.kind == .keyword {
            let kw = current.text
            let typeKw: Set<String> = ["int","char","short","long","float","double","void","bool","unsigned","signed",
                                       "struct","union","class","enum","typename","wchar_t","char16_t","char32_t"]
            return typeKw.contains(kw)
        }
        if current.kind == .identifier {
            // `(Foo)` where Foo is a type — heuristic; could be a parenthesized expression.
            // Look ahead: identifier then optional * & :: then ')'
            let save = pos
            advance()
            var looksType = false
            while true {
                if isOp("::") { advance(); if current.kind == .identifier { advance(); continue } }
                else if isOp("*") || isOp("&") || isOp("&&") { advance(); continue }
                break
            }
            if isPunct(")") { looksType = true }
            restore(save)
            return looksType
        }
        return false
    }

    private func consumeTypeUntilRParen() -> Bool {
        // current is just after '('; consume type tokens then expect ')'.
        while current.kind == .keyword || current.kind == .identifier || isOp("::") || isOp("*") || isOp("&") || isOp("&&") || isPunct("<") {
            if isPunct("<") { skipBalanced() ; continue }
            if isKeyword("const") || isKeyword("volatile") { advance(); continue }
            advance()
        }
        return match(")")
    }

    private func parseSizeOf() -> CExpr {
        let off = current.offset
        advance()
        if isPunct("(") {
            let save = pos
            advance()
            if isCastableTypeStart() {
                if consumeTypeUntilRParen() {
                    return .sizeOf(expr: nil, typeName: "type", off)
                }
            }
            restore(save)
            _ = expect("(")
            let e = parseExpression()
            _ = expect(")")
            return .sizeOf(expr: e, typeName: nil, off)
        }
        let e = parseUnary()
        return .sizeOf(expr: e, typeName: nil, off)
    }

    private func parseNew() -> CExpr {
        let off = current.offset
        advance()
        // array form new[]
        if isPunct("[") { skipSquareBalanced() }
        var typeName = ""
        while current.kind == .identifier || isOp("::") || current.kind == .keyword {
            if isOp("::") { typeName += "::"; advance(); continue }
            if isPunct("<") { skipBalanced(); typeName += "<>"; continue }
            if isKeyword("const") || isKeyword("struct") || isKeyword("class") { advance(); continue }
            typeName += current.text
            advance()
            break
        }
        var args: [CExpr] = []
        if isPunct("(") {
            advance()
            while !isPunct(")") && current.kind != .eof {
                args.append(parseAssignment())
                if !match(",") { break }
            }
            _ = match(")")
        }
        return .newExpr(typeName: typeName, args: args, off)
    }

    private func parsePrimary() -> CExpr {
        let tok = current
        switch tok.kind {
        case .number:
            advance()
            if tok.text.contains(".") || tok.text.contains("e") || tok.text.contains("E") {
                return .floatLiteral(tok.text, tok.offset)
            }
            return .integerLiteral(tok.text, tok.offset)
        case .string:
            advance()
            // concatenate adjacent string literals
            var text = tok.text
            while current.kind == .string { text += current.text; advance() }
            return .stringLiteral(text, tok.offset)
        case .character:
            advance()
            return .charLiteral(tok.text, tok.offset)
        case .identifier:
            advance()
            // keyword true/false
            if tok.text == "true" { return .booleanLiteral(true, tok.offset) }
            if tok.text == "false" { return .booleanLiteral(false, tok.offset) }
            // Rust macros (`format!(...)`, `println!(...)`) and Ruby bang methods
            // (`save!`): glue a trailing `!` onto the identifier so the following
            // call arguments attach to the right name.
            var text = tok.text
            while current.kind == .operator, current.text == "!" {
                text += "!"
                advance()
            }
            return .identifier(text, tok.offset)
        case .keyword:
            if tok.text == "true" { advance(); return .booleanLiteral(true, tok.offset) }
            if tok.text == "false" { advance(); return .booleanLiteral(false, tok.offset) }
            if tok.text == "this" { advance(); return .identifier("this", tok.offset) }
            // lambda capture default etc — treat identifier-like
            advance()
            return .identifier(tok.text, tok.offset)
        case .punct:
            if isPunct("(") {
                return parseGroupingOrCall()
            }
            if isPunct("{") {
                advance()
                var elems: [CExpr] = []
                while !isPunct("}") && current.kind != .eof {
                    if !isPunct(",") { elems.append(parseAssignment()) }
                    else { advance() }
                    if !match(",") {
                        if isPunct("}") { break }
                    }
                }
                _ = match("}")
                return .arrayInit(elements: elems, tok.offset)
            }
            advance()
            return .identifier(tok.text, tok.offset)
        case .operator:
            advance()
            return .unary(op: tok.text, operand: .identifier("", tok.offset), tok.offset)
        case .eof:
            return .identifier("", tok.offset)
        }
    }

    private func parseGroupingOrCall() -> CExpr {
        let off = current.offset
        _ = expect("(")
        if isPunct(")") {
            advance()
            return .paren(expr: .identifier("", off), off)
        }
        let inner = parseExpression()
        _ = match(")")
        return .paren(expr: inner, off)
    }

    /// Postfix: call/member/index with operands already parsed.
    private func parsePostfix(_ e: CExpr) -> CExpr {
        var cur = e
        while true {
            if isPunct("(") {
                // `offsetof(struct Tag, member)` — the first "argument" is a C
                // type-tag (`struct Tag`) that the generic expression parser
                // cannot consume, which truncates the enclosing expression.
                // offsetof(...) is a compile-time constant, so absorb the whole
                // balanced list and represent it as a sizeof (constant) node.
                if case .identifier(let name, _) = cur, name == "offsetof" {
                    let off = cur.offset
                    skipBalanced()
                    cur = .sizeOf(expr: nil, typeName: nil, off)
                    continue
                }
                // function call
                let off = cur.offset
                advance()
                var args: [CExpr] = []
                while !isPunct(")") && current.kind != .eof {
                    // designated initializers `=.foo` or empty
                    if isPunct("=") { advance(); continue }
                    args.append(parseAssignment())
                    if !match(",") { break }
                }
                _ = match(")")
                cur = .call(callee: cur, args: args, off)
                continue
            }
            if isPunct("[") {
                let off = cur.offset
                advance()
                let idx = parseExpression()
                _ = match("]")
                cur = .index(base: cur, index: idx, off)
                continue
            }
            if isPunct(".") || isOp(".") {
                // PHP uses `.` for string concatenation, not member access
                // (PHP uses `->` for object properties/methods).  Let `.`
                // fall through to `parseBinary` which treats it as a binary
                // operator with correct precedence.
                if isPHP { break }
                let off = cur.offset
                advance()
                let member = current.text
                advance()
                cur = .member(base: cur, member: member, isPtr: false, off)
                continue
            }
            if isPunct("->") || isOp("->") {
                let off = cur.offset
                advance()
                let member = current.text
                advance()
                cur = .member(base: cur, member: member, isPtr: true, off)
                continue
            }
            if isOp("::") {
                // Rust `::<...>` turbofish generics on static calls
                // (`bincode::deserialize::<Value>(u)`): skip the generic argument
                // list so the trailing `(...)` still attaches to the callee.
                let off = cur.offset
                let save = pos
                advance()
                if current.text == "<" {
                    skipBalanced()   // consume `::<...>`
                    if isPunct("(") {
                        continue
                    }
                    restore2(save)
                    break
                }
                // Qualified name chains (`fs::File::create`, `Net::HTTP.get_response`,
                // `Command::new`) parse like member access, normalizing `::` to `.`.
                let member = current.text
                advance()
                cur = .member(base: cur, member: member, isPtr: false, off)
                continue
            }
            if current.kind == .operator, current.text == "++" || current.text == "--" {
                let off = cur.offset
                let op = current.text
                advance()
                cur = .unary(op: op, operand: cur, off)
                continue
            }
            break
        }
        return cur
    }
}

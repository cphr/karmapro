// by cipher.org.uk
import Foundation

// MARK: - Native JavaScript expression/statement model
//
// A lightweight, JS-native AST built directly from the `JSTokenizer` token
// stream (independent of the CParser bridge, whose C-oriented grammar distorts
// JS constructs). The three security walks (taint / bounds / boundary) operate
// on this model. Template literals stay single tokens in the tokenizer for
// brace-correctness, and expose their `${...}` interpolations as parsed
// sub-expressions via `templateExprs`.

public indirect enum JSExpr {
    case ident(String, Int)
    case literal(String, Int)              // string / number / regex token
    case template(String, Int)             // backtick literal; interpolations via templateExprs
    case member(JSExpr, String, Int)       // base.name  /  base?.name
    case index(JSExpr, JSExpr, Int)        // base[expr]
    case call(JSExpr, [JSExpr], Int)
    case new(JSExpr, [JSExpr], Int)        // new Callee(args)
    case unary(String, JSExpr, Int)
    case binary(String, JSExpr, JSExpr, Int)
    case assign(String, JSExpr, JSExpr, Int)
    case ternary(JSExpr, JSExpr, JSExpr, Int)
    case arrayLit([JSExpr], Int)
    case objectLit(Int)                    // opaque { ... }
    case arrow([String], JSArrowBody, Int) // (a, b) => body   /   x => body

    var offset: Int {
        switch self {
        case .ident(_, let o), .literal(_, let o), .template(_, let o),
             .member(_, _, let o), .index(_, _, let o), .call(_, _, let o),
             .new(_, _, let o), .unary(_, _, let o), .binary(_, _, _, let o),
             .assign(_, _, _, let o), .ternary(_, _, _, let o),
             .arrayLit(_, let o), .objectLit(let o), .arrow(_, _, let o):
            return o
        }
    }

    /// Flattened dotted name for identifier/member chains, e.g. `fs.readFile`.
    var dottedName: String {
        switch self {
        case .ident(let n, _): return n
        case .member(let b, let m, _):
            let base = b.dottedName
            return base.isEmpty ? m : "\(base).\(m)"
        default: return ""
        }
    }
}

public enum JSArrowBody {
    case block([JSStmt])
    case expr(JSExpr)
}

public indirect enum JSStmt {
    case exprStmt(JSExpr, Int)
    case varDecl([(name: String, initExpr: JSExpr?)], Int)
    case ifStmt(JSExpr, [JSStmt], [JSStmt]?, Int)
    case forStmt(loopVar: String?, bound: JSExpr?, inclusive: Bool,
                 iterable: JSExpr?, isForOf: Bool, body: [JSStmt], Int)
    case whileStmt(JSExpr, [JSStmt], Int)
    case returnStmt(JSExpr?, Int)
    case block([JSStmt], Int)
    case throwStmt(JSExpr?, Int)

    var offset: Int {
        switch self {
        case .exprStmt(_, let o), .varDecl(_, let o), .ifStmt(_, _, _, let o),
             .forStmt(_, _, _, _, _, _, let o), .whileStmt(_, _, let o),
             .returnStmt(_, let o), .block(_, let o), .throwStmt(_, let o):
            return o
        }
    }
}

// MARK: - Parser

public final class JSExprParser {

    private let tokens: [CAstToken]
    private var i = 0

    public init(tokens: [CAstToken]) {
        self.tokens = tokens
    }

    // MARK: Statements

    /// Parses a top-level statement list until EOF or an unbalanced closer.
    public static func parseStatements(_ tokens: [CAstToken]) -> [JSStmt] {
        let p = JSExprParser(tokens: tokens)
        var stmts: [JSStmt] = []
        while !p.atEnd() {
            guard let s = p.parseStatement() else { break }
            stmts.append(s)
        }
        return stmts
    }

    func parseStatement() -> JSStmt? {
        guard !atEnd() else { return nil }
        let t = peek()
        if t.text == "}" || t.kind == .eof { return nil }

        // Blocks
        if t.text == "{" {
            return parseBlock()
        }
        // Control flow
        if t.text == "if" { return parseIf() }
        if t.text == "for" { return parseFor() }
        if t.text == "while" { return parseWhile() }
        if t.text == "return" { return parseReturn() }
        if t.text == "throw" { return parseThrow() }
        // Declarations
        if t.text == "const" || t.text == "let" || t.text == "var" {
            return parseVarDecl()
        }
        // Expression statement
        if let e = parseExpression() {
            skipTerminator()
            return .exprStmt(e, e.offset)
        }
        // Unrecognized: advance one token to guarantee progress.
        i += 1
        return nil
    }

    func parseBlock() -> JSStmt {
        let openOffset = peek().offset
        var inner: [JSStmt] = []
        // Current token should be `{`; skip it.
        if peek().text == "{" { i += 1 }
        var depth = 1
        while !atEnd() {
            let t = peek()
            if t.text == "}" { i += 1; break }
            if t.text == "{" { depth += 1 }
            if let s = parseStatement() { inner.append(s) } else {
                if atEnd() { break }
                if peek().text == "}" { i += 1; break }
            }
        }
        return .block(inner, openOffset)
    }

    func parseIf() -> JSStmt? {
        let offset = peek().offset
        i += 1 // if
        guard peek().text == "(" else { return nil }
        guard let cond = parseParenExpression() else { return nil }
        var thenBody: [JSStmt] = []
        if peek().text == "{" {
            if case .block(let b, _) = parseBlock() { thenBody = b }
        } else if let s = parseStatement() {
            thenBody = [s]
        }
        var elseBody: [JSStmt]? = nil
        if peek().text == "else" {
            i += 1
            if peek().text == "if", let nested = parseIf() {
                elseBody = [nested]
            } else if peek().text == "{" {
                if case .block(let b, _) = parseBlock() { elseBody = b }
            } else if let s = parseStatement() {
                elseBody = [s]
            }
        }
        return .ifStmt(cond, thenBody, elseBody, offset)
    }

    func parseFor() -> JSStmt? {
        let offset = peek().offset
        i += 1 // for
        guard peek().text == "(" else { return nil }
        i += 1
        // Detect for-of / for-in: `const x of expr` / `x in expr`
        var loopVar: String? = nil
        var iterable: JSExpr? = nil
        var isForOf = false
        var sawForOf = false
        var scan = i
        while scan < tokens.count, tokens[scan].text != ")" {
            if tokens[scan].text == "of" || tokens[scan].text == "in" {
                sawForOf = true
                isForOf = tokens[scan].text == "of"
                break
            }
            scan += 1
        }
        if sawForOf {
            // LHS: NAME | [a,b] | {a,b} | const NAME ...
            while !atEnd(), peek().text != "of", peek().text != "in" {
                if peek().kind == .identifier { loopVar = peek().text }
                i += 1
            }
            if peek().text == "of" || peek().text == "in" { i += 1 }
            iterable = parseExpression(until: ")")
            if peek().text == ")" { i += 1 }
            var body: [JSStmt] = []
            if peek().text == "{" {
                if case .block(let b, _) = parseBlock() { body = b }
            } else if let s = parseStatement() { body = [s] }
            return .forStmt(loopVar: loopVar, bound: nil, inclusive: false,
                            iterable: iterable, isForOf: isForOf, body: body, offset)
        }
        // Classic for: init; cond; update
        // Skip init up to first top-level `;`
        var depth = 0
        while !atEnd() {
            let t = peek()
            if t.text == "(" || t.text == "[" || t.text == "{" { depth += 1 }
            if t.text == ")" || t.text == "]" || t.text == "}" { depth -= 1 }
            if t.text == ";" && depth == 0 { i += 1; break }
            if t.kind == .eof { return nil }
            if t.kind == .identifier && t.text != "let" && t.text != "const" && t.text != "var" {
                // first identifier of the init is usually the loop variable
                if loopVar == nil { loopVar = t.text }
            }
            i += 1
        }
        var bound: JSExpr? = nil
        var inclusive = false
        if peek().text != ";" {
            if let cond = parseExpression(until: ";") {
                bound = cond
                if case .binary(let op, _, _, _) = cond, op == "<=" { inclusive = true }
            }
        }
        if peek().text == ";" { i += 1 }
        // Skip update
        depth = 0
        while !atEnd() {
            let t = peek()
            if t.text == "(" || t.text == "[" || t.text == "{" { depth += 1 }
            if t.text == ")" || t.text == "]" || t.text == "}" {
                if depth == 0 { break }
                depth -= 1
            }
            if t.kind == .eof { return nil }
            i += 1
        }
        if peek().text == ")" { i += 1 }
        var body: [JSStmt] = []
        if peek().text == "{" {
            if case .block(let b, _) = parseBlock() { body = b }
        } else if let s = parseStatement() { body = [s] }
        return .forStmt(loopVar: loopVar, bound: bound, inclusive: inclusive,
                        iterable: nil, isForOf: false, body: body, offset)
    }

    func parseWhile() -> JSStmt? {
        let offset = peek().offset
        i += 1
        guard peek().text == "(", let cond = parseParenExpression() else { return nil }
        var body: [JSStmt] = []
        if peek().text == "{" {
            if case .block(let b, _) = parseBlock() { body = b }
        } else if let s = parseStatement() { body = [s] }
        return .whileStmt(cond, body, offset)
    }

    func parseReturn() -> JSStmt? {
        let offset = peek().offset
        i += 1
        var e: JSExpr? = nil
        if !atEnd(), peek().text != ";" && peek().text != "}" {
            e = parseExpression()
        }
        skipTerminator()
        return .returnStmt(e, offset)
    }

    func parseThrow() -> JSStmt? {
        let offset = peek().offset
        i += 1
        var e: JSExpr? = nil
        if !atEnd(), peek().text != ";" && peek().text != "}" {
            e = parseExpression()
        }
        skipTerminator()
        return .throwStmt(e, offset)
    }

    func parseVarDecl() -> JSStmt? {
        let offset = peek().offset
        i += 1 // const/let/var
        var decls: [(String, JSExpr?)] = []
        // Split on top-level commas until `;` or statement end.
        while !atEnd() {
            // Destructuring: { a, b } / [a, b] = expr
            if peek().text == "{" || peek().text == "[" {
                let start = i
                let closer = peek().text == "{" ? "}" : "]"
                var depth = 0
                while !atEnd() {
                    if peek().text == "{" || peek().text == "[" { depth += 1 }
                    if peek().text == closer { depth -= 1; i += 1; if depth == 0 { break }; continue }
                    if peek().kind == .eof { return nil }
                    i += 1
                }
                // bound names inside the pattern
                for k in start..<i where tokens[k].kind == .identifier && !jsKeywords.contains(tokens[k].text) {
                    decls.append((tokens[k].text, nil))
                }
                if peek().text == "=" {
                    i += 1
                    let e = parseExpression(until: nil)
                    if !decls.isEmpty { decls[decls.count - 1].1 = e }
                }
            } else if peek().kind == .identifier {
                let name = peek().text
                i += 1
                var e: JSExpr? = nil
                if peek().text == "=" {
                    i += 1
                    e = parseExpression(until: nil)
                }
                decls.append((name, e))
            } else {
                i += 1
            }
            if peek().text == "," { i += 1; continue }
            break
        }
        skipTerminator()
        guard !decls.isEmpty else { return nil }
        return .varDecl(decls.map { (name: $0.0, initExpr: $0.1) }, offset)
    }

    func skipTerminator() {
        if !atEnd(), peek().text == ";" { i += 1 }
    }

    // MARK: Expressions (precedence climbing)

    func parseExpression(until: String? = nil) -> JSExpr? {
        let start = i
        guard let e = parseAssignment(until: until) else { i = start; return nil }
        return e
    }

    func parseAssignment(until: String?) -> JSExpr? {
        guard let lhs = parseTernary(until: until) else { return nil }
        if !atEnd(), isAssignOp(peek().text), peek().kind == .operator || peek().kind == .punct {
            let op = peek().text
            let offset = peek().offset
            i += 1
            guard let rhs = parseAssignment(until: until) else { return nil }
            return .assign(op, lhs, rhs, offset)
        }
        return lhs
    }

    func parseTernary(until: String?) -> JSExpr? {
        guard let cond = parseBinary(0, until: until) else { return nil }
        if !atEnd(), peek().text == "?" {
            let offset = cond.offset
            i += 1
            guard let t = parseAssignment(until: nil) else { return nil }
            if !atEnd(), peek().text == ":" {
                i += 1
                guard let f = parseAssignment(until: nil) else { return nil }
                return .ternary(cond, t, f, offset)
            }
            return t
        }
        return cond
    }

    static let binaryPrecedence: [String: Int] = [
        "||": 1, "&&": 2,
        "==": 3, "!=": 3, "===": 3, "!==": 3,
        "<": 4, ">": 4, "<=": 4, ">=": 4, "instanceof": 4, "in": 4,
        "+": 5, "-": 5,
        "*": 6, "/": 6, "%": 6,
        "**": 7,
    ]

    func parseBinary(_ minPrec: Int, until: String?) -> JSExpr? {
        guard let lhs = parseUnary(until: until) else { return nil }
        var result = lhs
        while !atEnd() {
            let t = peek()
            guard t.kind == .operator || t.kind == .keyword else { break }
            guard let prec = JSExprParser.binaryPrecedence[t.text], prec >= minPrec else { break }
            i += 1
            guard let rhs = parseBinary(prec + 1, until: until) else { return nil }
            result = .binary(t.text, result, rhs, result.offset)
        }
        return result
    }

    func parseUnary(until: String?) -> JSExpr? {
        guard !atEnd() else { return nil }
        let t = peek()
        if ["!", "-", "+", "~", "typeof", "await", "...", "delete", "void"].contains(t.text),
           t.kind == .operator || t.kind == .keyword {
            let offset = t.offset
            i += 1
            if let operand = parseUnary(until: until) {
                return .unary(t.text, operand, offset)
            }
            return nil
        }
        if t.text == "new" {
            let offset = t.offset
            i += 1
            if let callee = parseUnary(until: until) {
                var args: [JSExpr] = []
                if !atEnd(), peek().text == "(" {
                    args = parseArgumentList()
                }
                return .new(callee, args, offset)
            }
            return nil
        }
        return parsePostfix(until: until)
    }

    func parsePostfix(until: String?) -> JSExpr? {
        guard var e = parsePrimary(until: until) else { return nil }
        while !atEnd() {
            let t = peek()
            if t.text == "." || t.text == "?." {
                i += 1
                guard !atEnd(), peek().kind == .identifier || peek().kind == .keyword else { break }
                e = .member(e, peek().text, peek().offset)
                i += 1
                continue
            }
            if t.text == "[" {
                i += 1
                guard let idx = parseExpression(until: "]") else { break }
                if !atEnd(), peek().text == "]" { i += 1 }
                e = .index(e, idx, e.offset)
                continue
            }
            if t.text == "(" {
                let offset = e.offset
                let args = parseArgumentList()
                e = .call(e, args, offset)
                continue
            }
            if t.text == "++" || t.text == "--" {
                i += 1
                continue
            }
            break
        }
        return e
    }

    func parsePrimary(until: String?) -> JSExpr? {
        guard !atEnd() else { return nil }
        let t = peek()
        switch t.kind {
        case .number:
            i += 1
            return .literal(t.text, t.offset)
        case .string:
            i += 1
            if t.text.hasPrefix("`") {
                return .template(t.text, t.offset)
            }
            return .literal(t.text, t.offset)
        case .identifier:
            i += 1
            return .ident(t.text, t.offset)
        case .keyword:
            if ["true", "false", "null", "undefined", "this", "super", "eval"].contains(t.text) {
                i += 1
                return .ident(t.text, t.offset)
            }
            return nil
        case .punct:
            if t.text == "(" {
                // Possible arrow `(a, b) => ...`
                if let arrow = tryParseArrow() { return arrow }
                i += 1
                guard let e = parseExpression(until: ")") else { return nil }
                if !atEnd(), peek().text == ")" { i += 1 }
                return e
            }
            if t.text == "[" {
                let offset = t.offset
                i += 1
                var elems: [JSExpr] = []
                var depth = 1
                var current: [CAstToken] = []
                while !atEnd() {
                    let tk = peek()
                    if tk.text == "[" { depth += 1 }
                    if tk.text == "]" {
                        depth -= 1
                        if depth == 0 { i += 1; break }
                    }
                    if tk.text == "," && depth == 1 {
                        if let el = JSExprParser(tokens: current).parseExpression() { elems.append(el) }
                        current = []
                        i += 1
                        continue
                    }
                    current.append(tk)
                    i += 1
                }
                if !current.isEmpty, let el = JSExprParser(tokens: current).parseExpression() {
                    elems.append(el)
                }
                return .arrayLit(elems, offset)
            }
            if t.text == "{" {
                let offset = t.offset
                skipBalancedBraces()
                return .objectLit(offset)
            }
            return nil
        default:
            return nil
        }
    }

    /// Attempts to parse `(params) => body` at the current position; on failure
    /// restores the cursor and returns nil (callers fall back to paren expr).
    func tryParseArrow() -> JSExpr? {
        let saved = i
        guard peek().text == "(" else { return nil }
        i += 1
        var params: [String] = []
        var valid = true
        var depth = 1
        while !atEnd() {
            let t = peek()
            if t.text == "(" { depth += 1 }
            if t.text == ")" {
                depth -= 1
                if depth == 0 { i += 1; break }
            }
            if depth == 1, t.kind == .identifier, !jsKeywords.contains(t.text) {
                params.append(t.text)
            }
            if depth == 1, t.text == "," || t.kind == .identifier || t.kind == .punct { }
            if t.kind == .eof { valid = false; break }
            if depth == 1 && !["(", ")", ","].contains(t.text) && t.kind != .identifier {
                // default values / destructuring are still acceptable; keep scanning
            }
            i += 1
        }
        guard valid, !atEnd(), peek().text == "=>" else {
            i = saved
            return nil
        }
        let offset = tokens[saved].offset
        i += 1 // =>
        if peek().text == "{" {
            if case .block(let b, _) = parseBlock() {
                return .arrow(params, .block(b), offset)
            }
            return .arrow(params, .block([]), offset)
        }
        if let e = parseExpression() {
            return .arrow(params, .expr(e), offset)
        }
        i = saved
        return nil
    }

    func parseArgumentList() -> [JSExpr] {
        guard peek().text == "(" else { return [] }
        i += 1
        var args: [JSExpr] = []
        var depth = 1
        var current: [CAstToken] = []
        while !atEnd() {
            let t = peek()
            if t.text == "(" { depth += 1 }
            if t.text == ")" {
                depth -= 1
                if depth == 0 { i += 1; break }
            }
            if t.text == "," && depth == 1 {
                if let e = JSExprParser(tokens: current).parseExpression() { args.append(e) }
                current = []
                i += 1
                continue
            }
            current.append(t)
            i += 1
        }
        if !current.isEmpty, let e = JSExprParser(tokens: current).parseExpression() {
            args.append(e)
        }
        return args
    }

    func parseParenExpression() -> JSExpr? {
        guard peek().text == "(" else { return nil }
        i += 1
        guard let e = parseExpression(until: ")") else { return nil }
        if !atEnd(), peek().text == ")" { i += 1 }
        return e
    }

    func skipBalancedBraces() {
        guard peek().text == "{" else { return }
        var depth = 0
        while !atEnd() {
            let t = peek()
            if t.text == "{" { depth += 1 }
            if t.text == "}" {
                depth -= 1
                i += 1
                if depth == 0 { return }
                continue
            }
            i += 1
        }
    }

    func atEnd() -> Bool {
        i >= tokens.count || tokens[i].kind == .eof
    }

    func peek() -> CAstToken {
        tokens[min(i, tokens.count - 1)]
    }

    func isAssignOp(_ text: String) -> Bool {
        ["=", "+=", "-=", "*=", "/=", "%=", "&=", "|=", "^=", "**=", "<<=", ">>=",
         "??=", "&&=", "||="].contains(text)
    }
}

// MARK: - Template literal interpolation expansion

extension JSExpr {
    /// Parses each `${...}` interpolation of a template literal into a JSExpr
    /// with absolute source offsets. Returns [] for non-templates.
    public func templateExprs() -> [JSExpr] {
        guard case .template(let text, let baseOffset) = self else { return [] }
        var result: [JSExpr] = []
        var idx = text.startIndex
        while let dollar = text[idx...].firstIndex(of: "$"),
              text.index(after: dollar) < text.endIndex,
              text[text.index(after: dollar)] == "{" {
            var depth = 1
            // Start after the "${" so the interpolation expression excludes it.
            let exprStart = text.index(text.index(after: dollar), offsetBy: 1)
            var j = exprStart
            while j < text.endIndex {
                let c = text[j]
                if c == "{" { depth += 1 }
                if c == "}" {
                    depth -= 1
                    if depth == 0 { break }
                }
                j = text.index(after: j)
            }
            guard depth == 0, j < text.endIndex else { break }
            let inner = String(text[exprStart..<j])
            let absStart = baseOffset + exprStart.utf16Offset(in: text)
            let subTokens = JSTokenizer(source: inner).tokenize().map { tk in
                CAstToken(kind: tk.kind, text: tk.text, line: tk.line, column: tk.column,
                          offset: tk.offset + absStart)
            }
            if let e = JSExprParser(tokens: subTokens).parseExpression() {
                result.append(e)
            }
            idx = text.index(after: j)
        }
        return result
    }
}

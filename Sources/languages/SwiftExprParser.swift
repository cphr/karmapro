// by cipher.org.uk
import Foundation

// MARK: - Swift-native expression / statement model
//
// A lightweight Swift-only AST built directly from the CTokenizer token stream.
// Mirror of the JS-native model in JSExprParser: it represents Swift's actual
// syntax (optional chaining, forced unwrap, range operators, closures with
// `in`, `guard`, string interpolation) without the distortions the C-oriented
// CParser bridge would introduce. The three security walks (taint / bounds /
// boundary) and the taint-returning / write-through pass operate on this model.

public indirect enum SwiftExpr {
    case ident(String, Int)
    case member(SwiftExpr, String, Int)
    case index(SwiftExpr, SwiftExpr, Int)
    case literal(text: String, Int)                   // number / string token
    case call(callee: SwiftExpr, args: [SwiftExpr], Int)
    case newExpr(typeName: String, args: [SwiftExpr], Int) // Type(...) construction
    case unary(op: String, operand: SwiftExpr, Int)
    case binary(op: String, lhs: SwiftExpr, rhs: SwiftExpr, Int)
    case assign(op: String, lhs: SwiftExpr, rhs: SwiftExpr, Int)
    case ternary(cond: SwiftExpr, thenExpr: SwiftExpr, elseExpr: SwiftExpr, Int)
    case arrayLit([SwiftExpr], Int)
    case dictLit([(SwiftExpr, SwiftExpr)], Int)
    case paren(SwiftExpr, Int)
    case closure(params: [String], body: [SwiftStmt], Int)
    case forceUnwrap(SwiftExpr, Int)                  // expr!
    case optional(SwiftExpr, Int)                     // expr? (postfix)
    case interpolation(exprs: [SwiftExpr], Int)       // "\(x)" string literal
    case range(bound: String, lhs: SwiftExpr, rhs: SwiftExpr, Int) // ..<  or  ...
    case cast(op: String, operand: SwiftExpr, Int)    // as / as? / as!
    case placeholder(Int)                             // opaque/unparsed region

    var offset: Int {
        switch self {
        case .ident(_, let o), .literal(_, let o), .call(_, _, let o),
             .member(_, _, let o), .index(_, _, let o),
             .newExpr(_, _, let o), .unary(_, _, let o), .binary(_, _, _, let o),
             .assign(_, _, _, let o), .ternary(_, _, _, let o),
             .arrayLit(_, let o), .dictLit(_, let o), .paren(_, let o),
             .closure(_, _, let o), .forceUnwrap(_, let o), .optional(_, let o),
             .interpolation(_, let o), .range(_, _, _, let o), .cast(_, _, let o),
             .placeholder(let o):
            return o
        }
    }

    /// Flattened dotted name for identifier/member chains (`String.contentsOf`,
    /// `UserDefaults.standard.string`).
    var dottedName: String {
        switch self {
        case .ident(let n, _): return n
        case .member(let b, let m, _):
            let base = b.dottedName
            return base.isEmpty ? m : "\(base).\(m)"
        default: return ""
        }
    }

    /// The last path component of a dotted/call chain (`readLine` from
    /// `FileHandle.standardInput.readLine`).
    var leafName: String {
        switch self {
        case .ident(let n, _): return n
        case .member(_, let m, _): return m
        case .call(let c, _, _): return c.leafName
        case .paren(let x, _): return x.leafName
        default: return ""
        }
    }

    /// All direct sub-expressions (used by generic taint recursion).
    var children: [SwiftExpr] {
        switch self {
        case .member(let b, _, _): return [b]
        case .index(let b, let i, _): return [b, i]
        case .call(let c, let a, _): return [c] + a
        case .newExpr(_, let a, _): return a
        case .unary(_, let o, _): return [o]
        case .binary(_, let l, let r, _), .range(_, let l, let r, _):
            return [l, r]
        case .assign(_, let l, let r, _): return [l, r]
        case .ternary(let c, let t, let f, _): return [c, t, f]
        case .arrayLit(let a, _): return a
        case .dictLit(let pairs, _): return pairs.flatMap { [$0.0, $0.1] }
        case .paren(let x, _), .forceUnwrap(let x, _), .optional(let x, _),
             .cast(_, let x, _):
            return [x]
        case .interpolation(let e, _): return e
        case .closure, .ident, .literal, .placeholder: return []
        }
    }
}

// MARK: - Parser

/// A `let`/`var` binding with optional initialiser.
public struct SwiftVar {
    public let name: String
    public let isLet: Bool
    public let initExpr: SwiftExpr?
    public let offset: Int
}

public struct SwiftCase {
    public let body: [SwiftStmt]
    public let offset: Int
    public let isDefault: Bool
}

public indirect enum SwiftStmt {
    case block([SwiftStmt], Int)
    case varDecl([SwiftVar], Int)
    case ifStmt(cond: SwiftExpr, thenBody: [SwiftStmt], elseBody: [SwiftStmt]?, Int)
    case guardStmt(cond: SwiftExpr, body: [SwiftStmt], Int)
    case forStmt(loopVar: String?, iterable: SwiftExpr?, body: [SwiftStmt], Int)
    case whileStmt(cond: SwiftExpr, body: [SwiftStmt], Int)
    case switchStmt(expr: SwiftExpr, cases: [SwiftCase], Int)
    case returnStmt(SwiftExpr?, Int)
    case throwStmt(SwiftExpr?, Int)
    case exprStmt(SwiftExpr, Int)
    case repeatStmt(body: [SwiftStmt], cond: SwiftExpr?, Int)
    case deferStmt([SwiftStmt], Int)

    var offset: Int {
        switch self {
        case .block(_, let o), .varDecl(_, let o), .ifStmt(_, _, _, let o),
             .guardStmt(_, _, let o), .forStmt(_, _, _, let o),
             .whileStmt(_, _, let o), .switchStmt(_, _, let o),
             .returnStmt(_, let o), .throwStmt(_, let o), .exprStmt(_, let o),
             .repeatStmt(_, _, let o), .deferStmt(_, let o):
            return o
        }
    }
}

// MARK: - Parser

/// Parses a Swift statement list / expression list from a token slice. The
/// parser is deliberately tolerant: malformed or obscure Swift is skipped
/// token-by-token instead of failing, so the security walks always make
/// progress.
public final class SwiftExprParser {

    private let tokens: [CAstToken]
    private var i = 0

    public init(tokens: [CAstToken]) {
        self.tokens = tokens
    }

    // MARK: Statements

    public static func parseStatements(_ tokens: [CAstToken]) -> [SwiftStmt] {
        let p = SwiftExprParser(tokens: tokens)
        var out: [SwiftStmt] = []
        while !p.atEnd() {
            guard let s = p.parseStatement() else { break }
            out.append(s)
        }
        return out
    }

    func parseStatement() -> SwiftStmt? {
        guard !atEnd() else { return nil }
        let t = peek()
        if t.text == "}" || t.kind == .eof { return nil }

        switch t.text {
        case "{":
            return parseBlock()
        case "if":
            return parseIf()
        case "guard":
            return parseGuard()
        case "for":
            return parseFor()
        case "while":
            return parseWhile()
        case "switch":
            return parseSwitch()
        case "return", "throw":
            return parseReturnThrow()
        case "break", "continue":
            let o = peek().offset
            i += 1
            return .exprStmt(.placeholder(o), o)
        case "let", "var":
            return parseVarDecl()
        case "do", "defer":
            if t.text == "defer" {
                let o = peek().offset
                i += 1
                if let b = parseBlockToBrace() {
                    return .deferStmt(b, o)
                }
                return nil
            }
            // do { } catch { } — treat the whole as a block for taint.
            let o = peek().offset
            i += 1
            var collected: [SwiftStmt] = []
            if peek().text == "{" {
                if case .block(let b, _) = parseBlock() { collected = b }
                while peek().text == "catch" {
                    i += 1
                    if peek().text == "{" {
                        if case .block(let b, _) = parseBlock() { collected += b }
                    } else {
                        skipUntil("{")
                        if peek().text == "{" {
                            if case .block(let b, _) = parseBlock() { collected += b }
                        }
                    }
                }
            }
            return .block(collected, o)
        case "repeat":
            let o = peek().offset
            i += 1
            let body: [SwiftStmt] = {
                if peek().text == "{" {
                    if case .block(let b, _) = parseBlock() { return b }
                }
                return []
            }()
            _ = matchWord("while")
            let cond: SwiftExpr? = peek().text != "{" ? parseExpression() : nil
            return .repeatStmt(body: body, cond: cond, o)
        case "#if", "#else", "#elseif", "#endif", "#available", "#selector", "#keyPath":
            // Conditional compilation blocks: `#if` ... `#endif`. Scan ahead for
            // the matching `#if`/`#endif` pair so the block's contents are
            // walked (they may still be compiled-out, but scanning them is safe).
            if t.text == "#if" {
                let o = peek().offset
                i += 1
                // skip the condition until `{` / newline-ish expression end. The
                // condition is `#if os(iOS) && !targetEnvironment`. Simply skip
                // until `{` at depth 0.
                if peek().text == "{" {
                    if case .block(let b, _) = parseBlock() { return .block(b, o) }
                }
            }
            i += 1
            return nil
        default:
            if let e = parseExpression() {
                return .exprStmt(e, e.offset)
            }
            i += 1
            return nil
        }
    }

    func parseBlock() -> SwiftStmt? {
        let o = peek().offset
        guard peek().text == "{" else { return nil }
        i += 1
        var inner: [SwiftStmt] = []
        while !atEnd() {
            if peek().text == "}" { i += 1; break }
            if let s = parseStatement() { inner.append(s) }
            else {
                if atEnd() { break }
                if peek().text == "}" { i += 1; break }
                i += 1
            }
        }
        return .block(inner, o)
    }

    /// Parses `{ ... }` and returns the inner statements (for `defer`).
    func parseBlockToBrace() -> [SwiftStmt]? {
        if case .block(let b, _)? = parseBlock() { return b }
        return nil
    }

    func parseIf() -> SwiftStmt? {
        let o = peek().offset
        i += 1 // if
        // Optional-binding head: `if let x = expr, ... {`.
        var bound: (name: String, initExpr: SwiftExpr)? = nil
        if peek().text == "let" || peek().text == "var" {
            i += 1
            if peek().kind == .identifier {
                let name = peek().text
                i += 1
                if matchOp("=") {
                    if let e = parseExpression(until: ",{") {
                        bound = (name, e)
                    }
                }
            }
            // Skip any additional comma-separated clauses.
            while peek().text == "," {
                i += 1
                if peek().text == "let" || peek().text == "var" { i += 1 }
                _ = parseExpression(until: ",{")
            }
        }
        let cond: SwiftExpr? = bound?.initExpr ?? parseExpression(until: "{")
        var thenBody: [SwiftStmt] = []
        if peek().text == "{" {
            if case .block(let b, _) = parseBlock() { thenBody = b }
        } else {
            if let s = parseStatement() { thenBody = [s] }
        }
        var elseBody: [SwiftStmt]? = nil
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
        var condE = cond ?? .placeholder(o)
        if let b = bound {
            let eq: SwiftExpr = .binary(op: "=", lhs: .ident(b.name, o), rhs: b.initExpr, o)
            condE = .binary(op: "&&", lhs: condE, rhs: eq, o)
            _ = eq
        }
        return .ifStmt(cond: condE, thenBody: thenBody, elseBody: elseBody, o)
    }

    func parseGuard() -> SwiftStmt? {
        let o = peek().offset
        i += 1 // guard
        var cond: SwiftExpr? = nil
        var lastOffset = o
        // `guard a, b = x, c else …`: parse comma-separated conditions and
        // combine them with `&&` so the boundary pass sees the full constraint.
        while !atEnd(), peek().text != "else" {
            if peek().text == "let" || peek().text == "var" { i += 1 }
            if let e = parseExpression(until: "else") {
                cond = (cond == nil) ? e : .binary(op: "&&", lhs: cond!, rhs: e, lastOffset)
                lastOffset = e.offset
            }
            if peek().text == "," { i += 1 } else { break }
        }
        _ = matchWord("else")
        var body: [SwiftStmt] = []
        if peek().text == "{" {
            if case .block(let b, _) = parseBlock() { body = b }
        } else if let s = parseStatement() {
            body = [s]
        }
        if body.isEmpty {
            // no-op marker used when the guard body failed to parse so callers
            // see an empty (non-empty) body list.
            body = [.exprStmt(.placeholder(o), o)]
        }
        return .guardStmt(cond: cond ?? .placeholder(o), body: body, o)
    }

    func parseFor() -> SwiftStmt? {
        let o = peek().offset
        i += 1 // for
        if peek().text == "let" || peek().text == "var" { i += 1 }
        var loopVar: String? = nil
        if peek().kind == .identifier {
            loopVar = peek().text
            i += 1
        }
        if peek().text == "," {
            // `for (a, b) in pairs` destructuring: skip the tuple.
            var depth = 0
            while !atEnd() {
                let t = peek()
                if t.text == "(" || t.text == "[" { depth += 1 }
                else if t.text == ")" || t.text == "]" { depth -= 1 }
                if t.text == ")" || t.text == "]" { i += 1; depth = max(0, depth - 1) }
                else { i += 1 }
                if depth == 0 { break }
            }
        }
        _ = matchWord("in")
        let iterable: SwiftExpr? = parseExpression(until: "{")
        var body: [SwiftStmt] = []
        if peek().text == "{" {
            if case .block(let b, _) = parseBlock() { body = b }
        } else if let s = parseStatement() { body = [s] }
        return .forStmt(loopVar: loopVar, iterable: iterable, body: body, o)
    }

    func parseWhile() -> SwiftStmt? {
        let o = peek().offset
        i += 1
        if peek().text == "let" || peek().text == "var" { i += 1 }
        let cond = parseExpression(until: "{")
        var body: [SwiftStmt] = []
        if peek().text == "{" {
            if case .block(let b, _) = parseBlock() { body = b }
        } else if let s = parseStatement() { body = [s] }
        return .whileStmt(cond: cond ?? .placeholder(o), body: body, o)
    }

    func parseSwitch() -> SwiftStmt? {
        let o = peek().offset
        i += 1
        let scrut = parseExpression(until: "{")
        _ = matchWord("switch")
        _ = swBr()
        if peek().text == "{" { i += 1 }
        var cases: [SwiftCase] = []
        while !atEnd() {
            let t = peek()
            if t.text == "}" { i += 1; break }
            if t.kind == .eof { break }
            if t.text == "case" || t.text == "default" {
                let icase = t.text == "default"
                let off = t.offset
                i += 1
                // Skip case patterns up to the first top-level `:`.
                var depth = 0
                while !atEnd() {
                    let p = peek()
                    if p.text == "{" || p.text == "(" || p.text == "["
                        || p.text == "<" { depth += 1 }
                    else if p.text == "}" || p.text == ")" || p.text == "]" {
                        depth = max(0, depth - 1)
                    }
                    if p.text == ":" && depth == 0 { i += 1; break }
                    if p.kind == .eof { break }
                    i += 1
                }
                var body: [SwiftStmt] = []
                while !atEnd() {
                    if peek().text == "case" || peek().text == "default" || peek().text == "}" { break }
                    if let s = parseStatement() { body.append(s) }
                    else {
                        if atEnd() { break }
                        i += 1
                    }
                }
                cases.append(SwiftCase(body: body, offset: off, isDefault: icase))
                continue
            }
            i += 1
        }
        return .switchStmt(expr: scrut ?? .placeholder(o), cases: cases, o)
    }

    func parseReturnThrow() -> SwiftStmt? {
        let o = peek().offset
        let kind = peek().text
        i += 1
        var expr: SwiftExpr? = nil
        if peek().text != "}" && peek().text != "{" && !isNextStatementStart() {
            expr = parseExpression()
        }
        if kind == "return" { return .returnStmt(expr, o) }
        return .throwStmt(expr, o)
    }

    func parseVarDecl() -> SwiftStmt? {
        let o = peek().offset
        var decls: [SwiftVar] = []
        while !atEnd() {
            let isLet = peek().text == "let"
            if peek().text != "let" && peek().text != "var" { break }
            i += 1
            var name: String? = nil
            var nameOff = peek().offset
            if peek().kind == .identifier {
                name = peek().text
                nameOff = peek().offset
                i += 1
            }
            var initExpr: SwiftExpr? = nil
            // Type annotation `: T` (skipped for taint).
            if peek().kind == .punct, peek().text == ":" {
                skipTypeAnnotation()
            }
            if matchOp("=") {
                initExpr = parseExpression(until: ",}")
            }
            if let n = name {
                decls.append(SwiftVar(name: n, isLet: isLet, initExpr: initExpr, offset: nameOff))
            }
            if peek().text != "," { break }
            i += 1
        }
        if decls.isEmpty { return nil }
        return .varDecl(decls, o)
    }

    private func skipTypeAnnotation() {
        // `: T` or `: T!` / `: T?` — skip until `=` / `,` / `}` / `{`.
        var depth = 0
        while !atEnd() {
            let t = peek()
            if t.kind == .punct {
                if t.text == "(" || t.text == "[" || t.text == "<" || t.text == "{" { depth += 1 }
                else if t.text == ")" || t.text == "]" || t.text == ">" {
                    depth = max(0, depth - 1)
                    if depth == 0 && (t.text == ")" || t.text == "]") { break }
                }
                if depth <= 0, t.text == "=" || t.text == "," || t.text == "}" { break }
            }
            if depth <= 0, t.kind == .operator, t.text == "=" { break }
            if depth <= 0, t.text == "{" { break }
            i += 1
        }
    }

    // MARK: Expressions

    func parseExpression(until enders: String = "") -> SwiftExpr? {
        return parseAssignment(enders: enders)
    }

    private func dangerouslyConsumes(_ e: SwiftExpr?, _ start: Int) -> SwiftExpr? {
        if e == nil && i == start && !atEnd() {
            // Avoid infinite loops in statement parsing by skipping one token.
            i += 1
            return .placeholder(start < tokens.count ? tokens[start].offset : 0)
        }
        return e
    }

    // MARK: Precedence chain

    private func parseAssignment(enders: String) -> SwiftExpr? {
        let lhs = parseTernary(enders: enders)
        if let lhs = lhs {
            let opTok = peek()
            if opTok.kind == .operator,
               ["=", "+=", "-=", "*=", "/=", "%=", "<<=", ">>=", "&=", "|=", "^=", "??="].contains(opTok.text),
               !precededByEnding(enders, token: opTok) {
                let op = opTok.text
                let o = opTok.offset
                i += 1
                let rhs = parseAssignment(enders: enders)
                return .assign(op: op, lhs: lhs, rhs: rhs ?? .placeholder(o), o)
            }
        }
        return lhs
    }

    private func parseTernary(enders: String) -> SwiftExpr? {
        guard let cond = parseCoalesce(enders: enders) else { return nil }
        if peek().kind == .punct, peek().text == "?",
           !precededByEnding(enders, token: peek()) {
            let o = peek().offset
            // Distinguish ternary from optional-chaining `a?.b` handled in postfix.
            // Here we've already parsed `a`, so this `?` is a ternary.
            i += 1
            let thenE = parseAssignment(enders: enders)
            _ = matchWord(":")
            let elseE = parseAssignment(enders: enders)
            return .ternary(cond: cond, thenExpr: thenE ?? .placeholder(o), elseExpr: elseE ?? .placeholder(o), o)
        }
        return cond
    }

    private func parseCoalesce(enders: String) -> SwiftExpr? {
        guard var lhs = parseOr(enders: enders) else { return nil }
        while !atEnd() {
            let t = peek()
            if t.kind == .operator, t.text != "??" { break }
            if t.kind == .operator, t.text == "??",
               !precededByEnding(enders, token: t) {
                let o = t.offset
                i += 1
                guard let rhs = parseOr(enders: enders) else { return lhs }
                lhs = .binary(op: "??", lhs: lhs, rhs: rhs, o)
                continue
            }
            break
        }
        return lhs
    }

    private func parseOr(enders: String) -> SwiftExpr? {
        guard var lhs = parseAnd(enders: enders) else { return nil }
        while !atEnd() {
            let t = peek()
            if t.kind == .operator, t.text == "||", !precededByEnding(enders, token: t) {
                let o = t.offset
                i += 1
                guard let rhs = parseAnd(enders: enders) else { return lhs }
                lhs = .binary(op: "||", lhs: lhs, rhs: rhs, o)
                continue
            }
            break
        }
        return lhs
    }

    private func parseAnd(enders: String) -> SwiftExpr? {
        guard var lhs = parseComparison(enders: enders) else { return nil }
        while !atEnd() {
            let t = peek()
            if t.kind == .operator, t.text == "&&", !precededByEnding(enders, token: t) {
                let o = t.offset
                i += 1
                guard let rhs = parseComparison(enders: enders) else { return lhs }
                lhs = .binary(op: "&&", lhs: lhs, rhs: rhs, o)
                continue
            }
            break
        }
        return lhs
    }

    private func parseComparison(enders: String) -> SwiftExpr? {
        guard var lhs = parseAdditive(enders: enders) else { return nil }
        while !atEnd() {
            let t = peek()
            if t.kind == .operator,
               ["==", "!=", "===", "!==", "<", "<=", ">", ">=", "~=", "is"].contains(t.text),
               !precededByEnding(enders, token: t) {
                let o = t.offset
                i += 1
                guard let rhs = parseAdditive(enders: enders) else { return lhs }
                lhs = .binary(op: t.text, lhs: lhs, rhs: rhs, o)
                continue
            }
            break
        }
        return lhs
    }

    private func parseAdditive(enders: String) -> SwiftExpr? {
        guard var lhs = parseMultiplicative(enders: enders) else { return nil }
        while !atEnd() {
            let t = peek()
            if t.kind == .operator, (t.text == "+" || t.text == "-"),
               !precededByEnding(enders, token: t) {
                let o = t.offset
                i += 1
                guard let rhs = parseMultiplicative(enders: enders) else { return lhs }
                lhs = .binary(op: t.text, lhs: lhs, rhs: rhs, o)
                continue
            }
            break
        }
        return lhs
    }

    private func parseMultiplicative(enders: String) -> SwiftExpr? {
        guard var lhs = parseRange(enders: enders) else { return nil }
        while !atEnd() {
            let t = peek()
            if t.kind == .operator,
               [ "*", "/", "%", "&", "|", "^", "<<", ">>"].contains(t.text),
               !precededByEnding(enders, token: t) {
                let o = t.offset
                i += 1
                guard let rhs = parseRange(enders: enders) else { return lhs }
                lhs = .binary(op: t.text, lhs: lhs, rhs: rhs, o)
                continue
            }
            break
        }
        return lhs
    }

    private func parseRange(enders: String) -> SwiftExpr? {
        guard var lhs = parsePostfix(enders: enders) else { return nil }
        // `0..<n` and `0...n` come out of the tokenizer differently:
        //   `0 ... n`  ->  number, op "..." , ident   (single operator token)
        //   `0 ..< n`  ->  number, ".", ".", "<", ident  (two dot puncts)
        if peek().kind == .operator, peek().text == "...",
           !precededByEnding(enders, token: peek()) {
            let o = peek().offset
            i += 1
            guard let rhs = parsePostfix(enders: enders) else { return lhs }
            lhs = .range(bound: "...", lhs: lhs, rhs: rhs, o)
            return lhs
        }
        if peek().kind == .punct, peek().text == "." {
            let save = i
            i += 1
            if peek().kind == .punct, peek().text == "." {
                i += 1
                if peek().kind == .operator, peek().text == "<", !precededByEnding(enders, token: peek()) {
                    let o = tokens[save].offset
                    i += 1
                    if let rhs = parsePostfix(enders: enders) {
                        lhs = .range(bound: "..<", lhs: lhs, rhs: rhs, o)
                        return lhs
                    }
                }
            }
            i = save
        }
        return lhs
    }

    /// Parses a unary-prefixed postfix expression.
    private func parsePostfix(enders: String) -> SwiftExpr? {
        let t = peek()
        if t.kind == .operator {
            if ["!", "-", "+", "~", "&"].contains(t.text) {
                let o = t.offset
                i += 1
                guard let operand = parsePostfix(enders: enders) else { return nil }
                return .unary(op: t.text, operand: operand, o)
            }
        }
        if t.kind == .identifier {
            if t.text == "try" || t.text == "await" {
                let o = t.offset
                i += 1
                // `try?` / `try!` — postfix marker operator.
                var op = t.text
                let nx = peek()
                if nx.kind == .operator, nx.text == "?" || nx.text == "!" {
                    op = op + nx.text
                    i += 1
                }
                guard let operand = parsePostfix(enders: enders) else { return nil }
                return .unary(op: op, operand: operand, o)
            }
            if t.text == "Some" || t.text == "Optional" {
                // `Some(...)` / `Optional(...)` constructor wrappers parse as calls.
            }
            if t.text == "as" || t.text == "is" {
                // type-cast prefix `as T` (rare at expression head)
                let o = t.offset
                i += 1
                let nx = peek()
                if nx.kind == .operator, nx.text == "?" || nx.text == "!" {
                    _ = nx.text
                    i += 1
                }
                // skip the type name
                if peek().kind == .identifier || peek().kind == .keyword { i += 1 }
                return .cast(op: "as", operand: .placeholder(o), o)
            }
        }
        return parsePrimaryPostfix(enders: enders)
    }

    private func parsePrimaryPostfix(enders: String) -> SwiftExpr? {
        guard let base = parsePrimary(enders: enders) else { return nil }
        return parsePostfixSuffix(base, enders: enders)
    }

    private func parsePostfixSuffix(_ base: SwiftExpr, enders: String) -> SwiftExpr {
        var node = base
        while !atEnd() {
            let t = peek()
            if t.kind == .punct {
                if t.text == "." {
                    // member access; but `.` immediately after a literal with a
                    // second `.` was consumed by parseRange. Also `.` could start
                    // `..` — shouldn't happen here since parseRange pre-empted it.
                    let save = i
                    i += 1
                    // `.init(...)` / `.someMember`
                    if peek().text == "init" || peek().kind == .identifier || peek().kind == .keyword {
                        let m = peek().text
                        let o = peek().offset
                        i += 1
                        // If next is `(` treat as method call `base.m(args)`.
                        if peek().kind == .punct, peek().text == "(" {
                            if let args = parseArgList() {
                                node = .call(callee: .member(node, m, o), args: args, o)
                            }
                        } else if peek().kind == .punct, peek().text == "[" {
                            node = .index(.member(node, m, o), parseIndexArg() ?? .placeholder(o), o)
                        } else {
                            node = .member(node, m, o)
                        }
                        continue
                    }
                    // bare enum `.case` in expression (e.g. `switch x { case .foo:`)
                    if peek().text != "{" {
                        i = save
                        break
                    }
                } else if t.text == "(" {
                    let o = t.offset
                    if let args = parseArgList() {
                        node = .call(callee: node, args: args, o)
                        continue
                    }
                } else if t.text == "[" {
                    let o = t.offset
                    node = .index(node, parseIndexArg() ?? .placeholder(o), o)
                    continue
                } else {
                    break
                }
            } else if t.kind == .operator {
                if t.text == "!" {
                    let o = t.offset
                    i += 1
                    node = .forceUnwrap(node, o)
                    continue
                }
                if t.text == "?" {
                    // Postfix optional `foo?` — treat as optional chaining marker.
                    let o = t.offset
                    i += 1
                    // `foo?.bar` — the `?` is immediately followed by `.`.
                    if peek().kind == .punct, peek().text == "." {
                        i += 1
                        if peek().kind == .identifier || peek().kind == .keyword {
                            let m = peek().text
                            let mo = peek().offset
                            i += 1
                            if peek().kind == .punct, peek().text == "(" {
                                if let args = parseArgList() {
                                    node = .call(callee: .optional(.member(node, m, mo), o), args: args, o)
                                }
                            } else {
                                node = .optional(.member(node, m, mo), o)
                            }
                            continue
                        }
                        i -= 1
                    }
                    node = .optional(node, o)
                    continue
                }
                break
            } else {
                break
            }
        }
        return node
    }

    private func parseArgList() -> [SwiftExpr]? {
        guard peek().kind == .punct, peek().text == "(" else { return nil }
        i += 1
        var args: [SwiftExpr] = []
        while !atEnd() {
            let t = peek()
            if t.kind == .punct && t.text == ")" { i += 1; break }
            if t.kind == .eof { break }
            if t.kind == .punct && t.text == "," { i += 1; continue }
            // Labeled argument `label: value` — skip the label, keep the value.
            if t.kind == .identifier {
                let save = i
                i += 1
                if peek().kind == .punct, peek().text == ":" {
                    i += 1
                    if let v = parseExpression(until: ",)") {
                        args.append(v)
                        continue
                    }
                    continue
                }
                i = save
            }
            // Closure shorthand `{ ... }` argument.
            if peek().kind == .punct && peek().text == "{" {
                if let c = parseClosure() { args.append(c); continue }
                i += 1
                continue
            }
            if let e = parseExpression(until: ",)") {
                args.append(e)
            } else {
                i += 1
            }
        }
        return args
    }

    private func parseIndexArg() -> SwiftExpr? {
        guard peek().kind == .punct, peek().text == "[" else { return nil }
        i += 1
        let e = parseExpression(until: "]")
        if peek().kind == .punct, peek().text == "]" { i += 1 }
        return e
    }

    private func parseClosure() -> SwiftExpr? {
        guard peek().kind == .punct, peek().text == "{" else { return nil }
        let o = peek().offset
        i += 1
        var params: [String] = []
        // Closure head: `(a, b)` or `a, b` before `in`.
        if peek().kind == .punct, peek().text == "(" {
            i += 1
            var depth = 0
            var group: [CAstToken] = []
            while !atEnd() {
                let t = peek()
                if t.kind == .punct {
                    if t.text == "(" || t.text == "[" || t.text == "<" { depth += 1; if depth == 0 { group.append(t) } }
                    else if t.text == ")" || t.text == "]" || t.text == ">" {
                        depth = max(0, depth - 1)
                        if depth == 0 && t.text == ")" { i += 1; break }
                    }
                }
                if depth > 0 || (t.kind == .punct && t.text == "(") { /* skip outer delim */ }
                if t.kind != .punct || t.text != "(" {
                    if !(t.kind == .punct && (t.text == "(" || t.text == ")" )) {
                        group.append(t)
                    }
                }
                i += 1
                _ = group
            }
            params = closureParams(from: group)
        } else {
            // `{ x, y in ... }` — collect identifiers until `in`.
            while !atEnd() {
                let t = peek()
                if t.text == "in" { i += 1; break }
                if t.kind == .identifier, t.text != "in" {
                    params.append(t.text)
                    i += 1
                } else if t.kind == .punct || t.kind == .operator {
                    i += 1
                } else {
                    i += 1
                }
                if t.text == "{" || t.kind == .eof { break }
            }
        }
        var body: [SwiftStmt] = []
        while !atEnd() {
            let t = peek()
            if t.text == "}" { i += 1; break }
            if t.kind == .eof { break }
            if let s = parseStatement() { body.append(s) }
            else { i += 1 }
        }
        return .closure(params: params, body: body, o)
    }

    private func closureParams(from tokens: [CAstToken]) -> [String] {
        var names: [String] = []
        var group: [CAstToken] = []
        var depth = 0
        var pendingColonIdx = -1
        func collectGroup() {
            var name: String? = nil
            if pendingColonIdx >= 0 {
                var j = pendingColonIdx - 1
                if j >= group.count { j = group.count - 1 }
                while j >= 0 {
                    if group[j].kind == .identifier { name = group[j].text; break }
                    j -= 1
                }
            } else {
                for t in group where t.kind == .identifier { name = t.text }
            }
            if let n = name, !n.isEmpty, n != "_" { names.append(n) }
            group = []
            pendingColonIdx = -1
        }
        for t in tokens {
            if t.kind == .punct {
                if t.text == "(" || t.text == "[" { depth += 1 }
                else if t.text == ")" || t.text == "]" { depth = max(0, depth - 1) }
                else if t.text == "," && depth == 0 { collectGroup(); continue }
                else if t.text == ":" && depth == 0 { pendingColonIdx = group.count }
            }
            group.append(t)
        }
        collectGroup()
        return names
    }

    private func parsePrimary(enders: String) -> SwiftExpr? {
        guard !atEnd() else { return nil }
        let t = peek()
        if t.kind == .punct {
            switch t.text {
            case "(":
                let o = t.offset
                i += 1
                if peek().kind == .punct, peek().text == ")" {
                    // empty tuple `()`
                    return .literal(text: "()", o)
                }
                let inner = parseExpression(until: ")")
                if peek().kind == .punct, peek().text == ")" { i += 1 }
                if let inner = inner { return .paren(inner, o) }
                return .placeholder(o)
            case "[":
                return parseArrayOrDict()
            case "{":
                return parseClosure()
            default:
                return nil
            }
        }
        if t.kind == .operator {
            if t.text == "*" || t.text == "&" {
                // `*ptr` deref / `&var` — treat as unary.
                let o = t.offset
                i += 1
                if let operand = parsePostfix(enders: enders) {
                    return .unary(op: t.text, operand: operand, o)
                }
            }
            // `?`-prefixed implicit member — ignore.
            return nil
        }
        if t.kind == .number {
            let o = t.offset
            i += 1
            return .literal(text: t.text, o)
        }
        if t.kind == .string {
            let o = t.offset
            i += 1
            if t.text.contains("\\( ") == false, t.text.contains("\\(") {
                let exprs = SwiftExprParser.interpolationExprs(from: t.text, offset: o)
                return .interpolation(exprs: exprs, o)
            }
            return .literal(text: t.text, o)
        }
        if t.kind == .character {
            let o = t.offset
            i += 1
            return .literal(text: t.text, o)
        }
        if t.kind == .keyword {
            if t.text == "true" || t.text == "false" {
                let o = t.offset
                i += 1
                return .literal(text: t.text, o)
            }
            if t.text == "nil" {
                let o = t.offset
                i += 1
                return .literal(text: "nil", o)
            }
            if t.text == "self" || t.text == "super" {
                let o = t.offset
                i += 1
                return .ident(t.text, o)
            }
            if t.text == "new" || t.text == "this" {
                let o = t.offset
                i += 1
                return .ident(t.text, o)
            }
            if t.text == "class" || t.text == "struct" || t.text == "enum"
                || t.text == "func" || t.text == "extension" || t.text == "return" {
                // declaration-like keyword inside an expression — stop.
                return nil
            }
            // Type keyword followed by `(`: `Int(x)`, `Data("...")`, `String(...)`.
            if t.text == "int" || t.text == "char" || t.text == "float" || t.text == "double"
                || t.text == "long" || t.text == "short" || t.text == "bool"
                || t.text == "string" || t.text == "data" {
                let o = t.offset
                i += 1
                if peek().kind == .punct, peek().text == "(" {
                    if let args = parseArgList() {
                        return .newExpr(typeName: t.text, args: args, o)
                    }
                }
                return .ident(t.text, o)
            }
            // Any other keyword in expression position — consume it as an
            // identifier-like operand (e.g. Swift 5.3+ `using` a tokenized
            // keyword in arg-label position). Consuming prevents parse loops.
            let o = t.offset
            i += 1
            return .ident(t.text, o)
        }
        if t.kind == .identifier {
            let o = t.offset
            let name = t.text
            i += 1
            // Function call `name(...)` (lowercase) vs constructor `Type(...)`
            // (capitalized). Only capitalized names are treated as type
            // construction; lowercase identifiers are plain calls so the generic
            // sink rules (SQL, exec, …) can see them.
            if peek().kind == .punct, peek().text == "(" {
                if let args = parseArgList() {
                    if name.first?.isUppercase == true {
                        return .newExpr(typeName: name, args: args, o)
                    }
                    return .call(callee: .ident(name, o), args: args, o)
                }
                if name.first?.isUppercase == true {
                    return .newExpr(typeName: name, args: [], o)
                }
                return .call(callee: .ident(name, o), args: [], o)
            }
            return .ident(name, o)
        }
        return nil
    }

    private func parseArrayOrDict() -> SwiftExpr? {
        let o = peek().offset
        guard peek().kind == .punct, peek().text == "[" else { return nil }
        i += 1
        var elements: [SwiftExpr] = []
        var pairs: [(SwiftExpr, SwiftExpr)] = []
        var isDict = false
        while !atEnd() {
            let t = peek()
            if t.kind == .punct && t.text == "]" { i += 1; break }
            if t.kind == .eof { break }
            if t.kind == .punct && t.text == "," { i += 1; continue }
            if let e = parseExpression(until: ",:}]") {
                if peek().kind == .punct, peek().text == ":" {
                    i += 1
                    if let v = parseExpression(until: ",}]") {
                        pairs.append((e, v))
                        isDict = true
                        continue
                    }
                }
                elements.append(e)
                continue
            }
            i += 1
        }
        if isDict { return .dictLit(pairs, o) }
        return .arrayLit(elements, o)
    }

    // MARK: Helpers

    private func parseExpressionUntil(enders: String) -> SwiftExpr? {
        parseExpression(until: enders)
    }

    func atEnd() -> Bool { i >= tokens.count || tokens[i].kind == .eof }

    func peek() -> CAstToken {
        guard i < tokens.count else { return CAstToken(kind: .eof, text: "", line: 0, column: 0, offset: 0) }
        return tokens[i]
    }

    func matchOp(_ op: String) -> Bool {
        if peek().kind == .operator && peek().text == op {
            i += 1
            return true
        }
        return false
    }

    func matchWord(_ w: String) -> Bool {
        if peek().text == w { i += 1; return true }
        return false
    }

    /// True when `tok` is one of the `,` / `)` style enders at the current
    /// parse-depth, i.e. the token list ends or the caller asked us to stop.
    private func precededByEnding(_ enders: String, token: CAstToken) -> Bool {
        if enders.isEmpty { return false }
        return enders.contains(token.text)
    }

    private func isNextStatementStart() -> Bool {
        let t = peek()
        return ["if", "guard", "for", "while", "switch", "return", "let", "var",
                "do", "defer", "throw", "break", "continue", "repeat", "catch"].contains(t.text)
    }

    private func skipUntil(_ text: String) {
        while !atEnd() {
            if peek().text == text { return }
            i += 1
        }
    }

    private func swBr() -> Bool { false }

    // MARK: String interpolation

    /// Extracts the interpolated sub-expressions of a Swift string token such as
    /// `"hello \(name)!"`. Pieces between interpolations are constant text.
    static func interpolationExprs(from stringToken: String, offset: Int) -> [SwiftExpr] {
        var out: [SwiftExpr] = []
        let ns = stringToken as NSString
        let len = ns.length
        var i = 0
        while i < len {
            // Find `\(`.
            var foundAt = -1
            var j = i
            while j + 1 < len {
                if ns.character(at: j) == 0x5C && ns.character(at: j + 1) == 0x28 {
                    foundAt = j
                    break
                }
                j += 1
            }
            if foundAt < 0 { break }
            // Find matching `)` (nested aware).
            var depth = 0
            var k = foundAt + 2
            var close = -1
            while k < len {
                let c = ns.character(at: k)
                if c == 0x28 { depth += 1 }
                else if c == 0x29 {
                    depth -= 1
                    if depth == 0 { close = k; break }
                }
                k += 1
            }
            guard close >= 0 else { break }
            let inner = ns.substring(with: NSRange(location: foundAt + 2, length: close - (foundAt + 2)))
            let innerTokens = CTokenizer(source: inner).tokenize()
            let subParser = SwiftExprParser(tokens: innerTokens)
            if let e = subParser.parseExpressionUntil(enders: "") {
                out.append(e)
            }
            i = close + 1
        }
        return out
    }
}
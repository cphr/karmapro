// by cipher.org.uk
import Foundation

// MARK: - ObjC native parser
//
// Recursive-descent parser over the shared CTokenizer stream. Produces
// ObjCMethodDef bodies as flattened ObjCStmt lists (control-flow bodies are
// inlined after their condition statement, which the detector's guard
// analysis uses).
//
// Design notes:
//  * `@interface`/`@protocol` blocks carry no bodies and are skipped; only
//    `@implementation` bodies and top-level C functions are parsed.
//  * Message expressions `[recv sel:arg more:arg2]` are modeled as
//    `.message(receiver:parts:)`; bracket-style selector calls are the reason
//    this AST exists — the C-AST cannot represent them.
//  * Blocks `^{...}` / `^(args){...}` at statement level are flattened into
//    the enclosing statement list so sinks inside completion handlers are
//    analyzed. Blocks appearing as call/message arguments are parsed as
//    opaque sub-scopes in this revision (documented limitation).
//  * Subscripts (`buf[i]`) are recognized only in postfix position; a `[`
//    where a primary is expected is always a message (ObjC semantics —
//    NSArray subscripting lowers to messages anyway).

public final class ObjCParser {
    private let source: String
    private let tokens: [CAstToken]
    private var pos = 0

    public init(source: String) {
        self.source = source
        self.tokens = CTokenizer(source: source).tokenize()
    }

    // MARK: - Token helpers

    private var current: CAstToken { tokens[min(pos, tokens.count - 1)] }
    private func peek(_ ahead: Int = 1) -> CAstToken { tokens[min(pos + ahead, tokens.count - 1)] }
    @discardableResult
    private func advance() -> CAstToken {
        let t = current
        if pos < tokens.count - 1 { pos += 1 }
        return t
    }
    private var atEOF: Bool { current.kind == .eof }
    private func isAt(_ text: String) -> Bool { current.text == text }
    private func peekIs(_ text: String) -> Bool { peek().text == text }
    @discardableResult
    private func match(_ text: String) -> Bool {
        if isAt(text) { advance(); return true }
        return false
    }
    private func isIdentLike(_ t: CAstToken) -> Bool {
        t.kind == .identifier || t.kind == .keyword
    }
    private var isAtIdentLike: Bool {
        current.kind == .identifier || current.kind == .keyword
    }

    // MARK: - Public entry points

    /// Parses @implementation method bodies plus top-level C functions.
    public func parseFile() -> (defs: [ObjCMethodDef], bodies: [Int: [ObjCStmt]]) {
        var defs: [ObjCMethodDef] = []
        var bodies: [Int: [ObjCStmt]] = [:]

        while !atEOF {
            if isAt("@") {
                let directive = peek().text
                switch directive {
                case "implementation":
                    advance() // @
                    advance() // implementation
                    var container = ""
                    if isAtIdentLike { container = advance().text }
                    // Optional superclass `: Base` and category `(Name)`.
                    // Stop at method starters (`- (` / `+ (`) and the ivar
                    // block `{` so definitions are never swallowed.
                    while !atEOF && !isAt("@") {
                        if isAt("{") { break }
                        if (isAt("-") || isAt("+")), peekIs("(") { break }
                        advance()
                    }
                    // Optional ivar block.
                    if isAt("{") { skipBalanced(open: "{", close: "}") }
                    let (d, b) = parseImplementationBody(container: container)
                    defs.append(contentsOf: d)
                    bodies.merge(b) { cur, _ in cur }
                    continue
                case "interface", "protocol":
                    skipDirectiveBlock() // to matching @end
                    continue
                case "class":
                    advance(); advance()
                    while !atEOF && !isAt(";") { advance() }
                    match(";")
                    continue
                default:
                    advance()
                    continue
                }
            }

            // Top-level C function: `type name ( args ) { body }`.
            if let (def, stmts) = tryParseCFunction() {
                defs.append(def)
                bodies[def.bodyOpenOffset] = stmts
                continue
            }
            advance()
        }
        return (defs, bodies)
    }

    /// Compatibility entry point: definitions only.
    public func parseDefinitions() -> [ObjCMethodDef] {
        parseFile().defs
    }

    // MARK: - Directive skipping

    /// Skips an @interface/@protocol block, honoring nesting.
    private func skipDirectiveBlock() {
        var depth = 0
        while !atEOF {
            if isAt("@") {
                let d = peek().text
                if d == "interface" || d == "protocol" { depth += 1; advance(); continue }
                if d == "end" {
                    advance(); advance()
                    depth -= 1
                    if depth <= 0 { return }
                    continue
                }
            }
            advance()
        }
    }

    // MARK: - @implementation bodies

    private func parseImplementationBody(container: String) -> (defs: [ObjCMethodDef], bodies: [Int: [ObjCStmt]]) {
        var defs: [ObjCMethodDef] = []
        var bodies: [Int: [ObjCStmt]] = [:]

        while !atEOF {
            if isAt("@") {
                if peek().text == "end" { advance(); advance(); return (defs, bodies) }
                if peek().text == "property" || peek().text == "synthesize" || peek().text == "dynamic" {
                    advance(); advance()
                    while !atEOF && !isAt(";") { advance() }
                    match(";")
                    continue
                }
                advance()
                continue
            }
            if isAt("-") || isAt("+"), peek().text == "(" {
                let isClassMethod = isAt("+")
                if let (def, stmts) = parseMethodDef(container: container, isClassMethod: isClassMethod) {
                    defs.append(def)
                    bodies[def.bodyOpenOffset] = stmts
                }
                continue
            }
            if let (def, stmts) = tryParseCFunction() {
                defs.append(def)
                bodies[def.bodyOpenOffset] = stmts
                continue
            }
            advance()
        }
        return (defs, bodies)
    }

    /// Parses `- (void)name:(Type)arg more:(T2)a2 { ... }`.
    private func parseMethodDef(container: String, isClassMethod: Bool) -> (ObjCMethodDef, [ObjCStmt])? {
        advance() // - / +
        guard match("(") else { return nil }
        let returnType = parseTypeName()
        guard match(")") else { return nil }

        guard isAtIdentLike else { return nil }
        let first = advance()
        let nameOffset = first.offset
        var selectorPieces: [String] = []
        var params: [ObjCParam] = []
        var currentPiece = first.text

        let sawBody = false
        var bodyOpen = -1
        var bodyEnd = -1
        var stmts: [ObjCStmt] = []

        while true {
            if isAt(":") {
                advance()
                selectorPieces.append(currentPiece + ":")
                guard match("(") else { return nil }
                let ptype = parseTypeName()
                guard match(")") else { return nil }
                guard isAtIdentLike else { return nil }
                let pname = advance()
                params.append(ObjCParam(label: currentPiece + ":", name: pname.text, type: ptype, nameOffset: pname.offset))
                // Variadic tail: `, ...`.
                if isAt(","), peekIs("...") { advance(); advance() }
                // Next selector piece?
                if isAtIdentLike {
                    currentPiece = advance().text
                    if isAt(":") { continue }
                    selectorPieces.append(currentPiece) // nil-arg tail piece
                }
                break
            } else {
                selectorPieces.append(currentPiece) // no-arg method
                break
            }
        }
        _ = sawBody

        if match(";") {
            // Declaration without body (interface-style); no statements.
        } else if isAt("{") {
            bodyOpen = current.offset
            advance()
            stmts = parseStatementList()
            if isAt("}") { bodyEnd = current.offset; advance() }
        }

        let selector = selectorPieces.joined()
        let def = ObjCMethodDef(container: container,
                                isClassMethod: isClassMethod,
                                isCFunction: false,
                                selector: selector,
                                returnType: returnType,
                                params: params,
                                nameOffset: nameOffset,
                                bodyOpenOffset: bodyOpen,
                                bodyEndOffset: bodyEnd)
        return (def, stmts)
    }

    // MARK: - C functions in ObjC files

    /// Detects `type name ( args ) {` at the cursor (not control keywords).
    /// Returns the def together with its parsed body statements.
    private func tryParseCFunction() -> (ObjCMethodDef, [ObjCStmt])? {
        guard isAtIdentLike else { return nil }
        let kw = current.text
        let control = ["if", "while", "for", "switch", "return", "else", "do", "case", "default"]
        if control.contains(kw) { return nil }

        // Lookahead: find an identifier followed by '(' whose matching ')' is
        // directly followed by '{'. Bound the scan.
        var j = pos
        var steps = 0
        var nameToken: CAstToken? = nil
        while j < tokens.count && steps < 24 {
            let t = tokens[j]
            if t.kind == .identifier || t.kind == .keyword {
                if j + 1 < tokens.count, tokens[j + 1].text == "(" {
                    nameToken = t
                    // Match parens from j+1.
                    var depth = 0
                    var k = j + 1
                    while k < tokens.count {
                        if tokens[k].text == "(" { depth += 1 }
                        else if tokens[k].text == ")" {
                            depth -= 1
                            if depth == 0 { break }
                        }
                        k += 1
                    }
                    if k + 1 < tokens.count, tokens[k + 1].text == "{" {
                        // Found a function shape; move cursor to the name.
                        while pos < j { advance() }
                        _ = advance() // name
                        advance() // (
                        // Parse parameters: the last identifier before ',' or
                        // ')' is the parameter's local name.
                        var params: [ObjCParam] = []
                        while !atEOF && !isAt(")") {
                            var lastName: CAstToken? = nil
                            while !atEOF && !isAt(",") && !isAt(")") {
                                let t = current
                                if t.kind == .identifier || t.kind == .keyword { lastName = t }
                                advance()
                            }
                            if let pn = lastName {
                                params.append(ObjCParam(label: nil, name: pn.text, type: "", nameOffset: pn.offset))
                            }
                            if isAt(",") { advance() }
                        }
                        match(")")
                        guard isAt("{") else { return nil }
                        let bodyOpen = current.offset
                        advance()
                        let stmts = parseStatementList()
                        var bodyEnd = bodyOpen
                        if isAt("}") { bodyEnd = current.offset; advance() }
                        let def = ObjCMethodDef(container: "",
                                                isClassMethod: false,
                                                isCFunction: true,
                                                selector: nameToken?.text ?? t.text,
                                                returnType: "",
                                                params: params,
                                                nameOffset: nameToken?.offset ?? t.offset,
                                                bodyOpenOffset: bodyOpen,
                                                bodyEndOffset: bodyEnd)
                        return (def, stmts)
                    }
                }
            }
            j += 1
            steps += 1
        }
        return nil
    }

    // MARK: - Type parsing

    /// Consumes a (possibly qualified/pointer/generic) type and returns its
    /// textual form. Balances nested parens so block-pointer params survive.
    private func parseTypeName() -> String {
        var parts: [String] = []
        var depth = 0
        var angle = 0
        while !atEOF {
            let t = current
            if t.text == "(" { depth += 1; parts.append(t.text); advance(); continue }
            if t.text == ")" {
                if depth == 0 { break }
                depth -= 1; parts.append(t.text); advance(); continue
            }
            if depth > 0 { parts.append(t.text); advance(); continue }
            if t.text == "<" { angle += 1; parts.append(t.text); advance(); continue }
            if t.text == ">" { angle = max(0, angle - 1); parts.append(t.text); advance(); continue }
            if angle > 0 { parts.append(t.text); advance(); continue }
            if t.kind == .identifier || t.kind == .keyword || t.text == "*" {
                parts.append(t.text)
                advance()
                continue
            }
            break
        }
        return parts.joined(separator: " ")
    }

    // MARK: - Statement parsing

    private func parseStatementList() -> [ObjCStmt] {
        var out: [ObjCStmt] = []
        while !atEOF && !isAt("}") {
            let start = pos
            parseOneStatement(into: &out)
            if pos == start { advance() } // guarantee progress
        }
        return out
    }

    private func parseOneStatement(into out: inout [ObjCStmt]) {
        let offset = current.offset

        if match(";") { return }

        // Anonymous scope / block.
        if isAt("{") {
            advance()
            out.append(contentsOf: parseStatementList())
            match("}")
            return
        }

        // @-directives inside bodies.
        if isAt("@") {
            let d = peek().text
            advance() // @
            switch d {
            case "try", "catch", "finally", "autoreleasepool", "synchronized":
                advance() // directive word
                if isAt("(") {
                    advance()
                    if let cond = parseExpression(stopAtSelector: false) {
                        out.append(ObjCStmt(kind: .condition(cond), offset: offset))
                    }
                    match(")")
                }
                if isAt("{") {
                    advance()
                    out.append(contentsOf: parseStatementList())
                    match("}")
                }
                return
            default:
                return
            }
        }

        // Control flow.
        switch current.text {
        case "if":
            advance()
            if let cond = parseParenExpression() {
                out.append(ObjCStmt(kind: .condition(cond), offset: offset))
            }
            parseStatementOrBlock(into: &out)
            if isAt("else") {
                advance()
                if isAt("if") {
                    // else-if: recurse as an inline if.
                    parseOneStatement(into: &out)
                } else {
                    parseStatementOrBlock(into: &out)
                }
            }
            return
        case "while":
            advance()
            if let cond = parseParenExpression() {
                out.append(ObjCStmt(kind: .condition(cond), offset: offset))
            }
            parseStatementOrBlock(into: &out)
            return
        case "for":
            advance()
            if isAt("(") {
                advance()
                // C-style headers contain ';'; foreach headers contain 'in'.
                var sawSemi = false
                while !atEOF && !isAt(")") {
                    if isAt(";") { sawSemi = true; advance(); continue }
                    if isAt("in") { advance(); continue }
                    if let e = parseExpression(stopAtSelector: false) {
                        out.append(ObjCStmt(kind: .condition(e), offset: offset))
                    }
                    if isAt(",") { advance() }
                }
                _ = sawSemi
                match(")")
            }
            parseStatementOrBlock(into: &out)
            return
        case "switch":
            advance()
            _ = parseParenExpression()
            if isAt("{") {
                advance()
                // Flat parse; case/default labels consumed inline.
                while !atEOF && !isAt("}") {
                    if isAt("case") || isAt("default") {
                        advance()
                        while !atEOF && !isAt(":") && !isAt("{") { advance() }
                        match(":")
                        continue
                    }
                    let s2 = pos
                    parseOneStatement(into: &out)
                    if pos == s2 { advance() }
                }
                match("}")
            }
            return
        case "do":
            advance()
            parseStatementOrBlock(into: &out)
            if match("while") { _ = parseParenExpression() }
            match(";")
            return
        case "return":
            advance()
            if isAt(";") {
                advance()
                out.append(ObjCStmt(kind: .returnStmt(nil), offset: offset))
            } else {
                let e = parseExpression(stopAtSelector: false)
                match(";")
                out.append(ObjCStmt(kind: .returnStmt(e), offset: offset))
            }
            return
        case "break", "continue", "goto":
            advance()
            while !atEOF && !isAt(";") { advance() }
            match(";")
            return
        default:
            break
        }

        // Statement-level block literal: ^{...} / ^(args){...}.
        if isAt("^") {
            advance()
            if isAt("(") { skipBalanced(open: "(", close: ")") }
            if isAt("{") {
                advance()
                out.append(contentsOf: parseStatementList())
                match("}")
            }
            // Optional immediate invocation `(...)`.
            if isAt("(") { skipBalanced(open: "(", close: ")") }
            match(";")
            return
        }

        // Declaration or expression.
        if let decl = tryParseDeclaration() {
            out.append(decl)
            return
        }
        if let expr = parseExpression(stopAtSelector: false) {
            let compoundOps = ["+=", "-=", "*=", "/=", "%=", "&=", "|=", "^=", "<<=", ">>="]
            if isAt("=") || compoundOps.contains(current.text) {
                advance()
                let value = parseExpression(stopAtSelector: false)
                match(";")
                out.append(ObjCStmt(kind: .assignment(target: expr, value: value ?? .unknown(offset)), offset: offset))
                return
            }
            match(";")
            out.append(ObjCStmt(kind: .expression(expr), offset: offset))
            return
        }
        // Unparseable: skip a token to guarantee progress.
        advance()
    }

    private func parseStatementOrBlock(into out: inout [ObjCStmt]) {
        if isAt("{") {
            advance()
            out.append(contentsOf: parseStatementList())
            match("}")
            return
        }
        let s = pos
        parseOneStatement(into: &out)
        if pos == s { advance() }
    }

    private func parseParenExpression() -> ObjCExpr? {
        guard match("(") else { return nil }
        let e = parseExpression(stopAtSelector: false)
        match(")")
        return e
    }

    // MARK: - Declarations

    /// `Type name = expr;` / `Type *name;` / `char buf[64];` etc.
    private func tryParseDeclaration() -> ObjCStmt? {
        guard isAtIdentLike else { return nil }
        let declOffset = current.offset
        var j = pos
        var typeTokens = 0
        var sawStar = false
        var typeName = current.text
        // Qualifiers + type name(s). The scan stops when a token is followed
        // by `= ; , [` — that token is the declared NAME, not part of the type.
        while j < tokens.count {
            let t = tokens[j]
            if t.kind == .identifier || t.kind == .keyword {
                let nextText = j + 1 < tokens.count ? tokens[j + 1].text : ""
                if ["=", ";", ",", "["].contains(nextText) { break }
                typeName = t.text
                typeTokens += 1
                j += 1
                continue
            }
            if t.text == "*" { sawStar = true; j += 1; continue }
            if t.text == "<" {
                // Generics: skip to matching '>'.
                var depth = 0
                while j < tokens.count {
                    if tokens[j].text == "<" { depth += 1 }
                    else if tokens[j].text == ">" {
                        depth -= 1
                        if depth == 0 { j += 1; break }
                    }
                    j += 1
                }
                continue
            }
            break
        }
        guard typeTokens >= 1 else { return nil }
        // The name: an identifier after the type tokens.
        while j < tokens.count, tokens[j].text == "*" { sawStar = true; j += 1 }
        guard j < tokens.count, tokens[j].kind == .identifier else { return nil }
        let nameTok = tokens[j]
        // What follows decides: `=`, `;`, `,`, `[` (array), `(` would be a call — not a decl.
        guard j + 1 < tokens.count else { return nil }
        let after = tokens[j + 1]
        guard ["=", ";", ",", "["].contains(after.text) else { return nil }

        // Consume to (and including) the name.
        while pos <= j { advance() }
        var arraySize: Int? = nil
        if isAt("[") {
            advance()
            if current.kind == .number, let n = Int(current.text) { arraySize = n }
            while !atEOF && !isAt("]") { advance() }
            match("]")
        }
        var initExpr: ObjCExpr? = nil
        if match("=") {
            initExpr = parseExpression(stopAtSelector: false)
        }
        match(";")
        // Multiple declarators `int a = 1, b = 2;` — the tail is consumed as
        // a plain expression statement by the caller loop on the next pass.
        if isAt(",") { advance() }
        return ObjCStmt(kind: .declaration(type: typeName,
                                           name: nameTok.text,
                                           isPointer: sawStar,
                                           arraySize: arraySize,
                                           initExpr: initExpr),
                        offset: declOffset)
    }

    // MARK: - Expressions

    /// Parses an expression. When `stopAtSelector` is true (message arguments),
    /// parsing returns at an `identifier :` continuation so the message parser
    /// can consume the next selector part.
    private func parseExpression(stopAtSelector: Bool) -> ObjCExpr? {
        let cond = parseBinary(precedence: 0, stopAtSelector: stopAtSelector)
        if isAt("?") {
            advance()
            let thenE = parseExpression(stopAtSelector: false)
            guard match(":") else { return cond }
            let elseE = parseExpression(stopAtSelector: stopAtSelector)
            return .ternary(cond: cond ?? .unknown(cond?.offset ?? 0),
                            then: thenE ?? .unknown(0),
                            else: elseE ?? .unknown(0),
                            offset: cond?.offset ?? 0)
        }
        return cond
    }

    private static let binaryPrecedence: [String: Int] = [
        "||": 1, "&&": 2, "|": 3, "^": 4, "&": 5,
        "==": 6, "!=": 6, "<": 7, ">": 7, "<=": 7, ">=": 7,
        "<<": 8, ">>": 8, "+": 9, "-": 9, "*": 10, "/": 10, "%": 10,
    ]

    private func parseBinary(precedence: Int, stopAtSelector: Bool) -> ObjCExpr? {
        guard precedence <= 10 else { return parseUnary(stopAtSelector: stopAtSelector) }
        var lhs = parseBinary(precedence: precedence + 1, stopAtSelector: stopAtSelector) ?? {
            let o = current.offset
            advance()
            return ObjCExpr.unknown(o)
        }()
        while !atEOF {
            let op = current.text
            guard let prec = ObjCParser.binaryPrecedence[op], prec == precedence else { break }
            advance()
            let rhs = parseBinary(precedence: precedence + 1, stopAtSelector: stopAtSelector) ?? .unknown(current.offset)
            lhs = .binary(op: op, lhs: lhs, rhs: rhs, offset: lhs.offset)
        }
        return lhs
    }

    private func parseUnary(stopAtSelector: Bool) -> ObjCExpr? {
        let t = current
        if ["!", "-", "+", "*", "&", "++", "--", "~"].contains(t.text) {
            advance()
            let operand = parseUnary(stopAtSelector: stopAtSelector) ?? .unknown(t.offset)
            return .unary(op: t.text, operand: operand, offset: t.offset)
        }
        return parsePostfix(stopAtSelector: stopAtSelector)
    }

    private func parsePostfix(stopAtSelector: Bool) -> ObjCExpr? {
        guard var base = parsePrimary(stopAtSelector: stopAtSelector) else { return nil }
        while !atEOF {
            if isAt(".") || isAt("->") {
                advance()
                guard isAtIdentLike else { break }
                let name = advance()
                base = .member(base: base, name: name.text, offset: base.offset)
                continue
            }
            if isAt("[") {
                // Postfix subscript: buf[i].
                let open = current.offset
                advance()
                let index = parseExpression(stopAtSelector: false) ?? .unknown(open)
                match("]")
                base = .index(base: base, index: index, offset: open)
                continue
            }
            if isAt("(") {
                // Call on a member result, e.g. `foo().bar()`.
                guard case .member = base else { break }
                advance()
                var args: [ObjCExpr] = []
                while !atEOF && !isAt(")") {
                    if let a = parseExpression(stopAtSelector: false) { args.append(a) }
                    if isAt(",") { advance() }
                }
                match(")")
                base = .call(name: "(call)", args: args, offset: base.offset)
                continue
            }
            if isAt("++") || isAt("--") {
                advance()
                continue
            }
            break
        }
        return base
    }

    private func parsePrimary(stopAtSelector: Bool) -> ObjCExpr? {
        let t = current
        let offset = t.offset

        if t.kind == .string { advance(); return .string(t.text, offset: offset) }
        if t.kind == .number { advance(); return .number(t.text, offset: offset) }

        if isAt("@") {
            advance()
            if isAt("[") {
                advance()
                var items: [ObjCExpr] = []
                while !atEOF && !isAt("]") {
                    if let e = parseExpression(stopAtSelector: true) { items.append(e) }
                    if isAt(",") { advance() }
                }
                match("]")
                return .arrayLiteral(items, offset: offset)
            }
            if isAt("{") {
                advance()
                var entries: [(key: ObjCExpr, value: ObjCExpr)] = []
                while !atEOF && !isAt("}") {
                    if let k = parseExpression(stopAtSelector: true) {
                        match(":")
                        let v = parseExpression(stopAtSelector: true) ?? .unknown(current.offset)
                        entries.append((k, v))
                    }
                    if isAt(",") { advance() }
                }
                match("}")
                return .dictLiteral(entries, offset: offset)
            }
            if isAt("(") {
                advance()
                let e = parseExpression(stopAtSelector: false)
                match(")")
                return .paren(e ?? .unknown(offset), offset: offset)
            }
            if current.kind == .string {
                let s = advance()
                return .string(s.text, offset: offset)
            }
            if isAtIdentLike {
                let id = advance()
                return .identifier(id.text, offset: id.offset)
            }
            return .unknown(offset)
        }

        if isAt("[") {
            return parseMessage(offset: offset)
        }

        if isAt("(") {
            // Cast or plain parenthesized expression.
            if let inner = tryParseCastOrParen() { return inner }
            // Plain paren: consume '(', expression, ')'.
            advance()
            let innerExpr = parseExpression(stopAtSelector: false) ?? .unknown(offset)
            match(")")
            return .paren(innerExpr, offset: offset)
        }

        if isAtIdentLike {
            advance()
            if isAt("(") {
                // C-style call.
                advance()
                var args: [ObjCExpr] = []
                while !atEOF && !isAt(")") {
                    if let a = parseExpression(stopAtSelector: false) { args.append(a) }
                    if isAt(",") { advance() }
                }
                match(")")
                return .call(name: t.text, args: args, offset: offset)
            }
            return .identifier(t.text, offset: offset)
        }

        advance()
        return .unknown(offset)
    }

    /// `(Type *)expr` vs `(expr)`.
    private func tryParseCastOrParen() -> ObjCExpr? {
        // Lookahead: identifiers/keywords and '*' only, then ')', then a
        // primary-start token.
        var j = pos + 1
        var sawType = false
        while j < tokens.count {
            let tk = tokens[j]
            if tk.kind == .identifier || tk.kind == .keyword { sawType = true; j += 1; continue }
            if tk.text == "*" { j += 1; continue }
            if tk.text == ")" { break }
            return nil // operators inside → plain parenthesized expression
        }
        guard sawType, j < tokens.count, tokens[j].text == ")" else {
            return nil
        }
        let after = j + 1 < tokens.count ? tokens[j + 1] : tokens[tokens.count - 1]
        let startsPrimary = after.kind == .identifier || after.kind == .keyword ||
            after.kind == .string || after.text == "[" || after.text == "@" ||
            after.kind == .number
        guard startsPrimary else { return nil }

        // It's a cast: consume through ')', then parse the operand.
        advance() // (
        _ = parseTypeName()
        match(")")
        return parsePrimary(stopAtSelector: false)
    }

    // MARK: - Message expressions

    private func parseMessage(offset: Int) -> ObjCExpr {
        advance() // consume '['

        var receiver: ObjCExpr? = nil
        var parts: [(selector: String, arg: ObjCExpr?)] = []

        // Receiver: nested message, or identifier (with optional member chain).
        if isAt("[") {
            receiver = parseMessage(offset: current.offset)
        } else if isAtIdentLike {
            let id = advance()
            var base = ObjCExpr.identifier(id.text, offset: id.offset)
            while isAt(".") || isAt("->") {
                advance()
                guard isAtIdentLike else { break }
                let name = advance()
                base = .member(base: base, name: name.text, offset: base.offset)
            }
            receiver = base
        } else if isAt("(") {
            receiver = parsePrimary(stopAtSelector: false)
        } else if current.kind == .string {
            let s = advance()
            receiver = .string(s.text, offset: s.offset)
        }

        // Selector parts.
        while !atEOF && !isAt("]") {
            guard isAtIdentLike else {
                // Unexpected token inside a message (parse noise) — skip it.
                advance()
                continue
            }
            let piece = advance()
            if isAt(":") {
                advance()
                var arg = parseExpression(stopAtSelector: true)
                // Variadic continuations: `stringWithFormat:fmt, a1, a2` —
                // fold the extras into one expression so taint sees them.
                while isAt(",") {
                    advance()
                    let extra = parseExpression(stopAtSelector: true)
                    arg = .binary(op: ",",
                                  lhs: arg ?? .unknown(piece.offset),
                                  rhs: extra ?? .unknown(piece.offset),
                                  offset: piece.offset)
                }
                parts.append((selector: piece.text + ":", arg: arg))
            } else {
                parts.append((selector: piece.text, arg: nil))
                // A nil-arg piece must be the last; anything else is parse
                // noise — bail to the caller's loop.
                break
            }
        }
        match("]")

        // `[[X alloc] init]` receivers flatten naturally: the inner message is
        // the receiver of the outer selector.
        return .message(receiver: receiver, parts: parts, offset: offset)
    }

    // MARK: - Balanced skipping

    private func skipBalanced(open: String, close: String) {
        guard isAt(open) else { return }
        var depth = 0
        while !atEOF {
            if isAt(open) { depth += 1 }
            else if isAt(close) {
                depth -= 1
                advance()
                if depth == 0 { return }
                continue
            }
            advance()
        }
    }
}

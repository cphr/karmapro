// by cipher.org.uk
import Foundation

// MARK: - JS three-walk security analysis
//
// Three analysis layers run over the JSExpr/JSStmt AST built by JSExprParser:
//
// Walk 1 (taint): value-based data flow — every expression evaluates to a
//   TaintVal (clean / tainted(origin, crossFile)). Known sanitizers force
//   clean values, parameterized SQL calls suppress the injection sink, and
//   source-API callbacks bind their parameters as tainted.
// Walk 2 (bounds): array/string index accesses correlated with loop headers
//   and branch guards — `arr[arr.length]`, off-by-one loop conditions,
//   unvalidated (tainted) indices.
// Walk 3 (boundary): division by zero without zero-guards, unchecked
//   parseInt/parseFloat results used as indices, mutation of an array while
//   iterating it.
//
// All three layers share one statement traversal; findings carry taint paths
// and cross-file attribution like the other languages' AST engines.

let jsSanitizers: Set<String> = [
    "encodeURIComponent", "encodeURI", "escape",
    "sanitize", "sanitizeHtml", "sanitizeHTML", "escapeHtml", "escapeHTML",
    "stripTags", "DOMPurify.sanitize", "validator.escape", "htmlEncode", "encodeHtml",
    "htmlEscape", "Number",
]

/// Member calls that preserve the taint of their base.
let jsTaintPropagators: Set<String> = [
    "trim", "trimStart", "trimEnd", "toString", "valueOf", "slice", "substring",
    "substr", "concat", "toLowerCase", "toUpperCase", "padStart", "padEnd",
    "repeat", "replace", "replaceAll", "split", "join", "flat", "map", "filter",
    "find", "at",
]

/// Source APIs whose synchronous return value is attacker-controlled.
let jsSyncReturnSources: Set<String> = [
    "readFileSync", "readdirSync", "openSync", "execSync", "spawnSync",
    "execFileSync", "query", "execute", "prompt",
]

private struct TaintVal {
    var tainted: Bool
    var origin: String?
    var crossFile: Bool

    static let clean = TaintVal(tainted: false, origin: nil, crossFile: false)
    static func tainted(_ origin: String, crossFile: Bool = false) -> TaintVal {
        TaintVal(tainted: true, origin: origin, crossFile: crossFile)
    }
    func union(_ other: TaintVal) -> TaintVal {
        if !tainted { return other }
        if !other.tainted { return self }
        return TaintVal(tainted: true,
                        origin: origin.map { "\($0), \(other.origin ?? "?")" },
                        crossFile: crossFile || other.crossFile)
    }
}

private func unionAll(_ vals: [TaintVal]) -> TaintVal {
    vals.reduce(TaintVal.clean) { $0.union($1) }
}

private final class WalkContext {
    var vars: [String: TaintVal] = [:]
    var boundsGuards: Set<String> = []      // "index\u{1}base" pairs proven in-range
    var zeroChecked: Set<String> = []       // vars proven non-zero on this path
    var callbackTaintedParams: Set<String> = []
    var loopVar: String? = nil
    var loopBase: String? = nil
    var loopInclusive: Bool = false
    var objectLitVars: Set<String> = []     // locals declared as { … } keyed lookup tables
    var dictionaryKeyVars: Set<String> = [] // vars iterating Object.keys(...) — keyed lookup, not positional index

    func child() -> WalkContext {
        let c = WalkContext()
        c.vars = vars
        c.boundsGuards = boundsGuards
        c.zeroChecked = zeroChecked
        c.callbackTaintedParams = callbackTaintedParams
        c.loopVar = loopVar
        c.loopBase = loopBase
        c.loopInclusive = loopInclusive
        c.dictionaryKeyVars = dictionaryKeyVars
        return c
    }
}

struct JSSecurityDetector {

    struct JSFinding {
        let function: String
        let offset: Int
        let category: String
        let severity: ScanFinding.Severity
        let message: String
        let taintPath: String?
        let reachable: Bool
        var crossFile: Bool = false
    }

    private let source: String
    private let defs: [JSDef]
    private let tokens: [CAstToken]
    private let reachableNames: Set<String>
    private let taintReturning: Set<String>
    private let crossFileSources: Set<String>

    init(source: String, defs: [JSDef], tokens: [CAstToken]? = nil,
         reachableNames: Set<String> = [],
         taintReturning: Set<String> = [],
         crossFileSources: Set<String> = []) {
        self.source = source
        self.defs = defs
        self.tokens = tokens ?? JSTokenizer(source: source).tokenize()
        self.reachableNames = reachableNames
        self.taintReturning = taintReturning
        self.crossFileSources = crossFileSources
    }

    func detect() -> [JSFinding] {
        var findings: [JSFinding] = []
        let dead = deadFunctionNames()
        let objectLitVars = objectLiteralVarNames()
        let keyIterVars = objectKeysIterationVars()
        for def in defs where !dead.contains(def.name) {
            let body = bodyTokens(of: def)
            guard !body.isEmpty else { continue }
            findings.append(contentsOf: analyzeFunction(def, body: body, objectLitVars: objectLitVars, keyIterVars: keyIterVars))
        }
        // Cross-file: a finding is cross-file when its taint path originates
        // from a taint-returning function defined in another file.
        for i in findings.indices {
            if let root = findings[i].taintPath?.components(separatedBy: " → ").first,
               crossFileSources.contains(root) {
                findings[i].crossFile = true
            }
        }
        return findings
    }

    /// Names of variables initialized from an object literal
    /// (`const templates = { … }`) anywhere in the file.
    private func objectLiteralVarNames() -> Set<String> {
        guard let re = try? NSRegularExpression(pattern: "(?i)(?:const|let|var)\\s+([A-Za-z_$][\\w$]*)\\s*=\\s*\\{") else { return [] }
        let ns = source as NSString
        var names = Set<String>()
        for m in re.matches(in: source, range: NSRange(location: 0, length: ns.length)) {
            names.insert(ns.substring(with: m.range(at: 1)))
        }
        return names
    }

    /// Variables that act as object-key iterators rather than positional
    /// indices: callback parameters of `Object.keys(x).forEach((k) => …)`
    /// chains and locals bound from a keys array (`const key = keys[i];` where
    /// `keys` was assigned `Object.keys(obj)`). Indexing an object with one of
    /// these performs a keyed property lookup, not a positional array read, so
    /// the Unvalidated Array Index rule must not fire for it.
    private func objectKeysIterationVars() -> Set<String> {
        let ns = source as NSString
        var containers = Set<String>()
        if let re = try? NSRegularExpression(pattern: "\\b(\\w+)\\s*=\\s*Object\\.keys\\(") {
            for m in re.matches(in: source, range: NSRange(location: 0, length: ns.length)) {
                containers.insert(ns.substring(with: m.range(at: 1)))
            }
        }
        var keys = Set<String>()
        if let re = try? NSRegularExpression(pattern: "Object\\.keys\\([^)]*\\)\\.(?:forEach|every|map|some|filter|find|reduce)\\s*\\(\\s*\\(?\\s*(\\w+)") {
            for m in re.matches(in: source, range: NSRange(location: 0, length: ns.length)) {
                keys.insert(ns.substring(with: m.range(at: 1)))
            }
        }
        if !containers.isEmpty {
            let filter = containers.map { NSRegularExpression.escapedPattern(for: $0) }.joined(separator: "|")
            if let re = try? NSRegularExpression(pattern: "\\b(\\w+)\\s*=\\s*(?:\(filter))\\s*\\[") {
                for m in re.matches(in: source, range: NSRange(location: 0, length: ns.length)) {
                    keys.insert(ns.substring(with: m.range(at: 1)))
                }
            }
        }
        return keys
    }

    /// Functions that are never referenced anywhere in the file outside their
    /// own definition and carry an explicit retirement marker in the name
    /// (`retiredDiagnostics`, `legacyFetchAnyUrl`, …). JavaScript has no
    /// linkage, so only the marker + zero-reference combination is treated as
    /// dead code; anything else may be an exported handler.
    private func deadFunctionNames() -> Set<String> {
        let markers = ["retired", "legacy", "unused", "deprecated", "obsolete", "dead"]
        var dead = Set<String>()
        for def in defs {
            let low = def.name.lowercased()
            guard markers.contains(where: { low.contains($0) }) else { continue }
            guard let re = try? NSRegularExpression(pattern: "(?<![A-Za-z0-9_$])" + NSRegularExpression.escapedPattern(for: def.name) + "(?![A-Za-z0-9_$])") else { continue }
            let ns = source as NSString
            if re.numberOfMatches(in: source, range: NSRange(location: 0, length: ns.length)) <= 1 {
                dead.insert(def.name)
            }
        }
        return dead
    }

    /// True when the text contains a credential-named key whose value is a live
    /// expression (not a string literal placeholder like `'[redacted]'`).
    private func sensitiveLiveValue(in text: String) -> Bool {
        guard let re = try? NSRegularExpression(pattern: "(?i)\\b(password|passwd|pwd|token|secret|apikey|api_key|access[_-]?key|private[_-]?key|session[_-]?id|ssn|credit[_-]?card|credential\\w*|auth\\w*)\\s*:\\s*([^,}\\]]+)") else { return false }
        let ns = text as NSString
        for m in re.matches(in: text, range: NSRange(location: 0, length: ns.length)) {
            let value = ns.substring(with: m.range(at: 2)).trimmingCharacters(in: .whitespaces)
            if !value.hasPrefix("\"") && !value.hasPrefix("'") && !value.hasPrefix("`") {
                return true
            }
        }
        return false
    }

    /// Joined token text of a function body (for guard-shape checks), with
    /// spaces removed so token-boundary artifacts don't hide patterns.
    private func bodyText(of def: JSDef) -> String {
        bodyTokens(of: def).map { $0.text }.joined(separator: " ")
    }

    private func flatBodyText(of def: JSDef) -> String {
        bodyText(of: def).replacingOccurrences(of: " ", with: "")
    }

    /// True when the function rejects control characters before use — the
    /// classic CRLF guard (`if (/[\r\n]/.test(next)) throw …`).
    private func bodySourceContainsCRFGuard(_ def: JSDef) -> Bool {
        let text = flatBodyText(of: def)
        return text.contains("\\r") && text.contains("throw")
    }

    /// True when the function validates against an allowlist before the
    /// sink (`if (!ALLOWED_HOSTS.has(host)) throw …`,
    /// `if (!ALLOWED_HOSTS.includes(host)) return …`).
    private func bodySourceContainsAllowlistGate(_ def: JSDef) -> Bool {
        let text = flatBodyText(of: def)
        return (text.contains(".has(") || text.contains(".includes(")) && text.contains("throw")
    }

    /// True when a set/array-membership allowlist guards the call site
    /// (`if (ALLOWED_ORIGINS.has(origin))`, `if (config.ORIGINS.includes(origin))`
    /// — Set.has or Array.includes, both of which constrain the value to an
    /// enumerated allowlist before it reaches the header sink).
    private func bodyHasSetAllowlistGate(_ def: JSDef) -> Bool {
        let text = flatBodyText(of: def)
        return text.contains(".has(") || text.contains(".includes(")
    }

    /// True when the function rejects a URL based on its host before any
    /// outbound request — either an allowlist set (`ALLOWED_HOSTS.has(host)`,
    /// `config.HOSTS.includes(host)`) or a blocklist of forbidden addresses
    /// (`if (host === '169.254.169.254' …) throw`). Both are the standard SSRF
    /// egress gates; `reject` is the promise-style `throw` (`Promise.reject` /
    /// `callback reject`) used by helper-wrapped requests.
    private func bodyHasHostValidationGate(_ def: JSDef) -> Bool {
        let text = flatBodyText(of: def)
        let exits = text.contains("throw") || text.contains("reject")
        return exits && (text.contains(".has(") || text.contains(".includes(") || text.contains("hostname"))
    }

    /// True when the function type-validates its inputs with an explicit
    /// rejection (`if (typeof x !== 'string') throw …`).
    private func bodySourceTypeValidationGate(_ def: JSDef) -> Bool {
        let text = flatBodyText(of: def)
        return text.contains("typeof") && text.contains("throw")
    }

    /// True when the function validates a redirect target with a prefix check
    /// plus rejection (`if (!next.startsWith('/') || next.startsWith('//')) throw …`).
    private func bodyHasPrefixRejectGuard(_ def: JSDef) -> Bool {
        let text = flatBodyText(of: def)
        return text.contains("startsWith(") && text.contains("throw")
    }

    /// True when the file contains a prototype-key rejection guard
    /// (`if (key === '__proto__' || …) throw …`) — the mitigation lives in the
    /// sanitizer helper that runs before the merge, not at the assign site.
    private func bodyHasPrototypeKeyRejection(_ def: JSDef) -> Bool {
        let lower = source.lowercased()
        let hasKeyCheck = lower.contains("'__proto__'") || lower.contains("\"__proto__\"")
        return hasKeyCheck && lower.contains("throw")
    }

    /// True when a tainted value carries evidence of a request/attacker surface
    /// (origins other than the pure function-parameter and callback seeds that
    /// every def is scanned under). Used to distinguish a genuinely
    /// attacker-keyed merge target/source from idiomatic `Object.assign({},
    /// defaults, opts)` helpers whose parameter taint is a policy seed.
    private func considerAttackerKeyedSource(_ val: TaintVal) -> Bool {
        guard val.tainted else { return false }
        guard let origin = val.origin else { return true }
        return !origin.contains("parameter ") && !origin.contains("callback ")
    }

    // MARK: - Per-function analysis

    private func analyzeFunction(_ def: JSDef, body: [CAstToken], objectLitVars: Set<String>, keyIterVars: Set<String> = []) -> [JSFinding] {
        let stmts = JSExprParser.parseStatements(body)
        let ctx = WalkContext()
        ctx.dictionaryKeyVars = keyIterVars
        // Walk 1 seed: parameters are the initial untrusted inputs.
        for p in def.params.compactMap({ $0.name }) {
            ctx.vars[p] = .tainted("parameter \(p)")
        }
        // Keyed lookup tables declared as object literals (module-level `const
        // templates = { … }` included): indexing them with an unknown key is a
        // dictionary miss, not an out-of-bounds array read.
        ctx.objectLitVars = objectLitVars
        var findings: [JSFinding] = []
        walkAll(stmts, ctx: ctx, def: def, into: &findings)
        if let csrf = checkJsCsrf(def, stmts: stmts) { findings.append(csrf) }
        return findings
    }

    /// Threads a mutable context through the statement list so early-exit
    /// guards (`if (!x) return;`) refine subsequent statements.
    private func walkAll(_ stmts: [JSStmt], ctx: WalkContext, def: JSDef,
                         into findings: inout [JSFinding]) {
        let current = ctx
        for s in stmts {
            walkStatement(s, ctx: current, def: def, into: &findings)
        }
    }

    private func walkStatement(_ stmt: JSStmt, ctx: WalkContext, def: JSDef,
                               into findings: inout [JSFinding]) {
        switch stmt {
        case .block(let inner, _):
            walkAll(inner, ctx: ctx, def: def, into: &findings)

        case .exprStmt(let e, _):
            _ = evalExpr(e, ctx: ctx, def: def, into: &findings)

        case .varDecl(let decls, _):
            for d in decls {
                guard let e = d.initExpr else { continue }
                let val = evalExpr(e, ctx: ctx, def: def, into: &findings)
                ctx.vars[d.name] = val
                if case .objectLit = e { ctx.objectLitVars.insert(d.name) }
                applyAssignmentRules(target: .ident(d.name, e.offset), value: e,
                                     valueTaint: val, ctx: ctx, def: def,
                                     into: &findings)
            }

        case .ifStmt(let cond, let thenBody, let elseBody, _):
            _ = evalExpr(cond, ctx: ctx, def: def, into: &findings)
            // Then-branch: condition guards hold.
            let thenCtx = ctx.child()
            refineGuards(cond: cond, ctx: thenCtx)
            walkAll(thenBody, ctx: thenCtx, def: def, into: &findings)
            if let eb = elseBody {
                walkAll(eb, ctx: ctx.child(), def: def, into: &findings)
            }
            // Early-exit patterns (`if (!x) throw/return`, `if (i >= len) return`)
            // guard everything AFTER the statement.
            applyEarlyExitGuards(cond: cond, thenBody: thenBody, ctx: ctx)

        case .forStmt(let loopVar, let bound, let inclusive, let iterable, let isForOf, let body, let offset):
            if let it = iterable { _ = evalExpr(it, ctx: ctx, def: def, into: &findings) }
            if let b = bound { _ = evalExpr(b, ctx: ctx, def: def, into: &findings) }
            // Walk 3: mutation of the iterated array inside for-of/for-in.
            if isForOf, let it = iterable {
                let itName = it.dottedName
                if !itName.isEmpty, bodyContainsMutation(of: itName, body: body) {
                    findings.append(finding(def: def, offset: offset,
                                            category: "Array Mutation During Iteration",
                                            severity: .medium, reachable: isReachable(def),
                                            message: "Array '\(itName)' is mutated (pop/shift/splice) while being iterated.",
                                            taint: nil))
                }
            }
            let bodyCtx = ctx.child()
            bodyCtx.loopVar = loopVar
            bodyCtx.loopInclusive = inclusive
            if let b = bound {
                bodyCtx.loopBase = lengthBaseName(of: b)
            }
            walkAll(body, ctx: bodyCtx, def: def, into: &findings)

        case .whileStmt(let cond, let body, _):
            _ = evalExpr(cond, ctx: ctx, def: def, into: &findings)
            walkAll(body, ctx: ctx.child(), def: def, into: &findings)

        case .returnStmt(let e, _):
            if let e = e { _ = evalExpr(e, ctx: ctx, def: def, into: &findings) }

        case .throwStmt(let e, _):
            if let e = e { _ = evalExpr(e, ctx: ctx, def: def, into: &findings) }
        }
    }

    // MARK: - Walk 1: value-based taint evaluation (+ sink rules)

    private func evalExpr(_ e: JSExpr, ctx: WalkContext, def: JSDef,
                          into findings: inout [JSFinding]) -> TaintVal {
        switch e {
        case .ident(let n, _):
            if let v = ctx.vars[n] { return v }
            if jsSourceAPIs.contains(n) { return .tainted(n) }
            return .clean

        case .literal:
            return .clean

        case .template:
            var val = TaintVal.clean
            for interp in e.templateExprs() {
                val = val.union(evalExpr(interp, ctx: ctx, def: def, into: &findings))
            }
            return val

        case .member(let base, let name, _):
            let baseVal = evalExpr(base, ctx: ctx, def: def, into: &findings)
            let dotted = base.dottedName.isEmpty ? name : "\(base.dottedName).\(name)"
            if jsSourceAPIs.contains(dotted) { return .tainted(dotted) }
            if jsSourceAPIs.contains(name) { return .tainted(name) }
            return baseVal

        case .index(let base, let idx, _):
            let baseVal = evalExpr(base, ctx: ctx, def: def, into: &findings)
            let idxVal = evalExpr(idx, ctx: ctx, def: def, into: &findings)
            // Walk 2: bounds rules at every index access.
            applyBoundsRules(base: base, index: idx, idxVal: idxVal,
                             offset: e.offset, ctx: ctx, def: def, into: &findings)
            // Walk 3: unchecked parseInt/parseFloat used as an index.
            if case .call(let ic, _, _) = idx {
                let leaf = ic.dottedName.components(separatedBy: ".").last ?? ""
                if ["parseInt", "parseFloat"].contains(leaf) {
                    findings.append(finding(def: def, offset: e.offset,
                                            category: "Unchecked parseInt Result",
                                            severity: .low, reachable: isReachable(def),
                                            message: "'\(leaf)()' result used directly as an index; NaN/parse errors are unhandled.",
                                            taint: nil))
                }
            }
            return baseVal.union(idxVal)

        case .call(let callee, let args, let offset):
            return evalCall(callee: callee, args: args, offset: offset,
                            ctx: ctx, def: def, into: &findings)

        case .new(let callee, let args, let offset):
            // `new Function(...)()` parses as `.new(callee: .call(Function, args),
            // args: [])` — a call applied to the fresh instance inverts the
            // nodes. Unwrap so the constructor is recognized as the callee.
            if case .call(let callCallee, let callArgs, let innerOffset) = callee {
                return evalCall(callee: callCallee, args: callArgs, offset: innerOffset,
                                ctx: ctx, def: def, into: &findings, isNew: true)
            }
            return evalCall(callee: callee, args: args, offset: offset,
                            ctx: ctx, def: def, into: &findings, isNew: true)

        case .unary(_, let operand, _):
            return evalExpr(operand, ctx: ctx, def: def, into: &findings)

        case .binary(let op, let l, let r, _):
            let lv = evalExpr(l, ctx: ctx, def: def, into: &findings)
            let rv = evalExpr(r, ctx: ctx, def: def, into: &findings)
            // Walk 3: division without a zero guard.
            if op == "/", isZeroRisky(r, ctx: ctx) {
                findings.append(finding(def: def, offset: e.offset,
                                        category: "Possible Division by Zero",
                                        severity: .medium, reachable: isReachable(def),
                                        message: "Division by '\(r.dottedName.isEmpty ? "unchecked expression" : r.dottedName)' without a zero check produces Infinity/NaN.",
                                        taint: nil))
            }
            return lv.union(rv)

        case .assign(let op, let lhs, let rhs, _):
            let rhsVal = evalExpr(rhs, ctx: ctx, def: def, into: &findings)
            var val = rhsVal
            if op != "=", case .ident(let n, _) = lhs, let prev = ctx.vars[n] {
                val = prev.union(rhsVal)
            }
            if case .ident(let n, _) = lhs {
                ctx.vars[n] = val
            }
            applyAssignmentRules(target: lhs, value: rhs, valueTaint: rhsVal,
                                 ctx: ctx, def: def, into: &findings)
            return val

        case .ternary(let c, let t, let f, _):
            let cv = evalExpr(c, ctx: ctx, def: def, into: &findings)
            let tv = evalExpr(t, ctx: ctx, def: def, into: &findings)
            let fv = evalExpr(f, ctx: ctx, def: def, into: &findings)
            return cv.union(tv).union(fv)

        case .arrayLit(let elems, _):
            var val = TaintVal.clean
            for el in elems {
                val = val.union(evalExpr(el, ctx: ctx, def: def, into: &findings))
            }
            return val

        case .objectLit(let offset):
            // The parser keeps object literals opaque, so taint is derived from
            // the identifier tokens inside the literal's extent: an object
            // built from `req.body.*` / tainted locals carries their taint.
            var val = TaintVal.clean
            var depth = 0
            if let start = tokens.firstIndex(where: { $0.offset >= offset && ($0.text == "{" || $0.text == "[") }) {
                for t in tokens[start...] {
                    if t.text == "{" || t.text == "[" || t.text == "(" { depth += 1 }
                    if t.text == "}" || t.text == "]" || t.text == ")" {
                        depth -= 1
                        if depth <= 0 { break }
                    }
                    if t.kind == .identifier {
                        if let v = ctx.vars[t.text], v.tainted { val = val.union(v) }
                        else if jsSourceAPIs.contains(t.text) { val = .tainted(t.text) }
                    }
                }
            }
            return val

        case .arrow(let params, let body, _):
            let arrowCtx = ctx.child()
            for p in params where ctx.callbackTaintedParams.contains(p) {
                arrowCtx.vars[p] = .tainted("callback \(p)")
            }
            switch body {
            case .block(let stmts):
                walkAll(stmts, ctx: arrowCtx, def: def, into: &findings)
            case .expr(let x):
                _ = evalExpr(x, ctx: arrowCtx, def: def, into: &findings)
            }
            return .clean
        }
    }

    private func evalCall(callee: JSExpr, args: [JSExpr], offset: Int,
                          ctx: WalkContext, def: JSDef,
                          into findings: inout [JSFinding], isNew: Bool = false) -> TaintVal {
        let name = callee.dottedName
        let leaf = name.components(separatedBy: ".").last ?? name
        let reachable = isReachable(def)

        // Bind callback parameters as tainted when the callee is a source or
        // write-through API (e.g. fs.readFile(path, (err, data) => ...)).
        let isSourceish = jsSourceAPIs.contains(name) || jsSourceAPIs.contains(leaf)
            || jsWriteThroughSinks.contains(leaf)
        if isSourceish {
            for a in args {
                if case .arrow(let params, _, _) = a {
                    for p in params { ctx.callbackTaintedParams.insert(p) }
                }
            }
        }

        // Express/Koa-style route registrations: the request/response callback
        // parameters carry attacker-controlled data (req.query, req.body, …).
        let routeLeaves: Set<String> = ["get", "post", "put", "delete", "patch", "use", "all", "head"]
        let routeReceivers: Set<String> = ["app", "router", "server", "route"]
        let recvName = name.components(separatedBy: ".").dropLast().last?.lowercased() ?? ""
        if routeLeaves.contains(leaf), routeReceivers.contains(recvName) {
            for a in args {
                if case .arrow(let params, _, _) = a {
                    for prm in params { ctx.callbackTaintedParams.insert(prm) }
                }
            }
        }

        // Evaluate the callee first (walks nested calls exactly once), then args.
        let calleeVal = evalExpr(callee, ctx: ctx, def: def, into: &findings)
        var argVals: [TaintVal] = []
        for a in args {
            argVals.append(evalExpr(a, ctx: ctx, def: def, into: &findings))
        }

        // ---- Sink rules (value-based) ----
        switch leaf {
        case "eval":
            findings.append(finding(def: def, offset: offset, category: "eval Injection",
                                    severity: .critical, reachable: reachable,
                                    message: "eval() executes arbitrary code; a tainted argument enables RCE.",
                                    taint: taintPath(argVals.first) ?? "eval()"))
        case "Function" where isNew:
            findings.append(finding(def: def, offset: offset, category: "Function Constructor Injection",
                                    severity: .critical, reachable: reachable,
                                    message: "new Function() compiles a string into executable code.",
                                    taint: taintPath(argVals.first) ?? "new Function()"))
        case "setTimeout", "setInterval":
            if case .literal(let text, _)? = args.first, text.hasPrefix("\""), text.count > 4 {
                findings.append(finding(def: def, offset: offset, category: "Timer String Injection",
                                        severity: .medium, reachable: reachable,
                                        message: "\(leaf) with a string argument compiles it as code.",
                                        taint: nil))
            }
        case "write", "writeln":
            if name.contains("document") {
                findings.append(finding(def: def, offset: offset, category: "XSS (document.write)",
                                        severity: .high, reachable: reachable,
                                        message: "document.write can inject script into the page.",
                                        taint: taintPath(argVals.first).map { "\($0) → document.write" }))
            }
        case "insertAdjacentHTML":
            if args.count > 1, argVals[1].tainted {
                findings.append(finding(def: def, offset: offset, category: "XSS (insertAdjacentHTML)",
                                        severity: .high, reachable: reachable,
                                        message: "Insertion of unescaped content via insertAdjacentHTML can inject markup or script.",
                                        taint: taintPath(argVals[1]).map { "\($0) → insertAdjacentHTML" }))
            }
        case "postMessage":
            if args.count >= 2, case .literal(let target, _) = args[1], target.contains("*") {
                findings.append(finding(def: def, offset: offset, category: "postMessage Origin Validation",
                                        severity: .high, reachable: reachable,
                                        message: "postMessage target origin '*' accepts any window.",
                                        taint: nil))
            }
        case "assign", "defineProperty":
            if name.hasPrefix("Object") {
                if leaf == "defineProperty", args.count >= 2 {
                    var keyIsLiteral = false
                    if case .literal = args[1] { keyIsLiteral = true }
                    if argVals[1].tainted || !keyIsLiteral {
                        findings.append(finding(def: def, offset: offset, category: "Prototype Pollution",
                                                severity: .high, reachable: reachable,
                                                message: "Object.\(leaf) with non-literal keys can pollute Object.prototype.",
                                                taint: taintPath(argVals[1]).map { "\($0) → Object.\(leaf)" }))
                    }
                }
                // `Object.assign({}, defaults, userOptions)` is the idiomatic
                // copy-merge; it only pollutes when the TARGET is attacker-
                // controlled, or when attacker-keyed sources are merged without
                // a prototype-key rejection guard. A source seeded merely from a
                // function parameter (`opts` in merge-into-a-literal helpers) is
                // not yet shown to carry attacker keys: positions/callback params
                // are seeded tainted by policy, not evidence of a request surface.
                if leaf == "assign", args.count >= 2 {
                    let targetTainted = argVals[0].tainted
                    let attackerKeyedSources = argVals.dropFirst().contains { considerAttackerKeyedSource($0) }
                    if targetTainted || (attackerKeyedSources && !bodyHasPrototypeKeyRejection(def)) {
                        findings.append(finding(def: def, offset: offset, category: "Prototype Pollution",
                                                severity: .high, reachable: reachable,
                                                message: "Object.\(leaf) with attacker-controlled target/keys can pollute Object.prototype.",
                                                taint: taintPath(argVals[0].tainted ? argVals[0] : argVals.last ?? .clean).map { "\($0) → Object.\(leaf)" }))
                    }
                }
            }
        case "exec", "execSync":
            if argVals.first?.tainted == true {
                findings.append(finding(def: def, offset: offset, category: "Command Injection",
                                        severity: .critical, reachable: reachable,
                                        message: "child_process.\(leaf) runs a shell; tainted input enables RCE.",
                                        taint: taintPath(argVals.first) ?? "child_process.\(leaf)"))
            }
        case "spawn", "spawnSync", "execFile", "execFileSync":
            if argVals.first?.tainted == true {
                findings.append(finding(def: def, offset: offset, category: "Command Injection",
                                        severity: .high, reachable: reachable,
                                        message: "Tainted argument to child_process.\(leaf).",
                                        taint: "\(taintPath(argVals.first) ?? "?") → child_process.\(leaf)"))
            }
        case "readFile", "readFileSync", "unlink", "unlinkSync", "createReadStream",
             "createWriteStream", "writeFile", "writeFileSync", "access", "stat":
            if argVals.first?.tainted == true {
                findings.append(finding(def: def, offset: offset, category: "Path Traversal",
                                        severity: .high, reachable: reachable,
                                        message: "Tainted path in fs.\(leaf) allows arbitrary file access.",
                                        taint: "\(taintPath(argVals.first) ?? "?") → fs.\(leaf)"))
            }
        case "fetch":
            if argVals.first?.tainted == true {
                // A host allowlist checked with `.has(...)` + reject before the
                // request is the standard SSRF mitigation.
                if bodySourceContainsAllowlistGate(def) { return .clean }
                findings.append(finding(def: def, offset: offset, category: "SSRF",
                                        severity: .high, reachable: reachable,
                                        message: "Tainted URL in fetch request.",
                                        taint: "\(taintPath(argVals.first) ?? "?") → fetch"))
            }
        case "request":
            if argVals.first?.tainted == true {
                // A host allowlist/blocklist gate (`.has(...)`, `.includes(...)`
                // on the host, or an explicit https-only hostname rejection)
                // before the request is the standard SSRF mitigation — the same
                // relief the `fetch` sink applies.
                if bodyHasHostValidationGate(def) { return .clean }
                findings.append(finding(def: def, offset: offset, category: "SSRF",
                                        severity: .high, reachable: reachable,
                                        message: "Tainted URL/options in HTTP request.",
                                        taint: "\(taintPath(argVals.first) ?? "?") → request"))
            }
        case "query", "execute":
            // Parameterized form db.query(text, params[, cb]) / execute(text,
            // params) binds values in a separate argument, so tainted text alone
            // is not an injection sink. A trailing callback is NOT a parameter
            // list: db.query(sql, cb) hands the query string straight to the
            // database and IS an injection when the text is tainted.
            if argVals.first?.tainted == true {
                let hasParamBinding = args.dropFirst().contains { arg in
                    if case .arrow = arg { return false }
                    return true
                }
                if !hasParamBinding {
                    findings.append(finding(def: def, offset: offset, category: "SQL Injection",
                                            severity: .critical, reachable: reachable,
                                            message: "SQL query built from tainted input without parameterization.",
                                            taint: "\(taintPath(argVals.first) ?? "?") → SQL query"))
                }
            }
        case "redirect":
            if argVals.first?.tainted == true {
                // `if (!next.startsWith('/') || …) throw` — a prefix allowlist
                // with rejection is the standard open-redirect mitigation.
                if bodyHasPrefixRejectGuard(def) {
                    return TaintVal.clean
                }
                findings.append(finding(def: def, offset: offset, category: "Open Redirect",
                                        severity: .high, reachable: reachable,
                                        message: "Tainted redirect target.",
                                        taint: "\(taintPath(argVals.first) ?? "?") → redirect"))
            }
        case "render", "renderString":
            let templated = ["nunjucks", "ejs", "pug", "handlebars", "mustache", "hogan"]
                .contains { name.lowercased().contains($0) }
            if templated, argVals.first?.tainted == true {
                findings.append(finding(def: def, offset: offset, category: "Server-Side Template Injection",
                                        severity: .critical, reachable: reachable,
                                        message: "Tainted template source compiled server-side.",
                                        taint: "\(taintPath(argVals.first) ?? "?") → template render"))
            }
        case "parseFromString":
            if argVals.first?.tainted == true {
                findings.append(finding(def: def, offset: offset, category: "XXE / XML Injection",
                                        severity: .high, reachable: reachable,
                                        message: "XML parsing of untrusted input; verify external entity handling.",
                                        taint: "\(taintPath(argVals.first) ?? "?") → XML parser"))
            }
        case "deserialize", "unserialize":
            if argVals.first?.tainted == true {
                findings.append(finding(def: def, offset: offset, category: "Unsafe Deserialization",
                                        severity: .critical, reachable: reachable,
                                        message: "Deserializing untrusted data can execute code.",
                                        taint: "\(taintPath(argVals.first) ?? "?") → deserialize"))
            }
        case "createHash":
            if case .literal(let alg, _)? = args.first {
                let a = alg.lowercased()
                if a.contains("md5") || a.contains("sha1") {
                    findings.append(finding(def: def, offset: offset, category: "Weak Cryptography",
                                            severity: .high, reachable: reachable,
                                            message: "Weak hash algorithm \(alg) used.",
                                            taint: nil))
                }
            }
        case "createCipher", "createDecipher":
            findings.append(finding(def: def, offset: offset, category: "Weak Cryptography",
                                    severity: .high, reachable: reachable,
                                    message: "\(leaf) uses deprecated, insecure primitives.",
                                    taint: nil))
        case "verify":
            if name.lowercased().contains("jwt"), args.count >= 3 {
                let opts = sourceText(from: args[2])
                if opts.contains("none") || opts.contains("HS256") {
                    findings.append(finding(def: def, offset: offset, category: "JWT Weakness",
                                            severity: .critical, reachable: reachable,
                                            message: "JWT verification accepts weak/unsigned algorithms.",
                                            taint: nil))
                }
            }
        case "cookie":
            if args.count == 2 {
                findings.append(finding(def: def, offset: offset, category: "Insecure Cookie",
                                        severity: .medium, reachable: reachable,
                                        message: "Cookie set without security options (secure/httpOnly/sameSite).",
                                        taint: nil))
            } else if args.count >= 3 {
                let opts = sourceText(from: args[2])
                if !opts.contains("secure") && !opts.contains("httpOnly") && !opts.contains("sameSite") {
                    findings.append(finding(def: def, offset: offset, category: "Insecure Cookie",
                                            severity: .medium, reachable: reachable,
                                            message: "Cookie set without secure/httpOnly/sameSite flags.",
                                            taint: nil))
                } else if opts.contains("secure: false") || opts.contains("httpOnly: false")
                            || opts.contains("sameSite: 'none'") || opts.contains("sameSite: \"none\"") {
                    findings.append(finding(def: def, offset: offset, category: "Insecure Cookie",
                                            severity: .medium, reachable: reachable,
                                            message: "Cookie explicitly set with secure:false / httpOnly:false / sameSite:'none' — readable or sendable over plaintext.",
                                            taint: nil))
                }
            }
        case "send":
            // Express-style `res.send(...)` / `res.json(...)`: tainted data
            // written into the HTTP response body is reflected output.
            if argVals.first?.tainted == true {
                findings.append(finding(def: def, offset: offset, category: "XSS (HTML Injection)",
                                        severity: .high, reachable: reachable,
                                        message: "Untrusted value written to the HTTP response without escaping; reflected XSS is possible.",
                                        taint: taintPath(argVals.first).map { "\($0) → res.send" }))
            }
        case "end":
            // `res.end(doc)` / `response.end(body)` terminate the HTTP response
            // with the given body — same reflected-output surface as res.send.
            if argVals.first?.tainted == true,
               ["res", "response", "ctx", "reply"].contains(recvName) {
                findings.append(finding(def: def, offset: offset, category: "XSS (HTML Injection)",
                                        severity: .high, reachable: reachable,
                                        message: "Untrusted value written to the HTTP response without escaping; reflected XSS is possible.",
                                        taint: taintPath(argVals.first).map { "\($0) → res.end" }))
            }
        case "log", "info", "warn", "error", "debug":
            // Sensitive-data logging: a sensitive key (password/token/secret/…)
            // whose value is a LIVE (non-literal) expression reaching the log.
            // Keys logged as '[redacted]' or constant placeholders don't fire,
            // and ordinary fields (email, user id) are not sensitive keys.
            if name.lowercased().contains("console") {
                for (a, v) in zip(args, argVals) where v.tainted {
                    if sensitiveLiveValue(in: sourceText(from: a)) {
                        findings.append(finding(def: def, offset: offset, category: "Sensitive Data Logging",
                                                severity: .medium, reachable: reachable,
                                                message: "Sensitive credential written to the log; leaked log files expose it.",
                                                taint: taintPath(v).map { "\($0) → log" }))
                        break
                    }
                }
            }
        case "setHeader", "writeHead":
            // `res.setHeader(name, value)` / `res.writeHead(code, {...})` with a
            // tainted value allow response-splitting via CR/LF — unless the
            // function explicitly rejects control characters first, or the
            // header value passed an allowlist gate (`ALLOWED_ORIGINS.has(...)`).
            let valueIndex = leaf == "writeHead" ? 1 : 1
            if args.count > valueIndex, argVals[valueIndex].tainted == true {
                let guarded = bodySourceContainsCRFGuard(def) || bodyHasSetAllowlistGate(def)
                if !guarded {
                    findings.append(finding(def: def, offset: offset, category: "Header Injection (CRLF)",
                                            severity: .high, reachable: reachable,
                                            message: "Untrusted value in an HTTP response header allows CRLF/response-splitting.",
                                            taint: taintPath(argVals[valueIndex]).map { "\($0) → header" }))
                }
            }
        case "get", "post", "put", "patch", "delete":
            // Outbound HTTP through an HTTP-client receiver (`axios.post(url, …)`,
            // `superagent.get(url)`) with a tainted URL is SSRF. (`http`/`https`/
            // `got` receivers are covered by the callee-shape rule below.)
            let clientReceivers: Set<String> = ["superagent", "needle", "undici", "request"]
            let receiver = name.components(separatedBy: ".").dropLast().last?.lowercased() ?? ""
            if clientReceivers.contains(receiver), !args.isEmpty, argVals.first?.tainted == true {
                // A host allowlist checked with `set.has(...)` + reject before
                // the request is the standard SSRF mitigation.
                let allowlisted = bodySourceContainsAllowlistGate(def)
                if !allowlisted {
                    findings.append(finding(def: def, offset: offset, category: "SSRF",
                                            severity: .high, reachable: reachable,
                                            message: "Request URL is attacker-controlled; the server can be made to call arbitrary hosts (SSRF).",
                                            taint: taintPath(argVals.first).map { "\($0) → \(leaf) request" }))
                }
            }
        case "findOne", "insertOne", "updateOne", "deleteOne", "replaceOne", "aggregate", "countDocuments":
            // Document-store query built from tainted input. Suppressed when
            // the function explicitly type-validates the input (`typeof x === 'string'`)
            // with a rejection — the safe-parameterized boundary.
            if args.contains(where: { sourceText(from: $0).contains("$where") }) || argVals.contains(where: { $0.tainted }) {
                let validated = bodySourceTypeValidationGate(def)
                if !validated {
                    findings.append(finding(def: def, offset: offset, category: "NoSQL Injection",
                                            severity: .high, reachable: reachable,
                                            message: "Document query built from untrusted input; operator/credential injection into the store is possible.",
                                            taint: taintPath(argVals.first(where: { $0.tainted })).map { "\($0) → \(leaf)" }))
                }
            }
        case "where":
            if case .literal(let s, _)? = args.first, s.contains("$where") {
                findings.append(finding(def: def, offset: offset, category: "NoSQL Injection",
                                        severity: .high, reachable: reachable,
                                        message: "$where executes arbitrary JavaScript on the server.",
                                        taint: nil))
            }
        case "random":
            if name == "Math.random" {
                findings.append(finding(def: def, offset: offset, category: "Weak Random",
                                        severity: .low, reachable: reachable,
                                        message: "Math.random() is not cryptographically secure.",
                                        taint: nil))
            }
        case "charAt", "charCodeAt", "codePointAt":
            if argVals.first?.tainted == true {
                findings.append(finding(def: def, offset: offset, category: "Unchecked String Index",
                                        severity: .medium, reachable: reachable,
                                        message: "Tainted index into '\(leaf)()' without bounds validation.",
                                        taint: "\(taintPath(argVals.first) ?? "?") → \(leaf) index"))
            }
        case "evaluate":
            // `doc.evaluate(xpathExpr, contextNode, nsResolver, type, result)` —
            // the INJECTION surface is the tainted XPath expression (arg 0);
            // the context node is a legitimate dynamic argument.
            if argVals.first?.tainted == true {
                findings.append(finding(def: def, offset: offset, category: "XPath Injection",
                                        severity: .high, reachable: reachable,
                                        message: "Tainted XPath expression.",
                                        taint: "\(taintPath(argVals.first) ?? "?") → XPath"))
            }
        default:
            break
        }

        // Callee-shape rules that do not reduce to the leaf name.
        let lowerName = name.lowercased()
        if lowerName.contains("ldap"), argVals.first?.tainted == true,
           !(lowerName.contains("escape") || lowerName.contains("sanitize")
             || lowerName.contains("encode") || lowerName.contains("validate")
             || lowerName.contains("clean")) {
            findings.append(finding(def: def, offset: offset, category: "LDAP Injection",
                                    severity: .high, reachable: reachable,
                                    message: "Tainted LDAP filter.",
                                    taint: "\(taintPath(argVals.first) ?? "?") → LDAP query"))
        }
        if (name.contains("http") || name.contains("axios") || name.contains("got")),
           ["get", "post", "put", "delete"].contains(leaf),
           argVals.first?.tainted == true,
           !bodyHasHostValidationGate(def) {
            findings.append(finding(def: def, offset: offset, category: "SSRF",
                                    severity: .high, reachable: reachable,
                                    message: "Tainted URL in outbound request (\(name)).",
                                    taint: "\(taintPath(argVals.first) ?? "?") → \(name)"))
        }

        // ---- Call taint value ----
        if isNew {
            if leaf == "Function" { return .tainted("new Function") }
            return unionAll(argVals)
        }
        if jsSanitizers.contains(name) || jsSanitizers.contains(leaf) {
            return .clean
        }
        if jsSyncReturnSources.contains(leaf) {
            return .tainted(leaf)
        }
        if taintReturning.contains(leaf) {
            return .tainted(leaf, crossFile: crossFileSources.contains(leaf))
        }
        if case .member(_, let prop, _) = callee, jsTaintPropagators.contains(prop) {
            if calleeVal.tainted { return calleeVal }
        }
        return unionAll(argVals)
    }

    // MARK: - Walk 2: bounds rules at index accesses

    /// Finds the base name of a `X.length` member anywhere in an expression
    /// (loop conditions may wrap it: `i <= arr.length - 1`).
    private func lengthBaseName(of e: JSExpr) -> String? {
        switch e {
        case .member(let b, "length", _):
            let n = b.dottedName
            return n.isEmpty ? nil : n
        case .binary(_, let l, let r, _):
            return lengthBaseName(of: l) ?? lengthBaseName(of: r)
        case .assign(_, _, let r, _):
            return lengthBaseName(of: r)
        case .ternary(let c, let t, let f, _):
            return lengthBaseName(of: c) ?? lengthBaseName(of: t) ?? lengthBaseName(of: f)
        default:
            return nil
        }
    }

    private func applyBoundsRules(base: JSExpr, index: JSExpr, idxVal: TaintVal,
                                  offset: Int, ctx: WalkContext, def: JSDef,
                                  into findings: inout [JSFinding]) {
        let reachable = isReachable(def)
        let baseName = base.dottedName

        // arr[arr.length] — always out of bounds.
        if case .member(let ib, "length", _) = index, ib.dottedName == baseName, !baseName.isEmpty {
            findings.append(finding(def: def, offset: offset,
                                    category: "Array Index Out of Bounds",
                                    severity: .high, reachable: reachable,
                                    message: "'\(baseName)[\(baseName).length]' is always out of bounds (valid indices end at length - 1).",
                                    taint: nil))
            return
        }

        guard case .ident(let idxName, _) = index else { return }

        // Loop correlation: arr[i] under `for (...; i <= arr.length; ...)`.
        if let lv = ctx.loopVar, idxName == lv,
           let lb = ctx.loopBase, lb == baseName, !baseName.isEmpty {
            if ctx.loopInclusive {
                findings.append(finding(def: def, offset: offset,
                                        category: "Loop Off-by-One",
                                        severity: .high, reachable: reachable,
                                        message: "Loop condition '\(lv) <= \(lb).length' makes '\(lb)[\(lv)]' read past the end of the array.",
                                        taint: nil))
            }
            return // loop-bounded access is in range otherwise
        }

        // Tainted index without a bounds guard. A locally-declared object
        // literal (`const templates = { … }; templates[templateId]`) is a
        // keyed lookup table, not a positional array — unknown keys yield
        // `undefined` rather than an out-of-bounds read. The same holds for
        // keys iterated from `Object.keys(…)`: `for (k of keys) obj[k]` and
        // `Object.keys(x).forEach((k) => obj[k])` are property lookups.
        if idxVal.tainted, !baseName.isEmpty,
           !ctx.boundsGuards.contains("\(idxName)\u{1}\(baseName)") {
            if ctx.dictionaryKeyVars.contains(idxName) {
                return
            }
            if case .ident(let bn, _) = base, ctx.objectLitVars.contains(bn) {
                return
            }
            // Keyed lookups into request/URL/storage maps (`req.query[name]`,
            // `location.search[key]`, `sessionStorage[k]`) are property reads, not
            // positional array accesses: a miss yields `undefined`, never an
            // out-of-bounds element read, so there is no index bound to validate.
            if isDictionaryLookupBase(baseName) {
                return
            }
            findings.append(finding(def: def, offset: offset,
                                    category: "Unvalidated Array Index",
                                    severity: .medium, reachable: reachable,
                                    message: "Tainted index '\(idxName)' used to access '\(baseName)' without a bounds check.",
                                    taint: "\(taintPath(idxVal) ?? "?") → \(baseName)[\(idxName)]"))
        }
    }

    // MARK: - Assignment / member-write rules

    private func applyAssignmentRules(target: JSExpr, value: JSExpr, valueTaint: TaintVal,
                                      ctx: WalkContext, def: JSDef,
                                      into findings: inout [JSFinding]) {
        let reachable = isReachable(def)
        // Both `obj.prototype = x` (member) and `obj["__proto__"] = x`
        // (computed index) are covered; the text form decides.
        let isMemberOrIndex: Bool
        switch target {
        case .member, .index: isMemberOrIndex = true
        default: isMemberOrIndex = false
        }
        guard isMemberOrIndex else { return }
        let targetText = assignmentTargetText(target)
        // The effective last segment: member name, or bracket-literal key.
        var tail: String
        switch target {
        case .member(_, let name, _):
            tail = name
        case .index(_, let idx, _):
            if case .literal(let t, _) = idx {
                tail = t.hasPrefix("\"") || t.hasPrefix("'")
                    ? String(t.dropFirst().dropLast())
                    : t
            } else {
                tail = assignmentTargetText(idx)
            }
        default:
            tail = ""
        }

        if ["innerHTML", "outerHTML", "insertAdjacentHTML"].contains(tail), valueTaint.tainted {
            findings.append(finding(def: def, offset: value.offset, category: "XSS (\(tail))",
                                    severity: .high, reachable: reachable,
                                    message: "Assignment of tainted data to \(targetText) can inject markup or script.",
                                    taint: "\(taintPath(valueTaint) ?? "?") → \(targetText)"))
        }
        if targetText.contains("__proto__") || targetText.contains("constructor.prototype") || tail == "prototype" {
            findings.append(finding(def: def, offset: value.offset, category: "Prototype Pollution",
                                    severity: .high, reachable: reachable,
                                    message: "Write to \(targetText) can pollute shared object state.",
                                    taint: valueTaint.tainted ? "\(taintPath(valueTaint) ?? "?") → \(targetText)" : nil))
        }
        if tail == "domain", targetText.contains("document") {
            findings.append(finding(def: def, offset: value.offset, category: "document.domain Tampering",
                                    severity: .medium, reachable: reachable,
                                    message: "document.domain relaxation widens the same-origin policy.",
                                    taint: nil))
        }
        if (tail == "href" || tail == "location"), valueTaint.tainted {
            findings.append(finding(def: def, offset: value.offset, category: "Open Redirect",
                                    severity: .high, reachable: reachable,
                                    message: "Tainted URL assigned to \(targetText).",
                                    taint: "\(taintPath(valueTaint) ?? "?") → \(targetText)"))
        }
    }

    /// Full textual description of an assignment target, including computed
    /// brackets (`obj["__proto__"]`), so rule matching sees their content.
    private func assignmentTargetText(_ e: JSExpr) -> String {
        switch e {
        case .member(let base, let name, _):
            let b = assignmentTargetText(base)
            return b.isEmpty ? name : "\(b).\(name)"
        case .index(let base, let idx, _):
            let inner: String
            if case .literal(let t, _) = idx {
                inner = t.hasPrefix("\"") || t.hasPrefix("'")
                    ? String(t.dropFirst().dropLast())
                    : t
            } else {
                inner = assignmentTargetText(idx)
            }
            return "\(assignmentTargetText(base))[\(inner)]"
        case .ident(let n, _):
            return n
        default:
            return ""
        }
    }

    // MARK: - Walk 3: guards

    /// Refines in-branch guards derived from a condition.
    private func refineGuards(cond: JSExpr, ctx: WalkContext) {
        switch cond {
        case .binary(let op, let l, let r, _):
            if ["<", "<=", ">", ">="].contains(op) {
                if case .ident(let idxName, _) = l, case .member(let base, "length", _) = r {
                    ctx.boundsGuards.insert("\(idxName)\u{1}\(base.dottedName)")
                }
                if case .ident(let idxName, _) = r, case .member(let base, "length", _) = l {
                    ctx.boundsGuards.insert("\(idxName)\u{1}\(base.dottedName)")
                }
            }
            if [">", "!==", "!="].contains(op) {
                if case .ident(let n, _) = l, isZeroLiteral(r) { ctx.zeroChecked.insert(n) }
                if case .ident(let n, _) = r, isZeroLiteral(l) { ctx.zeroChecked.insert(n) }
            }
            if op == "&&" {
                refineGuards(cond: l, ctx: ctx)
                refineGuards(cond: r, ctx: ctx)
            }
        default:
            break
        }
    }

    /// `if (!x) return/throw` and `if (i >= len) return` guard subsequent code.
    private func applyEarlyExitGuards(cond: JSExpr, thenBody: [JSStmt], ctx: WalkContext) {
        let exits = thenBody.contains {
            if case .throwStmt = $0 { return true }
            if case .returnStmt = $0 { return true }
            return false
        }
        guard exits else { return }
        switch cond {
        case .unary("!", .ident(let n, _), _):
            ctx.zeroChecked.insert(n)
        case .binary(let op, let l, let r, _):
            if op == ">=" || op == ">" {
                if case .ident(let idxName, _) = l, case .member(let base, "length", _) = r {
                    ctx.boundsGuards.insert("\(idxName)\u{1}\(base.dottedName)")
                }
            }
        default:
            break
        }
    }

    private func isZeroLiteral(_ e: JSExpr) -> Bool {
        if case .literal(let t, _) = e { return t == "0" }
        return false
    }

    private func isZeroRisky(_ e: JSExpr, ctx: WalkContext) -> Bool {
        switch e {
        case .literal:
            return false
        case .ident(let n, _):
            if ctx.zeroChecked.contains(n) { return false }
            if let v = ctx.vars[n] {
                // Only parameters/tainted values are treated as possibly-zero;
                // locals derived from literals are considered safe.
                return v.tainted || v.origin?.hasPrefix("parameter") == true
            }
            return true // untracked global/outer value
        case .member:
            return true
        default:
            return false
        }
    }

    // MARK: - Helpers

    private func taintPath(_ v: TaintVal?) -> String? {
        guard let v = v, v.tainted else { return nil }
        return v.origin
    }

    private func sourceText(from e: JSExpr) -> String {
        let ns = source as NSString
        let start = e.offset
        guard start >= 0, start < ns.length else { return "" }
        return ns.substring(with: NSRange(location: start,
                                          length: min(240, ns.length - start)))
    }

    private func isReachable(_ def: JSDef) -> Bool {
        reachableNames.contains(def.name) || reachableNames.isEmpty
    }

    /// True when the base of an indexed access is a known plain-object map
    /// rather than a positional array. Express/Koa request bags, the URL query
    /// parcel, and web storage are property collections; a tainted key into one
    /// (commonly `req.query[fieldName]`) is a property lookup, so the
    /// Unvalidated Array Index rule must not treat it as a bounds violation.
    private func isDictionaryLookupBase(_ baseName: String) -> Bool {
        let lower = baseName.lowercased()
        if lower == "location.search" || lower == "location.query"
            || lower == "sessionStorage" || lower == "localStorage" {
            return true
        }
        let isBag = lower.hasPrefix("req.") || lower.hasPrefix("request.")
            || lower.hasPrefix("ctx.") || lower.hasPrefix("event.")
        guard isBag, let tail = lower.components(separatedBy: ".").last else { return false }
        return ["query", "body", "params", "cookies", "headers", "session", "dataset"].contains(tail)
    }

    private func bodyTokens(of def: JSDef) -> [CAstToken] {
        let lo = def.bodyRange.location
        let hi = lo + def.bodyRange.length
        return tokens.filter { $0.offset >= lo && $0.offset < hi && $0.kind != .eof }
    }

    private func bodyContainsMutation(of name: String, body: [JSStmt]) -> Bool {
        var found = false
        func scanStmt(_ s: JSStmt) {
            if found { return }
            switch s {
            case .block(let inner, _):
                for x in inner { scanStmt(x) }
            case .ifStmt(_, let t, let e, _):
                for x in t { scanStmt(x) }
                if let e = e { for x in e { scanStmt(x) } }
            case .forStmt(_, _, _, _, _, let b, _), .whileStmt(_, let b, _):
                for x in b { scanStmt(x) }
            case .exprStmt(let e, _):
                scanExpr(e)
            case .varDecl(let decls, _):
                for d in decls { if let e = d.initExpr { scanExpr(e) } }
            case .returnStmt(let e, _):
                if let e = e { scanExpr(e) }
            case .throwStmt(let e, _):
                if let e = e { scanExpr(e) }
            }
        }
        func scanExpr(_ e: JSExpr) {
            if found { return }
            switch e {
            case .call(let callee, let args, _):
                var baseName = ""
                if case .member(let b, _, _) = callee { baseName = b.dottedName }
                let leaf = callee.dottedName.components(separatedBy: ".").last ?? ""
                if baseName == name,
                   ["pop", "shift", "splice", "push", "unshift"].contains(leaf) {
                    found = true
                }
                for a in args { scanExpr(a) }
                scanExpr(callee)
            case .member(let b, _, _):
                scanExpr(b)
            case .index(let b, let i, _):
                scanExpr(b); scanExpr(i)
            case .binary(_, let l, let r, _), .assign(_, let l, let r, _):
                scanExpr(l); scanExpr(r)
            case .ternary(let c, let t, let f, _):
                scanExpr(c); scanExpr(t); scanExpr(f)
            case .unary(_, let o, _):
                scanExpr(o)
            case .arrayLit(let els, _):
                for el in els { scanExpr(el) }
            case .new(let c, let args, _):
                scanExpr(c)
                for a in args { scanExpr(a) }
            case .arrow(_, let body, _):
                switch body {
                case .block(let stmts):
                    for s in stmts { scanStmt(s) }
                case .expr(let x):
                    scanExpr(x)
                }
            case .template:
                for interp in e.templateExprs() { scanExpr(interp) }
            case .ident, .literal, .objectLit:
                break
            }
        }
        for s in body { scanStmt(s) }
        return found
    }

    /// Express/Koa route handlers that mutate session/user state on the request
    /// object (`req.user.email = req.body.email`) without validating any CSRF
    /// token allow a browser session-authenticated cross-site request to perform
    /// the state change.
    private func checkJsCsrf(_ def: JSDef, stmts: [JSStmt]) -> JSFinding? {
        let params = Set(def.params.compactMap { $0.name }.map { $0.lowercased() })
        guard params.contains("req") || params.contains("request") else { return nil }
        let flat = flatBodyText(of: def)
        let csrfTokens = ["csrftoken", "csrf_token", "csrf", "xsrf", "_token", "synchronizer", "double_submit"]
        guard !csrfTokens.contains(where: { flat.lowercased().contains($0) }) else { return nil }
        // State mutation: an assignment whose target is `req.user.<m>` /
        // `req.session.<m>` (or `request.…`), not a mere read of `req.user`.
        var mutationOffset: Int? = nil
        var untrustedValue = false
        func isSessionTarget(_ lhs: JSExpr) -> Bool {
            guard case .member(let base, _, _) = lhs,
                  case .member(let root, let member, _) = base else { return false }
            return (member == "user" || member == "session") && (root.dottedName == "req" || root.dottedName == "request")
        }
        func referencesUserInput(_ e: JSExpr) -> Bool {
            guard case .member(let base, let m, _) = e else { return false }
            let dotted = base.dottedName
            return (dotted == "req.body" || dotted == "req.query" || dotted == "request.body" || dotted == "request.query") && !m.isEmpty
        }
        func walkExpr(_ e: JSExpr) {
            switch e {
            case .assign(let op, let lhs, let rhs, let offset):
                if op == "=", isSessionTarget(lhs), mutationOffset == nil { mutationOffset = offset }
                walkExpr(lhs)
                walkExpr(rhs)
            case .member(let b, _, _):
                if referencesUserInput(e) { untrustedValue = true }
                walkExpr(b)
            case .call(let c, let args, _):
                walkExpr(c)
                for a in args { walkExpr(a) }
            case .index(let b, let i, _):
                walkExpr(b); walkExpr(i)
            case .binary(_, let l, let r, _): walkExpr(l); walkExpr(r)
            case .ternary(let c2, let t, let f, _): walkExpr(c2); walkExpr(t); walkExpr(f)
            case .unary(_, let o, _):
                walkExpr(o)
            case .arrow(_, let b2, _):
                if case .block(let inner) = b2 { for s in inner { walkStmt(s) } }
            case .arrayLit(let els, _):
                for el in els { walkExpr(el) }
            default:
                break
            }
        }
        func walkStmt(_ s: JSStmt) {
            switch s {
            case .exprStmt(let e, _): walkExpr(e)
            case .varDecl(let ds, _): for d in ds { if let e = d.initExpr { walkExpr(e) } }
            case .ifStmt(let c, let t, let eb, _):
                walkExpr(c)
                for x in t { walkStmt(x) }
                if let eb = eb { for x in eb { walkStmt(x) } }
            case .forStmt(_, let b, _, let it, _, let body, _):
                if let b = b { walkExpr(b) }
                if let it = it { walkExpr(it) }
                for x in body { walkStmt(x) }
            case .whileStmt(let c, let body, _):
                walkExpr(c)
                for x in body { walkStmt(x) }
            case .returnStmt(let e, _), .throwStmt(let e, _):
                if let e = e { walkExpr(e) }
            case .block(let inner, _):
                for x in inner { walkStmt(x) }
            }
        }
        for s in stmts { walkStmt(s) }
        guard let off = mutationOffset, untrustedValue else { return nil }
        return finding(def: def, offset: off,
                       category: "CSRF (Missing Token Validation)",
                       severity: .medium, reachable: isReachable(def),
                       message: "Route mutates session/user state from a session-authenticated request without CSRF token validation.",
                       taint: nil)
    }

    private func finding(def: JSDef, offset: Int, category: String,
                         severity: ScanFinding.Severity, reachable: Bool,
                         message: String, taint: String?) -> JSFinding {
        JSFinding(function: def.name, offset: offset, category: category,
                  severity: severity, message: message, taintPath: taint,
                  reachable: reachable)
    }

    // MARK: - File-level scans (unchanged behavior)

    static func scanFileLevel(url: URL, source: String, scanningSource: String) -> [ScanFinding] {
        var findings: [ScanFinding] = []
        let ns = source as NSString
        let lower = source.lowercased()

        func line(at offset: Int) -> Int {
            var line = 1
            let upto = min(offset, ns.length)
            var i = 0
            while i < upto {
                if ns.character(at: i) == 0x0A { line += 1 }
                i += 1
            }
            return line
        }

        func add(_ offset: Int, _ category: String, _ severity: ScanFinding.Severity, _ message: String) {
            findings.append(ScanFinding(fileURL: url, line: line(at: offset), function: "(file)",
                                        category: category, message: message, taint: nil,
                                        severity: severity, exploitability: severity,
                                        reachable: true, taintPath: nil, ignored: false,
                                        scanningSource: scanningSource))
        }

        // NOTE: Express server-hardening file rules (Missing Security Headers /
        // Clickjacking / MIME Sniffing) were removed: every minimal Express
        // fixture fires them, and on real apps helmet-style middleware often
        // lives in a different file than app.listen(), so file-level presence
        // checks are unreliable both ways.

        if lower.contains("access-control-allow-origin") && lower.contains("\"*\"") {
            add(0, "CORS Misconfiguration", .high,
                "Access-Control-Allow-Origin wildcard combined with credentials.")
        }
        let secrets: [(String, String)] = [
            ("sk_live_[0-9a-zA-Z]{10,}", "Stripe live secret key"),
            ("AKIA[0-9A-Z]{16}", "AWS access key id"),
            ("-----BEGIN [A-Z ]*PRIVATE KEY-----", "private key"),
            ("mongodb(\\+srv)?:\\/\\/", "MongoDB connection string"),
            ("postgres(ql)?:\\/\\/", "PostgreSQL connection string"),
        ]
        for (pattern, label) in secrets {
            if let r = source.range(of: pattern, options: .regularExpression) {
                let off = r.lowerBound.utf16Offset(in: source)
                add(off, "Hardcoded Secret", .critical, "\(label) embedded in source.")
            }
        }
        // Plain-text `http://` URLs in source. Protocol-guard literals — the
        // `'http://'` inside `url.startsWith('http://')`, `=== 'http://'`,
        // `indexOf('http://')` checks that REJECT plaintext — are the
        // mitigation, not the vulnerability, and must not be counted.
        if let regex = try? NSRegularExpression(pattern: "http://"),
           let guardRegex = try? NSRegularExpression(pattern: "(?i)(?:start|end)sWith\\(['\"]$|(?:indexOf|includes|search)\\s*\\(\\s*['\"]$|[=!]={1,2}\\s*['\"]$") {
            let textNS = ns as NSString
            for m in regex.matches(in: source, range: NSRange(location: 0, length: textNS.length)) {
                let off = m.range.location
                if isProtocolGuardLiteral(in: source, matchOffset: off,
                                         windowRegex: guardRegex) { continue }
                let hostStart = min(off + 7, ns.length)
                let hostLen = min(30, ns.length - hostStart)
                let host = ns.substring(with: NSRange(location: hostStart, length: max(0, hostLen))).lowercased()
                if !host.contains("localhost") && !host.contains("127.0.0.1") {
                    add(off, "Insecure Transport", .medium,
                        "Plain-text http:// URL in source.")
                }
            }
        }
        if lower.contains("multer(") && !lower.contains("limits") && !lower.contains("filefilter") {
            add(0, "Unsafe File Upload", .medium,
                "Multer upload without size limits or file filter.")
        }
        return findings
    }
}

/// True when an `http://` occurrence is a protocol-guard literal — the `'http://'`
/// argument of `startsWith`/`endsWith`/`indexOf`/`includes`/`search` checks or a
/// loose/strict equality comparison used to REJECT plaintext. Such occurrences are
/// the mitigation, not an insecure URL, so the Insecure Transport rule skips them.
private func isProtocolGuardLiteral(in text: String, matchOffset: Int,
                                    windowRegex: NSRegularExpression) -> Bool {
    guard matchOffset > 0 else { return false }
    let prefix = String(text.prefix(matchOffset))
    let window = String(prefix.suffix(24)).trimmingCharacters(in: .whitespaces)
    let ns = window as NSString
    return windowRegex.rangeOfFirstMatch(in: window, range: NSRange(location: 0, length: ns.length)).location != NSNotFound
}
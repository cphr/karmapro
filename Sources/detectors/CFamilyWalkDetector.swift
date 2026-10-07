// by cipher.org.uk
import Foundation

/// A finding produced by the dedicated C/C++ walk detector. Reports one of the
/// array-safety categories that the generic single-pass AST detector does not
/// cover at walk precision: Array Index Out of Bounds, Unvalidated Array Index,
/// Loop Off-by-One and Array Mutation During Iteration.
struct CFamilyWalkFinding {
    let function: String
    let offset: Int
    let category: String
    let severity: ScanFinding.Severity
    let message: String
    let taintPath: String?
    let reachable: Bool
    var crossFile: Bool = false
}

/// Structural security detector for non-kernel C/C++ files, built as a
/// **self-contained three-walk** analyser over the shared C AST.
///
/// Unlike `AstSecurityDetector` (one single-pass `scanFunction` for every
/// language) the array-safety categories here need independent walks because a
/// single forward pass cannot correlate an index access with the loop that
/// bounds it, the guard that rejects it, or the write that taints it:
///
///  - **Walk 1 (Taint walk)** threads the set of attacker-influenced variable
///    names through each function body in source order: C source APIs
///    (`getenv`, `scanf`, `fgets`, `fread`, `recv`, ...) seed and propagate the
///    taint, and every `arr[taintedIdx]` access is a candidate.
///  - **Walk 2 (Bounds walk)** collects, per path, which index bounds are
///    guaranteed: a `for (i = 0; i < n; i++)` loop header, an
///    `if (i < size)` then-branch guard, or an `if (i >= size) return;`
///    early-exit fallthrough. A tainted access inside a proven bound is
///    suppressed; a loop whose exit condition provably crosses the array
///    capacity (inclusive `<=` on the capacity) is a Loop Off-by-One.
///  - **Walk 3 (Boundary walk)** computes, to a fixpoint over the AST call
///    graph, which functions return tainted data and which parameters receive
///    tainted arguments, so taint crosses function boundaries.
///
/// The detector delegates the buffer-overflow / format-string / command
/// injection rules to the generic engine unchanged; it only adds the four
/// categories its walks can prove. Kernel-shaped and skb-shaped files are
/// excluded by the caller (KernelAstDetector owns those categories).
struct CFamilyWalkDetector {

    /// C source APIs whose *return value* holds attacker-influenced data.
    private static let returnTaintingSources: Set<String> = [
        "getenv", "getwd", "getpass", "getopt", "getopt_long",
        "strdup", "strndup", "strtok", "strtok_r", "strstr", "index", "rindex",
        "realpath", "readlink", "strchr",
    ]

    /// C source APIs that *write* attacker data through their first argument
    /// (the destination buffer), making that variable tainted afterwards.
    private static let writeThroughFirstArgSources: Set<String> = [
        "fgets", "gets", "fread", "read", "recv", "recvfrom",
        "asprintf", "vasprintf", "getline", "readline",
    ]

    /// `scanf`-family sources that write through their `&arg` operands.
    private static let scanfFamily: Set<String> = [
        "scanf", "fscanf", "sscanf",
    ]

    /// STL/container mutators whose call inside a loop over the same container
    /// invalidates iteration (Array Mutation During Iteration).
    fileprivate static let containerMutators: Set<String> = [
        "push_back", "push_front", "emplace_back", "emplace_front", "insert",
        "erase", "pop_back", "pop_front", "clear", "resize", "reserve",
        "assign", "swap", "remove", "remove_if", "sort", "reverse",
    ]

    private let source: String
    private let astFns: [String: CFunctionDef]
    private let reachableNames: Set<String>
    private let taintReturning: Set<String>
    private let crossFileSources: Set<String>

    /// Fixpoint context for Walk 3 (boundary).
    private struct Walk3Context {
        var taintReturningFns = Set<String>()
        var taintedParam: [String: Set<Int>] = [:]
    }

    /// Per-function structural facts computed once before Walk 1.
    private struct FnFacts {
        /// Local fixed-size array capacity: `name -> element count`.
        var capacities: [String: Int] = [:]
    }

    /// Result of one function-flow run (emit on/off).
    private struct FlowResult {
        var candidates: [CFamilyWalkFinding] = []
        var calls: [(callee: String, perArg: [Bool])] = []
        var returnsTainted = false
    }

    /// Cross-detector facts derived from the flow walk: variable names that are
    /// provably bounded above and provably non-zero on some control-flow path,
    /// unioned per function name. The generic security engine consumes these so
    /// its buffer-overflow / division-by-zero / integer-overflow checks inherit
    /// the walk's flow-ordered guards (while-loop conditions and loop headers
    /// the single-pass engine's whole-function walks do not bind).
    struct CFamilyWalkFacts {
        /// Names provably bounded from above: `<`/`<=` then-path guards,
        /// `>`/`>=` early-exit fallthrough, `while`-condition guards.
        var bounded: [String: Set<String>] = [:]
        /// Names provably non-zero: `!=`/`>`/`>= 1` then-path guards,
        /// `==`/`<=` early-exit fallthrough or else-branch, loop conditions.
        var nonZero: [String: Set<String>] = [:]
        /// Loop variables whose `for` header exit bound is a constant
        /// (`for (i = 0; i < 8; i++)`). Safe for integer-overflow suppression
        /// only — a loop-bound proof is not a byte-count capacity proof, so
        /// these are never merged into the spill-count size set.
        var constBounded: [String: Set<String>] = [:]
    }

    /// Loop-head facts threaded through a `for` body so index accesses can be
    /// correlated with the loop variable and its proven exit constant.
    private struct LoopFact {
        let varName: String
        let upperConst: Int?
        let inclusive: Bool
    }

    init(source: String, astFns: [String: CFunctionDef],
         reachableNames: Set<String> = [],
         taintReturning: Set<String> = [],
         crossFileSources: Set<String> = []) {
        self.source = source
        self.astFns = astFns
        self.reachableNames = reachableNames
        self.taintReturning = taintReturning
        self.crossFileSources = crossFileSources
    }

    // MARK: - Detect (three-walk driver)

    func detect() -> [CFamilyWalkFinding] {
        guard !astFns.isEmpty else { return [] }

        // Walk 3 (boundary) fixpoint: taint-returning functions and tainted
        // parameters stabilize over the AST call graph.
        var ctx = Walk3Context()
        var callGraph: [String: Set<String>] = [:]
        for fn in astFns.values {
            callGraph[fn.name] = callees(in: fn.body)
        }
        for _ in 0..<8 {
            var changed = false
            for fn in astFns.values {
                let facts = fnFacts(for: fn)
                let result = runFlow(fn: fn, facts: facts, ctx: ctx, emit: false, reached: false)
                if result.returnsTainted, !ctx.taintReturningFns.contains(fn.name) {
                    ctx.taintReturningFns.insert(fn.name); changed = true
                }
                for (callee, perArg) in result.calls {
                    guard let calleeFn = astFns[callee] else { continue }
                    for (k, isTainted) in perArg.enumerated() where k < calleeFn.params.count {
                        if isTainted, !(ctx.taintedParam[callee] ?? []).contains(k) {
                            ctx.taintedParam[callee, default: []].insert(k); changed = true
                        }
                    }
                }
            }
            if !changed { break }
        }

        // Reachability: entry-like functions, plus anything that transitively
        // receives a tainted argument, plus the scanner-provided reachables.
        var reached = Set<String>()
        for fn in astFns.values where isEntrylike(fn) {
            reached.insert(fn.name)
            for next in (callGraph[fn.name] ?? []) { reached.insert(next) }
        }
        for name in astFns.keys where !(ctx.taintedParam[name] ?? []).isEmpty {
            reached.insert(name)
        }
        var queue = reached.sorted()
        while !queue.isEmpty {
            let cur = queue.removeFirst()
            for next in (callGraph[cur] ?? []) where !reached.contains(next) {
                reached.insert(next)
                queue.append(next)
            }
        }
        reached.formUnion(reachableNames)

        // Walk 1 (taint) with emission on, using the boundary context.
        var findings: [CFamilyWalkFinding] = []
        for fn in astFns.values {
            let facts = fnFacts(for: fn)
            let result = runFlow(fn: fn, facts: facts, ctx: ctx,
                                 emit: true, reached: reached.contains(fn.name))
            findings.append(contentsOf: result.candidates)
            // Extra source-ordered safety passes over the AST that do not need
            // the taint/bounds walks: literal-NULL dereferences, constant
            // integer overflow (`INT_MAX + 1`) and returning stack-local
            // addresses. Emitted per function alongside the walk findings.
            findings.append(contentsOf: extraSafetyFindings(fn: fn,
                                                            reached: reached.contains(fn.name)))
        }

        // Cross-file attribution: a finding whose taint path roots in a source
        // function defined in another file is cross-file.
        for i in findings.indices {
            if let root = findings[i].taintPath?.components(separatedBy: " → ").first,
               crossFileSources.contains(root) || taintReturning.contains(root) {
                findings[i].crossFile = true
            }
        }
        return findings
    }

    // MARK: - Cross-over facts (shared with the generic security engine)

    /// Reduces the flow walk to per-function sets of names proven bounded above
    /// (`bounded`), proven non-zero (`nonZero`) and loop-const-bounded
    /// (`constBounded`) on at least one control-flow path. The generic detector
    /// merges these into its per-function `sizeBounded` / `zeroChecked` bases so
    /// buffered-copy, division-by-zero and integer-overflow checks inherit the
    /// walk's guards (notably `while (len < cap)` bodies and `for` headers,
    /// which its structural whole-function walks skip). Only sound, path-proven
    /// facts are emitted; loop-variable bounds are isolated to `constBounded`
    /// precisely because a loop header does not bound a memcpy byte count.
    func flowFacts() -> CFamilyWalkFacts {
        var out = CFamilyWalkFacts()
        for fn in astFns.values {
            var bounded = Set<String>()
            var nonZero = Set<String>()
            var constBounded = Set<String>()
            let facts = fnFacts(for: fn)
            factsWalk(fn.body, fn: fn, facts: facts,
                      bounded: &bounded, nonZero: &nonZero, constBounded: &constBounded)
            out.bounded[fn.name] = bounded
            out.nonZero[fn.name] = nonZero
            out.constBounded[fn.name] = constBounded
        }
        return out
    }

    private func factsWalk(_ stmt: CStmt, fn: CFunctionDef, facts: FnFacts,
                           bounded: inout Set<String>, nonZero: inout Set<String>,
                           constBounded: inout Set<String>) {
        switch stmt {
        case .block(let arr):
            var accB = bounded
            var accN = nonZero
            for s in arr {
                accB.formUnion(earlyExitBounded(in: s))
                accN.formUnion(earlyExitNonZero(in: s))
                factsWalk(s, fn: fn, facts: facts, bounded: &accB, nonZero: &accN,
                          constBounded: &constBounded)
            }
            bounded = accB
            nonZero = accN
        case .ifStmt(let cond, let thenBranch, let elseBranch, _):
            var thenB = bounded
            var thenN = nonZero
            for (varName, effOp) in comparisons(in: cond) {
                if effOp == "<" || effOp == "<=" { thenB.insert(varName) }
                if effOp == "!=" || effOp == ">" { thenN.insert(varName) }
                if effOp == ">=", positiveLowerBound(varName, in: cond) { thenN.insert(varName) }
            }
            factsWalk(thenBranch, fn: fn, facts: facts, bounded: &thenB, nonZero: &thenN,
                      constBounded: &constBounded)
            bounded.formUnion(thenB)
            nonZero.formUnion(thenN)
            if let eb = elseBranch {
                var elseB = bounded
                var elseN = nonZero
                for (varName, effOp) in comparisons(in: cond) {
                    if effOp == ">" || effOp == ">=" { elseB.insert(varName) }
                    if effOp == "==" || effOp == "<=" { elseN.insert(varName) }
                }
                factsWalk(eb, fn: fn, facts: facts, bounded: &elseB, nonZero: &elseN,
                          constBounded: &constBounded)
                bounded.formUnion(elseB)
                nonZero.formUnion(elseN)
            }
        case .whileStmt(let cond, let body, _):
            var bodyB = bounded
            var bodyN = nonZero
            for (varName, effOp) in comparisons(in: cond) {
                if effOp == "<" || effOp == "<=" { bodyB.insert(varName) }
                if effOp == "!=" || effOp == ">" { bodyN.insert(varName) }
                if effOp == ">=", positiveLowerBound(varName, in: cond) { bodyN.insert(varName) }
            }
            factsWalk(body, fn: fn, facts: facts, bounded: &bodyB, nonZero: &bodyN,
                      constBounded: &constBounded)
            bounded.formUnion(bodyB)
            nonZero.formUnion(bodyN)
        case .doWhileStmt(let body, let cond, _):
            var bodyB = bounded
            var bodyN = nonZero
            for (varName, effOp) in comparisons(in: cond) {
                if effOp == "<" || effOp == "<=" { bodyB.insert(varName) }
                if effOp == "!=" || effOp == ">" { bodyN.insert(varName) }
            }
            factsWalk(body, fn: fn, facts: facts, bounded: &bodyB, nonZero: &bodyN,
                      constBounded: &constBounded)
            bounded.formUnion(bodyB)
            nonZero.formUnion(bodyN)
        case .forStmt(let initS, let cond, _, let body, _):
            if let initS = initS {
                factsWalk(initS, fn: fn, facts: facts, bounded: &bounded, nonZero: &nonZero,
                          constBounded: &constBounded)
            }
            let lf = self.loopFact(for: cond, init: initS, facts: facts)
            if let lf = lf, lf.upperConst != nil {
                // `for (i = 0; i < 8; i++)` bounds `i` inside the body. Never a
                // byte-count capacity proof, but a sound overflow-taint bound.
                constBounded.insert(lf.varName)
            }
            var bodyB = bounded
            var bodyN = nonZero
            if let cond = cond {
                for (varName, effOp) in comparisons(in: cond) {
                    // Loop-variable bounds are excluded from the size set (a
                    // loop header is not a spill-capacity proof); whole-cond
                    // guards on other variables are fine.
                    if lf.map({ varName != $0.varName }) ?? true {
                        if effOp == "<" || effOp == "<=" { bodyB.insert(varName) }
                    }
                    if effOp == "!=" || effOp == ">" { bodyN.insert(varName) }
                }
            }
            factsWalk(body, fn: fn, facts: facts, bounded: &bodyB, nonZero: &bodyN,
                      constBounded: &constBounded)
            bounded.formUnion(bodyB)
            nonZero.formUnion(bodyN)
        case .switchStmt(_, let cases, _):
            for c in cases {
                for s in c.body {
                    factsWalk(s, fn: fn, facts: facts, bounded: &bounded, nonZero: &nonZero,
                              constBounded: &constBounded)
                }
            }
        case .labeledStmt(_, let s, _):
            factsWalk(s, fn: fn, facts: facts, bounded: &bounded, nonZero: &nonZero,
                      constBounded: &constBounded)
        default:
            break
        }
    }

    /// Non-zero facts established by an early-exit guard at the start of a
    /// statement, e.g. `if (n == 0) return;` / `if (n <= 0) return;` makes `n`
    /// non-zero on the fallthrough path.
    private func earlyExitNonZero(in stmt: CStmt) -> Set<String> {
        guard case .ifStmt(let cond, let thenBranch, let elseB, _) = stmt else { return [] }
        guard definitelyReturns(thenBranch), elseB == nil else { return [] }
        var out = Set<String>()
        for (vn, effOp) in comparisons(in: cond) where effOp == "==" || effOp == "<=" {
            out.insert(vn)
        }
        return out
    }

    /// Whether a `>=` guard's bound is provably positive (e.g. `n >= 1` proves
    /// `n` non-zero in the then branch; `n >= 0` does not).
    private func positiveLowerBound(_ varName: String, in cond: CExpr) -> Bool {
        guard let bound = lowerBoundExpr(varName, in: cond) else { return false }
        return (intValue(of: bound) ?? 0) > 0
    }

    /// The expression on the other side of a comparison over `varName`, e.g.
    /// `1` for `n >= 1`; nil when it is not a plain comparison.
    private func lowerBoundExpr(_ varName: String, in cond: CExpr) -> CExpr? {
        switch cond {
        case .binary(let op, let l, let r, _):
            if op == "||" || op == "&&" {
                return lowerBoundExpr(varName, in: l) ?? lowerBoundExpr(varName, in: r)
            }
            if op == "<" || op == "<=" || op == ">" || op == ">=" {
                if simpleIdentifier(l) == varName { return r }
                if simpleIdentifier(r) == varName { return l }
            }
            return nil
        case .paren(let x, _), .cast(let x, _):
            return lowerBoundExpr(varName, in: x)
        default:
            return nil
        }
    }

    // MARK: - Walk 1: taint flow + emission

    private func runFlow(fn: CFunctionDef, facts: FnFacts, ctx: Walk3Context,
                         emit: Bool, reached: Bool) -> FlowResult {
        var result = FlowResult()
        var tainted = Set<String>()
        var roots: [String: String] = [:]
        let entry = isEntrylike(fn)
        for (i, p) in fn.params.enumerated() {
            guard let n = p.name, !n.isEmpty else { continue }
            if entry || (ctx.taintedParam[fn.name] ?? []).contains(i) {
                tainted.insert(n)
                roots[n] = "parameter \(n)"
            }
        }

        let initialBounds = earlyExitBounded(in: fn.body)
        flowStmt(fn.body, fn: fn, facts: facts, ctx: ctx, emit: emit, reached: reached,
                 bounded: initialBounds, loop: nil, tainted: &tainted, roots: &roots,
                 result: &result)
        return result
    }

    private func isEntrylike(_ fn: CFunctionDef) -> Bool {
        if fn.name == "main" { return true }
        for p in fn.params {
            if let n = p.name, n == "argc" || n == "argv" { return true }
        }
        return false
    }

    private func flowStmt(_ stmt: CStmt, fn: CFunctionDef, facts: FnFacts, ctx: Walk3Context,
                          emit: Bool, reached: Bool, bounded: Set<String>, loop: LoopFact?,
                          tainted: inout Set<String>, roots: inout [String: String],
                          result: inout FlowResult) {
        switch stmt {
        case .block(let arr):
            var acc = bounded
            for s in arr {
                acc.formUnion(earlyExitBounded(in: s))
                flowStmt(s, fn: fn, facts: facts, ctx: ctx, emit: emit, reached: reached,
                         bounded: acc, loop: loop, tainted: &tainted, roots: &roots,
                         result: &result)
            }
        case .expr(let e):
            flowExpr(e, fn: fn, facts: facts, ctx: ctx, emit: emit, reached: reached,
                     bounded: bounded, loop: loop, bare: true,
                     tainted: &tainted, roots: &roots, result: &result)
        case .declaration(let d):
            if case .variable(_, let name, let initExpr) = d.kind {
                if let initializer = initExpr {
                    flowExpr(initializer, fn: fn, facts: facts, ctx: ctx, emit: emit, reached: reached,
                             bounded: bounded, loop: loop, bare: false,
                             tainted: &tainted, roots: &roots, result: &result)
                    if exprTainted(initializer, tainted: tainted, ctx: ctx), !name.isEmpty {
                        tainted.insert(name)
                        roots[name] = rootLabel(of: initializer, tainted: tainted, roots: roots,
                                                ctx: ctx) ?? "input"
                    }
                }
            }
        case .ifStmt(let cond, let thenBranch, let elseBranch, _):
            flowExpr(cond, fn: fn, facts: facts, ctx: ctx, emit: emit, reached: reached,
                     bounded: bounded, loop: loop, bare: false,
                     tainted: &tainted, roots: &roots, result: &result)
            var thenBounded = bounded
            for (varName, effOp) in comparisons(in: cond) where effOp == "<" || effOp == "<=" {
                thenBounded.insert(varName)
            }
            flowStmt(thenBranch, fn: fn, facts: facts, ctx: ctx, emit: emit, reached: reached,
                     bounded: thenBounded, loop: loop, tainted: &tainted, roots: &roots,
                     result: &result)
            if let elseBranch = elseBranch {
                flowStmt(elseBranch, fn: fn, facts: facts, ctx: ctx, emit: emit, reached: reached,
                         bounded: bounded, loop: loop, tainted: &tainted, roots: &roots,
                         result: &result)
            }
        case .whileStmt(let cond, let body, let off):
            flowExpr(cond, fn: fn, facts: facts, ctx: ctx, emit: emit, reached: reached,
                     bounded: bounded, loop: loop, bare: false,
                     tainted: &tainted, roots: &roots, result: &result)
            var bodyBounded = bounded
            for (varName, effOp) in comparisons(in: cond) where effOp == "<" || effOp == "<=" {
                bodyBounded.insert(varName)
            }
            flowStmt(body, fn: fn, facts: facts, ctx: ctx, emit: emit, reached: reached,
                     bounded: bodyBounded, loop: loop, tainted: &tainted, roots: &roots,
                     result: &result)
            checkWhileMutation(cond: cond, body: body, fn: fn, emit: emit, reached: reached,
                               offset: off, result: &result)
        case .doWhileStmt(let body, let cond, _):
            flowStmt(body, fn: fn, facts: facts, ctx: ctx, emit: emit, reached: reached,
                     bounded: bounded, loop: loop, tainted: &tainted, roots: &roots,
                     result: &result)
            flowExpr(cond, fn: fn, facts: facts, ctx: ctx, emit: emit, reached: reached,
                     bounded: bounded, loop: loop, bare: false,
                     tainted: &tainted, roots: &roots, result: &result)
        case .forStmt(let initS, let cond, let incr, let body, _):
            if let initS = initS {
                flowStmt(initS, fn: fn, facts: facts, ctx: ctx, emit: emit, reached: reached,
                         bounded: bounded, loop: loop, tainted: &tainted, roots: &roots,
                         result: &result)
            }
            let loopFact = self.loopFact(for: cond, init: initS, facts: facts)
            if let cond = cond {
                flowExpr(cond, fn: fn, facts: facts, ctx: ctx, emit: emit, reached: reached,
                         bounded: bounded, loop: loopFact, bare: false,
                         tainted: &tainted, roots: &roots, result: &result)
            }
            checkForMutation(cond: cond, incr: incr, body: body, fn: fn, emit: emit,
                             reached: reached, result: &result)
            flowStmt(body, fn: fn, facts: facts, ctx: ctx, emit: emit, reached: reached,
                     bounded: bounded, loop: loopFact, tainted: &tainted, roots: &roots,
                     result: &result)
            if let incr = incr {
                flowExpr(incr, fn: fn, facts: facts, ctx: ctx, emit: emit, reached: reached,
                         bounded: bounded, loop: loopFact, bare: false,
                         tainted: &tainted, roots: &roots, result: &result)
            }
        case .switchStmt(_, let cases, _):
            for c in cases {
                for s in c.body {
                    flowStmt(s, fn: fn, facts: facts, ctx: ctx, emit: emit, reached: reached,
                             bounded: bounded, loop: loop, tainted: &tainted, roots: &roots,
                             result: &result)
                }
            }
        case .returnStmt(let e, _):
            if let e = e {
                if exprTainted(e, tainted: tainted, ctx: ctx) { result.returnsTainted = true }
                flowExpr(e, fn: fn, facts: facts, ctx: ctx, emit: emit, reached: reached,
                         bounded: bounded, loop: loop, bare: false,
                         tainted: &tainted, roots: &roots, result: &result)
            }
        case .labeledStmt(_, let s, _):
            flowStmt(s, fn: fn, facts: facts, ctx: ctx, emit: emit, reached: reached,
                     bounded: bounded, loop: loop, tainted: &tainted, roots: &roots,
                     result: &result)
        default:
            break
        }
    }

    private func flowExpr(_ e: CExpr, fn: CFunctionDef, facts: FnFacts, ctx: Walk3Context,
                          emit: Bool, reached: Bool, bounded: Set<String>, loop: LoopFact?,
                          bare: Bool, tainted: inout Set<String>, roots: inout [String: String],
                          result: inout FlowResult) {
        switch e {
        case .call(let callee, let args, let offset):
            handleCall(callee: callee, args: args, offset: offset, fn: fn,
                       ctx: ctx, tainted: &tainted, roots: &roots, result: &result)
            for a in args {
                flowExpr(a, fn: fn, facts: facts, ctx: ctx, emit: emit, reached: reached,
                         bounded: bounded, loop: loop, bare: false,
                         tainted: &tainted, roots: &roots, result: &result)
            }
        case .assign(_, let lhs, let rhs, _):
            if exprTainted(rhs, tainted: tainted, ctx: ctx), let name = simpleIdentifier(lhs) {
                tainted.insert(name)
                roots[name] = rootLabel(of: rhs, tainted: tainted, roots: roots, ctx: ctx)
                    ?? "input"
            }
            flowExpr(lhs, fn: fn, facts: facts, ctx: ctx, emit: emit, reached: reached,
                     bounded: bounded, loop: loop, bare: false,
                     tainted: &tainted, roots: &roots, result: &result)
            flowExpr(rhs, fn: fn, facts: facts, ctx: ctx, emit: emit, reached: reached,
                     bounded: bounded, loop: loop, bare: false,
                     tainted: &tainted, roots: &roots, result: &result)
        case .index(let base, let idx, let offset):
            checkIndexAccess(base: base, index: idx, offset: offset, fn: fn, facts: facts,
                             bounded: bounded, loop: loop, emit: emit, reached: reached,
                             tainted: tainted, roots: roots, ctx: ctx, result: &result)
            flowExpr(base, fn: fn, facts: facts, ctx: ctx, emit: emit, reached: reached,
                     bounded: bounded, loop: loop, bare: false,
                     tainted: &tainted, roots: &roots, result: &result)
            flowExpr(idx, fn: fn, facts: facts, ctx: ctx, emit: emit, reached: reached,
                     bounded: bounded, loop: loop, bare: false,
                     tainted: &tainted, roots: &roots, result: &result)
        case .unary(_, let operand, _), .cast(let operand, _), .paren(let operand, _):
            flowExpr(operand, fn: fn, facts: facts, ctx: ctx, emit: emit, reached: reached,
                     bounded: bounded, loop: loop, bare: false,
                     tainted: &tainted, roots: &roots, result: &result)
        case .binary(_, let l, let r, _), .comma(let l, let r, _):
            flowExpr(l, fn: fn, facts: facts, ctx: ctx, emit: emit, reached: reached,
                     bounded: bounded, loop: loop, bare: false,
                     tainted: &tainted, roots: &roots, result: &result)
            flowExpr(r, fn: fn, facts: facts, ctx: ctx, emit: emit, reached: reached,
                     bounded: bounded, loop: loop, bare: false,
                     tainted: &tainted, roots: &roots, result: &result)
        case .ternary(let c, let t, let f, _):
            flowExpr(c, fn: fn, facts: facts, ctx: ctx, emit: emit, reached: reached,
                     bounded: bounded, loop: loop, bare: false,
                     tainted: &tainted, roots: &roots, result: &result)
            flowExpr(t, fn: fn, facts: facts, ctx: ctx, emit: emit, reached: reached,
                     bounded: bounded, loop: loop, bare: false,
                     tainted: &tainted, roots: &roots, result: &result)
            flowExpr(f, fn: fn, facts: facts, ctx: ctx, emit: emit, reached: reached,
                     bounded: bounded, loop: loop, bare: false,
                     tainted: &tainted, roots: &roots, result: &result)
        case .member(let base, _, _, _):
            flowExpr(base, fn: fn, facts: facts, ctx: ctx, emit: emit, reached: reached,
                     bounded: bounded, loop: loop, bare: false,
                     tainted: &tainted, roots: &roots, result: &result)
        case .arrayInit(let elements, _):
            for el in elements {
                flowExpr(el, fn: fn, facts: facts, ctx: ctx, emit: emit, reached: reached,
                         bounded: bounded, loop: loop, bare: false,
                         tainted: &tainted, roots: &roots, result: &result)
            }
        case .newExpr(_, let args, _):
            for a in args {
                flowExpr(a, fn: fn, facts: facts, ctx: ctx, emit: emit, reached: reached,
                         bounded: bounded, loop: loop, bare: false,
                         tainted: &tainted, roots: &roots, result: &result)
            }
        default:
            break
        }
    }

    // MARK: - Call handling (sources + boundary propagation)

    private func handleCall(callee: CExpr, args: [CExpr], offset: Int, fn: CFunctionDef,
                            ctx: Walk3Context, tainted: inout Set<String>,
                            roots: inout [String: String], result: inout FlowResult) {
        guard let name = calleeName(callee) else { return }
        if astFns[name] != nil {
            var perArg: [Bool] = []
            for a in args {
                perArg.append(exprTainted(a, tainted: tainted, ctx: ctx))
            }
            result.calls.append((name, perArg))
            return
        }

        if Self.writeThroughFirstArgSources.contains(name), let target = args.first.flatMap(simpleIdentifier) {
            tainted.insert(target)
            roots[target] = "\(name) source"
        }
        if Self.scanfFamily.contains(name) {
            for a in args {
                if case .unary("&", let operand, _) = a, let target = simpleIdentifier(operand) {
                    tainted.insert(target)
                    roots[target] = "\(name) source"
                }
            }
        }
    }

    // MARK: - Walk 2: bounds and index access rules

    private func checkIndexAccess(base: CExpr, index: CExpr, offset: Int, fn: CFunctionDef,
                                  facts: FnFacts, bounded: Set<String>, loop: LoopFact?,
                                  emit: Bool, reached: Bool, tainted: Set<String>,
                                  roots: [String: String], ctx: Walk3Context,
                                  result: inout FlowResult) {
        guard emit else { return }
        guard let baseName = simpleIdentifier(base) else { return }
        guard let capacity = facts.capacities[baseName] else { return }

        // Constant index >= capacity: always out of bounds.
        if let c = intValue(of: index) {
            if c >= capacity {
                emitFinding(&result, function: fn.name, offset: offset,
                            category: "Array Index Out of Bounds", severity: .high,
                            message: "'\(baseName)[\(c)]' indexes past the end of a \(capacity)-element array.",
                            taint: nil, reachable: reached)
            }
            return
        }

        // Loop-variable index: the loop bound decides (Loop Off-by-One below).
        // A safe (`i < n`) header bounds the variable, so no Unvalidated rule.
        if let lf = loop, let idxName = simpleIdentifier(index), idxName == lf.varName {
            if let cap = capacity as Int?, let upper = lf.upperConst {
                let crosses = lf.inclusive ? upper >= cap : upper > cap
                if crosses {
                    emitFinding(&result, function: fn.name, offset: offset,
                                category: "Loop Off-by-One", severity: .high,
                                message: "Loop variable '\(idxName)' reaches '\(upper)' while '\(baseName)' has only \(cap) elements.",
                                taint: nil, reachable: reached)
                }
            }
            return
        }

        // Tainted index without a proven bound.
        if exprTainted(index, tainted: tainted, ctx: ctx), let idxName = simpleIdentifier(index),
           !bounded.contains(idxName), loop?.varName != idxName {
            let root = rootLabel(of: index, tainted: tainted, roots: roots, ctx: ctx)
            emitFinding(&result, function: fn.name, offset: offset,
                        category: "Unvalidated Array Index", severity: .medium,
                        message: "Tainted index '\(idxName)' used to access '\(baseName)' without a bounds check.",
                        taint: taintPath(root: root, variable: idxName), reachable: reached)
        }
    }

    /// `for (...; v.size() cycle ...) { v.push_back(...) }` — mutating a
    /// container while iterating it destabilizes the loop bound.
    private func checkForMutation(cond: CExpr?, incr: CExpr?, body: CStmt, fn: CFunctionDef,
                                  emit: Bool, reached: Bool, result: inout FlowResult) {
        guard emit, let cond = cond else { return }
        guard let sizeBase = sizeBoundBase(in: cond) else { return }
        if body.containsMutatorCall(on: sizeBase) {
            emitFinding(&result, function: fn.name, offset: cond.offset,
                        category: "Array Mutation During Iteration", severity: .medium,
                        message: "Container '\(sizeBase)' is mutated while being iterated; the loop bound '\(sizeBase).size()' is unstable.",
                        taint: nil, reachable: reached)
        }
    }

    private func checkWhileMutation(cond: CExpr, body: CStmt, fn: CFunctionDef,
                                    emit: Bool, reached: Bool, offset: Int,
                                    result: inout FlowResult) {
        guard emit else { return }
        guard let sizeBase = sizeBoundBase(in: cond) else { return }
        if body.containsMutatorCall(on: sizeBase) {
            emitFinding(&result, function: fn.name, offset: offset,
                        category: "Array Mutation During Iteration", severity: .medium,
                        message: "Container '\(sizeBase)' is mutated while being iterated; the loop bound '\(sizeBase).size()' is unstable.",
                        taint: nil, reachable: reached)
        }
    }

    // MARK: - Walk 2 helpers

    /// Bounds established by an early-exit guard at the start of a statement,
    /// e.g. `if (i >= n) return;` bounds `i` on the fallthrough path.
    private func earlyExitBounded(in stmt: CStmt) -> Set<String> {
        guard case .ifStmt(let cond, let thenBranch, let elseB, _) = stmt else { return [] }
        guard definitelyReturns(thenBranch), elseB == nil else { return [] }
        var out = Set<String>()
        for (vn, effOp) in comparisons(in: cond) where effOp == ">" || effOp == ">=" {
            out.insert(vn)
        }
        return out
    }

    /// Extracts `(variable, effectiveOp)` pairs from a condition, e.g.
    /// `i < n` -> ("i","<"); `n > i` -> ("i","<"). Only plain comparisons and
    /// `||`/`&&` chains of them.
    private func comparisons(in cond: CExpr) -> [(String, String)] {
        var out: [(String, String)] = []
        switch cond {
        case .binary(let op, let l, let r, _):
            if op == "||" || op == "&&" {
                out.append(contentsOf: comparisons(in: l))
                out.append(contentsOf: comparisons(in: r))
                return out
            }
            switch (l, r) {
            case (.identifier(let vn, _), _):
                out.append((vn, op))
            case (_, .identifier(let vn, _)):
                let flipped: String
                switch op {
                case "<": flipped = ">"
                case "<=": flipped = ">="
                case ">": flipped = "<"
                case ">=": flipped = "<="
                default: flipped = op
                }
                out.append((vn, flipped))
            default:
                break
            }
        case .paren(let x, _), .cast(let x, _):
            return comparisons(in: x)
        default:
            break
        }
        return out
    }

    private func definitelyReturns(_ stmt: CStmt) -> Bool {
        switch stmt {
        case .returnStmt:
            return true
        case .block(let arr):
            return arr.last.map(definitelyReturns) ?? false
        case .ifStmt(_, let t, let e, _):
            return definitelyReturns(t) && e.map(definitelyReturns) ?? false
        case .labeledStmt(_, let s, _):
            return definitelyReturns(s)
        default:
            return false
        }
    }

    /// Loop-head facts for a `for` loop: the loop variable and, when the exit
    /// bound is a constant, its value and inclusivity.
    private func loopFact(for cond: CExpr?, init initS: CStmt?, facts: FnFacts) -> LoopFact? {
        guard let cond = cond else { return nil }
        guard case .binary(let op, let l, let r, _) = cond else { return nil }
        guard let varName = simpleIdentifier(l) else { return nil }
        let inclusive = op == "<=" || op == ">="
        let upper: Int?
        if op == "<" || op == "<=" {
            upper = intValue(of: r)
        } else {
            upper = intValue(of: l)
        }
        return LoopFact(varName: varName, upperConst: upper, inclusive: inclusive)
    }

    /// The base of a `.size()` / `.length()` bounding expression in a loop
    /// condition, e.g. `v.size()` in `i < v.size()` -> "v".
    private func sizeBoundBase(in cond: CExpr) -> String? {
        switch cond {
        case .binary(_, let l, let r, _):
            return sizeBase(of: l) ?? sizeBase(of: r)
        case .paren(let x, _), .cast(let x, _):
            return sizeBoundBase(in: x)
        default:
            return nil
        }
    }

    private func sizeBase(of e: CExpr) -> String? {
        switch e {
        case .call(let callee, _, _):
            guard case .member(let base, "size", _, _) = callee else { return nil }
            return simpleIdentifier(base)
        case .paren(let x, _), .cast(let x, _):
            return sizeBase(of: x)
        case .binary(_, let l, let r, _):
            return sizeBase(of: l) ?? sizeBase(of: r)
        default:
            return nil
        }
    }

    /// Constant-integer value of an index/bound expression (literals plus
    /// simple constant arithmetic), or nil.
    private func intValue(of e: CExpr) -> Int? {
        switch e {
        case .integerLiteral(let v, _):
            return Int(v)
        case .paren(let x, _), .cast(let x, _):
            return intValue(of: x)
        case .unary(let op, let x, _):
            guard let c = intValue(of: x) else { return nil }
            switch op {
            case "+": return c
            case "-": return -c
            default: return nil
            }
        case .binary(let op, let l, let r, _):
            guard let a = intValue(of: l), let b = intValue(of: r) else { return nil }
            switch op {
            case "+": return a + b
            case "-": return a - b
            case "*": return a * b
            case "/": return b == 0 ? nil : a / b
            default: return nil
            }
        default:
            return nil
        }
    }

    // MARK: - Structural facts

    private func fnFacts(for fn: CFunctionDef) -> FnFacts {
        var facts = FnFacts()
        walkStructurally(fn.body) { stmt in
            if case .declaration(let d) = stmt,
               case .variable(let typeName, let name, let initExpr) = d.kind {
                if let cap = arrayCapacity(typeName: typeName, initExpr: initExpr),
                   !name.isEmpty {
                    facts.capacities[name] = cap
                }
            }
        }
        return facts
    }

    /// `char buf[32];` -> 32 and `int a[] = {1,2,3};` -> 3.
    private func arrayCapacity(typeName: String?, initExpr: CExpr?) -> Int? {
        if let initExpr = initExpr, case .arrayInit(let elements, _) = initExpr {
            return elements.count
        }
        guard let t = typeName else { return nil }
        let pattern = "\\[(\\d+)\\]"
        guard let range = t.range(of: pattern, options: .regularExpression) else { return nil }
        let digits = t[range].dropFirst().dropLast()
        return Int(digits)
    }

    private func walkStructurally(_ stmt: CStmt, _ visit: (CStmt) -> Void) {
        visit(stmt)
        switch stmt {
        case .block(let arr):
            for s in arr { walkStructurally(s, visit) }
        case .ifStmt(_, let t, let e, _):
            walkStructurally(t, visit)
            if let e = e { walkStructurally(e, visit) }
        case .whileStmt(_, let b, _), .doWhileStmt(let b, _, _):
            walkStructurally(b, visit)
        case .forStmt(let i, _, _, let b, _):
            if let i = i { walkStructurally(i, visit) }
            walkStructurally(b, visit)
        case .switchStmt(_, let cases, _):
            for c in cases { for s in c.body { walkStructurally(s, visit) } }
        case .labeledStmt(_, let s, _):
            walkStructurally(s, visit)
        default:
            break
        }
    }

    private func callees(in body: CStmt) -> Set<String> {
        var set = Set<String>()
        collectCallees(body, into: &set)
        return set
    }

    private func collectCallees(_ stmt: CStmt, into set: inout Set<String>) {
        switch stmt {
        case .block(let arr):
            for s in arr { collectCallees(s, into: &set) }
        case .expr(let e):
            collectExprCallees(e, into: &set)
        case .declaration(let d):
            if case .variable(_, _, let initExpr?) = d.kind {
                collectExprCallees(initExpr, into: &set)
            }
        case .ifStmt(_, let t, let e, _):
            collectCallees(t, into: &set)
            if let e = e { collectCallees(e, into: &set) }
        case .whileStmt(_, let b, _), .doWhileStmt(let b, _, _):
            collectCallees(b, into: &set)
        case .forStmt(let i, _, _, let b, _):
            if let i = i { collectCallees(i, into: &set) }
            collectCallees(b, into: &set)
        case .switchStmt(_, let cases, _):
            for c in cases { for s in c.body { collectCallees(s, into: &set) } }
        case .labeledStmt(_, let s, _):
            collectCallees(s, into: &set)
        default:
            break
        }
    }

    private func collectExprCallees(_ e: CExpr, into set: inout Set<String>) {
        switch e {
        case .call(let callee, let args, _):
            if let name = calleeName(callee), astFns[name] != nil { set.insert(name) }
            for a in args { collectExprCallees(a, into: &set) }
        case .assign(_, let l, let r, _):
            collectExprCallees(l, into: &set)
            collectExprCallees(r, into: &set)
        case .unary(_, let o, _), .cast(let o, _), .paren(let o, _):
            collectExprCallees(o, into: &set)
        case .binary(_, let l, let r, _), .comma(let l, let r, _):
            collectExprCallees(l, into: &set)
            collectExprCallees(r, into: &set)
        case .ternary(let c, let t, let f, _):
            collectExprCallees(c, into: &set)
            collectExprCallees(t, into: &set)
            collectExprCallees(f, into: &set)
        case .member(let b, _, _, _):
            collectExprCallees(b, into: &set)
        case .index(let b, let i, _):
            collectExprCallees(b, into: &set)
            collectExprCallees(i, into: &set)
        case .arrayInit(let arr, _):
            for a in arr { collectExprCallees(a, into: &set) }
        case .newExpr(_, let args, _):
            for a in args { collectExprCallees(a, into: &set) }
        default:
            break
        }
    }

    // MARK: - Expression helpers

    private func calleeName(_ callee: CExpr) -> String? {
        switch callee {
        case .identifier(let n, _): return n
        case .member(_, let m, _, _): return m
        case .call(let inner, _, _): return calleeName(inner)
        default: return nil
        }
    }

    /// The variable written by `&var`, `(&var)`, `(char *)&var`, plain `var`,
    /// `var.member`, or `var[..]` (an array base); nil otherwise.
    private func simpleIdentifier(_ e: CExpr) -> String? {
        switch e {
        case .identifier(let n, _): return n
        case .paren(let x, _), .cast(let x, _): return simpleIdentifier(x)
        case .unary(let op, let x, _): return op == "&" ? simpleIdentifier(x) : nil
        case .member(let b, _, _, _): return simpleIdentifier(b)
        case .index(let b, _, _): return simpleIdentifier(b)
        default: return nil
        }
    }

    private func exprTainted(_ e: CExpr, tainted: Set<String>, ctx: Walk3Context) -> Bool {
        switch e {
        case .identifier(let n, _):
            return tainted.contains(n)
        case .call(let callee, _, _):
            if let name = calleeName(callee) {
                if Self.returnTaintingSources.contains(name) { return true }
                if taintReturning.contains(name) { return true }
                if ctx.taintReturningFns.contains(name) { return true }
            }
            return false
        case .assign(_, _, let r, _):
            return exprTainted(r, tainted: tainted, ctx: ctx)
        case .binary(_, let l, let r, _), .comma(let l, let r, _):
            return exprTainted(l, tainted: tainted, ctx: ctx)
                || exprTainted(r, tainted: tainted, ctx: ctx)
        case .ternary(let c, let t, let f, _):
            return exprTainted(c, tainted: tainted, ctx: ctx)
                || exprTainted(t, tainted: tainted, ctx: ctx)
                || exprTainted(f, tainted: tainted, ctx: ctx)
        case .unary(_, let o, _), .cast(let o, _), .paren(let o, _):
            return exprTainted(o, tainted: tainted, ctx: ctx)
        case .member(let b, _, _, _):
            return exprTainted(b, tainted: tainted, ctx: ctx)
        case .index(let b, let i, _):
            return exprTainted(b, tainted: tainted, ctx: ctx)
                || exprTainted(i, tainted: tainted, ctx: ctx)
        case .arrayInit(let arr, _):
            return arr.contains { exprTainted($0, tainted: tainted, ctx: ctx) }
        default:
            return false
        }
    }

    private func rootLabel(of e: CExpr, tainted: Set<String>, roots: [String: String],
                           ctx: Walk3Context) -> String? {
        switch e {
        case .identifier(let n, _):
            return roots[n] ?? (tainted.contains(n) ? n : nil)
        case .call(let callee, _, _):
            if let name = calleeName(callee) {
                if Self.returnTaintingSources.contains(name) { return name }
                if taintReturning.contains(name) || ctx.taintReturningFns.contains(name) {
                    return name
                }
            }
            return "input"
        case .assign(_, _, let r, _):
            return rootLabel(of: r, tainted: tainted, roots: roots, ctx: ctx)
        case .binary(_, let l, let r, _), .comma(let l, let r, _):
            return rootLabel(of: l, tainted: tainted, roots: roots, ctx: ctx)
                ?? rootLabel(of: r, tainted: tainted, roots: roots, ctx: ctx)
        case .ternary(let c, let t, let f, _):
            return rootLabel(of: c, tainted: tainted, roots: roots, ctx: ctx)
                ?? rootLabel(of: t, tainted: tainted, roots: roots, ctx: ctx)
                ?? rootLabel(of: f, tainted: tainted, roots: roots, ctx: ctx)
        case .unary(_, let o, _), .cast(let o, _), .paren(let o, _):
            return rootLabel(of: o, tainted: tainted, roots: roots, ctx: ctx)
        case .member(let b, _, _, _):
            return rootLabel(of: b, tainted: tainted, roots: roots, ctx: ctx)
        default:
            return nil
        }
    }

    private func taintPath(root: String?, variable: String) -> String? {
        guard let root = root, !root.isEmpty else { return nil }
        return "\(root) → \(variable)"
    }

    private func emitFinding(_ result: inout FlowResult, function: String, offset: Int,
                             category: String, severity: ScanFinding.Severity,
                             message: String, taint: String?, reachable: Bool) {
        result.candidates.append(CFamilyWalkFinding(function: function, offset: offset,
                                                    category: category, severity: severity,
                                                    message: message, taintPath: taint,
                                                    reachable: reachable))
    }

    // MARK: - Extra source-ordered safety passes

    /// Extremely-valued constant markers: macros and value literals at the
    /// signed/unsigned type boundaries (`INT_MAX`, `LONG_MIN`, `0x7fffffff`, ...).
    private static let extremeMaxNames: Set<String> = [
        "INT_MAX", "LONG_MAX", "LLONG_MAX", "INT64_MAX", "INT32_MAX", "SIZE_MAX",
        "UINT_MAX", "ULONG_MAX", "UINT64_MAX", "UINT32_MAX", "UINT16_MAX",
        "UINT8_MAX", "USHORT_MAX", "CHAR_MAX", "SCHAR_MAX", "SHRT_MAX",
        "INT16_MAX", "INT8_MAX", "INTMAX_MAX",
    ]
    private static let extremeMinNames: Set<String> = [
        "INT_MIN", "LONG_MIN", "LLONG_MIN", "INT64_MIN", "INT32_MIN", "INT16_MIN",
        "INT8_MIN", "SHRT_MIN", "SCHAR_MIN", "INTMAX_MIN",
    ]
    private static let extremeMaxLiterals: Set<String> = [
        "2147483647", "0x7fffffff", "4294967295", "0xffffffff",
        "9223372036854775807", "0x7fffffffffffffff",
    ]
    private static let extremeMinLiterals: Set<String> = [
        "2147483648", "0x80000000", "9223372036854775808", "0x8000000000000000",
    ]

    private enum ExtremeKind: Equatable { case max, min }

    private struct ExtraState: Equatable {
        var nullVars = Set<String>()
        /// Field names holding NULL, keyed by the plain base variable they were
        /// stored through: `n->next = NULL` records `next` under `n`.
        var nullFields: [String: Set<String>] = [:]
        var extremeMax = Set<String>()
        var extremeMin = Set<String>()

        mutating func clear(_ name: String) {
            nullVars.remove(name)
            // Reassigning the base replaces the object, so what was known
            // about its fields no longer applies.
            nullFields.removeValue(forKey: name)
            extremeMax.remove(name)
            extremeMin.remove(name)
        }
    }

    /// Path-sensitive pass emitting, per function:
    ///  - **Null Pointer Dereference**: dereferencing a variable that is NULL
    ///    on at least one path reaching the dereference (`*p`, `p[i]`,
    ///    `p->field`) — the classic `int *ptr = NULL; printf("%d", *ptr);`.
    ///  - **Integer Overflow**: arithmetic on a value that is extreme-constant
    ///    on at least one such path (`max_int = INT_MAX; max_int + 1`).
    ///  - **Return of Local Variable Address**: returning a stack-local array
    ///    (`char localString[] = ...; return localString;`) or `&local`.
    ///
    /// Control flow is followed rather than assumed: branches fork the state,
    /// arms that `return`/`break`/`continue` do not contribute to the join at
    /// their target, and the surviving paths are unioned so a value that is
    /// NULL anywhere is tracked after the join.
    private func extraSafetyFindings(fn: CFunctionDef, reached: Bool) -> [CFamilyWalkFinding] {
        var state = ExtraState()
        var findings: [CFamilyWalkFinding] = []
        let localArrays = stackArrayNames(of: fn)
        let localNames = declaredNames(in: fn.body)
        var exits = FlowExits()
        _ = extraWalk(fn.body, fn: fn, reached: reached, state: &state, findings: &findings,
                      localArrays: localArrays, localNames: localNames, exits: &exits)
        // Loop bodies are walked a second time to cover their back edge, which
        // can re-emit something the first pass already reported.
        var seen = Set<String>()
        return findings.filter { seen.insert("\($0.offset)|\($0.category)").inserted }
    }

    /// Names declared as stack-local arrays (`char buf[10]`, `int a[] = {...}`,
    /// `char s[] = "..."`). Returning these addresses escapes the stack frame.
    private func stackArrayNames(of fn: CFunctionDef) -> Set<String> {
        var out = Set<String>()
        walkStructurally(fn.body) { stmt in
            if case .declaration(let d) = stmt,
               case .variable(let typeName, let name, _) = d.kind, !name.isEmpty,
               let t = typeName, t.contains("[") {
                out.insert(name)
            }
        }
        return out
    }

    /// Every variable name declared anywhere in the body (for `&local` returns).
    private func declaredNames(in stmt: CStmt) -> Set<String> {
        var out = Set<String>()
        walkStructurally(stmt) { s in
            if case .declaration(let d) = s,
               case .variable(_, let name, _) = d.kind, !name.isEmpty {
                out.insert(name)
            }
        }
        return out
    }

    /// Where control goes after a statement. The three non-fall-through
    /// outcomes matter because they join at different points: `break` leaves an
    /// enclosing switch/loop, `continue` feeds the loop's back edge, and
    /// `return`/`goto` reach neither.
    private enum FlowOutcome: Equatable {
        case fellThrough
        case broke
        case continued
        case returned
    }

    /// States captured while walking nested constructs, drained by whichever
    /// switch or loop encloses the `break`/`continue` that produced them.
    private struct FlowExits {
        var breaks: [ExtraState] = []
        var continues: [ExtraState] = []
    }

    private static func union(_ a: ExtraState, _ b: ExtraState) -> ExtraState {
        var r = a
        r.nullVars.formUnion(b.nullVars)
        r.extremeMax.formUnion(b.extremeMax)
        r.extremeMin.formUnion(b.extremeMin)
        for (base, fields) in b.nullFields { r.nullFields[base, default: []].formUnion(fields) }
        return r
    }

    private static func union(_ states: [ExtraState]) -> ExtraState? {
        guard var acc = states.first else { return nil }
        for s in states.dropFirst() { acc = union(acc, s) }
        return acc
    }

    /// Returns how control leaves `stmt`. In addition to the return value,
    /// `exits` accumulates the states carried by `break`/`continue` so the
    /// enclosing construct can join them where they actually land.
    private func extraWalk(_ stmt: CStmt, fn: CFunctionDef, reached: Bool,
                           state: inout ExtraState, findings: inout [CFamilyWalkFinding],
                           localArrays: Set<String>, localNames: Set<String>,
                           exits: inout FlowExits) -> FlowOutcome {
        switch stmt {
        case .block(let arr):
            for s in arr {
                let outcome = extraWalk(s, fn: fn, reached: reached, state: &state,
                                        findings: &findings, localArrays: localArrays,
                                        localNames: localNames, exits: &exits)
                if outcome != .fellThrough { return outcome }
            }
            return .fellThrough
        case .expr(let e):
            detectNullDerefs(in: e, fn: fn, reached: reached, state: state, findings: &findings)
            detectConstantOverflow(in: e, fn: fn, reached: reached, state: state, findings: &findings)
            updateState(from: e, state: &state)
            return .fellThrough
        case .declaration(let d):
            if case .variable(_, let name, let initExpr) = d.kind {
                if let initExpr = initExpr {
                    detectNullDerefs(in: initExpr, fn: fn, reached: reached, state: state, findings: &findings)
                    detectConstantOverflow(in: initExpr, fn: fn, reached: reached, state: state, findings: &findings)
                }
                if let initExpr = initExpr, !name.isEmpty {
                    updateState(rhs: initExpr, for: name, state: &state)
                }
            }
            return .fellThrough
        case .ifStmt(let cond, let thenBranch, let elseBranch, _):
            detectNullDerefs(in: cond, fn: fn, reached: reached, state: state, findings: &findings)
            detectConstantOverflow(in: cond, fn: fn, reached: reached, state: state, findings: &findings)
            updateState(from: cond, state: &state)
            // Each arm starts from the state at the branch, refined by what the
            // condition proves for that arm, and contributes to the join only
            // if control actually falls out the bottom of the arm.
            let entry = state
            var thenState = entry
            refineNullState(cond, whenTrue: true, state: &thenState)
            let thenOutcome = extraWalk(thenBranch, fn: fn, reached: reached, state: &thenState,
                                        findings: &findings, localArrays: localArrays,
                                        localNames: localNames, exits: &exits)
            var elseState = entry
            refineNullState(cond, whenTrue: false, state: &elseState)
            let elseOutcome = elseBranch.map {
                extraWalk($0, fn: fn, reached: reached, state: &elseState, findings: &findings,
                          localArrays: localArrays, localNames: localNames, exits: &exits)
            } ?? .fellThrough
            var falling: [ExtraState] = []
            if thenOutcome == .fellThrough { falling.append(thenState) }
            if elseOutcome == .fellThrough { falling.append(elseState) }
            if let joined = Self.union(falling) {
                state = joined
                return .fellThrough
            }
            return [thenOutcome, elseOutcome].first(where: { $0 != .fellThrough }) ?? .returned
        case .whileStmt(let cond, let body, _):
            detectNullDerefs(in: cond, fn: fn, reached: reached, state: state, findings: &findings)
            detectConstantOverflow(in: cond, fn: fn, reached: reached, state: state, findings: &findings)
            updateState(from: cond, state: &state)
            let loopEntry = state
            var local = FlowExits()
            let bodyExit = walkLoopBody(cond: cond, body: body, entry: loopEntry, fn: fn,
                                        reached: reached, findings: &findings,
                                        localArrays: localArrays, localNames: localNames,
                                        exits: &local)
            // The loop may run zero times, so the state at the top joins back in.
            state = Self.union([loopEntry].compactMap { $0 } + [bodyExit].compactMap { $0 }
                               + local.breaks) ?? loopEntry
            return .fellThrough
        case .doWhileStmt(let body, let cond, _):
            let loopEntry = state
            var local = FlowExits()
            // The condition has not been evaluated on the first pass, so no
            // refinement narrows the entry state for the body.
            var after = walkLoopBody(cond: nil, body: body, entry: loopEntry, fn: fn,
                                     reached: reached, findings: &findings,
                                     localArrays: localArrays, localNames: localNames,
                                     exits: &local) ?? loopEntry
            detectNullDerefs(in: cond, fn: fn, reached: reached, state: after, findings: &findings)
            detectConstantOverflow(in: cond, fn: fn, reached: reached, state: after, findings: &findings)
            updateState(from: cond, state: &after)
            state = Self.union([after] + local.breaks) ?? after
            return .fellThrough
        case .forStmt(let initS, let cond, let incr, let body, _):
            if let initS = initS {
                let outcome = extraWalk(initS, fn: fn, reached: reached, state: &state,
                                        findings: &findings, localArrays: localArrays,
                                        localNames: localNames, exits: &exits)
                if outcome != .fellThrough { return outcome }
            }
            if let cond = cond {
                detectNullDerefs(in: cond, fn: fn, reached: reached, state: state, findings: &findings)
                detectConstantOverflow(in: cond, fn: fn, reached: reached, state: state, findings: &findings)
                updateState(from: cond, state: &state)
            }
            let loopEntry = state
            var local = FlowExits()
            var bodyExit = walkLoopBody(cond: cond, body: body, entry: loopEntry, fn: fn,
                                        reached: reached, findings: &findings,
                                        localArrays: localArrays, localNames: localNames,
                                        exits: &local)
            // The increment runs on the back edge, before the next condition test.
            if let incr = incr, var s = bodyExit {
                detectNullDerefs(in: incr, fn: fn, reached: reached, state: s, findings: &findings)
                detectConstantOverflow(in: incr, fn: fn, reached: reached, state: s, findings: &findings)
                updateState(from: incr, state: &s)
                bodyExit = s
            }
            state = Self.union([loopEntry].compactMap { $0 } + [bodyExit].compactMap { $0 }
                               + local.breaks) ?? loopEntry
            return .fellThrough
        case .switchStmt(_, let cases, _):
            // Every arm starts from the state at the switch rather than from
            // wherever the previous arm happened to end, and the states that
            // survive to the statement after the switch are unioned together.
            let entry = state
            var local = FlowExits()
            var arms: [ExtraState] = []
            let hasDefault = cases.contains(where: { $0.isDefault })
            for c in cases {
                let breaksBefore = local.breaks.count
                var armState = entry
                var armOutcome = FlowOutcome.fellThrough
                for s in c.body {
                    armOutcome = extraWalk(s, fn: fn, reached: reached, state: &armState,
                                           findings: &findings, localArrays: localArrays,
                                           localNames: localNames, exits: &local)
                    if armOutcome != .fellThrough { break }
                }
                // A `break` already recorded its state; only a fall-through
                // arm still carries one that has not been captured.
                if armOutcome == .fellThrough { arms.append(armState) }
                arms.append(contentsOf: local.breaks.dropFirst(breaksBefore))
                local.breaks.removeSubrange(breaksBefore...)
            }
            if !hasDefault { arms.append(entry) }
            state = Self.union(arms) ?? entry
            // `continue` inside a switch still belongs to the enclosing loop.
            exits.continues.append(contentsOf: local.continues)
            return .fellThrough

        case .returnStmt(let e, let off):
            if let e = e {
                detectNullDerefs(in: e, fn: fn, reached: reached, state: state, findings: &findings)
                detectConstantOverflow(in: e, fn: fn, reached: reached, state: state, findings: &findings)
                if returnsStackAddress(e, localArrays: localArrays, localNames: localNames) {
                    findings.append(CFamilyWalkFinding(function: fn.name, offset: off,
                                                       category: "Return of Local Variable Address",
                                                       severity: .high,
                                                       message: "Function returns the address of a stack-local variable; the storage is reclaimed when the function returns (use-after-scope).",
                                                       taintPath: nil, reachable: reached))
                }
            }
            return .returned
        case .breakStmt:
            exits.breaks.append(state)
            return .broke
        case .continueStmt:
            exits.continues.append(state)
            return .continued
        case .gotoStmt:
            return .returned
        case .labeledStmt(_, let s, _):
            return extraWalk(s, fn: fn, reached: reached, state: &state, findings: &findings,
                             localArrays: localArrays, localNames: localNames, exits: &exits)
        default:
            return .fellThrough
        }
    }

    /// Walks a loop body, then walks it again from the back-edge join when the
    /// first pass taught the loop-top state anything new, so dereferences only
    /// reachable from the second iteration onward are still seen. Returns the
    /// state after the last pass (nil when the body left the loop outright).
    private func walkLoopBody(cond: CExpr?, body: CStmt, entry: ExtraState,
                              fn: CFunctionDef, reached: Bool,
                              findings: inout [CFamilyWalkFinding],
                              localArrays: Set<String>, localNames: Set<String>,
                              exits: inout FlowExits) -> ExtraState? {
        var bodyState = entry
        if let cond = cond { refineNullState(cond, whenTrue: true, state: &bodyState) }
        let outcome = extraWalk(body, fn: fn, reached: reached, state: &bodyState,
                                findings: &findings, localArrays: localArrays,
                                localNames: localNames, exits: &exits)
        guard outcome == .fellThrough || outcome == .continued else { return nil }
        var top = Self.union([entry, bodyState] + exits.continues) ?? entry
        if let cond = cond { refineNullState(cond, whenTrue: true, state: &top) }
        exits.continues.removeAll()
        if top != entry {
            var second = top
            let secondOutcome = extraWalk(body, fn: fn, reached: reached, state: &second,
                                          findings: &findings, localArrays: localArrays,
                                          localNames: localNames, exits: &exits)
            if secondOutcome == .fellThrough || secondOutcome == .continued { bodyState = second }
            exits.continues.removeAll()
        }
        return bodyState
    }

    /// Narrows the tracked nullness of pointers using a branch condition.
    ///
    /// Deliberately **one-directional**: it only ever proves a pointer is
    /// *not* NULL (removing it from `nullVars`). Proving the opposite — that a
    /// branch establishes NULL — would need the other arm to be proven
    /// unreachable before the join, which this pass does not track; folding
    /// such an assumption into the union afterwards would report dereferences
    /// on paths that are actually guarded (e.g. `if (p == NULL) exit(1);`).
    private func refineNullState(_ cond: CExpr, whenTrue: Bool, state: inout ExtraState) {
        switch unwrap(cond) {
        case .binary(let op, let lhs, let rhs, _):
            switch op {
            case "==":
                if !whenTrue { proveNonNull(lhs, other: rhs, state: &state)
                               proveNonNull(rhs, other: lhs, state: &state) }
            case "!=":
                if whenTrue { proveNonNull(lhs, other: rhs, state: &state)
                              proveNonNull(rhs, other: lhs, state: &state) }
            case "&&":
                // Both conjuncts hold only when the whole condition is true.
                if whenTrue {
                    refineNullState(lhs, whenTrue: true, state: &state)
                    refineNullState(rhs, whenTrue: true, state: &state)
                }
            case "||":
                // Both disjuncts fail only when the whole condition is false.
                if !whenTrue {
                    refineNullState(lhs, whenTrue: false, state: &state)
                    refineNullState(rhs, whenTrue: false, state: &state)
                }
            default:
                break
            }
        case .unary(let op, let operand, _):
            if op == "!" { refineNullState(operand, whenTrue: !whenTrue, state: &state) }
        case .identifier(let name, _):
            // `if (p)` / `while (p)` — a true test rules NULL out.
            if whenTrue && !name.isEmpty && name != "NULL" { state.nullVars.remove(name) }
        default:
            break
        }
    }

    private func proveNonNull(_ expr: CExpr, other: CExpr, state: inout ExtraState) {
        guard isNullConstant(other), let name = simpleIdentifier(expr), !name.isEmpty else { return }
        state.nullVars.remove(name)
    }

    /// Throws away the value a variable had and applies its new value's
    /// classification to the tracking state (NULL / extreme-constant / other).
    private func updateState(from e: CExpr, state: inout ExtraState) {
        guard case .assign(_, let lhs, let rhs, _) = e else { return }
        switch unwrap(lhs) {
        case .identifier(let name, _):
            updateState(rhs: rhs, for: name, state: &state)
        case .member(let base, let field, _, _):
            // `n->next = NULL` nulls the field, not `n`. Collapsing this to
            // the base (as read-side flow does) would mark the whole object
            // NULL and report unrelated members of it.
            guard case .identifier(let owner, _) = unwrap(base), !owner.isEmpty else { break }
            var fields = state.nullFields[owner] ?? []
            fields.remove(field)
            if isNullConstant(rhs) { fields.insert(field) }
            if fields.isEmpty { state.nullFields.removeValue(forKey: owner) }
            else { state.nullFields[owner] = fields }
        default:
            // `buf[i] = 0` and `*p = 0` store through the pointer; they say
            // nothing about the pointer's own value.
            break
        }
    }

    private func updateState(rhs: CExpr, for name: String, state: inout ExtraState) {
        state.clear(name)
        if isNullConstant(rhs) {
            state.nullVars.insert(name)
        } else if let kind = extremeKind(of: rhs, state: state) {
            if kind == .max { state.extremeMax.insert(name) }
            else { state.extremeMin.insert(name) }
        }
    }

    /// True when the expression is the literal `NULL` or the integer `0`.
    private func isNullConstant(_ e: CExpr) -> Bool {
        switch unwrap(e) {
        case .identifier(let n, _): return n == "NULL"
        case .integerLiteral(let v, _): return v == "0"
        default: return false
        }
    }

    /// Unwraps cast/paren layers (the address-of and deref operators keep their
    /// meaning and are not peeled).
    private func unwrap(_ e: CExpr) -> CExpr {
        switch e {
        case .paren(let x, _), .cast(let x, _): return unwrap(x)
        default: return e
        }
    }

    private func extremeKind(of e: CExpr, state: ExtraState) -> ExtremeKind? {
        switch unwrap(e) {
        case .identifier(let n, _):
            if Self.extremeMaxNames.contains(n) || state.extremeMax.contains(n) { return .max }
            if Self.extremeMinNames.contains(n) || state.extremeMin.contains(n) { return .min }
            return nil
        case .integerLiteral(let v, _):
            if Self.extremeMaxLiterals.contains(v) { return .max }
            if Self.extremeMinLiterals.contains(v) { return .min }
            return nil
        default:
            return nil
        }
    }

    /// NULL-dereference detection: `*p`, `p[i]`, `p->field` where `p` holds NULL.
    private func detectNullDerefs(in e: CExpr, fn: CFunctionDef, reached: Bool,
                                  state: ExtraState, findings: inout [CFamilyWalkFinding]) {
        switch e {
        case .unary(let op, let operand, let off):
            if op == "*", holdsNull(operand, state: state) {
                findings.append(CFamilyWalkFinding(function: fn.name, offset: off,
                                                   category: "Null Pointer Dereference",
                                                   severity: .high,
                                                   message: "Dereference of a pointer that was assigned NULL/0; this crashes or reads from address zero.",
                                                   taintPath: nil, reachable: reached))
            }
            detectNullDerefs(in: operand, fn: fn, reached: reached, state: state, findings: &findings)
        case .index(let base, let idx, let off):
            if holdsNull(base, state: state) {
                findings.append(CFamilyWalkFinding(function: fn.name, offset: off,
                                                   category: "Null Pointer Dereference",
                                                   severity: .high,
                                                   message: "Subscripting a pointer that was assigned NULL/0.",
                                                   taintPath: nil, reachable: reached))
            }
            detectNullDerefs(in: base, fn: fn, reached: reached, state: state, findings: &findings)
            detectNullDerefs(in: idx, fn: fn, reached: reached, state: state, findings: &findings)
        case .member(let base, _, let isPtr, let off):
            if isPtr, holdsNull(base, state: state) {
                findings.append(CFamilyWalkFinding(function: fn.name, offset: off,
                                                   category: "Null Pointer Dereference",
                                                   severity: .high,
                                                   message: "Member access through a pointer that was assigned NULL/0.",
                                                   taintPath: nil, reachable: reached))
            }
            detectNullDerefs(in: base, fn: fn, reached: reached, state: state, findings: &findings)
        case .assign(_, let l, let r, _):
            detectNullDerefs(in: l, fn: fn, reached: reached, state: state, findings: &findings)
            detectNullDerefs(in: r, fn: fn, reached: reached, state: state, findings: &findings)
        case .binary(_, let l, let r, _):
            detectNullDerefs(in: l, fn: fn, reached: reached, state: state, findings: &findings)
            detectNullDerefs(in: r, fn: fn, reached: reached, state: state, findings: &findings)
        case .ternary(let c, let t, let f, _):
            detectNullDerefs(in: c, fn: fn, reached: reached, state: state, findings: &findings)
            detectNullDerefs(in: t, fn: fn, reached: reached, state: state, findings: &findings)
            detectNullDerefs(in: f, fn: fn, reached: reached, state: state, findings: &findings)
        case .call(let callee, let args, _):
            detectNullDerefs(in: callee, fn: fn, reached: reached, state: state, findings: &findings)
            for a in args {
                detectNullDerefs(in: a, fn: fn, reached: reached, state: state, findings: &findings)
            }
        case .comma(let a, let b, _):
            detectNullDerefs(in: a, fn: fn, reached: reached, state: state, findings: &findings)
            detectNullDerefs(in: b, fn: fn, reached: reached, state: state, findings: &findings)
        case .cast(let x, _), .paren(let x, _):
            detectNullDerefs(in: x, fn: fn, reached: reached, state: state, findings: &findings)
        case .arrayInit(let arr, _):
            for x in arr {
                detectNullDerefs(in: x, fn: fn, reached: reached, state: state, findings: &findings)
            }
        case .newExpr(_, let args, _):
            for x in args {
                detectNullDerefs(in: x, fn: fn, reached: reached, state: state, findings: &findings)
            }
        default:
            break
        }
    }

    /// True when the expression is known to hold NULL on some path reaching
    /// this point: either a tracked variable or a tracked `base->field`.
    private func holdsNull(_ e: CExpr, state: ExtraState) -> Bool {
        switch unwrap(e) {
        case .identifier(let n, _):
            return state.nullVars.contains(n)
        case .member(let base, let field, _, _):
            guard case .identifier(let owner, _) = unwrap(base) else { return false }
            return state.nullFields[owner]?.contains(field) == true
        default:
            return false
        }
    }

    /// Constant integer-overflow detection: `+`/`-`/`*` involving an operand
    /// assigned from an extreme constant (`max_int + 1`), or the constant
    /// directly (`INT_MAX + 1`).
    private func detectConstantOverflow(in e: CExpr, fn: CFunctionDef, reached: Bool,
                                        state: ExtraState, findings: inout [CFamilyWalkFinding]) {
        switch e {
        case .binary(let op, let l, let r, let off):
            let lk = extremeKind(of: l, state: state)
            let rk = extremeKind(of: r, state: state)
            var overflow = false
            switch op {
            case "+":
                overflow = (lk == .max || rk == .max)
                    || (lk == .min && rk == .min)
            case "-":
                overflow = (lk == .min)
                    || (lk == .max && rk == .min)
            case "*":
                if (lk ?? rk) != nil {
                    let other = (lk != nil) ? r : l
                    overflow = !literalIsZeroOrOne(other)
                }
            default:
                break
            }
            if overflow {
                findings.append(CFamilyWalkFinding(function: fn.name, offset: off,
                                                   category: "Integer Overflow",
                                                   severity: .medium,
                                                   message: "Arithmetic on a value at an extreme constant boundary (\(op)) wraps past the type limit (integer overflow).",
                                                   taintPath: nil, reachable: reached))
            }
            detectConstantOverflow(in: l, fn: fn, reached: reached, state: state, findings: &findings)
            detectConstantOverflow(in: r, fn: fn, reached: reached, state: state, findings: &findings)
        case .unary(let op, let operand, let off):
            var overflow = false
            if op == "++" || op == "+=" {
                if let n = simpleIdentifier(operand), state.extremeMax.contains(n) { overflow = true }
            } else if op == "--" || op == "-=" {
                if let n = simpleIdentifier(operand), state.extremeMin.contains(n) { overflow = true }
            }
            if overflow {
                findings.append(CFamilyWalkFinding(function: fn.name, offset: off,
                                                   category: "Integer Overflow",
                                                   severity: .medium,
                                                   message: "Incrementing/decrementing a value at an extreme constant boundary wraps past the type limit (integer overflow).",
                                                   taintPath: nil, reachable: reached))
            }
            detectConstantOverflow(in: operand, fn: fn, reached: reached, state: state, findings: &findings)
        case .assign(let op, let lhs, let rhs, let off):
            if op.hasSuffix("="), op != "=" {
                let lk = extremeKind(of: lhs, state: state)
                let rExtreme = extremeKind(of: rhs, state: state)
                var overflow = false
                if op == "+=" { overflow = lk == .max || rExtreme == .max }
                else if op == "-=" { overflow = lk == .min || rExtreme == .min }
                else if op == "*=" { overflow = lk != nil && !literalIsZeroOrOne(rhs) }
                if overflow {
                    findings.append(CFamilyWalkFinding(function: fn.name, offset: off,
                                                       category: "Integer Overflow",
                                                       severity: .medium,
                                                       message: "Compound assignment on a value at an extreme constant boundary wraps past the type limit (integer overflow).",
                                                       taintPath: nil, reachable: reached))
                }
            }
            detectConstantOverflow(in: lhs, fn: fn, reached: reached, state: state, findings: &findings)
            detectConstantOverflow(in: rhs, fn: fn, reached: reached, state: state, findings: &findings)
        case .call(let callee, let args, _):
            detectConstantOverflow(in: callee, fn: fn, reached: reached, state: state, findings: &findings)
            for a in args {
                detectConstantOverflow(in: a, fn: fn, reached: reached, state: state, findings: &findings)
            }
        case .ternary(let c, let t, let f, _):
            detectConstantOverflow(in: c, fn: fn, reached: reached, state: state, findings: &findings)
            detectConstantOverflow(in: t, fn: fn, reached: reached, state: state, findings: &findings)
            detectConstantOverflow(in: f, fn: fn, reached: reached, state: state, findings: &findings)
        case .comma(let a, let b, _):
            detectConstantOverflow(in: a, fn: fn, reached: reached, state: state, findings: &findings)
            detectConstantOverflow(in: b, fn: fn, reached: reached, state: state, findings: &findings)
        case .cast(let x, _), .paren(let x, _):
            detectConstantOverflow(in: x, fn: fn, reached: reached, state: state, findings: &findings)
        case .index(let base, let idx, _):
            detectConstantOverflow(in: base, fn: fn, reached: reached, state: state, findings: &findings)
            detectConstantOverflow(in: idx, fn: fn, reached: reached, state: state, findings: &findings)
        case .member(let base, _, _, _):
            detectConstantOverflow(in: base, fn: fn, reached: reached, state: state, findings: &findings)
        case .arrayInit(let arr, _):
            for x in arr {
                detectConstantOverflow(in: x, fn: fn, reached: reached, state: state, findings: &findings)
            }
        case .newExpr(_, let args, _):
            for x in args {
                detectConstantOverflow(in: x, fn: fn, reached: reached, state: state, findings: &findings)
            }
        default:
            break
        }
    }

    private func literalIsZeroOrOne(_ e: CExpr) -> Bool {
        if case .integerLiteral(let v, _) = unwrap(e) {
            return v == "0" || v == "1"
        }
        return false
    }

    /// True when `e` is a stack-local address: a local array identifier
    /// (`return buf;`), `&local`, or `localArray + k`.
    private func returnsStackAddress(_ e: CExpr, localArrays: Set<String>,
                                     localNames: Set<String>) -> Bool {
        switch unwrap(e) {
        case .identifier(let n, _):
            return localArrays.contains(n)
        case .unary("&", let operand, _):
            guard let n = simpleIdentifier(operand) else { return false }
            return localNames.contains(n)
        case .binary("+", let l, let r, _):
            if case .identifier(let n, _) = unwrap(l), localArrays.contains(n) { return true }
            if case .identifier(let n, _) = unwrap(r), localArrays.contains(n) { return true }
            return false
        default:
            return false
        }
    }
}

/// Whether a statement body mutates a given container variable via a
/// member-method mutator call (`v.push_back(...)`, `v.erase(...)`, ...).
private extension CStmt {
    func containsMutatorCall(on name: String) -> Bool {
        var found = false
        func scan(_ e: CExpr) {
            guard !found else { return }
            switch e {
            case .call(let callee, let args, _):
                if case .member(let base, let m, _, _) = callee,
                   CFamilyWalkDetector.containerMutators.contains(m),
                   Self.baseName(base) == name {
                    found = true
                    return
                }
                args.forEach { scan($0) }
            case .assign(_, let l, let r, _):
                scan(l)
                scan(r)
            case .binary(_, let l, let r, _), .comma(let l, let r, _):
                scan(l)
                scan(r)
            case .ternary(let c, let t, let f, _):
                scan(c)
                scan(t)
                scan(f)
            case .unary(_, let o, _), .cast(let o, _), .paren(let o, _):
                scan(o)
            case .member(let b, _, _, _):
                scan(b)
            case .index(let b, let i, _):
                scan(b)
                scan(i)
            case .arrayInit(let arr, _):
                arr.forEach { scan($0) }
            default:
                break
            }
        }
        func scanStmt(_ s: CStmt) {
            guard !found else { return }
            switch s {
            case .block(let arr):
                for x in arr { scanStmt(x) }
            case .expr(let e):
                scan(e)
            case .declaration(let d):
                if case .variable(_, _, let initExpr?) = d.kind { scan(initExpr) }
            case .ifStmt(_, let t, let e, _):
                scanStmt(t)
                if let e = e { scanStmt(e) }
            case .whileStmt(_, let b, _), .doWhileStmt(let b, _, _):
                scanStmt(b)
            case .forStmt(let i, _, _, let b, _):
                if let i = i { scanStmt(i) }
                scanStmt(b)
            case .switchStmt(_, let cases, _):
                for c in cases { for s in c.body { scanStmt(s) } }
            case .labeledStmt(_, let s, _):
                scanStmt(s)
            default:
                break
            }
        }
        scanStmt(self)
        return found
    }

    static func baseName(_ e: CExpr) -> String? {
        switch e {
        case .identifier(let n, _): return n
        case .paren(let x, _), .cast(let x, _): return baseName(x)
        case .unary(let op, let x, _): return op == "&" ? baseName(x) : nil
        default: return nil
        }
    }
}
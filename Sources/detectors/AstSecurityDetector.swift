// by cipher.org.uk
import Foundation

/// A structural security detector that walks the parsed `CStmt`/`CExpr` AST
/// (produced by `CAnalyzer` for C/C++ and `JAnalyzer` for Java) and reports
/// sink calls whose dangerous argument is tainted.
///
/// This is the "AST on top of heuristics" layer: it performs real data-flow
/// over the expression tree (resolving calls, arguments, assignments and
/// interprocedural taint) rather than grepping the raw source with regular
/// expressions. Findings produced here are labelled `AST` in the scan table;
/// findings that only the regex/token heuristics catch remain `Heuristic`.
struct AstFinding {
    let function: String
    let offset: Int          // absolute UTF-16 offset into the file source
    let category: String
    let severity: ScanFinding.Severity
    let message: String
    let taintPath: String?
    let reachable: Bool
    let crossFile: Bool      // true when taint originates from a source in another file
}
struct AstSinkRule {
    let category: String
    let severity: ScanFinding.Severity
    let vulnArgIndex: Int?      // dangerous argument (0-based); nil => evaluate args generically
    let alwaysVulnerable: Bool
    let formatArgIndex: Int?    // argument that, when non-literal, is a format-string sink
    let bufferOverflowOnFormat: Bool  // when true: if format arg (index 0) is a string literal containing unbounded %s, flag as Buffer Overflow
}

/// C source APIs that return attacker-controlled data (mirrors the scanner set).
enum AstCSourceAPIs {
    static let cSourceAPIs: Set<String> = [
        "getenv", "gets", "getwd", "getpass", "fgets", "fgetc", "read", "recv",
        "recvfrom", "fread", "scanf", "fscanf", "sscanf", "strdup", "strndup",
        "getopt", "getopt_long", "realpath", "readlink", "asprintf", "vasprintf",
        "dlsym", "strchr", "strrchr", "strstr", "strtok", "strtok_r", "index", "rindex",
        "memdup_user", "memdup_user_nul", "kstrdup", "kasprintf", "kstrndup",
        "ksize", "simple_strtoul", "simple_strtol",
    ]
}

struct AstSecurityDetector {

    let astFns: [String: CFunctionDef]
    let source: String
    let isJava: Bool
    let isCSharp: Bool
    private let isGo: Bool
    private let isKotlin: Bool
    private let isPython: Bool
    private let isRuby: Bool
    private let isRust: Bool
    private let isPHP: Bool
    let isSolidity: Bool
    let solidityPre08: Bool
    private let isKernel: Bool
    private let taintReturning: Set<String>
    private let crossFileSources: Set<String>
    private let writeThroughParam: [String: Set<Int>]
    /// Project-wide write-through table, consulted via lookup (never merged
    /// into the local map — that was O(files x global entries)).
    private let globalWriteThroughParam: [String: Set<Int>]
    /// Project-wide parameter-taint table: functions whose parameters are tainted
    /// at some call site, keyed by function name with the set of tainted parameter
    /// indices. If a function has no entry, seed all params (existing behavior).
    private let paramTaintSeeds: [String: Set<Int>]
    /// Object-like string macros (`#define NAME "..."` in any project file).
    /// A format argument naming one is a constant format string.
    let stringMacros: [String: String]
    /// Project-wide rejecting functions classified by body shape
    /// (`"id"` validator / `"path"` path sanitizer). A guard
    /// `if (!F(x)) return;` or a null-check on a path-sanitizer result marks
    /// `x` as whitelist-guarded for the matching categories.
    private let sanitizingFunctions: [String: String]
    /// Project-wide Python functions proven to return an SSRF-safe URL.
    let pythonSSRFValidatedFunctions: Set<String>
    /// Project-wide user-defined function names (unqualified). A bare-name sink
    /// call that collides with one of these resolves to the project function, not
    /// the C/POSIX library sink — `Session::open(id)` must not fire the `open`
    /// path-traversal rule.
    let userDefinedFunctions: Set<String>
    /// Namespace/global-scope `const char*`/`std::string` constants initialized
    /// to a string literal anywhere in the project — constant format arguments.
    let globalConstantFormats: Set<String>
    private let reachableNames: Set<String>
    /// Cross-over facts from the C-family walk detector (`CFamilyWalkDetector`):
    /// per-function names the flow walk proves bounded above (`walkBounded`) or
    /// non-zero (`walkNonZero`), and loop variables with constant `for` headers
    /// (`walkConstBounded`). Merged into the per-function guard bases so the
    /// buffered-copy / division-by-zero / overflow checks inherit while-loop
    /// and loop-header guards the structural whole-function walks skip. Only
    /// non-kernel, non-skb C/C++ files populate these (kernel files route to
    /// KernelAstDetector and keep their baselines untouched).
    private let walkBounded: [String: Set<String>]
    private let walkNonZero: [String: Set<String>]
    private let walkConstBounded: [String: Set<String>]

    /// This file's language-specific source APIs only (tiny set). Seed
    /// membership checks consult this *and* the shared project-wide
    /// `taintReturning` set via `isSeedFn(_:)` — materializing their union
    /// copied tens of thousands of entries once per file on large projects.
    private let langSourceAPIs: Set<String>

    init(astFns: [String: CFunctionDef],
                source: String,
                isJava: Bool,
                isCSharp: Bool = false,
                isGo: Bool = false,
                isKotlin: Bool = false,
                isPython: Bool = false,
                isRuby: Bool = false,
                isRust: Bool = false,
                isPHP: Bool = false,
                isSolidity: Bool = false,
                solidityPre08: Bool = false,
                isKernel: Bool = false,
                taintReturning: Set<String>,
                crossFileSources: Set<String>,
                writeThroughParam: [String: Set<Int>],
                globalWriteThroughParam: [String: Set<Int>] = [:],
                paramTaintSeeds: [String: Set<Int>] = [:],
                stringMacros: [String: String] = [:],
                sanitizingFunctions: [String: String] = [:],
                pythonSSRFValidatedFunctions: Set<String> = [],
                userDefinedFunctions: Set<String> = [],
                globalConstantFormats: Set<String> = [],
                walkBounded: [String: Set<String>] = [:],
                walkNonZero: [String: Set<String>] = [:],
                walkConstBounded: [String: Set<String>] = [:],
                reachableNames: Set<String>) {
        self.astFns = astFns
        self.source = source
        self.isJava = isJava
        self.isCSharp = isCSharp
        self.isGo = isGo
        self.isKotlin = isKotlin
        self.isPython = isPython
        self.isRuby = isRuby
        self.isRust = isRust
        self.isPHP = isPHP
        self.isSolidity = isSolidity
        self.solidityPre08 = solidityPre08
        self.isKernel = isKernel
        self.taintReturning = taintReturning
        self.crossFileSources = crossFileSources
        self.writeThroughParam = writeThroughParam
        self.globalWriteThroughParam = globalWriteThroughParam
        self.paramTaintSeeds = paramTaintSeeds
        self.stringMacros = stringMacros
        self.sanitizingFunctions = sanitizingFunctions
        self.pythonSSRFValidatedFunctions = pythonSSRFValidatedFunctions
        self.userDefinedFunctions = userDefinedFunctions
        self.globalConstantFormats = globalConstantFormats
        self.reachableNames = reachableNames
        self.walkBounded = walkBounded
        self.walkNonZero = walkNonZero
        self.walkConstBounded = walkConstBounded
        self.langSourceAPIs = Self.langAPIs(isCSharp: isCSharp, isJava: isJava,
                                            isGo: isGo, isKotlin: isKotlin,
                                            isPython: isPython, isRuby: isRuby,
                                            isRust: isRust, isPHP: isPHP,
                                            isSolidity: isSolidity)
    }

    /// Seed-function membership without materializing the union.
    func isSeedFn(_ name: String) -> Bool {
        langSourceAPIs.contains(name) || taintReturning.contains(name)
    }

    private static func langAPIs(isCSharp: Bool, isJava: Bool, isGo: Bool,
                                 isKotlin: Bool, isPython: Bool, isRuby: Bool,
                                 isRust: Bool, isPHP: Bool, isSolidity: Bool) -> Set<String> {
        if isCSharp { return csharpSourceAPIs }
        if isJava { return javaSourceAPIs }
        if isGo { return goSourceAPIs }
        if isKotlin { return kotlinSourceAPIs }
        if isPython { return pythonSourceAPIs }
        if isRuby { return rubySourceAPIs }
        if isRust { return rustSourceAPIs }
        if isPHP { return phpSourceAPIs }
        if isSolidity { return soliditySourceAPIs }
        return AstCSourceAPIs.cSourceAPIs
    }

    func detect() -> [AstFinding] {
        var out: [AstFinding] = []
        let dead = deadFunctionNames()
        for (name, fn) in astFns {
            if dead.contains(name) { continue }
            let reachable = reachableNames.isEmpty || reachableNames.contains(name)
            out.append(contentsOf: scanFunction(name: name, fn: fn, reachable: reachable))
        }
        return out
    }

    /// Function names that are dead code: never referenced anywhere in the file
    /// outside their own definition and either provably file-local (C `static`
    /// internal linkage, Java `private`) or carrying an explicit retirement
    /// marker in the name for the linkage-less script languages. Findings inside
    /// them are unreachable-at-runtime noise from retired code, not live defects.
    private func deadFunctionNames() -> Set<String> {
        var dead = Set<String>()
        let ns = source as NSString
        let markers = ["retired", "legacy", "unused", "deprecated", "obsolete", "dead"]
        // One tokenized pass counts identifier occurrences per name (token
        // boundaries are exact word boundaries); the per-function regex over
        // the whole file was O(functions x file size).
        let tokens = CTokenizer(source: source).tokenize()
        let names = Set(astFns.keys)
        var occurrenceCounts: [String: Int] = [:]
        for t in tokens where t.kind == .identifier && names.contains(t.text) {
            occurrenceCounts[t.text, default: 0] += 1
        }
        // C-static suppression only applies when the file has a recognized
        // entry point: without one, every unreferenced function may be an
        // externally registered callback (kernel ioctls, workqueue handlers).
        let hasEntryPoint = !reachableNames.isEmpty
        for (name, fn) in astFns {
            // The definition itself contributes one occurrence, so more than
            // one means the function is referenced. Each branch decides
            // independently whether it needs references: provable-dead cases
            // (C `static`, Java `private`) are also dead with zero call sites.
            if fn.qualifiers.contains("static") {
                // C/C++: `static` gives internal linkage, so with a live entry
                // point present an unreferenced static function is dead code.
                if hasEntryPoint, !reachableNames.contains(name) { dead.insert(name) }
            } else if isJava {
                // Java: a `private` method cannot be called from outside the
                // class, so findings there are internal regardless of call
                // sites. The check looks only at this declaration's own prefix
                // (after the last `;`, `{` or `}`), not the previous member's
                // modifiers.
                let lo = max(0, fn.startOffset - 400)
                let before = ns.substring(with: NSRange(location: lo, length: fn.startOffset - lo))
                let separators: [(Character)] = [";", "{", "}"]
                let fragments = before.split(whereSeparator: { c in separators.contains(c) })
                let prefix = fragments.last.map(String.init) ?? before
                if prefix.contains("private") { dead.insert(name) }
            } else if isPython || isRuby || isGo || isRust || isKotlin || isPHP || isCSharp {
                // Script languages have no linkage: require an explicit
                // retirement marker so live API surface is never suppressed.
                let low = name.lowercased()
                if markers.contains(where: { low.contains($0) }) { dead.insert(name) }
            }
        }
        return dead
    }

    /// True when the statement tree contains the given identifier anywhere
    /// (any position: condition, call, assignment).
    func bodyHasIdentifierStmt(_ stmt: CStmt, _ name: String) -> Bool {
        switch stmt {
        case .block(let arr):
            return arr.contains { bodyHasIdentifierStmt($0, name) }
        case .expr(let e):
            return exprHasIdentifier(e, name)
        case .declaration(let d):
            if case .variable(_, _, let ie?) = d.kind {
                return exprHasIdentifier(ie, name)
            }
            return false
        case .ifStmt(let cond, let t, let e, _):
            return exprHasIdentifier(cond, name) || bodyHasIdentifierStmt(t, name) || (e.map { bodyHasIdentifierStmt($0, name) } ?? false)
        case .whileStmt(let cond, let b, _):
            return exprHasIdentifier(cond, name) || bodyHasIdentifierStmt(b, name)
        case .doWhileStmt(let b, let cond, _):
            return bodyHasIdentifierStmt(b, name) || exprHasIdentifier(cond, name)
        case .forStmt(let initS, let cond, let inc, let b, _):
            return (initS.map { bodyHasIdentifierStmt($0, name) } ?? false)
                || (cond.map { exprHasIdentifier($0, name) } ?? false)
                || (inc.map { exprHasIdentifier($0, name) } ?? false)
                || bodyHasIdentifierStmt(b, name)
        case .returnStmt(let e, _):
            return e.map { exprHasIdentifier($0, name) } ?? false
        case .switchStmt(let expr, let cases, _):
            return exprHasIdentifier(expr, name) || cases.contains { c in c.body.contains { bodyHasIdentifierStmt($0, name) } }
        case .labeledStmt(_, let s, _):
            return bodyHasIdentifierStmt(s, name)
        case .breakStmt, .continueStmt, .gotoStmt, .empty:
            return false
        }
    }

    private func exprHasIdentifier(_ e: CExpr, _ name: String) -> Bool {
        switch e {
        case .identifier(let n, _):
            return n == name
        case .unary(_, let x, _), .cast(let x, _), .paren(let x, _):
            return exprHasIdentifier(x, name)
        case .binary(_, let l, let r, _), .comma(let l, let r, _):
            return exprHasIdentifier(l, name) || exprHasIdentifier(r, name)
        case .ternary(let c, let t, let f, _):
            return exprHasIdentifier(c, name) || exprHasIdentifier(t, name) || exprHasIdentifier(f, name)
        case .assign(_, let l, let r, _):
            return exprHasIdentifier(l, name) || exprHasIdentifier(r, name)
        case .call(let callee, let args, _):
            return exprHasIdentifier(callee, name) || args.contains { exprHasIdentifier($0, name) }
        case .member(let base, let m, _, _):
            return m == name || exprHasIdentifier(base, name)
        case .index(let base, let idx, _):
            return exprHasIdentifier(base, name) || exprHasIdentifier(idx, name)
        case .arrayInit(let els, _):
            return els.contains { exprHasIdentifier($0, name) }
        case .newExpr(_, let args, _):
            return args.contains { exprHasIdentifier($0, name) }
        case .sizeOf, .lambda, .integerLiteral, .floatLiteral, .stringLiteral, .charLiteral, .booleanLiteral:
            return false
        }
    }

    // MARK: - Per-function scan

    private func scanFunction(name: String, fn: CFunctionDef, reachable: Bool) -> [AstFinding] {
        var tainted = Set<String>()
        var crossTainted = Set<String>()
        // Seed only parameters that are tainted at actual call sites when
        // project-wide parameter-taint seeds are available; otherwise seed all
        // params (existing behavior for C and other analyzers without seeds).
        if let seeds = paramTaintSeeds[name], !seeds.isEmpty {
            for idx in seeds where idx < fn.params.count {
                if let pname = fn.params[idx].name { tainted.insert(pname) }
            }
        } else {
            for p in fn.params where p.name != nil { tainted.insert(p.name!) }
        }

        // PHP superglobals arrive in the AST as bare identifiers (`_GET`, `_POST`,
        // etc., the `$` being a tokenizer artifact). Seed them as tainted sources so
        // `mysqli_query($c, $_POST['x'])`, `echo $_GET['q']`, etc. propagate.
        if isPHP {
            tainted.formUnion(Self.phpSuperglobalSeeds)
        }

        // C# parameters often arrive as `out`/`ref` (write-through seeds) and the
        // body may read them before assigning; the parameter itself is a caller
        // input, so seed it tainted like the other languages.
        let guarded = whitelistGuardedVars(in: fn.body)
        var sizeB = sizeBoundedVars(in: fn.body)
        constantStringRef.vars = constantStringVars(in: fn.body)
        zeroCheckedRef.vars = zeroCheckedVars(in: fn.body)
        // Cross-over: the walk detector's flow-proven facts extend the
        // structural bases with guards the single-pass walks skip (while-loop
        // conditions, `for` headers). Loop-variable const bounds go only to the
        // overflow suppression box — never into `sizeB`, since a loop header is
        // not a spill-capacity proof for buffered copies.
        if let wb = walkBounded[name], !wb.isEmpty { sizeB.formUnion(wb) }
        if let wn = walkNonZero[name], !wn.isEmpty { zeroCheckedRef.vars.formUnion(wn) }
        overflowConstBoundedRef.vars = walkConstBounded[name] ?? []

        var findings: [AstFinding] = []
        scanStmt(fn.body, function: name, params: Set(fn.params.compactMap { $0.name }), tainted: &tainted, crossTainted: &crossTainted, guarded: guarded, sizeBounded: sizeB, findings: &findings, reachable: reachable)
        // C++-shaped structural patterns the generic C sink table cannot see:
        // `std::ifstream file(path)` parses into an object read + a ctor-style
        // call named after the *variable*, so no sink name matches. Detect the
        // file-stream open, a `filesystem::exists`-then-open TOCTOU, and an
        // encoded-path-traversal guard (`find("..")` only) feeding a return.
        if !isKernel && !isJava && !isCSharp && !isGo && !isKotlin && !isPython
            && !isRuby && !isRust && !isPHP && !isSolidity {
            checkCxxPatterns(fn: fn, function: name, tainted: tainted, crossTainted: crossTainted, guarded: guarded, findings: &findings, reachable: reachable)
        }
        // Userspace memory-safety walk (double free / use after free / leak).
        // Kernel-shaped files are owned by the dedicated KernelAstDetector,
        // which already reports kernel UAF with higher precision.
        if !isKernel && !isJava && !isCSharp && !isGo && !isKotlin && !isPython
            && !isRuby && !isRust && !isPHP && !isSolidity {
            checkMemorySafety(fn: fn, function: name, findings: &findings, reachable: reachable)
        }
        if isJava {
            applyJavaSuppressions(fn: fn, findings: &findings)
        }
        if isGo {
            applyGoSuppressions(fn: fn, findings: &findings)
        }
        // Rust path-join + SSRF hardening (see RustSecurityDetector.swift).
        if isRust {
            applyRustSuppressions(fn: fn, findings: &findings)
        }
        // C# path containment + XXE hardening vectors (see CSharpSecurityDetector.swift).
        if isCSharp {
            applyCSharpSuppressions(fn: fn, findings: &findings)
        }
        if isKotlin {
            applyKotlinSuppressions(fn: fn, findings: &findings)
        }
        if isRuby {
            applyRubySuppressions(fn: fn, findings: &findings)
        }
        // PHP file-level suppressions (allowlist / hardening guards that make the
        // findings for a category inapplicable). The guards live in
        // PHPSecurityDetector.swift.
        if isPHP {
            applyPHPSuppressions(findings: &findings)
        }
        if isPython {
            applyPythonSuppressions(fn: fn, findings: &findings)
        }
        // Solidity structural ("3-walk") checks run after the per-call scan so
        // crossTainted is populated by taint propagation. They reason over the
        // whole function body (external-call vs. state-write ordering, guard
        // presence), not a single call site.
        if isSolidity {
            checkSolidityStructural(function: name, fn: fn, params: Set(fn.params.compactMap { $0.name }), tainted: tainted, crossTainted: crossTainted, findings: &findings, reachable: reachable)
        }
        // Kotlin JWT: accepting the unsigned `alg == "none"` header and returning
        // the claims without any signature verification is a complete auth bypass.
        if isKotlin {
            checkKotlinJwtAlgNone(fn: fn, function: name, findings: &findings, reachable: reachable)
            checkKotlinMobileStructural(fn: fn, function: name, tainted: tainted, crossTainted: crossTainted, findings: &findings, reachable: reachable)
            // Mobile post-sink suppressions run last so they see the structural
            // findings (WebView property assignment, Intent routing, X509) too.
            applyKotlinMobileSuppressions(fn: fn, findings: &findings)
        }
        // PHP: a loose `==` equality between two caller-supplied values used as
        // the authorization decision allows type-juggling bypasses
        // (`"0e1…" == "0e2…"`). The classic `return $a == $b;` in an
        // auth-named function with no strict/hashed comparison is the defect.
        if isPHP {
            checkPHPLooseAuthCompare(fn: fn, function: name, params: Set(fn.params.compactMap { $0.name }), findings: &findings, reachable: reachable)
        }
        return findings
    }

    // MARK: - Statement walking

    private func scanStmt(_ stmt: CStmt, function: String, params: Set<String>, tainted: inout Set<String>, crossTainted: inout Set<String>, guarded: Set<String>, sizeBounded: Set<String>, findings: inout [AstFinding], reachable: Bool) {
        switch stmt {
        case .block(let arr):
            for s in arr {
                scanStmt(s, function: function, params: params, tainted: &tainted, crossTainted: &crossTainted, guarded: guarded, sizeBounded: sizeBounded, findings: &findings, reachable: reachable)
            }
        case .expr(let e):
            scanExpr(e, function: function, params: params, tainted: &tainted, crossTainted: &crossTainted, guarded: guarded, sizeBounded: sizeBounded, findings: &findings, reachable: reachable)
        case .declaration(let d):            if case .variable(_, let name, let initExpr?) = d.kind {
                if exprTainted(initExpr, tainted: tainted) != nil {
                    tainted.insert(name)
                } else if plainSourceCall(initExpr) != nil {
                    tainted.insert(name)
                }
                if crossFileSourceCall(initExpr) != nil || exprCrossFile(initExpr, crossTainted: crossTainted) {
                    crossTainted.insert(name)
                }
                scanExpr(initExpr, function: function, params: params, tainted: &tainted, crossTainted: &crossTainted, guarded: guarded, sizeBounded: sizeBounded, findings: &findings, reachable: reachable)
            }
        case .ifStmt(_, let t, let e, _):
            scanStmt(t, function: function, params: params, tainted: &tainted, crossTainted: &crossTainted, guarded: guarded, sizeBounded: sizeBounded, findings: &findings, reachable: reachable)
            if let e = e { scanStmt(e, function: function, params: params, tainted: &tainted, crossTainted: &crossTainted, guarded: guarded, sizeBounded: sizeBounded, findings: &findings, reachable: reachable) }
        case .whileStmt(_, let b, _):
            scanStmt(b, function: function, params: params, tainted: &tainted, crossTainted: &crossTainted, guarded: guarded, sizeBounded: sizeBounded, findings: &findings, reachable: reachable)
        case .doWhileStmt(let b, _, _):
            scanStmt(b, function: function, params: params, tainted: &tainted, crossTainted: &crossTainted, guarded: guarded, sizeBounded: sizeBounded, findings: &findings, reachable: reachable)
        case .forStmt(let initS, let cond, _, let b, _):
            if let initS = initS {
                scanStmt(initS, function: function, params: params, tainted: &tainted, crossTainted: &crossTainted, guarded: guarded, sizeBounded: sizeBounded, findings: &findings, reachable: reachable)
            }
            // Enhanced-for (`for (String s : coll)`): the loop variable is a bare
            // declaration and the collection is the condition; seed the variable
            // from a tainted collection so `s` itself taints its uses.
            if let cond = cond, let loopVar = enhancedForVar(initS) {
                if exprTainted(cond, tainted: tainted) != nil {
                    tainted.insert(loopVar)
                }
                if exprCrossFile(cond, crossTainted: crossTainted) {
                    crossTainted.insert(loopVar)
                }
            }
            scanStmt(b, function: function, params: params, tainted: &tainted, crossTainted: &crossTainted, guarded: guarded, sizeBounded: sizeBounded, findings: &findings, reachable: reachable)
        case .switchStmt(_, let cases, _):
            for c in cases {
                for s in c.body {
                    scanStmt(s, function: function, params: params, tainted: &tainted, crossTainted: &crossTainted, guarded: guarded, sizeBounded: sizeBounded, findings: &findings, reachable: reachable)
                }
            }
        case .returnStmt(let e, _):
            if let e = e { scanExpr(e, function: function, params: params, tainted: &tainted, crossTainted: &crossTainted, guarded: guarded, sizeBounded: sizeBounded, findings: &findings, reachable: reachable) }
        case .labeledStmt(_, let s, _):
            scanStmt(s, function: function, params: params, tainted: &tainted, crossTainted: &crossTainted, guarded: guarded, sizeBounded: sizeBounded, findings: &findings, reachable: reachable)
        default:
            break
        }
    }

    private func scanExpr(_ e: CExpr, function: String, params: Set<String>, tainted: inout Set<String>, crossTainted: inout Set<String>, guarded: Set<String>, sizeBounded: Set<String>, findings: inout [AstFinding], reachable: Bool) {
        switch e {
        case .call(let callee, let args, let offset):
            let matched = handleCall(callee: callee, args: args, offset: offset, function: function, params: params, tainted: &tainted, crossTainted: &crossTainted, guarded: guarded, sizeBounded: sizeBounded, findings: &findings, reachable: reachable)
            // Java builder accumulation: `StringBuilder.append(tainted)` (and
            // chainable mutators on it) sink taint into the builder variable, so
            // a later `builder.toString()` reaching a sink is flagged.
            if isJava, callName(callee) == "append", let recv = identifierReceiver(callee),
               args.contains(where: { exprTainted($0, tainted: tainted) != nil }) {
                tainted.insert(recv)
                if args.contains(where: { exprCrossFile($0, crossTainted: crossTainted) }) {
                    crossTainted.insert(recv)
                }
            }
            // The heuristic reports at most one sink per call statement and then
            // skips past the whole call so nested identifiers are not re-scanned.
            // Mirror that for the script languages: a recognized sink call is
            // emitted as a whole, and its argument list is not re-walked for
            // further sinks (e.g. `renameTo(File("/data/" + target))` fires
            // TOCTOU only).
            if matched && (isGo || isKotlin || isPython || isRuby || isRust || isPHP || isSolidity) { break }
            for a in args {
                scanExpr(a, function: function, params: params, tainted: &tainted, crossTainted: &crossTainted, guarded: guarded, sizeBounded: sizeBounded, findings: &findings, reachable: reachable)
            }
            // Chained receivers (`reqwest::get(url).unwrap()`,
            // `requests.get(url).json()`) place the inner call in the callee
            // subtree; walk it so the inner sink is still caught. The C-family
            // and Go/Kotlin paths do not need this and keep their behavior.
            if isPython || isRuby || isRust || isPHP || isGo || isJava {
                scanExpr(callee, function: function, params: params, tainted: &tainted, crossTainted: &crossTainted, guarded: guarded, sizeBounded: sizeBounded, findings: &findings, reachable: reachable)
            }
        case .assign(let op, let lhs, let rhs, let offset):
            if let name = simpleIdentifier(lhs),
               !isPythonSSRFValidatedURL(rhs),
               exprTainted(rhs, tainted: tainted) != nil {
                tainted.insert(name)
            }
            if let name = simpleIdentifier(lhs),
               (crossFileSourceCall(rhs) != nil || exprCrossFile(rhs, crossTainted: crossTainted)) {
                crossTainted.insert(name)
            }
            checkCOverflowAssign(op: op, lhs: lhs, rhs: rhs, offset: offset, function: function, tainted: tainted, guarded: guarded, sizeBounded: sizeBounded, findings: &findings, reachable: reachable)
            scanExpr(lhs, function: function, params: params, tainted: &tainted, crossTainted: &crossTainted, guarded: guarded, sizeBounded: sizeBounded, findings: &findings, reachable: reachable)
            scanExpr(rhs, function: function, params: params, tainted: &tainted, crossTainted: &crossTainted, guarded: guarded, sizeBounded: sizeBounded, findings: &findings, reachable: reachable)
        case .unary(_, let o, _):
            scanExpr(o, function: function, params: params, tainted: &tainted, crossTainted: &crossTainted, guarded: guarded, sizeBounded: sizeBounded, findings: &findings, reachable: reachable)
        case .binary(let op, let l, let r, let offset):
            scanExpr(l, function: function, params: params, tainted: &tainted, crossTainted: &crossTainted, guarded: guarded, sizeBounded: sizeBounded, findings: &findings, reachable: reachable)
            scanExpr(r, function: function, params: params, tainted: &tainted, crossTainted: &crossTainted, guarded: guarded, sizeBounded: sizeBounded, findings: &findings, reachable: reachable)
            checkCOverflowBinary(op: op, l: l, r: r, offset: offset, function: function, tainted: tainted, guarded: guarded, sizeBounded: sizeBounded, findings: &findings, reachable: reachable)
        case .comma(let l, let r, _):
            scanExpr(l, function: function, params: params, tainted: &tainted, crossTainted: &crossTainted, guarded: guarded, sizeBounded: sizeBounded, findings: &findings, reachable: reachable)
            scanExpr(r, function: function, params: params, tainted: &tainted, crossTainted: &crossTainted, guarded: guarded, sizeBounded: sizeBounded, findings: &findings, reachable: reachable)
        case .ternary(let c, let t, let f, _):
            scanExpr(c, function: function, params: params, tainted: &tainted, crossTainted: &crossTainted, guarded: guarded, sizeBounded: sizeBounded, findings: &findings, reachable: reachable)
            scanExpr(t, function: function, params: params, tainted: &tainted, crossTainted: &crossTainted, guarded: guarded, sizeBounded: sizeBounded, findings: &findings, reachable: reachable)
            scanExpr(f, function: function, params: params, tainted: &tainted, crossTainted: &crossTainted, guarded: guarded, sizeBounded: sizeBounded, findings: &findings, reachable: reachable)
        case .member(let b, _, _, _):
            scanExpr(b, function: function, params: params, tainted: &tainted, crossTainted: &crossTainted, guarded: guarded, sizeBounded: sizeBounded, findings: &findings, reachable: reachable)
        case .index(let b, let idx, _):
            scanExpr(b, function: function, params: params, tainted: &tainted, crossTainted: &crossTainted, guarded: guarded, sizeBounded: sizeBounded, findings: &findings, reachable: reachable)
            scanExpr(idx, function: function, params: params, tainted: &tainted, crossTainted: &crossTainted, guarded: guarded, sizeBounded: sizeBounded, findings: &findings, reachable: reachable)
        case .cast(let x, _), .paren(let x, _):
            scanExpr(x, function: function, params: params, tainted: &tainted, crossTainted: &crossTainted, guarded: guarded, sizeBounded: sizeBounded, findings: &findings, reachable: reachable)
        case .arrayInit(let arr, _):
            for a in arr { scanExpr(a, function: function, params: params, tainted: &tainted, crossTainted: &crossTainted, guarded: guarded, sizeBounded: sizeBounded, findings: &findings, reachable: reachable) }
        case .newExpr(let typeName, let args, let offset):
            checkNewExprSinks(name: typeName, args: args, offset: offset, function: function, tainted: tainted, crossTainted: crossTainted, guarded: guarded, sizeBounded: sizeBounded, findings: &findings, reachable: reachable)
            if isCSharp {
                checkCSharpNewExprSinks(name: typeName, args: args, offset: offset, function: function, tainted: tainted, crossTainted: crossTainted, guarded: guarded, sizeBounded: sizeBounded, findings: &findings, reachable: reachable)
            }
            for a in args { scanExpr(a, function: function, params: params, tainted: &tainted, crossTainted: &crossTainted, guarded: guarded, sizeBounded: sizeBounded, findings: &findings, reachable: reachable) }
        default:
            break
        }
    }

    // MARK: - C-family integer arithmetic findings

    /// C-family userspace gate: C/C++/ObjC-style arithmetic wrapped in the
    /// integer model. Kernel files are owned by the dedicated kernel detector,
    /// and script/managed languages model overflow differently.
    var isCArithmeticTarget: Bool {
        !isKernel && !isJava && !isCSharp && !isGo && !isKotlin && !isPython
            && !isRuby && !isRust && !isPHP && !isSolidity
    }

    // MARK: - Sink handling

    private func handleCall(callee: CExpr, args: [CExpr], offset: Int, function: String, params: Set<String>, tainted: inout Set<String>, crossTainted: inout Set<String>, guarded: Set<String>, sizeBounded: Set<String>, findings: inout [AstFinding], reachable: Bool) -> Bool {
        // Caller-injected behavior: calling one of the enclosing function's own
        // *parameters* (dependency injection, e.g. `def hook(urlopen, url):
        // urlopen(url)`) means the sink decision belongs to the call site, not
        // this function. The real call site is analyzed where it appears.
        if case .identifier(let calleeIdent, _) = callee, params.contains(calleeIdent) {
            return false
        }
        // Member calls (`obj.method(...)`) and plain calls both contain the method
        // name as a trailing identifier; resolve it for sink matching.
        guard let name = callName(callee) else { return false }
        // Qualified dot path as written (`exec.Command`, `syscall.Exec`, `db.Query`,
        // `Files.newOutputStream`); Go/Kotlin sink tables are keyed on these.
        let qualified = callQualifiedName(callee) ?? name

        // Write-through: a sink that fills arg k with untrusted data taints it.
        // Union of local + global tables (lookup only, no per-file merge).
        let wtIdxs: Set<Int>?
        switch (writeThroughParam[name], globalWriteThroughParam[name]) {
        case (let a?, let b?): wtIdxs = a.union(b)
        case (let a?, nil): wtIdxs = a
        case (nil, let b?): wtIdxs = b
        default: wtIdxs = nil
        }
        if let idxs = wtIdxs {
            let crossFileFn = crossFileSources.contains(name)
            for k in idxs where k < args.count {
                if let aName = simpleIdentifier(args[k]) {
                    tainted.insert(aName)
                    if crossFileFn { crossTainted.insert(aName) }
                }
            }
        }

        if isGo {
            return checkGoSinks(name: name, qualified: qualified, args: args, offset: offset, function: function, params: params, tainted: tainted, crossTainted: crossTainted, guarded: guarded, sizeBounded: sizeBounded, findings: &findings, reachable: reachable)
        }
        if isKotlin {
            return checkKotlinSinks(name: name, qualified: qualified, callee: callee, args: args, offset: offset, function: function, tainted: tainted, crossTainted: crossTainted, guarded: guarded, sizeBounded: sizeBounded, findings: &findings, reachable: reachable)
        }
        if isPython {
            return checkPythonSinks(name: name, qualified: qualified, args: args, offset: offset, function: function, tainted: tainted, crossTainted: crossTainted, guarded: guarded, sizeBounded: sizeBounded, findings: &findings, reachable: reachable)
        }
        if isRuby {
            return checkRubySinks(name: name, qualified: qualified, args: args, offset: offset, function: function, params: params, tainted: tainted, crossTainted: crossTainted, guarded: guarded, sizeBounded: sizeBounded, findings: &findings, reachable: reachable)
        }
        if isRust {
            return checkRustSinks(name: name, qualified: qualified, args: args, offset: offset, function: function, tainted: tainted, crossTainted: crossTainted, guarded: guarded, sizeBounded: sizeBounded, findings: &findings, reachable: reachable)
        }
        if isPHP {
            return checkPHPSinks(name: name, qualified: qualified, args: args, offset: offset, function: function, tainted: tainted, crossTainted: crossTainted, guarded: guarded, sizeBounded: sizeBounded, findings: &findings, reachable: reachable)
        }
        if isSolidity {
            return checkSoliditySinks(name: name, qualified: qualified, callee: callee, args: args, offset: offset, function: function, tainted: tainted, crossTainted: crossTainted, guarded: guarded, sizeBounded: sizeBounded, findings: &findings, reachable: reachable)
        }
        // C/C++, Java, C#: C-family sinks plus language-specific tables. The
        // C-sink table (lowercase C * functions) does not apply to the script
        // languages.
        checkCSinks(name: name, args: args, offset: offset, function: function, tainted: tainted, crossTainted: crossTainted, guarded: guarded, sizeBounded: sizeBounded, findings: &findings, reachable: reachable, calleeIsMember: isMemberCall(callee))
        if isJava {
            checkJavaSinks(name: name, args: args, offset: offset, function: function, tainted: tainted, crossTainted: crossTainted, guarded: guarded, sizeBounded: sizeBounded, findings: &findings, reachable: reachable)
        }
        if isCSharp {
            checkCSharpSinks(name: name, args: args, offset: offset, function: function, tainted: tainted, crossTainted: crossTainted, guarded: guarded, sizeBounded: sizeBounded, findings: &findings, reachable: reachable)
        }
        return false
    }

    /// Whether a call expression's callee was reached through a member access
    /// (`obj.method(...)`, `h5->vnd->open(...)`), meaning it is an object method
    /// or ops-table callback dispatch rather than a bare free function call.
    private func isMemberCall(_ callee: CExpr) -> Bool {
        switch callee {
        case .member: return true
        case .call(let innerCallee, _, _): return isMemberCall(innerCallee)
        default: return false
        }
    }

    func callName(_ callee: CExpr) -> String? {
        switch callee {
        case .identifier(let n, _): return n
        // A member call (`obj.method(...)` or `Type.staticMethod(...)`) is named
        // by its trailing member (the method). Recurse into a nested call so a
        // chained receiver like `Runtime.getRuntime().exec(...)` still yields
        // `exec`.
        case .member(_, let member, _, _):
            return member
        case .call(let innerCallee, _, _):
            return callName(innerCallee)
        default: return nil
        }
    }

    /// The dotted call path as written in source: `exec.Command`, `syscall.Exec`,
    /// `db.Query`, `Runtime.getRuntime.exec`, `URL.openStream`.
    /// Used to match Go/Kotlin sink rules that are registered with a package path.
    func callQualifiedName(_ callee: CExpr) -> String? {
        switch callee {
        case .identifier(let n, _):
            return n
        case .member(let base, let m, _, _):
            if let bn = callQualifiedName(base) { return bn + "." + m }
            return m
        case .call(let innerCallee, _, _):
            return callQualifiedName(innerCallee)
        default:
            return nil
        }
    }

    /// The base identifier a call is dispatched on (`script` for
    /// `script.append(x)`, including `this.field.append(...)` chains), or nil
    /// for static/free calls.
    func identifierReceiver(_ callee: CExpr) -> String? {
        switch callee {
        case .identifier(let n, _): return n
        case .member(let base, _, _, _): return identifierReceiver(base)
        default: return nil
        }
    }

    /// The loop variable of an enhanced-for statement (`for (String s : coll)`
    /// parses as a bare no-init declaration in init, the collection in cond),
    /// or nil for an ordinary three-part for loop.
    private func enhancedForVar(_ initS: CStmt?) -> String? {
        guard let initS = initS else { return nil }
        if case .declaration(let d) = initS,
           case .variable(_, let name, nil) = d.kind {
            return name
        }
        return nil
    }

    // MARK: - Go / Kotlin sink checks

    /// Generic evaluation of a Go/Kotlin sink rule: emits when the dangerous
    /// argument (or any argument for `vulnArgIndex == nil`) is tainted, or when
    /// the sink is always-vulnerable.
    func evaluateGenericRule(_ rule: AstSinkRule, name: String, args: [CExpr], offset: Int, function: String, tainted: Set<String>, crossTainted: Set<String>, guarded: Set<String>, sizeBounded: Set<String>, findings: inout [AstFinding], reachable: Bool) {
        if rule.alwaysVulnerable {
            emit(&findings, function, offset, rule, message: "\(name) is used without bounds/algorithm checks on attacker-influenced data.", taint: nil, reachable: reachable, crossFile: false)
            return
        }
        if let vi = rule.vulnArgIndex, vi < args.count {
            if exprTainted(args[vi], tainted: tainted) != nil,
               !isGuarded(args[vi], guarded: guarded, category: rule.category) {
                emit(&findings, function, offset, rule, message: "\(name) receives data that flows from an untrusted source.", taint: taintLabel(args[vi], tainted: tainted), reachable: reachable, crossFile: exprCrossFile(args[vi], crossTainted: crossTainted))
            }
        } else {
            if args.contains(where: { exprTainted($0, tainted: tainted) != nil && !isGuarded($0, guarded: guarded, category: rule.category) }) {
                let cross = args.contains(where: { exprCrossFile($0, crossTainted: crossTainted) })
                emit(&findings, function, offset, rule, message: "\(name) called with potentially untrusted data.", taint: nil, reachable: reachable, crossFile: cross)
            }
        }
    }

    /// Compact builder for script-language sink rules (Go/Kotlin rows use the
    /// full `AstSinkRule` literal for clarity).
    func rule(_ category: String, _ severity: ScanFinding.Severity, vuln: Int? = nil, always: Bool = false) -> AstSinkRule {
        AstSinkRule(category: category, severity: severity, vulnArgIndex: vuln, alwaysVulnerable: always, formatArgIndex: nil, bufferOverflowOnFormat: false)
    }

    func lastSeg(_ name: String) -> String {
        name.split(separator: ".").last.map(String.init) ?? name
    }

    // MARK: - Whitelist guards

    /// Walks the function to collect variable names that are proven to pass a
    /// whitelist (`matches`/`Regex.IsMatch`) rejection guard before they are
    /// used. Only applies to categories where such a check is a real mitigation
    /// (Command Injection / SQL Injection / Path Traversal).
    private func whitelistGuardedVars(in body: CStmt) -> Set<String> {
        var guarded = Set<String>()
        let pathResults = pathSanitizerResultVars(in: body)
        collectGuardedVars(in: body, into: &guarded, pathResults: pathResults)
        return guarded
    }

    /// Variables assigned from a call to a classified path sanitizer
    /// (`p = safe_join(...)`). Null-guarding such a result
    /// (`if (!p) return;`) is the consumer side of the sanitizer's
    /// reject-on-traversal contract, so the surviving value is traversal-safe.
    private func pathSanitizerResultVars(in body: CStmt) -> Set<String> {
        var out = Set<String>()
        func walk(_ stmt: CStmt) {
            switch stmt {
            case .block(let arr):
                for s in arr { walk(s) }
            case .declaration(let d):
                if case .variable(_, let name, let initExpr?) = d.kind,
                   isPathSanitizerCall(initExpr) {
                    out.insert(name)
                }
            case .expr(let e):
                if case .assign("=", let lhs, let rhs, _) = e,
                   case .identifier(let name, _) = lhs,
                   isPathSanitizerCall(rhs) {
                    out.insert(name)
                }
            case .ifStmt(_, let t, let eb, _):
                walk(t)
                if let e = eb { walk(e) }
            case .whileStmt(_, let b, _), .doWhileStmt(let b, _, _):
                walk(b)
            case .forStmt(_, _, _, let b, _):
                walk(b)
            case .switchStmt(_, let cases, _):
                for c in cases { for s in c.body { walk(s) } }
            case .labeledStmt(_, let s, _):
                walk(s)
            default:
                break
            }
        }
        walk(body)
        return out
    }

    private func isPathSanitizerCall(_ e: CExpr) -> Bool {
        if case .call(let callee, _, _) = e {
            if case .identifier(let fnName, _) = callee {
                return sanitizingFunctions[fnName] == "path"
            }
            if case .member(_, let member, _, _) = callee {
                return sanitizingFunctions[member] == "path"
            }
        }
        return false
    }

    private func collectGuardedVars(in stmt: CStmt, into guarded: inout Set<String>, pathResults: Set<String>) {
        switch stmt {
        case .block(let arr):
            for s in arr { collectGuardedVars(in: s, into: &guarded, pathResults: pathResults) }
        case .expr(let e):
            // Sanitizing reassignment: `name = preg_replace('/[A-Za-z0-9._-]/', …)`
            // rewrites the value onto a character allowlist, which mitigates the
            // path/command-shaped categories the same way a whitelist guard does.
            if case .assign("=", let lhs, let rhs, _) = e,
               case .identifier(let name, _) = lhs,
               case .call(let callee, let args, _) = rhs,
               case .identifier(let fnName, _) = callee,
               fnName == "preg_replace", let pat = args.first,
               case .stringLiteral(let lit, _) = pat,
               lit.contains("[") && lit.contains("]") {
                guarded.insert(name)
            }
        case .declaration(let d):
            if case .variable(_, let name, let initExpr?) = d.kind,
               case .call(let callee, let args, _) = initExpr,
               case .identifier(let fnName, _) = callee,
               fnName == "preg_replace", let pat = args.first,
               case .stringLiteral(let lit, _) = pat,
               lit.contains("[") && lit.contains("]") {
                guarded.insert(name)
            }
        case .ifStmt(let cond, let thenBranch, let elseBranch, _):
            if let target = whitelistTarget(in: cond) {
                // `if (!var.matches(re)) return;`  => then-branch returns when
                // the value does NOT match, so var is only used once it matches.
                if isNegated(cond), statementReturns(thenBranch) {
                    guarded.insert(target)
                }
                // `if (var.matches(re)) { use } else { return; }` => else-branch
                // rejects non-matching values, so var is only used once it matches.
                if let eb = elseBranch, !isNegated(cond), statementReturns(eb) {
                    guarded.insert(target)
                }
            }
            // Null-guard on a path-sanitizer result: `if (!path) return;` where
            // `path` was assigned `safe_join(...)` — the sanitizer returns NULL
            // exactly when the input contained traversal, so a surviving value
            // is a fixed-base path.
            if let target = sanitizerNullGuard(in: cond, pathResults: pathResults),
               statementReturns(thenBranch) {
                guarded.insert(target)
            }
            collectGuardedVars(in: thenBranch, into: &guarded, pathResults: pathResults)
            if let eb = elseBranch { collectGuardedVars(in: eb, into: &guarded, pathResults: pathResults) }
        case .whileStmt(_, let b, _):
            collectGuardedVars(in: b, into: &guarded, pathResults: pathResults)
        case .doWhileStmt(let b, _, _):
            collectGuardedVars(in: b, into: &guarded, pathResults: pathResults)
        case .forStmt(_, _, _, let b, _):
            collectGuardedVars(in: b, into: &guarded, pathResults: pathResults)
        case .labeledStmt(_, let s, _):
            collectGuardedVars(in: s, into: &guarded, pathResults: pathResults)
        case .switchStmt(_, let cases, _):
            for c in cases { for s in c.body { collectGuardedVars(in: s, into: &guarded, pathResults: pathResults) } }
        default:
            break
        }
    }

    /// Returns the variable name a whitelist test targets, or nil.
    /// Handles `var.matches(...)`, `Regex.IsMatch(var, ...)` and their negations.
    private func whitelistTarget(in e: CExpr) -> String? {
        let unnegated: CExpr
        switch e {
        case .unary(_, let o, _):
            unnegated = o
        default:
            unnegated = e
        }

        switch unnegated {
        case .call(let callee, let args, _):
            switch callee {
            case .member(let base, let member, _, _):
                // `var.matches(pattern)`
                if member == "matches", let n = simpleIdentifier(base) { return n }
                // `strings.HasPrefix(var, safeRoot)` — Go containment guard: the
                // value is only used once confirmed to live under safeRoot.
                if member == "HasPrefix", lastSeg(callQualifiedName(base) ?? "") == "strings",
                   let first = args.first, let vName = simpleIdentifier(first) {
                    return vName
                }
                // `Regex.IsMatch(var, pattern)` — also the fully-qualified form
                // `System.Text.RegularExpressions.Regex.IsMatch(var, pattern)`.
                if member == "IsMatch", lastSeg(callQualifiedName(base) ?? "") == "Regex",
                   let first = args.first, let vName = simpleIdentifier(first) {
                    return vName
                }
                // `ns::only_identifier(tag)` — namespace-qualified free-function
                // validator (`idcheck::onlyIdentifier(tag)`), which parses as a
                // member call whose base is the namespace.
                if sanitizingFunctions[member] == "id",
                   simpleIdentifier(base) != nil,
                   let first = args.first, let vName = simpleIdentifier(first) {
                    return vName
                }
                return nil
            default:
                // Free-function rejecting validator: `only_identifier(tag)` —
                // a direct call to a classified cross-file validator whose
                // negation (`if (!F(x)) return;`) guards `x`.
                if case .identifier(let fnName, _) = callee,
                   sanitizingFunctions[fnName] == "id",
                   let first = args.first, let vName = simpleIdentifier(first) {
                    return vName
                }
                return nil
            }
        default:
            return nil
        }
    }

    /// The variable a `!path` / `path == NULL` null-check targets when `path`
    /// is the result of a path-sanitizer call (`if (!path) return;`).
    private func sanitizerNullGuard(in cond: CExpr, pathResults: Set<String>) -> String? {
        guard !pathResults.isEmpty else { return nil }
        func target(_ e: CExpr) -> String? {
            switch e {
            case .identifier(let n, _):
                return pathResults.contains(n) ? n : nil
            case .paren(let x, _), .cast(let x, _):
                return target(x)
            default:
                return nil
            }
        }
        switch cond {
        case .unary(let op, let o, _):
            if op == "!" { return target(o) }
            return nil
        case .binary(let op, let l, let r, _):
            // `path == NULL` / `path != NULL` / `NULL == path`
            if op == "==" || op == "!=" {
                if let n = target(l), isNullValue(r) { return n }
                if let n = target(r), isNullValue(l) { return n }
            }
            return nil
        default:
            return nil
        }
    }

    private func isNullValue(_ e: CExpr) -> Bool {
        switch e {
        case .identifier(let n, _):
            return n == "NULL" || n == "nullptr" || n == "null" || n == "false"
        case .integerLiteral(let v, _):
            return Int(v.trimmingCharacters(in: .whitespaces)).map { $0 == 0 } ?? false
        case .paren(let x, _), .cast(let x, _):
            return isNullValue(x)
        default:
            return false
        }
    }

    private func isNegated(_ e: CExpr) -> Bool {
        if case .unary(let op, _, _) = e, op == "!" { return true }
        return false
    }

    /// True if a statement unconditionally exits (a `return` at the end of the
    /// statement, or a block whose last statement returns).
    private func statementReturns(_ stmt: CStmt) -> Bool {
        switch stmt {
        case .returnStmt:
            return true
        case .block(let arr):
            return arr.last.map { statementReturns($0) } ?? false
        case .ifStmt:
            // treat conservatively: if both branches return, it returns
            return false
        default:
            return false
        }
    }

    /// True when a guarded-eligible argument is a variable that has already
    /// passed a whitelist rejection guard (only relevant for guardable
    /// categories). Handles both a bare guarded variable and an expression
    /// (e.g. a concatenation `prefix + input`) that references one.
    func isGuarded(_ e: CExpr, guarded: Set<String>, category: String) -> Bool {
        let guardableCats: Set<String> = ["Command Injection", "SQL Injection", "Path Traversal"]
        guard guardableCats.contains(category) else { return false }
        if guarded.isEmpty { return false }
        return referencesGuarded(e, guarded: guarded)
    }

    private func referencesGuarded(_ e: CExpr, guarded: Set<String>) -> Bool {
        switch e {
        case .identifier(let n, _):
            return guarded.contains(n)
        case .call(_, let args, _):
            return args.contains { referencesGuarded($0, guarded: guarded) }
        case .member(let b, _, _, _):
            return referencesGuarded(b, guarded: guarded)
        case .index(let b, let idx, _):
            return referencesGuarded(b, guarded: guarded) || referencesGuarded(idx, guarded: guarded)
        case .unary(_, let o, _):
            return referencesGuarded(o, guarded: guarded)
        case .binary(_, let l, let r, _), .comma(let l, let r, _):
            return referencesGuarded(l, guarded: guarded) || referencesGuarded(r, guarded: guarded)
        case .assign(_, let l, let r, _):
            return referencesGuarded(l, guarded: guarded) || referencesGuarded(r, guarded: guarded)
        case .ternary(let c, let t, let f, _):
            return referencesGuarded(c, guarded: guarded) || referencesGuarded(t, guarded: guarded) || referencesGuarded(f, guarded: guarded)
        case .cast(let x, _), .paren(let x, _):
            return referencesGuarded(x, guarded: guarded)
        case .arrayInit(let arr, _):
            return arr.contains { referencesGuarded($0, guarded: guarded) }
        case .newExpr(_, let args, _):
            return args.contains { referencesGuarded($0, guarded: guarded) }
        default:
            return false
        }
    }

    // MARK: - Size-bound guards

    /// Collects variable names that are provably bounded from above by an
    /// explicit size guard before/by the time a memory sink uses them, e.g.
    /// `if (len < cap) { memcpy(...len...) }` and `if (len > cap) return;`.
    /// Used to suppress buffer-overflow flags on exact-byte copies whose count
    /// is bounded by the destination capacity (the safe/negative patterns).
    private func sizeBoundedVars(in body: CStmt) -> Set<String> {
        var bounded = Set<String>()
        sizeBoundsWalk(body, into: &bounded)
        return bounded
    }

    /// Variables proven non-zero by a guard anywhere in the function body
    /// (`if (n != 0)`, `while (n > 0)`, `if (n == 0) return;`). Used to
    /// suppress division-by-zero findings for checked divisors.
    private func zeroCheckedVars(in body: CStmt) -> Set<String> {
        var checked = Set<String>()
        zeroCheckWalk(body, into: &checked)
        return checked
    }

    private func zeroCheckWalk(_ stmt: CStmt, into checked: inout Set<String>) {
        switch stmt {
        case .block(let arr):
            for s in arr { zeroCheckWalk(s, into: &checked) }
        case .ifStmt(let cond, let thenBranch, let elseBranch, _):
            let thenReturns = definitelyReturns(thenBranch)
            let elseReturns = elseBranch.map(definitelyReturns) ?? false
            for (varName, effOp) in zeroComparisons(in: cond) {
                // `if (n != 0) { ... }` or `if (n > 0) { ... }` — `n` is non-zero
                // inside the then branch.
                if effOp == "!=" || effOp == ">" { checked.insert(varName) }
                // `if (n == 0) return;` / `if (n <= 0) return;` — `n` is non-zero
                // in the rest of the function (the else branch).
                if effOp == "==", thenReturns { checked.insert(varName) }
                if effOp == "<=", thenReturns { checked.insert(varName) }
                // `if (n == 0) { ... } else { ... }` — `n` is non-zero in the
                // else branch.
                if effOp == "==", elseReturns { checked.insert(varName) }
                if effOp == "<=", elseReturns { checked.insert(varName) }
            }
            zeroCheckWalk(thenBranch, into: &checked)
            if let eb = elseBranch { zeroCheckWalk(eb, into: &checked) }
        case .whileStmt(let cond, let b, _), .doWhileStmt(let b, let cond, _):
            for (varName, effOp) in zeroComparisons(in: cond) {
                // `while (n != 0)` / `while (n > 0)` — `n` is non-zero inside
                // the loop body.
                if effOp == "!=" || effOp == ">" { checked.insert(varName) }
            }
            zeroCheckWalk(b, into: &checked)
        case .forStmt(_, _, _, let b, _):
            zeroCheckWalk(b, into: &checked)
        case .switchStmt(_, let cases, _):
            for c in cases { for s in c.body { zeroCheckWalk(s, into: &checked) } }
        case .labeledStmt(_, let s, _):
            zeroCheckWalk(s, into: &checked)
        default:
            break
        }
    }

    /// Extracts `(variable, effectiveOp)` pairs where the variable is compared
    /// against literal zero (via `<`, `>`, `==`, `!=`), with the effectiveOp
    /// expressed on the variable (`0 < len` and `len > 0` both yield `>`).
    private func zeroComparisons(in cond: CExpr) -> [(String, String)] {
        var out: [(String, String)] = []
        switch cond {
        case .binary(let op, let l, let r, _):
            if op == "||" || op == "&&" {
                out.append(contentsOf: zeroComparisons(in: l))
                out.append(contentsOf: zeroComparisons(in: r))
                return out
            }
            let isZero: (CExpr) -> Bool = { e in
                if case .integerLiteral(let s, _) = e { return s.trimmingCharacters(in: .alphanumerics.inverted) == "0" }
                return false
            }
            if isZero(l), let rk = sizePathKey(r) {
                if op == "!=" { out.append((rk, "!=")) }
                if op == "<" { out.append((rk, ">")) }
                if op == ">" { out.append((rk, "<")) }
                if op == "==" { out.append((rk, "==")) }
                if op == "<=" { out.append((rk, ">=")) }
                if op == ">=" { out.append((rk, "<=")) }
            } else if isZero(r), let lk = sizePathKey(l) {
                if op == "!=" { out.append((lk, "!=")) }
                if op == ">" { out.append((lk, ">")) }
                if op == "<" { out.append((lk, "<")) }
                if op == "==" { out.append((lk, "==")) }
                if op == ">=" { out.append((lk, ">=")) }
                if op == "<=" { out.append((lk, "<=")) }
            }
        case .paren(let x, _), .cast(let x, _):
            return zeroComparisons(in: x)
        default:
            break
        }
        return out
    }

    /// Variables only ever assigned string literals in the function body
    /// (`const char *format = "intel/ibt-%04x";`). A format argument that is
    /// such a variable is a constant format string, not a taint/format sink.
    /// (Boxed so the per-function cache can be updated without mutating the
    /// detector struct.)
    final class ConstantStringRefBox {
        var vars: Set<String> = []
    }
    let constantStringRef = ConstantStringRefBox()

    /// Variables proven non-zero by a guard (`if (n != 0)`, `while (n > 0)`,
    /// `if (n == 0) return;`) anywhere in the current function body. Used to
    /// suppress division-by-zero findings when the divisor is provably checked.
    /// (Boxed so the per-function cache can be updated without mutating the
    /// detector struct.)
    final class ZeroCheckedBox {
        var vars: Set<String> = []
    }
    let zeroCheckedRef = ZeroCheckedBox()

    /// Loop variables with constant `for` headers (`for (i = 0; i < 8; i++)`)
    /// for the current function, fed by the walk detector's cross-over facts.
    /// Consulted by the integer-overflow suppression only (see
    /// `checkCOverflowBinary`); loop bounds are never treated as spill-count
    /// capacities. (Boxed so the per-function value can be updated without
    /// mutating the detector struct.)
    final class OverflowConstBoundedBox {
        var vars: Set<String> = []
    }
    let overflowConstBoundedRef = OverflowConstBoundedBox()

    private func constantStringVars(in body: CStmt) -> Set<String> {
        var literalAssigns = Set<String>()
        var otherAssigns = Set<String>()

        func walkExpr(_ e: CExpr) {
            switch e {
            case .assign(_, let lhs, let rhs, _):
                if let n = simpleIdentifier(lhs) {
                    if case .stringLiteral = rhs { literalAssigns.insert(n) }
                    else { otherAssigns.insert(n) }
                }
                walkExpr(rhs)
            case .call(_, let args, _):
                for a in args { walkExpr(a) }
            case .binary(_, let l, let r, _), .comma(let l, let r, _):
                walkExpr(l); walkExpr(r)
            case .unary(_, let o, _), .cast(let o, _), .paren(let o, _):
                walkExpr(o)
            case .ternary(let c, let t, let f, _):
                walkExpr(c); walkExpr(t); walkExpr(f)
            case .member(let b, _, _, _):
                walkExpr(b)
            case .index(let b, let i, _):
                walkExpr(b); walkExpr(i)
            case .arrayInit(let els, _):
                for el in els { walkExpr(el) }
            case .newExpr(_, let args, _):
                for a in args { walkExpr(a) }
            case .sizeOf, .lambda, .integerLiteral, .floatLiteral, .stringLiteral, .charLiteral, .booleanLiteral, .identifier:
                break
            }
        }
        func walkStmt(_ s: CStmt) {
            switch s {
            case .block(let arr):
                for x in arr { walkStmt(x) }
            case .expr(let e):
                walkExpr(e)
            case .declaration(let d):
                if case .variable(_, let declName, let ie?) = d.kind {
                    if case .stringLiteral = ie { literalAssigns.insert(declName) }
                    else { otherAssigns.insert(declName) }
                    walkExpr(ie)
                }
            case .ifStmt(let cond, let t, let e, _):
                walkExpr(cond); walkStmt(t); if let e = e { walkStmt(e) }
            case .whileStmt(let cond, let b, _):
                walkExpr(cond); walkStmt(b)
            case .doWhileStmt(let b, let cond, _):
                walkStmt(b); walkExpr(cond)
            case .forStmt(let initS, let cond, let inc, let b, _):
                if let initS = initS { walkStmt(initS) }
                if let cond = cond { walkExpr(cond) }
                if let inc = inc { walkExpr(inc) }
                walkStmt(b)
            case .returnStmt(let e, _):
                if let e = e { walkExpr(e) }
            case .switchStmt(let expr, let cases, _):
                walkExpr(expr)
                for c in cases { for x in c.body { walkStmt(x) } }
            case .labeledStmt(_, let inner, _):
                walkStmt(inner)
            default:
                break
            }
        }
        walkStmt(body)
        return literalAssigns.subtracting(otherAssigns)
    }

    private func sizeBoundsWalk(_ stmt: CStmt, into bounded: inout Set<String>) {
        switch stmt {
        case .block(let arr):
            for s in arr { sizeBoundsWalk(s, into: &bounded) }
        case .ifStmt(let cond, let thenBranch, let elseBranch, _):
            let thenReturns = definitelyReturns(thenBranch)
            let elseReturns = elseBranch.map(definitelyReturns) ?? false
            for (varName, effOp) in sizeComparisons(in: cond) {
                // `if (len > cap) return;` — overlarge values are rejected, so
                // `len` is bounded for code that follows.
                if effOp == ">", thenReturns { bounded.insert(varName) }
                // `if (len > cap) { ... return; }` rejected in the else branch.
                else if effOp == "<", elseReturns { bounded.insert(varName) }
                // `if (len < cap) { use } ...` — a positive upper-bound guard.
                else if effOp == "<" { bounded.insert(varName) }
                // Clamp assignment: `if (x >= cap) x = cap - 1;` or
                // `if (x > cap) x = cap;` — after the guard, `x` can never
                // exceed the cap, so subsequent uses are bounded.
                else if effOp == ">", thenReturns == false,
                        isCapAssignment(thenBranch, varName: varName) {
                    bounded.insert(varName)
                }
                else if effOp == ">=", thenReturns == false,
                        isCapAssignment(thenBranch, varName: varName) {
                    bounded.insert(varName)
                }
            }
            // Relational sum guard: `if (a + b >= cap) return;` — after the
            // guard, both `a` and `b` are bounded by `cap` (since `a + b < cap`).
            if thenReturns, let sumVars = sumGuardVariables(in: cond) {
                for v in sumVars { bounded.insert(v) }
            }
            sizeBoundsWalk(thenBranch, into: &bounded)
            if let eb = elseBranch { sizeBoundsWalk(eb, into: &bounded) }
        case .whileStmt(_, let b, _), .doWhileStmt(let b, _, _):
            sizeBoundsWalk(b, into: &bounded)
        case .forStmt(_, _, _, let b, _):
            sizeBoundsWalk(b, into: &bounded)
        case .switchStmt(_, let cases, _):
            for c in cases { for s in c.body { sizeBoundsWalk(s, into: &bounded) } }
        case .labeledStmt(_, let s, _):
            sizeBoundsWalk(s, into: &bounded)
        case .declaration(let d):
            // Alias propagation: `m = n;` (or a min-clamp `n = (x < cap) ? x : cap;`)
            // carries the bound of the right side onto the new variable.
            if case .variable(_, let name, let initExpr) = d.kind,
               let rhs = initExpr, assignmentBoundsName(rhs, bounded: bounded) {
                bounded.insert(name)
            }
        case .expr(let e):
            if case .assign(_, let lhs, let rhs, _) = e,
               let name = simpleIdentifier(lhs), assignmentBoundsName(rhs, bounded: bounded) {
                bounded.insert(name)
            }
        default:
            break
        }
    }

    /// Renders the addressable name of an expression as a stability key:
    /// `len` for a plain identifier, `kb.len` for `kb->len`, `tbl[0]` for
    /// `tbl[0]`. Used so both size guards (`kb->len > cap`) and their size
    /// arguments (`memcpy(... kb->len)`) compare against the same key.
    private func sizePathKey(_ e: CExpr) -> String? {
        switch e {
        case .identifier(let n, _):
            return n
        case .member(let base, let name, _, _):
            guard let bk = sizePathKey(base) else { return nil }
            return "\(bk).\(name)"
        case .index(let base, let idx, _):
            guard let bk = sizePathKey(base), let ik = sizePathKey(idx) else { return nil }
            return "\(bk)[\(ik)]"
        case .paren(let x, _), .cast(let x, _):
            return sizePathKey(x)
        default:
            return nil
        }
    }

    /// Extracts `(variable, effectiveOp)` pairs from a condition, where the
    /// effectiveOp expresses the comparison *on the variable* (`len < cap` and
    /// `cap > len` both yield `<`; `len > cap` and `cap < len` both yield `>`).
    private func sizeComparisons(in cond: CExpr) -> [(String, String)] {
        var out: [(String, String)] = []
        switch cond {
        case .binary(let op, let l, let r, _):
            if op == "||" {
                out.append(contentsOf: sizeComparisons(in: l))
                out.append(contentsOf: sizeComparisons(in: r))
                return out
            }
            let gtOps: Set<String> = [">", ">="]
            let ltOps: Set<String> = ["<", "<="]
            if let lk = sizePathKey(l) {
                if gtOps.contains(op) { out.append((lk, ">")) }
                else if ltOps.contains(op) { out.append((lk, "<")) }
            } else if let rk = sizePathKey(r) {
                if gtOps.contains(op) { out.append((rk, "<")) }
                else if ltOps.contains(op) { out.append((rk, ">")) }
            }
        case .paren(let x, _), .cast(let x, _):
            return sizeComparisons(in: x)
        default:
            break
        }
        return out
    }

    /// True when a statement cannot fall through (used to recognize
    /// `if (... ) return;` guard patterns).
    func definitelyReturns(_ stmt: CStmt) -> Bool {
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

    /// True when a size/count expression is provably bounded: a literal, a
    /// `sizeof`, a variable proven bounded by an earlier guard, or a `var - const`
    /// form thereof (e.g. `strncpy(dst, src, dstsize - 1)`).
    func sizeArgSafe(_ e: CExpr, sizeBounded: Set<String>) -> Bool {
        switch e {
        case .integerLiteral, .floatLiteral, .charLiteral, .sizeOf:
            return true
        case .paren(let x, _), .cast(let x, _):
            return sizeArgSafe(x, sizeBounded: sizeBounded)
        case .identifier(let n, _):
            return sizeBounded.contains(n)
        case .member, .index:
            if let key = sizePathKey(e) { return sizeBounded.contains(key) }
            return false
        case .ternary(_, let t, let f, _):
            // Min-clamp: `n = (len < cap) ? len : cap` is bounded when at least
            // one branch is a proven length and the other is a capacity (or also
            // a proven length). Both branches unproven => not bounded.
            let ts = sizeArgSafe(t, sizeBounded: sizeBounded)
            let fs = sizeArgSafe(f, sizeBounded: sizeBounded)
            if ts && fs { return true }
            let ti = isPlainScopedIdentifier(t)
            let fi = isPlainScopedIdentifier(f)
            return (ts && fi) || (fs && ti)
        case .binary(let op, let l, let r, _):
            if op == "+" { return sizeArgSafe(l, sizeBounded: sizeBounded) && sizeArgSafe(r, sizeBounded: sizeBounded) }
            if op == "-" { return sizeArgSafe(l, sizeBounded: sizeBounded) && isPlainLiteral(r) }
            if op == "*" { return sizeArgSafe(l, sizeBounded: sizeBounded) && sizeArgSafe(r, sizeBounded: sizeBounded) }
            return false
        default:
            return false
        }
    }

    private func isPlainLiteral(_ e: CExpr) -> Bool {
        switch e {
        case .integerLiteral, .floatLiteral, .charLiteral: return true
        case .paren(let x, _), .cast(let x, _): return isPlainLiteral(x)
        default: return false
        }
    }

    /// True when an expression is a bare variable/capacity reference (an
    /// identifier, possibly parenthesised/cast) — the else-branch of a
    /// min-clamp: `(len < cap) ? len : cap`.
    private func isPlainScopedIdentifier(_ e: CExpr) -> Bool {
        switch e {
        case .identifier: return true
        case .paren(let x, _), .cast(let x, _): return isPlainScopedIdentifier(x)
        default: return false
        }
    }

    /// True when an expression is provably bounded as a copy count: provably
    /// bounded by guards/aliases, or an explicit min-clamp against a capacity.
    private func assignmentBoundsName(_ rhs: CExpr, bounded: Set<String>) -> Bool {
        if sizeArgSafe(rhs, sizeBounded: bounded) { return true }
        switch rhs {
        case .ternary(_, let t, let f, _):
            let ts = sizeArgSafe(t, sizeBounded: bounded)
            let fs = sizeArgSafe(f, sizeBounded: bounded)
            if ts && fs { return true }
            return (ts && isPlainScopedIdentifier(f)) || (fs && isPlainScopedIdentifier(t))
        case .paren(let x, _), .cast(let x, _):
            return assignmentBoundsName(x, bounded: bounded)
        default:
            return false
        }
    }

    /// True when `thenBranch` contains an assignment of the form
    /// `varName = cap - 1` or `varName = cap` (the clamp idiom), where `cap`
    /// is a plain identifier and the right side is a `cap - const` form.
    private func isCapAssignment(_ stmt: CStmt, varName: String) -> Bool {
        switch stmt {
        case .block(let arr):
            return arr.contains { isCapAssignment($0, varName: varName) }
        case .expr(let e):
            return isCapAssignmentExpr(e, varName: varName)
        case .declaration:
            return false
        default:
            return false
        }
    }

    private func isCapAssignmentExpr(_ e: CExpr, varName: String) -> Bool {
        switch e {
        case .assign(_, let lhs, let rhs, _):
            if let n = simpleIdentifier(lhs), n == varName {
                return isCapMinusConst(rhs) || isPlainIdentifier(rhs)
            }
            return false
        case .paren(let x, _), .cast(let x, _):
            return isCapAssignmentExpr(x, varName: varName)
        default:
            return false
        }
    }

    private func isCapMinusConst(_ e: CExpr) -> Bool {
        switch e {
        case .binary(let op, let l, let r, _):
            if op == "-", isPlainIdentifier(l), isPlainLiteral(r) { return true }
            return false
        case .paren(let x, _), .cast(let x, _):
            return isCapMinusConst(x)
        default:
            return false
        }
    }

    private func isPlainIdentifier(_ e: CExpr) -> Bool {
        if case .identifier = e { return true }
        return false
    }

    /// Extracts variables from a binary `+` expression on the left side of a
    /// `>=`/`>` guard, e.g. `if (used + more >= cap) return;` → `[used, more]`.
    private func sumGuardVariables(in cond: CExpr) -> [String]? {
        switch cond {
        case .binary(let op, let l, let r, _):
            guard op == ">=" || op == ">" else { return nil }
            // The guard must compare a sum against a size budget (`sizeof`, an
            // integer literal, or a capacity variable like `cap`) so the derived
            // bounds are meaningful:
            //   `if (bl + 1 + ll + 1 > sizeof joined) return;`
            //   `if (used + more >= cap) return -1;   /* would overflow */`
            if !isSizeBudget(r) { return nil }
            var vars: [String] = []
            var ok = collectSumIdentifiers(l, into: &vars)
            if vars.isEmpty { ok = false }
            return ok ? vars : nil
        case .paren(let x, _), .cast(let x, _):
            return sumGuardVariables(in: x)
        default:
            return nil
        }
    }

    private func isSizeBudget(_ e: CExpr) -> Bool {
        switch e {
        case .integerLiteral, .floatLiteral, .charLiteral, .sizeOf, .identifier:
            return true
        case .paren(let x, _), .cast(let x, _):
            return isSizeBudget(x)
        default:
            return false
        }
    }

    /// Collects identifier operands from a `+` chain (`bl + 1 + ll + 1` → bl,
    /// ll), skipping integer/char constants and sizeof subexpressions. Returns
    /// false if the expression is not a pure additive chain of identifiers and
    /// constants.
    private func collectSumIdentifiers(_ e: CExpr, into out: inout [String]) -> Bool {
        switch e {
        case .identifier(let n, _):
            out.append(n)
            return true
        case .integerLiteral, .floatLiteral, .charLiteral, .sizeOf:
            return true
        case .binary(let op, let l, let r, _):
            guard op == "+" else { return false }
            return collectSumIdentifiers(l, into: &out) && collectSumIdentifiers(r, into: &out)
        case .paren(let x, _), .cast(let x, _):
            return collectSumIdentifiers(x, into: &out)
        default:
            return false
        }
    }

    // MARK: - Taint

    private func plainSourceCall(_ e: CExpr) -> String? {
        if case .call(let callee, _, _) = e {
            // Match simple identifier calls and member-qualified calls against
            // the seed set so cross-file taint-returning functions defined in
            // other files are recognized as sources.
            if case .identifier(let n, _) = callee, isSeedFn(n) { return n }
            if let q = callQualifiedName(callee), isSeedFn(q) { return q }
            if let m = callName(callee), isSeedFn(m) { return m }
        }
        if case .member(let b, _, _, _) = e { return plainSourceCall(b) }
        return nil
    }

    func crossFileSourceCall(_ e: CExpr) -> String? {
        if case .call(let callee, _, _) = e {
            if case .identifier(let n, _) = callee, crossFileSources.contains(n) { return n }
            if let q = callQualifiedName(callee), crossFileSources.contains(q) { return q }
            if let m = callName(callee), crossFileSources.contains(m) { return m }
        }
        if case .member(let b, _, _, _) = e { return crossFileSourceCall(b) }
        return nil
    }

    func exprCrossFile(_ e: CExpr, crossTainted: Set<String>) -> Bool {
        // TRUE if the expression's taint root originates from a cross-file source.
        if crossFileSourceCall(e) != nil { return true }
        switch e {
        case .identifier(let n, _):
            return crossTainted.contains(n)
        case .call(let callee, let args, _):
            for a in args { if exprCrossFile(a, crossTainted: crossTainted) { return true } }
            // `cmd.c_str()` retains the receiver's cross-file taint.
            if case .member(let base, _, _, _) = callee, exprCrossFile(base, crossTainted: crossTainted) { return true }
            return false
        case .member(let b, _, _, _):
            return exprCrossFile(b, crossTainted: crossTainted)
        case .index(let b, let idx, _):
            return exprCrossFile(b, crossTainted: crossTainted) || exprCrossFile(idx, crossTainted: crossTainted)
        case .unary(_, let o, _):
            return exprCrossFile(o, crossTainted: crossTainted)
        case .binary(_, let l, let r, _), .comma(let l, let r, _):
            return exprCrossFile(l, crossTainted: crossTainted) || exprCrossFile(r, crossTainted: crossTainted)
        case .assign(_, let l, let r, _):
            return exprCrossFile(l, crossTainted: crossTainted) || exprCrossFile(r, crossTainted: crossTainted)
        case .ternary(let c, let t, let f, _):
            return exprCrossFile(c, crossTainted: crossTainted) || exprCrossFile(t, crossTainted: crossTainted) || exprCrossFile(f, crossTainted: crossTainted)
        case .cast(let x, _), .paren(let x, _):
            return exprCrossFile(x, crossTainted: crossTainted)
        case .sizeOf(let x, _, _):
            return x.map { exprCrossFile($0, crossTainted: crossTainted) } ?? false
        case .arrayInit(let arr, _):
            for a in arr { if exprCrossFile(a, crossTainted: crossTainted) { return true } }
            return false
        case .newExpr(_, let args, _):
            for a in args { if exprCrossFile(a, crossTainted: crossTainted) { return true } }
            return false
        default:
            return false
        }
    }

    /// Returns a taint label if `e` references a tainted variable, a source/taint-
    /// returning call, or contains one transitively.
    /// Script languages seed taint from framework source identifiers; the
    /// C-family/Solidity engines keep their stricter, list-driven semantics.
    private var scriptSeedIdentifiers: Bool {
        isPython || isRuby || isGo || isRust || isKotlin || isPHP
    }

    func exprTainted(_ e: CExpr, tainted: Set<String>) -> String? {
        switch e {
        case .identifier(let n, _):
            if tainted.contains(n) { return n }
            // Script-language framework source roots (`request`, `params`,
            // `env`, …) are attacker-controlled data by definition.
            if scriptSeedIdentifiers, isSeedFn(n) { return n }
            return nil
        case .call(let callee, let args, _):
            // A call that returns tainted data (from a source API or a function
            // that transitively returns tainted data, including defined in
            // another file) taints the whole call expression.
            if case .identifier(let cname, _) = callee, isSeedFn(cname) { return cname }
            if let q = callQualifiedName(callee), isSeedFn(q) { return q }
            if let m = callName(callee), isSeedFn(m) { return m }
            // A call on a tainted receiver stays tainted
            // (`request.args.get(..)`, `params.url.clone()`).
            if scriptSeedIdentifiers, let t = exprTainted(callee, tainted: tainted) { return t }
            // A method call on a tainted receiver (`cmd.c_str()`,
            // `user.toLower()`, `params.url.clone()`) retains the receiver's
            // taint in every language, not just script frameworks.
            if case .member(let base, _, _, _) = callee, let t = exprTainted(base, tainted: tainted) { return t }
            // Sanitizing calls produce a clean value: their output does not
            // carry the taint of the raw input passed into them.
            if let m = callName(callee), ["basename", "htmlspecialchars", "htmlentities",
                                          "preg_quote", "escapeshellarg", "urlencode",
                                          "rawurlencode", "HtmlEncode", "HtmlAttributeEncode",
                                          "UrlEncode", "UrlPathEncode", "JavaScriptStringEncode"].contains(m) {
                return nil
            }
            if let q = callQualifiedName(callee), ["bleach.clean", "html.escape", "cgi.escape",
                                                   "markupsafe.escape", "html.escape_s",
                                                   "HtmlEncoder.escape", "HtmlEncoder.escapeHtml",
                                                   "HtmlEncoder.htmlEscape", "HttpUtility.HtmlEncode",
                                                   "WebUtility.HtmlEncode", "Server.HtmlEncode",
                                                   "HttpUtility.HtmlAttributeEncode",
                                                   "System.Text.Encodings.Web.HtmlEncoder.Encode"].contains(q) {
                return nil
            }
            // Cross-file registered sanitizers (validators/path sanitizers
            // classified by ProjectIndex) strip taint from their return value.
            if let m = callName(callee), sanitizingFunctions[m] != nil {
                return nil
            }
            if let q = callQualifiedName(callee), sanitizingFunctions[q] != nil {
                return nil
            }
            for a in args {
                if let t = exprTainted(a, tainted: tainted) { return t }
            }
            return nil
        case .member(let b, _, _, _):
            return exprTainted(b, tainted: tainted)
        case .index(let b, let idx, _):
            return exprTainted(b, tainted: tainted) ?? exprTainted(idx, tainted: tainted)
        case .unary(_, let o, _):
            return exprTainted(o, tainted: tainted)
        case .binary(_, let l, let r, _), .comma(let l, let r, _):
            return exprTainted(l, tainted: tainted) ?? exprTainted(r, tainted: tainted)
        case .assign(_, let l, let r, _):
            return exprTainted(l, tainted: tainted) ?? exprTainted(r, tainted: tainted)
        case .ternary(let c, let t, let f, _):
            return exprTainted(c, tainted: tainted) ?? exprTainted(t, tainted: tainted) ?? exprTainted(f, tainted: tainted)
        case .cast(let x, _), .paren(let x, _):
            return exprTainted(x, tainted: tainted)
        case .sizeOf(let x, _, _):
            return x.flatMap { exprTainted($0, tainted: tainted) }
        case .arrayInit(let arr, _):
            for a in arr { if let t = exprTainted(a, tainted: tainted) { return t } }
            return nil
        case .newExpr(_, let args, _):
            for a in args { if let t = exprTainted(a, tainted: tainted) { return t } }
            return nil
        case .stringLiteral(let s, _):
            // PHP string interpolation: detect tainted superglobals inside double-quoted strings
            // e.g. "ping -c $_SESSION[count] $_POST[host]"
            if isPHP {
                let phpTaintedGlobals = ["_POST", "_GET", "_REQUEST", "_SERVER", "_ENV", "_COOKIE", "_FILES", "_SESSION"]
                for global in phpTaintedGlobals {
                    // Match $GLOBAL[...] or ${GLOBAL[...]} patterns
                    if s.contains("$" + global + "[") || s.contains("${" + global + "[") {
                        return global
                    }
                }
            }
            return nil
        default:
            return nil
        }
    }

    func taintLabel(_ e: CExpr, tainted: Set<String>) -> String? {
        if case .call(let callee, let args, _) = e {
            if case .identifier(let n, _) = callee { return "\(n)()" }
            for a in args { if let t = taintLabel(a, tainted: tainted) { return t } }
        }
        return exprTainted(e, tainted: tainted)
    }

    func simpleIdentifier(_ e: CExpr) -> String? {
        if case .identifier(let n, _) = e, !n.isEmpty { return n }
        return nil
    }

    func stringLiteralOf(_ e: CExpr?) -> String? {
        guard case .stringLiteral(let s, _)? = e else { return nil }
        // The tokenizer stores the raw text including surrounding quotes; strip
        // them (plus any language prefix like `L`/`u8`) so content checks match.
        var v = s
        if v.hasPrefix("\"") && v.hasSuffix("\"") && v.count >= 2 {
            v = String(v.dropFirst().dropLast())
        }
        return v
    }

    // MARK: - Output

    func emit(_ findings: inout [AstFinding], _ function: String, _ offset: Int, _ rule: AstSinkRule,
                      message: String, taint: String?, reachable: Bool, crossFile: Bool) {
        findings.append(AstFinding(function: function,
                                   offset: offset,
                                   category: rule.category,
                                   severity: rule.severity,
                                   message: message,
                                   taintPath: taint,
                                   reachable: reachable,
                                   crossFile: crossFile))
    }

    func isWeakAlgorithm(_ s: String) -> Bool {
        let low = s.lowercased()
        if low == "md5" || low == "sha1" || low == "md5-sha1" || low == "des" || low == "desede" || low == "rc2" || low == "rc4" { return true }
        if low.hasPrefix("aes/ecb") || low.contains("/ecb/") { return true }
        return false
    }

}

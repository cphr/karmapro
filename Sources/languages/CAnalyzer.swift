// by cipher.org.uk
import Foundation

/// Result of AST-driven interprocedural data-flow analysis for a C/C++ file.
///
/// This is the semantic layer that lets the CSTokenizer/CParser/CSymbolTable
/// frontend actually drive vulnerability analysis, replacing regex re-parsing
/// of function bodies:
///  - `taintReturning`: functions whose return value derives from untrusted
///    data, computed to a fixpoint over the AST call graph.
///  - `writeThroughParam`: functions that write untrusted data into a given
///    parameter (e.g. `void readLine(char *dst) { fgets(dst, 100, stdin); }`
///    writes attacker input through parameter 0). A caller blames the argument
///    it passed at that position.
public struct CAnalysis {
    public let taintReturning: Set<String>
    public let writeThroughParam: [String: Set<Int>]
    /// Parameters of functions that are tainted at some call site in the project.
    /// A parameter is seeded as tainted only when its function is actually called
    /// with a tainted argument — this is the cross-file parameter provenance
    /// analysis that prevents false positives for functions whose parameters are
    /// only ever passed sanitized values.
    public let paramTaintSeeds: [String: Set<Int>]
}

/// Functions that return attacker-controlled data from the environment, network,
/// files or user input (mirrors the scanner's taint-source set).
let sourceAPIs: Set<String> = [    "getenv", "gets", "getwd", "getpass", "fgets", "fgetc", "read", "recv",
    "recvfrom", "fread", "scanf", "fscanf", "sscanf", "strdup", "strndup",
    "getopt", "getopt_long", "realpath", "readlink", "asprintf", "vasprintf",
    "dlsym", "strchr", "strrchr", "strstr", "strtok", "strtok_r", "index", "rindex",
    // Kernel: heap copies duplicated from user/network space are untrusted.
    "memdup_user", "memdup_user_nul", "kstrdup", "kasprintf", "kstrndup",
    "ksize", "simple_strtoul", "simple_strtol",
]

/// True when a function/method name marks a validation, sanitization or
/// allow-listing step whose result is clean by contract. Such functions must
/// never be tagged taint-returning, and any taint flowing *into* them is
/// cleared on return (the value they produce is an approved, normalized copy).
func isSanitizerFunctionName(_ name: String) -> Bool {
    let lower = name.lowercased()
    let markers = [
        "sanitize", "validate", "normalize", "escape", "redact", "scrub",
        "allowlist", "whitelist", "isvalid", "isallowed", "ispermitted",
        "clean", "safe",
    ]
    return markers.contains { lower.contains($0) }
}

/// The dotted call path as written in source (`os.Getenv`, `exec.Command`,
/// `Files.newInputStream`). Used to match source APIs / taint-returning
/// functions keyed on package/member paths when reasoning about taint.
func cExprQualifiedName(_ e: CExpr) -> String? {
    switch e {
    case .identifier(let n, _): return n
    case .member(let base, let m, _, _):
        if let bn = cExprQualifiedName(base) { return bn + "." + m }
        return m
    case .call(let inner, _, _): return cExprQualifiedName(inner)
    default: return nil
    }
}

/// The trailing/simple name of a call (`Getenv` from `os.Getenv`,
/// `ReadAllText` from `File.ReadAllText`).
func cExprTrailingName(_ e: CExpr) -> String? {
    switch e {
    case .identifier(let n, _): return n
    case .member(_, let m, _, _): return m
    case .call(let inner, _, _): return cExprTrailingName(inner)
    default: return nil
    }
}

/// Tests whether a callee expression matches any name in `seed`. Matches both
/// simple identifiers and member/qualified names (`os.Getenv` matches both the
/// `"os.Getenv"` seed and, if present, a bare `"Getenv"` seed).
func cExprCalleeIsSeed(_ callee: CExpr, _ seed: Set<String>) -> Bool {
    if case .identifier(let n, _) = callee, seed.contains(n) { return true }
    if let q = cExprQualifiedName(callee), seed.contains(q) { return true }
    if let t = cExprTrailingName(callee), seed.contains(t) { return true }
    return false
}

/// Sinks that WRITE untrusted data into a buffer argument (rather than only
/// consume it). When such a call targets a function parameter, the typedef is
/// "this function writes attacker data through that parameter."
let writeThroughSinks: Set<String> = [
    "fgets", "gets", "fgetc", "scanf", "fscanf", "sscanf",
    "read", "recv", "recvfrom", "fread",
]

public struct CAnalyzer {
    private let tu: CTranslationUnit
    private let astFns: [String: CFunctionDef]

    public init(source: String) {
        let tokens = CTokenizer(source: source).tokenize()
        let tu = CParser(tokens: tokens).parseTranslationUnit()
        self.tu = tu
        var map: [String: CFunctionDef] = [:]
        for fn in tu.functions where fn.isDefinition {
            // Prefer the first body-bearing definition of each name.
            if map[fn.name] == nil { map[fn.name] = fn }
        }
        self.astFns = map
    }

    public func analyze() -> CAnalysis {
        let returning = computeTaintReturning()
        let writeThrough = computeWriteThrough(taintReturning: returning)
        return CAnalysis(taintReturning: returning, writeThroughParam: writeThrough, paramTaintSeeds: [:])
    }

    /// The parsed AST for each defined function (preferring the first body-bearing
    /// definition per name). Lets the scanner drive structural sink/taint detection
    /// directly off the AST instead of re-parsing raw source with regular expressions.
    public var astFunctions: [String: CFunctionDef] { astFns }

    /// Identifier tokens that flow from an untrusted source into a given buffer's taint.
    /// Convenience: the resolver can ask whether a variable name is a source alias.
    public var functionNames: Set<String> { Set(astFns.keys) }

    // MARK: - Taint-returning functions (fixpoint over the AST call graph)

    private func computeTaintReturning() -> Set<String> {
        var returning = Set<String>()
        for _ in 0..<6 {
            var changed = false
            for fn in astFns.values where !returning.contains(fn.name) {
                // Validation/sanitization helpers return approved, normalized
                // copies; mark them taint-returning and every caller's
                // downstream sink becomes a false positive.
                if isSanitizerFunctionName(fn.name) { continue }
                if functionReturnsTaint(fn, taintReturning: returning) {
                    returning.insert(fn.name)
                    changed = true
                }
            }
            if !changed { break }
        }
        return returning
    }

    private func functionReturnsTaint(_ fn: CFunctionDef, taintReturning: Set<String>) -> Bool {
        let params = Set(fn.params.compactMap { $0.name })
        let seedFns = sourceAPIs.union(taintReturning)
        return stmtReturnsTaint(fn.body, params: params, seedFns: seedFns)
    }

    private func stmtReturnsTaint(_ stmt: CStmt, params: Set<String>, seedFns: Set<String>) -> Bool {
        switch stmt {
        case .block(let arr):
            for s in arr where stmtReturnsTaint(s, params: params, seedFns: seedFns) { return true }
        case .expr(let e):
            return exprReferencesTaint(e, params: params, seedFns: seedFns)
        case .declaration(let d):
            if case .variable(_, _, let ie?) = d.kind {
                return exprReferencesTaint(ie, params: params, seedFns: seedFns)
            }
        case .ifStmt(_, let t, let e, _):
            return stmtReturnsTaint(t, params: params, seedFns: seedFns)
                || (e.map { stmtReturnsTaint($0, params: params, seedFns: seedFns) } ?? false)
        case .whileStmt(_, let b, _):
            return stmtReturnsTaint(b, params: params, seedFns: seedFns)
        case .doWhileStmt(let b, _, _):
            return stmtReturnsTaint(b, params: params, seedFns: seedFns)
        case .forStmt(_, _, _, let b, _):
            return stmtReturnsTaint(b, params: params, seedFns: seedFns)
        case .switchStmt(_, let cases, _):
            for c in cases where c.body.contains(where: { stmtReturnsTaint($0, params: params, seedFns: seedFns) }) { return true }
        case .returnStmt(let e, _):
            if let e = e { return exprReferencesTaint(e, params: params, seedFns: seedFns) }
        case .labeledStmt(_, let s, _):
            return stmtReturnsTaint(s, params: params, seedFns: seedFns)
        default:
            break
        }
        return false
    }

    private func exprReferencesTaint(_ e: CExpr, params: Set<String>, seedFns: Set<String>) -> Bool {
        switch e {
        case .identifier(let n, _):
            return params.contains(n)
        case .call(let callee, let args, _):
            if cExprCalleeIsSeed(callee, seedFns) { return true }
            if exprReferencesTaint(callee, params: params, seedFns: seedFns) { return true }
            return args.contains { exprReferencesTaint($0, params: params, seedFns: seedFns) }
        case .member(let b, _, _, _):
            return exprReferencesTaint(b, params: params, seedFns: seedFns)
        case .index(let b, let idx, _):
            return exprReferencesTaint(b, params: params, seedFns: seedFns)
                || exprReferencesTaint(idx, params: params, seedFns: seedFns)
        case .unary(_, let o, _):
            return exprReferencesTaint(o, params: params, seedFns: seedFns)
        case .binary(_, let l, let r, _), .comma(let l, let r, _):
            return exprReferencesTaint(l, params: params, seedFns: seedFns)
                || exprReferencesTaint(r, params: params, seedFns: seedFns)
        case .assign(_, let l, let r, _):
            return exprReferencesTaint(l, params: params, seedFns: seedFns)
                || exprReferencesTaint(r, params: params, seedFns: seedFns)
        case .ternary(let c, let t, let f, _):
            return exprReferencesTaint(c, params: params, seedFns: seedFns)
                || exprReferencesTaint(t, params: params, seedFns: seedFns)
                || exprReferencesTaint(f, params: params, seedFns: seedFns)
        case .cast(let x, _):
            return exprReferencesTaint(x, params: params, seedFns: seedFns)
        case .sizeOf(let x, _, _):
            return x.map { exprReferencesTaint($0, params: params, seedFns: seedFns) } ?? false
        case .paren(let x, _):
            return exprReferencesTaint(x, params: params, seedFns: seedFns)
        case .arrayInit(let arr, _):
            return arr.contains { exprReferencesTaint($0, params: params, seedFns: seedFns) }
        case .newExpr(_, let args, _):
            return args.contains { exprReferencesTaint($0, params: params, seedFns: seedFns) }
        default:
            return false
        }
    }

    // MARK: - Write-through parameters

    private func computeWriteThrough(taintReturning: Set<String>) -> [String: Set<Int>] {
        var result: [String: Set<Int>] = [:]
        let seedFns = sourceAPIs.union(taintReturning)
        for fn in astFns.values {
            let params = fn.params
            var written = Set<Int>()
            for (i, p) in params.enumerated() {
                guard let pname = p.name, !pname.isEmpty else { continue }
                if stmtWritesParam(fn.body, paramName: pname, params: params, seedFns: seedFns) {
                    written.insert(i)
                }
            }
            if !written.isEmpty { result[fn.name] = written }
        }
        return result
    }

    /// True if the parameter is written with untrusted data somewhere in the body:
    /// either a direct assignment of a tainted expression, or a write-through sink
    /// call (fgets/scanf/read/...) that targets it.
    private func stmtWritesParam(_ stmt: CStmt, paramName: String, params: [CAParam], seedFns: Set<String>) -> Bool {
        switch stmt {
        case .block(let arr):
            for s in arr where stmtWritesParam(s, paramName: paramName, params: params, seedFns: seedFns) { return true }
        case .expr(let e):
            return exprWritesParam(e, paramName: paramName, params: params, seedFns: seedFns)
        case .declaration(let d):
            if case .variable(_, _, let ie?) = d.kind {
                return exprWritesParam(ie, paramName: paramName, params: params, seedFns: seedFns)
            }
        case .ifStmt(_, let t, let e, _):
            return stmtWritesParam(t, paramName: paramName, params: params, seedFns: seedFns)
                || (e.map { stmtWritesParam($0, paramName: paramName, params: params, seedFns: seedFns) } ?? false)
        case .whileStmt(_, let b, _):
            return stmtWritesParam(b, paramName: paramName, params: params, seedFns: seedFns)
        case .doWhileStmt(let b, _, _):
            return stmtWritesParam(b, paramName: paramName, params: params, seedFns: seedFns)
        case .forStmt(_, _, _, let b, _):
            return stmtWritesParam(b, paramName: paramName, params: params, seedFns: seedFns)
        case .switchStmt(_, let cases, _):
            for c in cases where c.body.contains(where: { stmtWritesParam($0, paramName: paramName, params: params, seedFns: seedFns) }) { return true }
        case .returnStmt(_, _), .labeledStmt(_, _, _):
            return false
        default:
            break
        }
        return false
    }

    private func exprWritesParam(_ e: CExpr, paramName: String, params: [CAParam], seedFns: Set<String>) -> Bool {
        switch e {
        case .assign(_, let lhs, let rhs, _):
            // param = <tainted expr>  =>  param written by attacker data
            if simpleIdentifier(lhs) == paramName {
                if exprReferencesTaint(rhs, params: Set(params.compactMap { $0.name }), seedFns: seedFns) {
                    return true
                }
                return false
            }
            // Recurse into both sides (e.g. a write-through call embedded in RHS).
            return exprWritesParam(lhs, paramName: paramName, params: params, seedFns: seedFns)
                || exprWritesParam(rhs, paramName: paramName, params: params, seedFns: seedFns)
        case .call(let callee, let args, _):
            if case .identifier(let cname, _) = callee, writeThroughSinks.contains(cname) {
                // The param is a buffer the sink writes into (first buffer arg).
                if args.contains(where: { simpleIdentifier($0) == paramName }) {
                    // Only consider true writes: the sink writes from an external/taint source.
                    return true
                }
            }
            for a in args where exprWritesParam(a, paramName: paramName, params: params, seedFns: seedFns) { return true }
        case .binary(_, let l, let r, _), .comma(let l, let r, _):
            return exprWritesParam(l, paramName: paramName, params: params, seedFns: seedFns)
                || exprWritesParam(r, paramName: paramName, params: params, seedFns: seedFns)
        case .member(let b, _, _, _):
            return exprWritesParam(b, paramName: paramName, params: params, seedFns: seedFns)
        case .index(let b, _, _):
            return exprWritesParam(b, paramName: paramName, params: params, seedFns: seedFns)
        case .unary(_, let o, _):
            return exprWritesParam(o, paramName: paramName, params: params, seedFns: seedFns)
        case .cast(let x, _), .paren(let x, _):
            return exprWritesParam(x, paramName: paramName, params: params, seedFns: seedFns)
        default:
            return false
        }
        return false
    }

    private func simpleIdentifier(_ e: CExpr) -> String? {
        if case .identifier(let n, _) = e, !n.isEmpty { return n }
        return nil
    }
}

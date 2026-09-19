// by cipher.org.uk
import Foundation

/// A resolved symbol: name, its declared type, and structural facts that
/// taint analysis needs (is it a fixed-size array, a pointer, a scalar).
public struct CSymbol {
    public let name: String
    public let type: String?
    public let offset: Int
    public let isArray: Bool
    public let isPointer: Bool
    public let isParam: Bool
    public let isReference: Bool
}

/// A single interprocedural fact gathered from a function body: a call site,
/// an assignment of one identifier to another, a return, or a sink-adjacent use.
public enum CFlowFact {
    case call(callee: String, argOffsets: [Int], offset: Int)
    case assign(target: String, source: String, offset: Int)   // target = source (both simple identifiers)
    case sinkCall(callee: String, argOffsets: [Int], offset: Int)
    case returnVar(String, Int)                                 // return <identifier>
}

/// Per-function analysis: symbol scopes + flow facts, used to drive CFG/taint.
public struct CFunctionSummary {
    public let name: String
    public let params: [CAParam]
    public let returnType: String?
    public let symbols: [String: CSymbol]     // name -> resolved symbol (params + locals)
    public let flowFacts: [CFlowFact]
    public let sinkCandidateCalls: Set<String> // functions we may want to flag at call sites
}

/// Builds symbol scopes and taint-relevant flow facts by walking a parsed
/// function's AST. This is the semantic layer between the AST parser and the
/// interprocedural taint analysis.
public struct CSymbolTable {

    public init() {}

    /// Analyze a single function definition into a summary.
    public func analyze(_ fn: CFunctionDef) -> CFunctionSummary {
        var symbols: [String: CSymbol] = [:]

        // Parameters enter the top scope first.
        for p in fn.params {
            if let pname = p.name {
                symbols[pname] = CSymbol(name: pname, type: p.type, offset: p.offset,
                                         isArray: (p.type?.contains("[") ?? false),
                                         isPointer: isPointerType(p.type),
                                         isParam: true, isReference: (p.type?.contains("&") ?? false))
            }
        }

        var facts: [CFlowFact] = []
        walkStmt(fn.body, symbols: &symbols, facts: &facts)

        var sinks = Set<String>()
        for f in facts {
            if case .call(let c, _, _) = f, isSinkCandidate(c) {
                sinks.insert(c)
            }
            if case .sinkCall(let c, _, _) = f {
                sinks.insert(c)
            }
        }

        return CFunctionSummary(name: fn.name, params: fn.params, returnType: fn.returnType,
                                symbols: symbols, flowFacts: facts, sinkCandidateCalls: sinks)
    }

    private func isPointerType(_ t: String?) -> Bool {
        guard let t = t else { return false }
        return t.contains("*")
    }

    // MARK: - Statement walking

    private func walkStmt(_ stmt: CStmt, symbols: inout [String: CSymbol], facts: inout [CFlowFact]) {
        switch stmt {
        case .block(let arr):
            for s in arr { walkStmt(s, symbols: &symbols, facts: &facts) }

        case .declaration(let d):
            if case .variable(let typeName, let name, let initExpr) = d.kind, !name.isEmpty {
                let sym = CSymbol(name: name, type: typeName, offset: d.offset,
                                  isArray: (typeName?.contains("[") ?? false) || hasArraySuffix(initExpr),
                                  isPointer: isPointerType(typeName),
                                  isParam: false, isReference: (typeName?.contains("&") ?? false))
                symbols[name] = sym
                if let e = initExpr { walkExpr(e, symbols: &symbols, facts: &facts) }
            }

        case .expr(let e):
            walkExpr(e, symbols: &symbols, facts: &facts)

        case .ifStmt(let c, let t, let e, _):
            walkExpr(c, symbols: &symbols, facts: &facts)
            walkStmt(t, symbols: &symbols, facts: &facts)
            if let e = e { walkStmt(e, symbols: &symbols, facts: &facts) }

        case .whileStmt(let c, let b, _):
            walkExpr(c, symbols: &symbols, facts: &facts)
            walkStmt(b, symbols: &symbols, facts: &facts)

        case .doWhileStmt(let b, let c, _):
            walkStmt(b, symbols: &symbols, facts: &facts)
            walkExpr(c, symbols: &symbols, facts: &facts)

        case .forStmt(let init_, let cond, let inc, let b, _):
            if let i = init_ { walkStmt(i, symbols: &symbols, facts: &facts) }
            if let c = cond { walkExpr(c, symbols: &symbols, facts: &facts) }
            if let inc = inc { walkExpr(inc, symbols: &symbols, facts: &facts) }
            walkStmt(b, symbols: &symbols, facts: &facts)

        case .switchStmt(_, let cases, _):
            for c in cases { for s in c.body { walkStmt(s, symbols: &symbols, facts: &facts) } }

        case .returnStmt(let e, _):
            if let e = e { walkExpr(e, symbols: &symbols, facts: &facts) }

        case .labeledStmt(_, let s, _):
            walkStmt(s, symbols: &symbols, facts: &facts)

        default:
            break
        }
    }

    // MARK: - Expression walking

    /// Records a flow fact when a simple identifier variable `target` is assigned from `sourceExpr`.
    private func recordAssign(target: String?, source: CExpr, facts: inout [CFlowFact], offset: Int) {
        guard let target = target, !target.isEmpty else { return }
        if case .identifier(let srcName, _) = source, srcName != target {
            facts.append(.assign(target: target, source: srcName, offset: offset))
        }
    }

    private func walkExpr(_ e: CExpr, symbols: inout [String: CSymbol], facts: inout [CFlowFact]) {
        switch e {
        case .assign(let op, let lhs, let rhs, let off):
            // Capture simple `name = name` taint flows. Compound assigns too.
            let targetName = simpleIdentifier(lhs)
            if op == "=" {
                recordAssign(target: targetName, source: rhs, facts: &facts, offset: off)
            } else if let tname = targetName {
                // target += src  => tainted rhs flows into target
                facts.append(.assign(target: tname, source: simpleIdentifier(rhs) ?? "", offset: off))
            }
            walkExpr(lhs, symbols: &symbols, facts: &facts)
            walkExpr(rhs, symbols: &symbols, facts: &facts)

        case .binary(_, let lhs, let rhs, _):
            walkExpr(lhs, symbols: &symbols, facts: &facts)
            walkExpr(rhs, symbols: &symbols, facts: &facts)

        case .unary(_, let opd, _):
            walkExpr(opd, symbols: &symbols, facts: &facts)

        case .ternary(let c, let t, let f, _):
            walkExpr(c, symbols: &symbols, facts: &facts)
            walkExpr(t, symbols: &symbols, facts: &facts)
            walkExpr(f, symbols: &symbols, facts: &facts)

        case .comma(let lhs, let rhs, _):
            walkExpr(lhs, symbols: &symbols, facts: &facts)
            walkExpr(rhs, symbols: &symbols, facts: &facts)

        case .member(let b, _, _, _):
            walkExpr(b, symbols: &symbols, facts: &facts)

        case .index(let b, let idxExpr, _):
            walkExpr(b, symbols: &symbols, facts: &facts)
            walkExpr(idxExpr, symbols: &symbols, facts: &facts)

        case .cast(let ex, _):
            walkExpr(ex, symbols: &symbols, facts: &facts)

        case .sizeOf(let ex, _, _):
            if let inner = ex { walkExpr(inner, symbols: &symbols, facts: &facts) }

        case .call(let callee, let args, let off):
            let cname = calleeName(callee)
            if isSinkCall(cname) {
                facts.append(.sinkCall(callee: cname, argOffsets: args.map { $0.offset }, offset: off))
            } else {
                facts.append(.call(callee: cname, argOffsets: args.map { $0.offset }, offset: off))
            }
            for a in args { walkExpr(a, symbols: &symbols, facts: &facts) }

        case .arrayInit(let elems, _):
            for el in elems { walkExpr(el, symbols: &symbols, facts: &facts) }

        case .newExpr(_, let args, _):
            for a in args { walkExpr(a, symbols: &symbols, facts: &facts) }

        default:
            break
        }
    }

    private func calleeName(_ callee: CExpr) -> String {
        switch callee {
        case .identifier(let n, _): return n
        case .member(_, let m, _, _): return m
        case .call(let inner, _, _): return calleeName(inner)
        default: return ""
        }
    }

    private func simpleIdentifier(_ e: CExpr) -> String? {
        if case .identifier(let n, _) = e, !n.isEmpty { return n }
        return nil
    }

    private func hasArraySuffix(_ e: CExpr?) -> Bool {
        if let e = e, case .arrayInit(_, _) = e { return true }
        return false
    }

    // MARK: - Sink classification (mirrors scanner sinks for the C frontend)

    private func isSinkCall(_ name: String) -> Bool {
        sinkFunctions.contains(name)
    }
    private func isSinkCandidate(_ name: String) -> Bool {
        sinkFunctions.contains(name)
    }

    private let sinkFunctions: Set<String> = [
        // memory
        "memcpy","memmove","strcpy","strncpy","strcat","strncat","sprintf","vsprintf","snprintf",
        "strlcpy","strlcat",
        // exec
        "system","popen","execl","execlp","execle","execv","execvp","execve","posix_spawn",
        // mysql / sql
        "mysql_query","mysql_real_query","PQexec","sqlite3_exec","sqlite3_prepare","sqlite3_prepare_v2",
        // files
        "fopen","freopen","open","creat","fwrite","write","fread","read",
        // crypto
        "DES_set_key","RC4","MD5_Init","SHA1_Init",
    ]
}

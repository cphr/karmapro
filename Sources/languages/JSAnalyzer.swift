// by cipher.org.uk
import Foundation

/// AST-driven interprocedural data-flow analysis for JavaScript/TypeScript,
/// mirroring `ScriptAnalyzer`/`JAnalyzer`. Function bodies located by the fresh
/// `JSParser` are sliced from the shared JS token stream and parsed with the
/// shared `CParser`, producing real `CStmt` trees for the 3-walk AST layer,
/// plus `taintReturning` and `writeThroughParam` seeded from `jsSourceAPIs`.
public struct JSAnalyzer {

    private let astFns: [String: CFunctionDef]
    private let sourceAPIs: Set<String>
    private let writeThroughSinks: Set<String>

    public init(source: String, defs: [JSDef], tokens: [CAstToken]? = nil,
                sourceAPIs: Set<String>,
                writeThroughSinks: Set<String>) {
        let allTokens = tokens ?? JSTokenizer(source: source).tokenize()
        let eof = allTokens.last
        var map: [String: CFunctionDef] = [:]
        for d in defs {
            var slices = allTokens.filter {
                $0.offset >= d.bodyRange.location &&
                $0.offset < d.bodyRange.location + d.bodyRange.length
            }
            // Expression-bodied arrows have no braces: wrap in synthetic braces
            // so `CParser.parseBlockFromCurrent` (which requires a `{`) works.
            if !d.hasBraceBody {
                slices.insert(CAstToken(kind: .punct, text: "{", line: 0, column: 0,
                                        offset: d.bodyRange.location), at: 0)
                slices.append(CAstToken(kind: .punct, text: "}", line: 0, column: 0,
                                        offset: d.bodyRange.location + d.bodyRange.length))
            }
            // CParser relies on a terminating `.eof` token.
            if slices.isEmpty {
                if let eof = eof { slices.append(eof) }
            } else if slices.last?.kind != .eof {
                if let eof = eof { slices.append(eof) }
            }
            guard let block = CParser(tokens: slices, isPHP: false, isGo: false).parseBlockFromCurrent() else { continue }
            let fn = CFunctionDef(name: d.name,
                                  returnType: nil,
                                  params: d.params,
                                  body: block,
                                  startOffset: d.startOffset,
                                  bodyOffset: d.hasBraceBody ? d.bodyOpenOffset : d.bodyRange.location,
                                  endOffset: d.bodyRange.location + d.bodyRange.length,
                                  isDefinition: true,
                                  isMethod: d.kind == .method,
                                  qualifiers: [])
            if map[fn.name] == nil { map[fn.name] = fn }
        }
        self.sourceAPIs = sourceAPIs
        self.writeThroughSinks = writeThroughSinks
        self.astFns = map
    }

    public func analyze() -> CAnalysis {
        let returning = computeTaintReturning()
        let writeThrough = computeWriteThrough(taintReturning: returning)
        let paramSeeds = computeParamTaintSeeds()
        return CAnalysis(taintReturning: returning, writeThroughParam: writeThrough, paramTaintSeeds: paramSeeds)
    }

    public var astFunctions: [String: CFunctionDef] { astFns }

    // MARK: - Taint-returning functions (fixpoint over the shared AST)

    private func computeTaintReturning() -> Set<String> {
        var returning = Set<String>()
        for _ in 0..<6 {
            var changed = false
            for fn in astFns.values where !returning.contains(fn.name) {
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
            // A `.replace(...)` / `.replaceAll(...)` call is a transformation
            // step (e.g. `String(value).replace(/[\u0000-\u001f]/g, …)` escaping
            // control characters): its OUTPUT is a derived, sanitized value, so
            // the raw taint of the input does not flow through the return.
            if case .member(_, let m, _, _) = callee, ["replace", "replaceAll"].contains(m) {
                return false
            }
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
        case .labeledStmt(_, let s, _):
            return stmtWritesParam(s, paramName: paramName, params: params, seedFns: seedFns)
        default:
            break
        }
        return false
    }

    private func exprWritesParam(_ e: CExpr, paramName: String, params: [CAParam], seedFns: Set<String>) -> Bool {
        switch e {
        case .call(let callee, let args, _):
            let calleeName = cExprCalleeName(callee)
            if writeThroughSinks.contains(calleeName) {
                for a in args where exprIsParam(a, paramName: paramName) { return true }
            }
            // Writes into member/index of the param count too (obj[p] = ...).
            for a in args where exprWritesParam(a, paramName: paramName, params: params, seedFns: seedFns) { return true }
            if exprReferencesTaint(callee, params: Set(params.compactMap { $0.name }), seedFns: seedFns) { return true }
            return false
        case .assign(_, let lhs, let rhs, _):
            if exprBaseIsParam(lhs, paramName: paramName) { return true }
            return exprWritesParam(rhs, paramName: paramName, params: params, seedFns: seedFns)
        case .paren(let x, _):
            return exprWritesParam(x, paramName: paramName, params: params, seedFns: seedFns)
        case .comma(let l, let r, _):
            return exprWritesParam(l, paramName: paramName, params: params, seedFns: seedFns)
                || exprWritesParam(r, paramName: paramName, params: params, seedFns: seedFns)
        default:
            return false
        }
    }

    private func exprIsParam(_ e: CExpr, paramName: String) -> Bool {
        if case .identifier(let n, _) = e { return n == paramName }
        return false
    }

    private func exprBaseIsParam(_ e: CExpr, paramName: String) -> Bool {
        switch e {
        case .identifier(let n, _):
            return n == paramName
        case .member(let b, _, _, _):
            return exprBaseIsParam(b, paramName: paramName)
        case .index(let b, _, _):
            return exprBaseIsParam(b, paramName: paramName)
        case .paren(let x, _):
            return exprBaseIsParam(x, paramName: paramName)
        default:
            return false
        }
    }

    private func cExprCalleeName(_ e: CExpr) -> String {
        switch e {
        case .identifier(let n, _): return n
        case .member(_, let m, _, _): return m
        case .paren(let x, _): return cExprCalleeName(x)
        default: return ""
        }
    }

    private func cExprCalleeIsSeed(_ e: CExpr, _ seedFns: Set<String>) -> Bool {
        switch e {
        case .identifier(let n, _):
            return seedFns.contains(n)
        case .member(let b, let m, _, _):
            // Match dotted source APIs (`process.env`, `req.query`) as well as
            // bare member names (`readFile`).
            if seedFns.contains(m) { return true }
            let base = cExprCalleeName(b)
            if base.isEmpty { return false }
            return seedFns.contains("\(base).\(m)")
        case .paren(let x, _):
            return cExprCalleeIsSeed(x, seedFns)
        default:
            return false
        }
    }

    /// Cross-file parameter provenance: which parameters of each JS function
    /// are tainted at some call site in the file.
    public func computeParamTaintSeeds() -> [String: Set<Int>] {
        var result: [String: Set<Int>] = [:]
        var changed = true
        while changed {
            changed = false
            for fn in astFns.values {
                let paramCount = fn.params.count
                let paramNames = Set(fn.params.compactMap { $0.name })
                var tainted: Set<String> = []
                if let seeds = result[fn.name] {
                    for idx in seeds where idx < paramCount {
                        if let pname = fn.params[idx].name { tainted.insert(pname) }
                    }
                }
                var sites: [(name: String, indices: Set<Int>)] = []
                var taintedLocals: Set<String> = []
                walkTaintAndRecord(
                    fn.body,
                    tainted: &tainted,
                    taintedLocals: &taintedLocals,
                    seededParams: paramNames,
                    seedFns: sourceAPIs,
                    taintReturning: Set(result.keys),
                    callSites: &sites
                )
                for (callee, indices) in sites {
                    if result[callee] == nil || !result[callee]!.isSuperset(of: indices) {
                        result[callee, default: Set<Int>()].formUnion(indices)
                        changed = true
                    }
                }
            }
        }
        return result
    }

    private func walkTaintAndRecord(
        _ stmt: CStmt,
        tainted: inout Set<String>,
        taintedLocals: inout Set<String>,
        seededParams: Set<String>,
        seedFns: Set<String>,
        taintReturning: Set<String>,
        callSites: inout [(name: String, indices: Set<Int>)]
    ) {
        switch stmt {
        case .block(let arr):
            for s in arr { walkTaintAndRecord(s, tainted: &tainted, taintedLocals: &taintedLocals, seededParams: seededParams, seedFns: seedFns, taintReturning: taintReturning, callSites: &callSites) }
        case .expr(let e):
            recordCallSites(e, tainted: tainted, seedFns: seedFns, callSites: &callSites)
            updateTaint(e, tainted: &tainted, taintedLocals: &taintedLocals, seededParams: seededParams, seedFns: seedFns, taintReturning: taintReturning)
        case .declaration(let d):
            if case .variable(_, _, let initExpr) = d.kind {
                if let expr = initExpr { updateTaint(expr, tainted: &tainted, taintedLocals: &taintedLocals, seededParams: seededParams, seedFns: seedFns, taintReturning: taintReturning) }
            }
        case .ifStmt(_, let t, let e, _):
            walkTaintAndRecord(t, tainted: &tainted, taintedLocals: &taintedLocals, seededParams: seededParams, seedFns: seedFns, taintReturning: taintReturning, callSites: &callSites)
            if let e = e { walkTaintAndRecord(e, tainted: &tainted, taintedLocals: &taintedLocals, seededParams: seededParams, seedFns: seedFns, taintReturning: taintReturning, callSites: &callSites) }
        case .whileStmt(_, let body, _):
            walkTaintAndRecord(body, tainted: &tainted, taintedLocals: &taintedLocals, seededParams: seededParams, seedFns: seedFns, taintReturning: taintReturning, callSites: &callSites)
        case .doWhileStmt(let body, _, _):
            walkTaintAndRecord(body, tainted: &tainted, taintedLocals: &taintedLocals, seededParams: seededParams, seedFns: seedFns, taintReturning: taintReturning, callSites: &callSites)
        case .forStmt(let initS, _, _, let body, _):
            if let initS = initS { walkTaintAndRecord(initS, tainted: &tainted, taintedLocals: &taintedLocals, seededParams: seededParams, seedFns: seedFns, taintReturning: taintReturning, callSites: &callSites) }
            walkTaintAndRecord(body, tainted: &tainted, taintedLocals: &taintedLocals, seededParams: seededParams, seedFns: seedFns, taintReturning: taintReturning, callSites: &callSites)
        case .switchStmt(_, let cases, _):
            for c in cases { for s in c.body { walkTaintAndRecord(s, tainted: &tainted, taintedLocals: &taintedLocals, seededParams: seededParams, seedFns: seedFns, taintReturning: taintReturning, callSites: &callSites) } }
        case .labeledStmt(_, let s, _):
            walkTaintAndRecord(s, tainted: &tainted, taintedLocals: &taintedLocals, seededParams: seededParams, seedFns: seedFns, taintReturning: taintReturning, callSites: &callSites)
        default: break
        }
    }

    private func updateTaint(_ e: CExpr, tainted: inout Set<String>, taintedLocals: inout Set<String>, seededParams: Set<String>, seedFns: Set<String>, taintReturning: Set<String>) {
switch e {
            case .assign(_, let lhs, let rhs, _):
                if simpleIdentifier(lhs) != nil {
                if exprTainted(rhs, tainted: tainted, seedFns: seedFns, taintReturning: taintReturning) != nil {
                    if let n = simpleIdentifier(lhs) { tainted.insert(n); taintedLocals.insert(n) }
                }
            }
            updateTaint(lhs, tainted: &tainted, taintedLocals: &taintedLocals, seededParams: seededParams, seedFns: seedFns, taintReturning: taintReturning)
            updateTaint(rhs, tainted: &tainted, taintedLocals: &taintedLocals, seededParams: seededParams, seedFns: seedFns, taintReturning: taintReturning)
        case .call(let callee, let args, _):
            for a in args { updateTaint(a, tainted: &tainted, taintedLocals: &taintedLocals, seededParams: seededParams, seedFns: seedFns, taintReturning: taintReturning) }
            updateTaint(callee, tainted: &tainted, taintedLocals: &taintedLocals, seededParams: seededParams, seedFns: seedFns, taintReturning: taintReturning)
        case .member(let b, _, _, _):
            updateTaint(b, tainted: &tainted, taintedLocals: &taintedLocals, seededParams: seededParams, seedFns: seedFns, taintReturning: taintReturning)
        case .index(let b, let idx, _):
            updateTaint(b, tainted: &tainted, taintedLocals: &taintedLocals, seededParams: seededParams, seedFns: seedFns, taintReturning: taintReturning)
            updateTaint(idx, tainted: &tainted, taintedLocals: &taintedLocals, seededParams: seededParams, seedFns: seedFns, taintReturning: taintReturning)
        case .unary(_, let o, _):
            updateTaint(o, tainted: &tainted, taintedLocals: &taintedLocals, seededParams: seededParams, seedFns: seedFns, taintReturning: taintReturning)
        case .binary(_, let l, let r, _), .comma(let l, let r, _):
            updateTaint(l, tainted: &tainted, taintedLocals: &taintedLocals, seededParams: seededParams, seedFns: seedFns, taintReturning: taintReturning)
            updateTaint(r, tainted: &tainted, taintedLocals: &taintedLocals, seededParams: seededParams, seedFns: seedFns, taintReturning: taintReturning)
        case .cast(let x, _), .paren(let x, _):
            updateTaint(x, tainted: &tainted, taintedLocals: &taintedLocals, seededParams: seededParams, seedFns: seedFns, taintReturning: taintReturning)
        default: break
        }
    }

    private func recordCallSites(_ e: CExpr, tainted: Set<String>, seedFns: Set<String>, callSites: inout [(name: String, indices: Set<Int>)]) {
        switch e {
        case .call(let callee, let args, _):
            if cExprCalleeName(callee) != "" {
                var taintedIdxs: Set<Int> = []
                for (i, a) in args.enumerated() {
                    if exprTainted(a, tainted: tainted, seedFns: seedFns, taintReturning: Set()) != nil {
                        taintedIdxs.insert(i)
                    }
                }
                if !taintedIdxs.isEmpty {
                    let name = cExprCalleeName(callee)
                    callSites.append((name: name, indices: taintedIdxs))
                }
            }
            recordCallSites(callee, tainted: tainted, seedFns: seedFns, callSites: &callSites)
            for a in args { recordCallSites(a, tainted: tainted, seedFns: seedFns, callSites: &callSites) }
        case .member(let b, _, _, _):
            recordCallSites(b, tainted: tainted, seedFns: seedFns, callSites: &callSites)
        case .index(let b, let idx, _):
            recordCallSites(b, tainted: tainted, seedFns: seedFns, callSites: &callSites)
            recordCallSites(idx, tainted: tainted, seedFns: seedFns, callSites: &callSites)
        case .unary(_, let o, _):
            recordCallSites(o, tainted: tainted, seedFns: seedFns, callSites: &callSites)
        case .binary(_, let l, let r, _), .comma(let l, let r, _):
            recordCallSites(l, tainted: tainted, seedFns: seedFns, callSites: &callSites)
            recordCallSites(r, tainted: tainted, seedFns: seedFns, callSites: &callSites)
        case .cast(let x, _), .paren(let x, _):
            recordCallSites(x, tainted: tainted, seedFns: seedFns, callSites: &callSites)
        default: break
        }
    }

    private func simpleIdentifier(_ e: CExpr) -> String? {
        if case .identifier(let n, _) = e, !n.isEmpty { return n }
        return nil
    }

    private func exprTainted(_ e: CExpr, tainted: Set<String>, seedFns: Set<String>, taintReturning: Set<String>) -> String? {
        switch e {
        case .identifier(let n, _):
            if tainted.contains(n) { return n }
            return nil
        case .call(let callee, let args, _):
            if case .identifier(let cname, _) = callee, seedFns.contains(cname) { return cname }
            if let t = exprTainted(callee, tainted: tainted, seedFns: seedFns, taintReturning: taintReturning) { return t }
            for a in args { if let t = exprTainted(a, tainted: tainted, seedFns: seedFns, taintReturning: taintReturning) { return t } }
            return nil
        case .member(let b, _, _, _):
            return exprTainted(b, tainted: tainted, seedFns: seedFns, taintReturning: taintReturning)
        case .index(let b, let idx, _):
            return exprTainted(b, tainted: tainted, seedFns: seedFns, taintReturning: taintReturning)
                ?? exprTainted(idx, tainted: tainted, seedFns: seedFns, taintReturning: taintReturning)
        case .unary(_, let o, _):
            return exprTainted(o, tainted: tainted, seedFns: seedFns, taintReturning: taintReturning)
        case .binary(_, let l, let r, _), .comma(let l, let r, _):
            return exprTainted(l, tainted: tainted, seedFns: seedFns, taintReturning: taintReturning)
                ?? exprTainted(r, tainted: tainted, seedFns: seedFns, taintReturning: taintReturning)
        case .cast(let x, _), .paren(let x, _):
            return exprTainted(x, tainted: tainted, seedFns: seedFns, taintReturning: taintReturning)
        default: return nil
        }
    }
}

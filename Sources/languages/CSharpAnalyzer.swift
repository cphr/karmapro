// by cipher.org.uk
import Foundation

/// AST-driven interprocedural data-flow analysis for C# files, mirroring
/// `CAnalyzer` (C/C++) and `JAnalyzer` (Java). It reuses the shared
/// `CStmt`/`CExpr` representation by parsing each method body with `CParser`,
/// then computes:
///  - `taintReturning`: methods whose return value derives from untrusted data.
///  - `writeThroughParam`: methods that write untrusted data into a parameter.
/// It is structurally identical to `JAnalyzer` but seeded with the C# source /
/// write-through sets from `CSharpPlatform.swift`.
public struct CSharpAnalyzer {

    private let astFns: [String: CFunctionDef]

    public init(source: String, methods: [CSharpMethodDef]) {
        let allTokens = CTokenizer(source: source).tokenize()
        let eof = allTokens.last
        var map: [String: CFunctionDef] = [:]
        for m in methods {
            var slices = allTokens.filter {
                $0.offset >= m.bodyOffset && $0.offset < (m.bodyRange.location + m.bodyRange.length)
            }
            // The CParser relies on a terminating `.eof` token so its scan-to-eof
            // loops terminate. The slice above always drops it, so re-append it.
            if slices.isEmpty {
                if let eof = eof { slices.append(eof) }
            } else if slices.last?.kind != .eof {
                if let eof = eof { slices.append(eof) }
            }
            guard let block = CParser(tokens: slices).parseBlockFromCurrent() else { continue }
            let fn = CFunctionDef(name: m.name,
                                  returnType: nil,
                                  params: m.params,
                                  body: block,
                                  startOffset: m.startOffset,
                                  bodyOffset: m.bodyOffset,
                                  endOffset: m.bodyRange.location + m.bodyRange.length,
                                  isDefinition: true,
                                  isMethod: true,
                                  qualifiers: m.qualifiers)
            if map[fn.name] == nil { map[fn.name] = fn }
        }
        self.astFns = map
    }

    public func analyze() -> CAnalysis {
        let returning = computeTaintReturning()
        let writeThrough = computeWriteThrough(taintReturning: returning)
        return CAnalysis(taintReturning: returning, writeThroughParam: writeThrough, paramTaintSeeds: [:])
    }

    /// The parsed AST for each defined method (body parsed into the shared
    /// `CStmt`/`CExpr` representation), letting the scanner run structural
    /// sink/taint detection over C# method bodies.
    public var astFunctions: [String: CFunctionDef] { astFns }

    // MARK: - Taint-returning methods (fixpoint over the shared AST)

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
        let seedFns = csharpSourceAPIs.union(taintReturning)
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

    private func callName(_ callee: CExpr) -> String? {
        switch callee {
        case .identifier(let n, _): return n
        case .member(_, let member, _, _): return member
        case .call(let inner, _, _): return callName(inner)
        default: return nil
        }
    }

    // MARK: - Write-through parameters

    private func computeWriteThrough(taintReturning: Set<String>) -> [String: Set<Int>] {
        var result: [String: Set<Int>] = [:]
        let seedFns = csharpSourceAPIs.union(taintReturning)
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
        case .returnStmt(let e, _):
            if let e = e { return exprWritesParam(e, paramName: paramName, params: params, seedFns: seedFns) }
        case .labeledStmt(_, let s, _):
            return stmtWritesParam(s, paramName: paramName, params: params, seedFns: seedFns)
        default:
            break
        }
        return false
    }

    private func exprWritesParam(_ e: CExpr, paramName: String, params: [CAParam], seedFns: Set<String>) -> Bool {
        switch e {
        case .assign(_, let lhs, let rhs, _):
            return writesTarget(lhs, paramName: paramName) || exprWritesParam(rhs, paramName: paramName, params: params, seedFns: seedFns)
        case .call(let callee, let args, _):
            if cExprCalleeIsSeed(callee, seedFns) {
                // reading APIs that fill a value into an argument position
                if args.contains(where: { exprWritesParam($0, paramName: paramName, params: params, seedFns: seedFns) }) { return true }
            }
            return args.contains { exprWritesParam($0, paramName: paramName, params: params, seedFns: seedFns) }
        case .identifier(let n, _):
            return n == paramName
        case .member(let b, _, _, _), .index(let b, _, _):
            return exprWritesParam(b, paramName: paramName, params: params, seedFns: seedFns)
        default:
            return false
        }
    }

    private func writesTarget(_ e: CExpr, paramName: String) -> Bool {
        if case .identifier(let n, _) = e { return n == paramName }
        if case .member(let b, _, _, _) = e { return writesTarget(b, paramName: paramName) }
        return false
    }
}

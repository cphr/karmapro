// by cipher.org.uk
import Foundation

/// AST-driven interprocedural data-flow analysis for Swift.
///
/// Mirrors `JSAnalyzer`: function bodies located by `SwiftParser` (and located
/// precisely by the shared `CTokenizer` stream) are parsed with the Swift-native
/// `SwiftExprParser`, producing the `SwiftStmt`/`SwiftExpr` trees the three-walk
/// security detector operates on, plus:
///  - `taintReturning`: functions whose return value derives from untrusted data
///    (computed to a fixpoint over the file's call graph),
///  - `writeThroughParam`: functions that write untrusted data into a mutable
///    (`inout`/pointer) parameter,
///  - placeholder `astFns` (`CFunctionDef` values) so the project index can
///    record Swift definitions alongside the other languages.
///
/// Unlike the C/Java/C# analyzers the Swift bodies are NOT bridged through the
/// C grammar — Swift syntax (guards, closures with `in`, string interpolation,
/// optional chaining) distorts it. The three-walk detector instead consumes the
/// native AST directly.
public struct SwiftAnalyzer {

    private let astFns: [String: CFunctionDef]
    private let sourceAPIs: Set<String>
    private let writeThroughSinks: Set<String>
    private let defs: [SwiftDef]
    private let tokens: [CAstToken]

    public init(source: String, defs: [SwiftDef], tokens: [CAstToken]? = nil,
                sourceAPIs: Set<String>,
                writeThroughSinks: Set<String>) {
        self.defs = defs
        self.tokens = tokens ?? CTokenizer(source: source).tokenize()
        self.sourceAPIs = sourceAPIs
        self.writeThroughSinks = writeThroughSinks
        var map: [String: CFunctionDef] = [:]
        for d in defs {
            map[d.name] = CFunctionDef(name: d.name,
                                       returnType: nil,
                                       params: d.params,
                                       body: .block([]),
                                       startOffset: d.startOffset,
                                       bodyOffset: d.bodyOpenOffset,
                                       endOffset: d.bodyEndOffset,
                                       isDefinition: true,
                                       isMethod: d.kind != .function,
                                       qualifiers: d.qualifiers)
        }
        self.astFns = map
    }

    public func analyze() -> CAnalysis {
        let returning = computeTaintReturning()
        let writeThrough = computeWriteThrough(taintReturning: returning)
        return CAnalysis(taintReturning: returning, writeThroughParam: writeThrough, paramTaintSeeds: [:])
    }

    public var astFunctions: [String: CFunctionDef] { astFns }

    // MARK: - Per-definition body helpers

    private func statements(of def: SwiftDef) -> [SwiftStmt] {
        let lo = def.bodyRange.location
        let hi = lo + def.bodyRange.length
        let bodyTokens = tokens.filter { $0.offset >= lo && $0.offset < hi && $0.kind != .eof }
        guard !bodyTokens.isEmpty else { return [] }
        return SwiftExprParser.parseStatements(bodyTokens)
    }

    // MARK: - Taint-returning functions (fixpoint over the Swift AST)

    private func computeTaintReturning() -> Set<String> {
        var returning = Set<String>()
        for _ in 0..<6 {
            var changed = false
            for d in defs where !returning.contains(d.name) {
                if functionReturnsTaint(d, taintReturning: returning) {
                    returning.insert(d.name)
                    changed = true
                }
            }
            if !changed { break }
        }
        return returning
    }

    private func functionReturnsTaint(_ d: SwiftDef, taintReturning: Set<String>) -> Bool {
        let params = Set(d.params.compactMap { $0.name })
        let seedFns = sourceAPIs.union(taintReturning)
        return stmtsReturnTaint(statements(of: d), params: params, seedFns: seedFns)
    }

    private func stmtsReturnTaint(_ stmts: [SwiftStmt], params: Set<String>, seedFns: Set<String>) -> Bool {
        for s in stmts {
            if stmtReturnsTaint(s, params: params, seedFns: seedFns) { return true }
        }
        return false
    }

    private func stmtReturnsTaint(_ stmt: SwiftStmt, params: Set<String>, seedFns: Set<String>) -> Bool {
        switch stmt {
        case .block(let arr, _):
            return stmtsReturnTaint(arr, params: params, seedFns: seedFns)
        case .varDecl(let decls, _):
            return decls.contains { d in
                if let e = d.initExpr { return exprReferencesTaint(e, params: params, seedFns: seedFns) }
                return false
            }
        case .ifStmt(_, let t, let e, _):
            return stmtsReturnTaint(t, params: params, seedFns: seedFns)
                || (e.map { stmtsReturnTaint($0, params: params, seedFns: seedFns) } ?? false)
        case .guardStmt(_, let body, _):
            return stmtsReturnTaint(body, params: params, seedFns: seedFns)
        case .forStmt(_, let iterable, let body, _):
            if let it = iterable, exprReferencesTaint(it, params: params, seedFns: seedFns) { return true }
            return stmtsReturnTaint(body, params: params, seedFns: seedFns)
        case .whileStmt(_, let body, _):
            return stmtsReturnTaint(body, params: params, seedFns: seedFns)
        case .switchStmt(_, let cases, _):
            return cases.contains { c in stmtsReturnTaint(c.body, params: params, seedFns: seedFns) }
        case .returnStmt(let e, _):
            if let e = e { return exprReferencesTaint(e, params: params, seedFns: seedFns) }
        case .throwStmt(let e, _):
            if let e = e { return exprReferencesTaint(e, params: params, seedFns: seedFns) }
        case .exprStmt(let e, _):
            return exprReferencesTaint(e, params: params, seedFns: seedFns)
        case .repeatStmt(let body, let cond, _):
            if let c = cond, exprReferencesTaint(c, params: params, seedFns: seedFns) { return true }
            return stmtsReturnTaint(body, params: params, seedFns: seedFns)
        case .deferStmt(let body, _):
            return stmtsReturnTaint(body, params: params, seedFns: seedFns)
        }
        return false
    }

    private func exprReferencesTaint(_ e: SwiftExpr, params: Set<String>, seedFns: Set<String>) -> Bool {
        switch e {
        case .ident(let n, _):
            return params.contains(n)
        case .member(let b, _, _):
            // `CommandLine.arguments`, `UserDefaults.standard.string` etc. are
            // sources even though their base is a plain identifier.
            if seedFns.contains(e.dottedName) { return true }
            return exprReferencesTaint(b, params: params, seedFns: seedFns)
        case .index(let b, let i, _):
            return exprReferencesTaint(b, params: params, seedFns: seedFns)
                || exprReferencesTaint(i, params: params, seedFns: seedFns)
        case .call(let callee, let args, _):
            if swiftCalleeIsSeed(callee, seedFns) { return true }
            if exprReferencesTaint(callee, params: params, seedFns: seedFns) { return true }
            return args.contains { exprReferencesTaint($0, params: params, seedFns: seedFns) }
        case .newExpr(_, let args, _):
            return args.contains { exprReferencesTaint($0, params: params, seedFns: seedFns) }
        case .unary(_, let o, _):
            return exprReferencesTaint(o, params: params, seedFns: seedFns)
        case .binary(_, let l, let r, _), .range(_, let l, let r, _):
            return exprReferencesTaint(l, params: params, seedFns: seedFns)
                || exprReferencesTaint(r, params: params, seedFns: seedFns)
        case .assign(_, let l, let r, _):
            return exprReferencesTaint(l, params: params, seedFns: seedFns)
                || exprReferencesTaint(r, params: params, seedFns: seedFns)
        case .ternary(let c, let t, let f, _):
            return exprReferencesTaint(c, params: params, seedFns: seedFns)
                || exprReferencesTaint(t, params: params, seedFns: seedFns)
                || exprReferencesTaint(f, params: params, seedFns: seedFns)
        case .arrayLit(let arr, _):
            return arr.contains { exprReferencesTaint($0, params: params, seedFns: seedFns) }
        case .dictLit(let pairs, _):
            return pairs.contains {
                exprReferencesTaint($0.0, params: params, seedFns: seedFns)
                    || exprReferencesTaint($0.1, params: params, seedFns: seedFns)
            }
        case .paren(let x, _), .forceUnwrap(let x, _), .optional(let x, _), .cast(_, let x, _):
            return exprReferencesTaint(x, params: params, seedFns: seedFns)
        case .interpolation(let exprs, _):
            return exprs.contains { exprReferencesTaint($0, params: params, seedFns: seedFns) }
        case .closure(_, let body, _):
            return stmtsReturnTaint(body, params: params, seedFns: seedFns)
        case .literal, .placeholder:
            return false
        }
    }

    private func swiftCalleeIsSeed(_ e: SwiftExpr, _ seedFns: Set<String>) -> Bool {
        let dotted = e.dottedName
        if !dotted.isEmpty, seedFns.contains(dotted) { return true }
        let leaf = e.leafName
        if seedFns.contains(leaf) { return true }
        // `UserDefaults.standard.string` — dotted is always non-empty for the
        // member chain, but a bare `.ident` returns its own name already.
        switch e {
        case .member(_, let m, _), .ident(let m, _):
            _ = m
            return false
        case .paren(let x, _):
            return swiftCalleeIsSeed(x, seedFns)
        default:
            return false
        }
    }

    // MARK: - Write-through parameters

    private func computeWriteThrough(taintReturning: Set<String>) -> [String: Set<Int>] {
        var result: [String: Set<Int>] = [:]
        let seedFns = sourceAPIs.union(taintReturning)
        for d in defs {
            let params = d.params
            var written = Set<Int>()
            var tokensApplied: Set<String> = []
            for (i, p) in params.enumerated() {
                guard let pname = p.name?.trimmingCharacters(in: .whitespaces), !pname.isEmpty, !tokensApplied.contains(pname) else { continue }
                if stmtsWriteParam(statements(of: d), paramName: pname, seedFns: seedFns) {
                    written.insert(i)
                    tokensApplied.insert(pname)
                }
            }
            if !written.isEmpty { result[d.name] = written }
        }
        return result
    }

    private func stmtsWriteParam(_ stmts: [SwiftStmt], paramName: String, seedFns: Set<String>) -> Bool {
        for s in stmts {
            if stmtWritesParam(s, paramName: paramName, seedFns: seedFns) { return true }
        }
        return false
    }

    private func stmtWritesParam(_ stmt: SwiftStmt, paramName: String, seedFns: Set<String>) -> Bool {
        switch stmt {
        case .block(let arr, _):
            return stmtsWriteParam(arr, paramName: paramName, seedFns: seedFns)
        case .varDecl(let decls, _):
            return decls.contains { d in
                if let e = d.initExpr { return exprWritesParam(e, paramName: paramName, seedFns: seedFns) }
                return false
            }
        case .ifStmt(_, let t, let e, _):
            return stmtsWriteParam(t, paramName: paramName, seedFns: seedFns)
                || (e.map { stmtsWriteParam($0, paramName: paramName, seedFns: seedFns) } ?? false)
        case .guardStmt(_, let body, _):
            return stmtsWriteParam(body, paramName: paramName, seedFns: seedFns)
        case .forStmt(_, _, let body, _):
            return stmtsWriteParam(body, paramName: paramName, seedFns: seedFns)
        case .whileStmt(_, let body, _):
            return stmtsWriteParam(body, paramName: paramName, seedFns: seedFns)
        case .switchStmt(_, let cases, _):
            return cases.contains { stmtsWriteParam($0.body, paramName: paramName, seedFns: seedFns) }
        case .exprStmt(let e, _):
            return exprWritesParam(e, paramName: paramName, seedFns: seedFns)
        case .returnStmt(let e, _):
            if let e = e { return exprWritesParam(e, paramName: paramName, seedFns: seedFns) }
        case .throwStmt(let e, _):
            if let e = e { return exprWritesParam(e, paramName: paramName, seedFns: seedFns) }
        case .repeatStmt(let body, _, _):
            return stmtsWriteParam(body, paramName: paramName, seedFns: seedFns)
        case .deferStmt(let body, _):
            return stmtsWriteParam(body, paramName: paramName, seedFns: seedFns)
        }
        return false
    }

    private func exprWritesParam(_ e: SwiftExpr, paramName: String, seedFns: Set<String>) -> Bool {
        switch e {
        case .call(let callee, let args, _):
            let leaf = callee.leafName
            if writeThroughSinks.contains(leaf) {
                for a in args where exprArgIsParam(a, paramName: paramName) { return true }
            }
            for a in args where exprWritesParam(a, paramName: paramName, seedFns: seedFns) { return true }
            return false
        case .assign(_, let lhs, let rhs, _):
            if exprBaseIsParam(lhs, paramName: paramName) { return true }
            return exprWritesParam(rhs, paramName: paramName, seedFns: seedFns)
        case .paren(let x, _), .forceUnwrap(let x, _), .optional(let x, _):
            return exprWritesParam(x, paramName: paramName, seedFns: seedFns)
        case .binary(_, let l, let r, _):
            return exprWritesParam(l, paramName: paramName, seedFns: seedFns)
                || exprWritesParam(r, paramName: paramName, seedFns: seedFns)
        case .ternary(let c, let t, let f, _):
            return exprWritesParam(c, paramName: paramName, seedFns: seedFns)
                || exprWritesParam(t, paramName: paramName, seedFns: seedFns)
                || exprWritesParam(f, paramName: paramName, seedFns: seedFns)
        case .closure(_, let body, _):
            return stmtsWriteParam(body, paramName: paramName, seedFns: seedFns)
        default:
            return false
        }
    }

    private func exprArgIsParam(_ e: SwiftExpr, paramName: String) -> Bool {
        switch e {
        case .ident(let n, _):
            return n == paramName
        case .unary(let op, let o, _):
            if op == "&" { return exprArgIsParam(o, paramName: paramName) }
            return false
        case .paren(let x, _), .forceUnwrap(let x, _), .optional(let x, _):
            return exprArgIsParam(x, paramName: paramName)
        default:
            return false
        }
    }

    private func exprBaseIsParam(_ e: SwiftExpr, paramName: String) -> Bool {
        switch e {
        case .ident(let n, _):
            return n == paramName
        case .member(let b, _, _), .index(let b, _, _):
            return exprBaseIsParam(b, paramName: paramName)
        case .paren(let x, _):
            return exprBaseIsParam(x, paramName: paramName)
        default:
            return false
        }
    }
}
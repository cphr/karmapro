// by cipher.org.uk
import Foundation

/// AST-driven interprocedural data-flow analysis for Objective-C method bodies.
///
/// ObjC methods (`- (void)foo:(Type)arg ... { }` / `+ (id)bar { }`) are located by
/// `ObjCMethodParser`, their bodies sliced at the opening `{` and parsed with the
/// shared `CParser`, then analyzed for `taintReturning` functions and
/// `writeThroughParam` parameters, seeded with the same C source / write-through
/// sets (`sourceAPIs` / `writeThroughSinks`). This lets the `AstSecurityDetector`
/// run on real ObjC method syntax — previously only C-style functions in `.m`
/// files were AST-scanned because the C frontend does not parse `-`/`+` method heads.
public struct ObjCAnalyzer {

    private let astFns: [String: CFunctionDef]
    private let methodDefs: [ObjCMethodParser.ObjCMethodDef]

    public init(source: String) {
        let defs = ObjCMethodParser(source: source).parseDefinitions()
        self.methodDefs = defs
        let allTokens = CTokenizer(source: source).tokenize()
        let eof = allTokens.last
        var map: [String: CFunctionDef] = [:]
        for def in defs {
            // The opening '{' of the method body sits immediately after the
            // signature (ObjCMethodParser.signatureRange ends at that brace).
            let bodyOpen = def.signatureRange.location + def.signatureRange.length
            let endOffset = def.bodyRange.location + def.bodyRange.length
            var slices = allTokens.filter { $0.offset >= bodyOpen && $0.offset < endOffset }
            // CParser relies on a terminating `.eof` token; the slice above drops
            // it, so re-append it when missing.
            if slices.isEmpty {
                if let eof = eof { slices.append(eof) }
            } else if slices.last?.kind != .eof {
                if let eof = eof { slices.append(eof) }
            }
            guard let block = CParser(tokens: slices, isPHP: false).parseBlockFromCurrent() else { continue }
            let params = ObjCAnalyzer.extractParams(source: source, signature: def.signatureRange)
            let fn = CFunctionDef(name: def.name,
                                  returnType: nil,
                                  params: params,
                                  body: block,
                                  startOffset: def.signatureRange.location,
                                  bodyOffset: bodyOpen,
                                  endOffset: endOffset,
                                  isDefinition: true,
                                  isMethod: true,
                                  qualifiers: [])
            if map[fn.name] == nil { map[fn.name] = fn }
        }
        self.astFns = map
    }

    public func analyze() -> CAnalysis {
        let returning = computeTaintReturning()
        let writeThrough = computeWriteThrough(taintReturning: returning)
        return CAnalysis(taintReturning: returning, writeThroughParam: writeThrough, paramTaintSeeds: [:])
    }

    /// The parsed AST for each ObjC method (preferring the first body-bearing
    /// definition per name), for the scanner's structural sink/taint detection.
    public var astFunctions: [String: CFunctionDef] { astFns }

    /// The located ObjC method definitions, so the scanner can also run the
    /// heuristic per-function pass over real method bodies.
    public var methodDefinitions: [ObjCMethodParser.ObjCMethodDef] { methodDefs }

    // MARK: - Parameter extraction from the method signature

    /// Extracts parameter names from an ObjC method signature
    /// (`- (void)foo:(NSString *)arg1 tag:(int)arg2 { }`).
    ///
    /// For each top-level `:` (a parameter introducer), the name is the last
    /// identifier in the following segment that is not the next selector label
    /// (an identifier immediately preceding another `:`).
    private static func extractParams(source: String, signature: NSRange) -> [CAParam] {
        guard signature.length > 0 else { return [] }
        let ns = source as NSString
        let sig = ns.substring(with: signature)
        let tokens = CTokenizer(source: sig).tokenize()

        // Positions (in `tokens`) of top-level ':' introducers.
        var colonIdx: [Int] = []
        var depth = 0
        for (i, t) in tokens.enumerated() {
            if t.kind == .punct {
                if t.text == "(" || t.text == "[" || t.text == "{" || t.text == "<" { depth += 1 }
                else if t.text == ")" || t.text == "]" || t.text == "}" || t.text == ">" { depth = max(0, depth - 1) }
                else if t.text == ":" && depth == 0 { colonIdx.append(i) }
            }
        }
        guard !colonIdx.isEmpty else { return [] }

        var params: [CAParam] = []
        // For each ':', the segment runs until the next top-level ':' (exclusive)
        // or the end of the signature. The param name is the last identifier in
        // that segment, excluding the trailing selector label of the *next*
        // argument (the identifier immediately preceding a following ':').
        for (k, ci) in colonIdx.enumerated() {
            let nextCi = k + 1 < colonIdx.count ? colonIdx[k + 1] : nil
            let segmentEnd = nextCi ?? tokens.count
            var name: (String, Int)? = nil
            var j = ci + 1
            while j < segmentEnd {
                let t = tokens[j]
                // A trailing selector label belongs to the next argument's ':',
                // not to this parameter (e.g. `src into :` -> `into` is a label).
                if nextCi != nil, j == segmentEnd - 1, t.kind == .identifier {
                    break
                }
                if t.kind == .identifier { name = (t.text, t.offset) }
                j += 1
            }
            if let n = name {
                // offset is relative to the signature substring; add the base.
                params.append(CAParam(type: nil, name: n.0, offset: signature.location + n.1))
            }
        }
        return params
    }

    // MARK: - Taint-returning functions (fixpoint over the AST)

    private func computeTaintReturning() -> Set<String> {
        var returning = Set<String>()
        for _ in 0..<6 {
            var changed = false
            for fn in astFns.values where !returning.contains(fn.name) {
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
            if simpleIdentifier(lhs) == paramName {
                if exprReferencesTaint(rhs, params: Set(params.compactMap { $0.name }), seedFns: seedFns) {
                    return true
                }
                return false
            }
            return exprWritesParam(lhs, paramName: paramName, params: params, seedFns: seedFns)
                || exprWritesParam(rhs, paramName: paramName, params: params, seedFns: seedFns)
        case .call(let callee, let args, _):
            if case .identifier(let cname, _) = callee, writeThroughSinks.contains(cname) {
                if args.contains(where: { simpleIdentifier($0) == paramName }) {
                    return true
                }
            }
            for a in args {
                if exprWritesParam(a, paramName: paramName, params: params, seedFns: seedFns) { return true }
            }
            return false
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
    }

    private func simpleIdentifier(_ e: CExpr) -> String? {
        if case .identifier(let n, _) = e, !n.isEmpty { return n }
        return nil
    }
}

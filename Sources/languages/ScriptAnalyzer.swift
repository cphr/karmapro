// by cipher.org.uk
import Foundation

/// AST-driven interprocedural data-flow analysis for Go / Kotlin files,
/// mirroring `JAnalyzer`. Method bodies are located by `ScriptMethodParser`,
/// sliced and parsed with the shared `CParser`, then analyzed for
/// `taintReturning` functions and `writeThroughParam` parameters, seeded with
/// the Go / Kotlin source and write-through sets from `ScriptPlatform.swift`.
public struct ScriptAnalyzer {

    private let astFns: [String: CFunctionDef]
    private let sourceAPIs: Set<String>
    private let writeThroughSinks: Set<String>

    /// Tokens with offset in [lo, hi), located by binary search (token
    /// offsets are in ascending order).
    private static func tokensBetween(_ lo: Int, _ hi: Int, in tokens: [CAstToken]) -> [CAstToken] {
        let start = lowerBound(of: lo, in: tokens)
        let end = lowerBound(of: hi, in: tokens)
        guard start < end else { return [] }
        return Array(tokens[start..<end])
    }

    private static func lowerBound(of offset: Int, in tokens: [CAstToken]) -> Int {
        var lo = 0
        var hi = tokens.count
        while lo < hi {
            let mid = (lo + hi) / 2
            if tokens[mid].offset < offset { lo = mid + 1 } else { hi = mid }
        }
        return lo
    }

    public init(source: String, methods: [ScriptMethodDef], sourceAPIs: Set<String>, writeThroughSinks: Set<String>) {
        let isPHP = methods.first?.language == .php
        let isGo = methods.first?.language == .go
        // Strip PHP tags (<?php, ?>, <?=, <?) from source for PHP to allow CParser to parse
        let strippedSource = isPHP ? Self.stripPHPTags(source) : source
        let allTokens = CTokenizer(source: strippedSource).tokenize()
        let eof = allTokens.last
        var map: [String: CFunctionDef] = [:]
        for m in methods {
            // Binary-search the token slice for this body (token offsets are
            // ascending): filtering the whole array per method was
            // O(methods x tokens) and dominated large script projects.
            var slices = Self.tokensBetween(m.bodyOffset,
                                            m.bodyRange.location + m.bodyRange.length,
                                            in: allTokens)
            // Python/Ruby bodies are indentation-based: wrap the token range in
            // synthetic braces so the shared `CParser.parseBlockFromCurrent`
            // (which requires a `{`) can parse them like any other block.
            if m.syntheticBraces {
                slices.insert(CAstToken(kind: .punct, text: "{", line: 0, column: 0, offset: m.bodyOffset), at: 0)
                slices.append(CAstToken(kind: .punct, text: "}", line: 0, column: 0, offset: m.bodyRange.location + m.bodyRange.length))
            }
            // The CParser relies on a terminating `.eof` token so its scan-to-eof
            // loops terminate. The slice above always drops it, so re-append it.
            if slices.isEmpty {
                if let eof = eof { slices.append(eof) }
            } else if slices.last?.kind != .eof {
                if let eof = eof { slices.append(eof) }
            }
            guard let block = CParser(tokens: slices, isPHP: isPHP, isGo: isGo).parseBlockFromCurrent() else { continue }
            let fn = CFunctionDef(name: m.name,
                                  returnType: nil,
                                  params: m.params,
                                  body: block,
                                  startOffset: m.startOffset,
                                  bodyOffset: m.bodyOffset,
                                  endOffset: m.bodyRange.location + m.bodyRange.length,
                                  isDefinition: true,
                                  isMethod: false,
                                  qualifiers: [])
            if map[fn.name] == nil { map[fn.name] = fn }
        }
        self.sourceAPIs = sourceAPIs
        self.writeThroughSinks = writeThroughSinks
        self.astFns = map
    }

    public func analyze() -> CAnalysis {
        // Source APIs (`request`, `params`, `urlopen`, …) are taint-returning
        // calls by definition; merging them into the set lets the heuristic
        // taint engine seed flows that read framework request objects.
        let returning = sourceAPIs.union(computeTaintReturning())
        let writeThrough = computeWriteThrough(taintReturning: returning)
        return CAnalysis(taintReturning: returning, writeThroughParam: writeThrough, paramTaintSeeds: [:])
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
            if cExprCalleeIsSeed(callee, seedFns) { return true }
            // Recurse into the callee so sources nested in a member chain
            // (`env.var(x).unwrap_or_default()`) are still recognized.
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

    private static func stripPHPTags(_ source: String) -> String {
        // Replace PHP tags with spaces to preserve source offsets for line attribution
        var result = source
        result = result.replacingOccurrences(of: "<?php", with: "     ")
        result = result.replacingOccurrences(of: "<?=", with: "   ")
        result = result.replacingOccurrences(of: "<?", with: "  ")
        result = result.replacingOccurrences(of: "?>", with: "   ")
        return result
    }
}

// by cipher.org.uk
import Foundation

/// AST-driven interprocedural data-flow analysis for Solidity files, mirroring
/// `CSharpAnalyzer`. It reuses the shared `CStmt`/`CExpr` representation by
/// parsing each function/modifier body with `CParser`, then computes:
///  - `taintReturning`: functions/methods whose return value derives from
///    untrusted data (msg/tx globals, external calls, ABI decoders).
///  - `writeThroughParam`: methods that write untrusted data into a parameter.
public struct SolidityAnalyzer {

    private let astFns: [String: CFunctionDef]

    public init(source: String, methods: [SolidityMethodDef]) {
        let norm = Self.normalizeSolidityBodies(source)
        let allTokens = CTokenizer(source: norm).tokenize()
        let eof = allTokens.last
        var map: [String: CFunctionDef] = [:]
        for m in methods {
            var slices = allTokens.filter {
                $0.offset >= m.bodyOffset && $0.offset < (m.bodyRange.location + m.bodyRange.length)
            }
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

    /// Rewrites Solidity idioms that the shared C parser does not understand,
    /// replacing the problem characters with whitespace of equal length so all
    /// byte offsets are preserved and line numbers map back to the original
    /// source. Two constructs are handled:
    ///   1. Inline call-option braces: `obj.call{value: x}(...)` becomes
    ///      `obj.call            (...)`, so Tokenizer sees a normal call.
    ///   2. Tuple destructuring assignment: `(bool ok, ) = foo(...)` becomes
    ///      `              foo(...)`, keeping the trailing call expression.
    static func normalizeSolidityBodies(_ source: String) -> String {
        let ns = source as NSString
        var out = Array(source.utf16)
        let spacing: (_ range: NSRange) -> Void = { range in
            guard range.location >= 0, range.location + range.length <= out.count else { return }
            for i in range.location ..< (range.location + range.length) {
                if out[i] == 0x0A { continue }
                out[i] = 0x20
            }
        }
        let options: NSRegularExpression.Options = []
        if let callOpts = try? NSRegularExpression(pattern: "(?<=\\w) *\\{[^\\n{}/]*\\} *(?=\\()", options: options) {
            for m in callOpts.matches(in: source, options: [], range: NSRange(location: 0, length: ns.length)).reversed() {
                spacing(m.range)
            }
        }
        // Tuple destructuring: `(bool ok, ) = call(...)` → `bool ok = call(...)`.
        // Preserve the variable name and `= ` so the consumed-call detector can
        // link the variable to the call's return value.
        if let tupleAssign = try? NSRegularExpression(pattern: "\\((\\s*[A-Za-z_$][\\w$]*)(?:\\s+([A-Za-z_$][\\w$]*))?(?:\\s*,\\s*[A-Za-z_$][\\w$]*(?:\\s+[A-Za-z_$][\\w$]*)*)*\\s*,?\\s*\\)\\s*=\\s*", options: options) {
            for m in tupleAssign.matches(in: source, options: [], range: NSRange(location: 0, length: ns.length)).reversed() {
                let fullRange = m.range
                guard fullRange.location >= 0, fullRange.location + fullRange.length <= out.count else { continue }
                // The variable that receives the first return value is the
                // second token of the first tuple element (`bool success`), or
                // the only token when there is no declared type (`(ok, )`).
                let varName: String
                let vr = m.range(at: 2)
                if vr.location != NSNotFound, vr.location >= 0, vr.location + vr.length <= ns.length {
                    varName = (source as NSString).substring(with: vr)
                } else {
                    let tr = m.range(at: 1)
                    if tr.location != NSNotFound, tr.location >= 0, tr.location + tr.length <= ns.length {
                        varName = (source as NSString).substring(with: tr)
                    } else {
                        spacing(fullRange)
                        continue
                    }
                }
                // Build replacement: "varName = " padded to same length.
                let pad = max(0, fullRange.length - varName.count - 3)
                let replacement = varName + " = " + String(repeating: " ", count: pad)
                for (i, ch) in replacement.utf16.enumerated() {
                    let idx = fullRange.location + i
                    guard idx < out.count else { break }
                    if out[idx] == 0x0A { continue }
                    out[idx] = ch
                }
            }
        }
        // 3. 0.4.x `var` type inference: the C body parser has no `var` type,
        // so the statement (and everything after it in the body) is dropped.
        // Rewrite `var` to `int` — same length, offsets preserved.
        if let varDecl = try? NSRegularExpression(pattern: "\\bvar\\s+(?=[A-Za-z_$])", options: options) {
            for m in varDecl.matches(in: source, options: [], range: NSRange(location: 0, length: ns.length)).reversed() {
                let typeRange = m.range
                guard typeRange.location >= 0, typeRange.length >= 3 else { continue }
                let replacement = "int" + String(repeating: " ", count: typeRange.length - 3)
                for (i, ch) in replacement.utf16.enumerated() {
                    let idx = typeRange.location + i
                    guard idx < out.count else { break }
                    if out[idx] == 0x0A { continue }
                    out[idx] = ch
                }
            }
        }
        // 4. For-loop init declarations with Solidity integer types: the C
        // parser only recognizes C type keywords in the for-init position, so
        // `for (uint256 i = 0; ...)` mangles the whole loop. Rewrite the type
        // to `int` padded to the same length (offset-preserving).
        if let forUint = try? NSRegularExpression(pattern: "\\bfor\\s*\\(\\s*(u?int(?:8|16|24|32|40|48|56|64|72|80|88|96|104|112|120|128|136|144|152|160|168|176|184|192|200|208|216|224|232|240|248|256)?)\\b", options: options) {
            for m in forUint.matches(in: source, options: [], range: NSRange(location: 0, length: ns.length)).reversed() {
                let typeRange = m.range(at: 1)
                guard typeRange.location >= 0, typeRange.length >= 3 else { continue }
                let replacement = "int" + String(repeating: " ", count: typeRange.length - 3)
                for (i, ch) in replacement.utf16.enumerated() {
                    let idx = typeRange.location + i
                    guard idx < out.count else { break }
                    if out[idx] == 0x0A { continue }
                    out[idx] = ch
                }
            }
        }
        return String(utf16CodeUnits: out, count: out.count)
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
        let seedFns = soliditySourceAPIs.union(taintReturning)
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
            // A member access rooted at an untrusted global (`msg.data`,
            // `tx.origin`, `block.timestamp`, ...) is itself untrusted data.
            if let q = cExprQualifiedName(e), seedFns.contains(q) { return true }
            if let t = cExprTrailingName(e), seedFns.contains(t) { return true }
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
        let seedFns = soliditySourceAPIs.union(taintReturning)
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

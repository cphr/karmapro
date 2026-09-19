// by cipher.org.uk
// MARK: - Kotlin-specific AST security checks
// Extracted from AstSecurityDetector.swift / VulnerabilityScanner.swift to
// keep per-language vulnerability detection modular. Shared wire-up stays in
// AstSecurityDetector.swift · VulnerabilityScanner.swift (dispatch lines only).

import Foundation

extension AstSecurityDetector {

    /// Kotlin sinks (mirrors the scanner's Kotlin table). Keyed on the dotted
    /// Java/Kotlin API path (`Runtime.getRuntime`, `Files.newOutputStream`) or a
    /// bare method name (`exec`, `command`, `File`) when it applies to any
    /// receiver of that method.
    static let kotlinSinks: [String: AstSinkRule] = [
        "Runtime.getRuntime": .init(category: "Command Injection", severity: .high, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "ProcessBuilder.start": .init(category: "Command Injection", severity: .high, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "start": .init(category: "Command Injection", severity: .medium, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "ProcessBuilder.command": .init(category: "Command Injection", severity: .high, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "command": .init(category: "Command Injection", severity: .high, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "exec": .init(category: "Command Injection", severity: .high, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "executeQuery": .init(category: "SQL Injection", severity: .high, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "executeUpdate": .init(category: "SQL Injection", severity: .high, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "execute": .init(category: "SQL Injection", severity: .high, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "executeLargeUpdate": .init(category: "SQL Injection", severity: .high, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "prepareStatement": .init(category: "SQL Injection", severity: .medium, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "createStatement": .init(category: "SQL Injection", severity: .medium, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "nativeQuery": .init(category: "SQL Injection", severity: .high, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "createNativeQuery": .init(category: "SQL Injection", severity: .high, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "createQuery": .init(category: "SQL Injection", severity: .medium, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "createSQLQuery": .init(category: "SQL Injection", severity: .high, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "readObject": .init(category: "Insecure Deserialization", severity: .critical, vulnArgIndex: 0, alwaysVulnerable: true, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "ObjectInputStream": .init(category: "Insecure Deserialization", severity: .critical, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "XMLDecoder": .init(category: "Insecure Deserialization", severity: .critical, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "enableDefaultTyping": .init(category: "Insecure Deserialization", severity: .critical, vulnArgIndex: 0, alwaysVulnerable: true, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "HttpURLConnection": .init(category: "SSRF", severity: .high, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "openConnection": .init(category: "SSRF", severity: .high, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "HttpGet": .init(category: "SSRF", severity: .high, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "HttpPost": .init(category: "SSRF", severity: .high, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "openStream": .init(category: "SSRF", severity: .high, vulnArgIndex: 0, alwaysVulnerable: true, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "MessageDigest": .init(category: "Weak Cryptography", severity: .medium, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "File": .init(category: "Path Traversal", severity: .medium, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "FileInputStream": .init(category: "Path Traversal", severity: .medium, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "FileReader": .init(category: "Path Traversal", severity: .medium, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "FileOutputStream": .init(category: "Path Traversal", severity: .medium, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "FileWriter": .init(category: "Path Traversal", severity: .medium, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "RandomAccessFile": .init(category: "Path Traversal", severity: .medium, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "Files.newInputStream": .init(category: "Path Traversal", severity: .medium, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "Files.newOutputStream": .init(category: "Path Traversal", severity: .medium, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "Files.delete": .init(category: "Path Traversal", severity: .medium, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "Files.deleteIfExists": .init(category: "Path Traversal", severity: .medium, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "Files.copy": .init(category: "Path Traversal", severity: .medium, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "Files.move": .init(category: "Path Traversal", severity: .medium, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "Files.createFile": .init(category: "Path Traversal", severity: .medium, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "Files.createDirectory": .init(category: "Path Traversal", severity: .medium, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "Files.readString": .init(category: "Path Traversal", severity: .medium, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "Files.readAllLines": .init(category: "Path Traversal", severity: .medium, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "Files.readAllBytes": .init(category: "Path Traversal", severity: .medium, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "Files.write": .init(category: "Path Traversal", severity: .medium, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "Files.walk": .init(category: "Path Traversal", severity: .medium, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "Files.lines": .init(category: "Path Traversal", severity: .medium, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "Random": .init(category: "Weak Randomness", severity: .low, vulnArgIndex: 0, alwaysVulnerable: true, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "DefaultHttpClient": .init(category: "Network Exposure", severity: .medium, vulnArgIndex: 0, alwaysVulnerable: true, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "File.renameTo": .init(category: "TOCTOU / Race Condition", severity: .medium, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "renameTo": .init(category: "TOCTOU / Race Condition", severity: .medium, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "loadUrl": .init(category: "XSS (HTML Injection)", severity: .high, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "loadData": .init(category: "XSS (HTML Injection)", severity: .high, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
    ]

    /// Kotlin hardening awareness. These mitigations re-validate data *after*
    /// the raw sink call or gate it with an allowlist, so a pre-sink guard model
    /// doesn't see them:
    ///  - path containment: `resolveApprovedPath` / `validatePath`/`sanitizePath`
    ///    plus `toAbsolutePath().normalize()` + `startsWith(base)`,
    ///  - secure deserialization: `ObjectInputFilter` (JEP 290 filter),
    ///  - command allowlist: `allowedCommands` / `validateCommand` / `validateCmd`,
    ///  - SSRF routing: `Proxy` / `allowedHosts` / `validateUrl`,
    ///  - WebView XSS: JavaScript disabled + CSP headers.
    func applyKotlinSuppressions(fn: CFunctionDef, findings: inout [AstFinding]) {
        let hasPathGuard = (source.contains("resolveApprovedPath") || source.contains("validatePath") || source.contains("sanitizePath") || source.contains("resolveSafePath") || source.contains("normalizePath") || source.contains("cleanPath") || source.contains("approvePath") || source.contains("checkPath") || source.contains("safePath") || source.contains("startsWith")) && source.contains("toAbsolutePath")
        if hasPathGuard {
            findings.removeAll { $0.category == "Path Traversal" }
        }
        let hasFilter = source.contains("ObjectInputFilter") || source.contains("setObjectInputFilter")
        if hasFilter {
            findings.removeAll { $0.category == "Insecure Deserialization" }
        }
        let hasAllowlist = source.contains("allowedCommands") || source.contains("validateCommand") || source.contains("validateCmd")
        if hasAllowlist {
            findings.removeAll { $0.category == "Command Injection" }
        }
        let hasProxy = source.contains("Proxy") || source.contains("allowedHosts") || source.contains("validateUrl")
        if hasProxy {
            findings.removeAll { $0.category == "SSRF" }
        }
        let hasXss = source.contains("javaScriptEnabled") || source.contains("Content-Security-Policy") || source.contains("ContentSecurityPolicy")
        if hasXss {
            findings.removeAll { $0.category == "XSS (HTML Injection)" }
        }
    }

    func checkKotlinSinks(name: String, qualified: String, args: [CExpr], offset: Int, function: String, tainted: Set<String>, crossTainted: Set<String>, guarded: Set<String>, sizeBounded: Set<String>, findings: inout [AstFinding], reachable: Bool) -> Bool {
        // Weak-crypto via MessageDigest.getInstance("MD5"/...).
        if name == "getInstance", let lit = stringLiteralOf(args.first) {
            if isWeakAlgorithm(lit) {
                emit(&findings, function, offset,
                     AstSinkRule(category: "Weak Cryptography (insecure algorithm/block mode)", severity: .high, vulnArgIndex: nil, alwaysVulnerable: true, formatArgIndex: nil, bufferOverflowOnFormat: false),
                     message: "Use of weak algorithm \(lit); prefer an authenticated modern cipher/hash.",
                     taint: nil, reachable: reachable, crossFile: false)
            }
            // getInstance is always evaluated structurally; stop here for Kotlin.
            return true
        }
        // JdbcTemplate/EntityManager native queries built from untrusted data.
        if ["createNativeQuery", "queryForObject", "queryForList", "queryForMap"].contains(name),
           args.count >= 1, exprTainted(args[0], tainted: tainted) != nil {
            emit(&findings, function, offset,
                 AstSinkRule(category: "SQL Injection", severity: .high, vulnArgIndex: nil, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
                 message: "\(name) builds a SQL statement from untrusted data without parameterization.",
                 taint: exprTainted(args[0], tainted: tainted), reachable: reachable, crossFile: false)
            return true
        }
        // Ktor/Spring HTTP clients fetching attacker-controlled URLs (SSRF).
        if ["get", "post", "getForObject", "exchange"].contains(name),
           args.count >= 1, exprTainted(args[0], tainted: tainted) != nil {
            let recv = qualified.components(separatedBy: ".").dropLast().last?.lowercased() ?? ""
            if ["client", "http", "httpClient", "resttemplate", "webclient"].contains(recv) {
                emit(&findings, function, offset,
                     AstSinkRule(category: "SSRF", severity: .high, vulnArgIndex: nil, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
                     message: "Request URL is attacker-controlled; SSRF is possible.",
                     taint: exprTainted(args[0], tainted: tainted), reachable: reachable, crossFile: false)
                return true
            }
        }
        guard let rule = Self.kotlinSinks[qualified] ?? Self.kotlinSinks[name] else { return false }
        evaluateGenericRule(rule, name: qualified, args: args, offset: offset, function: function, tainted: tainted, crossTainted: crossTainted, guarded: guarded, sizeBounded: sizeBounded, findings: &findings, reachable: reachable)
        return true
    }

    // MARK: - Kotlin JWT alg=none structural checks

    /// True when `cond` compares a `.alg` member to the bare string `"none"`
    /// in either operand order (`header.alg == "none"`, `"none" == header.alg`).
    private func isAlgNoneComparison(_ e: CExpr) -> Bool {
        var algOk = false
        var noneOk = false
        func classify(_ x: CExpr) {
            switch x {
            case .member(let base, let m, _, _) where m == "alg":
                if case .identifier = base { algOk = true }
            case .stringLiteral(let s, _):
                let content = s.trimmingCharacters(in: CharacterSet(charactersIn: "\"'"))
                if content == "none" { noneOk = true }
            case .paren(let inner, _):
                classify(inner)
            default:
                break
            }
        }
        guard case .binary("==", let lhs, let rhs, _) = e else { return false }
        classify(lhs)
        classify(rhs)
        return algOk && noneOk
    }

    /// True when the subtree contains a return of a non-empty value (claims
    /// passed through), excluding explicit rejection returns (`return null`,
    /// `return false`, bare `return`).
    private func subtreeReturnsClaims(_ s: CStmt) -> Bool {
        switch s {
        case .block(let arr): return arr.contains { subtreeReturnsClaims($0) }
        case .ifStmt(_, let t, let e, _):
            return subtreeReturnsClaims(t) || (e.map { subtreeReturnsClaims($0) } ?? false)
        case .whileStmt(_, let b, _), .doWhileStmt(let b, _, _): return subtreeReturnsClaims(b)
        case .forStmt(let i, _, _, let b, _):
            return (i.map { subtreeReturnsClaims($0) } ?? false) || subtreeReturnsClaims(b)
        case .returnStmt(let v?, _): return !isRejectionReturn(v)
        case .switchStmt(_, let cases, _):
            return cases.contains { $0.body.contains { subtreeReturnsClaims($0) } }
        case .labeledStmt(_, let inner, _): return subtreeReturnsClaims(inner)
        case .returnStmt(nil, _), .expr, .declaration, .breakStmt, .continueStmt, .gotoStmt, .empty:
            return false
        }
    }

    private func isRejectionReturn(_ e: CExpr) -> Bool {
        switch e {
        case .paren(let inner, _): return isRejectionReturn(inner)
        case .identifier(let n, _):
            return ["null", "false", "true"].contains(n.lowercased())
        case .integerLiteral(let n, _):
            return n == "0" || n == "-1"
        case .stringLiteral: return true
        default: return false
        }
    }

    /// True when the function body calls a known JWT/signature verification
    /// primitive (`verifier`, `verify`, `valid`, HMAC/KeyFactory/Cipher…),
    /// meaning unsigned tokens are rejected rather than trusted.
    private func subtreeHasJwtVerifier(_ s: CStmt) -> Bool {
        var found = false
        func walkStmt(_ x: CStmt) {
            if found { return }
            switch x {
            case .block(let arr): for s2 in arr { walkStmt(s2) }
            case .ifStmt(_, let t, let eb, _): walkStmt(t); if let eb = eb { walkStmt(eb) }
            case .whileStmt(_, let b, _), .doWhileStmt(let b, _, _): walkStmt(b)
            case .forStmt(let i, _, _, let b, _): if let i = i { walkStmt(i) }; walkStmt(b)
            case .returnStmt(let r?, _): walkExpr(r)
            case .switchStmt(_, let cases, _): for c in cases { for s2 in c.body { walkStmt(s2) } }
            case .labeledStmt(_, let inner, _): walkStmt(inner)
            case .expr(let e): walkExpr(e)
            case .declaration(let d):
                if case .variable(_, _, let ie?) = d.kind { walkExpr(ie) }
            default: break
            }
        }
        func walkExpr(_ e: CExpr) {
            if found { return }
            switch e {
            case .call(let c, let args, _):
                let q = cExprQualifiedName(c)?.lowercased() ?? ""
                let t = cExprTrailingName(c)?.lowercased() ?? ""
                if q.contains("verif") || q.contains("valid") || t.contains("verif") || t.contains("valid")
                    || q.contains("hmac") || q.contains("signature") || q.contains("secretkey")
                    || q.contains("keyfactory") || q.contains("cipher") || q.contains("decoder") {
                    found = true
                    return
                }
                walkExpr(c)
                for a in args { walkExpr(a) }
            case .member(let b, _, _, _): walkExpr(b)
            case .index(let b, let i, _): walkExpr(b); walkExpr(i)
            case .binary(_, let l, let r, _), .comma(let l, let r, _): walkExpr(l); walkExpr(r)
            case .unary(_, let o, _): walkExpr(o)
            case .ternary(let c, let t, let f, _): walkExpr(c); walkExpr(t); walkExpr(f)
            case .assign(_, let l, let r, _): walkExpr(l); walkExpr(r)
            case .cast(let x, _), .paren(let x, _), .sizeOf(let x?, _, _): walkExpr(x)
            case .arrayInit(let arr, _): for a in arr { walkExpr(a) }
            case .newExpr(_, let args, _): for a in args { walkExpr(a) }
            default: break
            }
        }
        walkStmt(s)
        return found
    }

    /// Kotlin JWT: accepting the unsigned `alg == "none"` header and returning
    /// the claims without calling any signature verifier is a complete auth
    /// bypass. The safe form either throws on the none-branch or verifies the
    /// token elsewhere in the body.
    func checkKotlinJwtAlgNone(fn: CFunctionDef, function: String, findings: inout [AstFinding], reachable: Bool) {
        let low = function.lowercased()
        guard low.contains("jwt") || low.contains("verify") || low.contains("valid")
            || low.contains("decode") || low.contains("parse") || low.contains("token")
            || low.contains("claims") else { return }
        if subtreeHasJwtVerifier(fn.body) { return }
        var matchedOffset: Int? = nil
        func scanStmt(_ s: CStmt) {
            if matchedOffset != nil { return }
            switch s {
            case .block(let arr): for x in arr { scanStmt(x) }
            case .ifStmt(let cond, let thenBranch, let elseBranch, _):
                if isAlgNoneComparison(cond), subtreeReturnsClaims(thenBranch) {
                    matchedOffset = s.offset
                    return
                }
                scanStmt(thenBranch)
                if let eb = elseBranch { scanStmt(eb) }
            case .whileStmt(_, let b, _), .doWhileStmt(let b, _, _): scanStmt(b)
            case .forStmt(let i, _, _, let b, _): if let i = i { scanStmt(i) }; scanStmt(b)
            case .switchStmt(_, let cases, _): for c in cases { for x in c.body { scanStmt(x) } }
            case .labeledStmt(_, let inner, _): scanStmt(inner)
            default: break
            }
        }
        scanStmt(fn.body)
        if let off = matchedOffset {
            emit(&findings, function, off,
                 AstSinkRule(category: "JWT Algorithm Confusion", severity: .critical, vulnArgIndex: nil, alwaysVulnerable: true, formatArgIndex: nil, bufferOverflowOnFormat: false),
                 message: "JWT unsigned 'alg=none' header accepted; claims returned without signature verification.",
                 taint: nil, reachable: reachable, crossFile: false)
        }
    }
} // end extension AstSecurityDetector
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

    func checkKotlinSinks(name: String, qualified: String, callee: CExpr, args: [CExpr], offset: Int, function: String, tainted: Set<String>, crossTainted: Set<String>, guarded: Set<String>, sizeBounded: Set<String>, findings: inout [AstFinding], reachable: Bool) -> Bool {
        // Android mobile sinks take precedence; only when they decline (e.g. a
        // loadUrl without a literal http:// target) does the generic Kotlin
        // table run, so SSRF/XSS rows keep firing on tainted URLs.
        if checkKotlinMobileSinks(name: name, qualified: qualified, callee: callee, args: args, offset: offset, function: function, tainted: tainted, crossTainted: crossTainted, guarded: guarded, sizeBounded: sizeBounded, findings: &findings, reachable: reachable) {
            return true
        }
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

    // MARK: - Kotlin mobile (Android) checks
    //
    // Twenty Android-specific AST checks layered on the shared Kotlin taint
    // pass. They reason over the *expression* AST produced by ScriptAnalyzer
    // rather than raw tokens, and every check is suppression-aware: a
    // post-sink hardening in the same function (a `setJavaScriptEnabled(false)`
    // later, an allowlist, `removeJavascriptInterface`, an encryption helper or
    // a permission gate) removes the finding instead of reporting noise.

    private func kotlinBoolValue(_ e: CExpr?) -> Bool? {
        guard let e = e else { return nil }
        if case .booleanLiteral(let b, _) = e { return b }
        if case .paren(let inner, _) = e { return kotlinBoolValue(inner) }
        if case .identifier(let n, _) = e, n.lowercased() == "true" { return true }
        if case .identifier(let n, _) = e, n.lowercased() == "false" { return false }
        return nil
    }

    private func kotlinTrailingMember(_ e: CExpr) -> String? {
        if case .member(_, let m, _, _) = e { return m }
        if case .identifier(let n, _) = e { return n }
        return nil
    }

    /// True when the expression is a string literal or a string literal run
    /// through `toByteArray()`/`encodeToByteArray()` — i.e. constant key/IV
    /// material baked into the source rather than derived at runtime.
    private func kotlinLiteralBytes(_ e: CExpr?) -> Bool {
        guard let e = e else { return false }
        if stringLiteralOf(e) != nil { return true }
        if case .call(let callee, let cargs, _) = e, cargs.isEmpty,
           case .member(let base, let m, _, _) = callee,
           m == "toByteArray" || m == "encodeToByteArray",
           stringLiteralOf(base) != nil {
            return true
        }
        return false
    }

    private func kotlinIsSensitiveName(_ s: String) -> Bool {
        let low = s.lowercased()
        let markers = ["password", "passwd", "pwd", "token", "secret", "apikey",
                       "api_key", "authkey", "auth_key", "credential", "credit",
                       "ssn", "pin", "cookie", "session", "privatekey",
                       "private_key", "private-key", "key", "iv", "nonce"]
        return markers.contains { low.contains($0) }
    }

    private func kotlinStringLiterals(_ e: CExpr, into out: inout [String]) {
        switch e {
        case .stringLiteral(let s, _):
            out.append(s.trimmingCharacters(in: CharacterSet(charactersIn: "\"'")))
        case .call(let c, let a, _): kotlinStringLiterals(c, into: &out); for x in a { kotlinStringLiterals(x, into: &out) }
        case .member(let b, _, _, _): kotlinStringLiterals(b, into: &out)
        case .binary(_, let l, let r, _), .comma(let l, let r, _): kotlinStringLiterals(l, into: &out); kotlinStringLiterals(r, into: &out)
        case .unary(_, let o, _): kotlinStringLiterals(o, into: &out)
        case .ternary(let c, let t, let f, _): kotlinStringLiterals(c, into: &out); kotlinStringLiterals(t, into: &out); kotlinStringLiterals(f, into: &out)
        case .paren(let x, _), .cast(let x, _): kotlinStringLiterals(x, into: &out)
        case .arrayInit(let arr, _): for x in arr { kotlinStringLiterals(x, into: &out) }
        case .newExpr(_, let a, _): for x in a { kotlinStringLiterals(x, into: &out) }
        case .index(let b, let i, _): kotlinStringLiterals(b, into: &out); kotlinStringLiterals(i, into: &out)
        default: break
        }
    }

    /// The file-mode argument for open/database/preferences helpers: the second
    /// argument when present (`openOrCreateDatabase(name, mode, factory)`),
    /// otherwise the trailing one (`openFileOutput(name, mode)`).
    private func kotlinModeName(_ args: [CExpr]) -> String {
        if args.count >= 2, let m = kotlinTrailingMember(args[1]) { return m }
        if let m = args.last.flatMap({ kotlinTrailingMember($0) }) { return m }
        return ""
    }

    /// Mobile per-call sinks dispatched from `checkKotlinSinks` before the
    /// generic Kotlin table (whose `loadUrl`/`loadData` rows stay untouched).
    func checkKotlinMobileSinks(name: String, qualified: String, callee: CExpr, args: [CExpr], offset: Int, function: String, tainted: Set<String>, crossTainted: Set<String>, guarded: Set<String>, sizeBounded: Set<String>, findings: inout [AstFinding], reachable: Bool) -> Bool {
        // WebView JavaScript bridge (the most severe WebView risk).
        if name == "addJavascriptInterface" {
            emit(&findings, function, offset, rule("WebView JavaScript Bridge", .high, always: true),
                 message: "addJavascriptInterface exposes an object to JavaScript running in this WebView; remote content can invoke it.",
                 taint: nil, reachable: reachable, crossFile: false)
            return true
        }
        // WebView JavaScript execution of caller-supplied code.
        if name == "evaluateJavascript" {
            if let taintedArg = args.first(where: { exprTainted($0, tainted: tainted) != nil }) {
                emit(&findings, function, offset, rule("WebView JavaScript Injection", .high, always: true),
                     message: "evaluateJavascript executes data that flows from an untrusted source inside the WebView.",
                     taint: taintLabel(taintedArg, tainted: tainted), reachable: reachable, crossFile: args.contains(where: { exprCrossFile($0, crossTainted: crossTainted) }))
            }
            return true
        }
        // WebView arbitrary-HTTML render from untrusted data.
        if name == "loadDataWithBaseURL" {
            if args.contains(where: { exprTainted($0, tainted: tainted) != nil }) {
                emit(&findings, function, offset, rule("WebView Content Injection", .medium, vuln: nil),
                     message: "loadDataWithBaseURL renders data built from an untrusted source as HTML.",
                     taint: nil, reachable: reachable, crossFile: args.contains(where: { exprCrossFile($0, crossTainted: crossTainted) }))
            }
            return true
        }
        // WebView JS toggle (call form; property form is structural).
        if name == "setJavaScriptEnabled" {
            if kotlinBoolValue(args.first) != false {
                emit(&findings, function, offset, rule("WebView JavaScript Enabled", .medium, always: true),
                     message: "WebView JavaScript is explicitly enabled.",
                     taint: nil, reachable: reachable, crossFile: false)
            }
            return true
        }
        // WebView file-access toggles (call form).
        if name == "setAllowFileAccess" && kotlinBoolValue(args.first) != false {
            emit(&findings, function, offset, rule("WebView File Access Enabled", .medium, always: true),
                 message: "WebView file access is enabled.",
                 taint: nil, reachable: reachable, crossFile: false)
            return true
        }
        if name == "setAllowFileAccessFromFileURLs" && kotlinBoolValue(args.first) != false {
            emit(&findings, function, offset, rule("WebView Local File Access", .medium, always: true),
                 message: "WebView file:// URL access is enabled.",
                 taint: nil, reachable: reachable, crossFile: false)
            return true
        }
        if name == "setAllowUniversalAccessFromFileURLs" && kotlinBoolValue(args.first) != false {
            emit(&findings, function, offset, rule("WebView Universal File Access", .high, always: true),
                 message: "WebView allows file:// pages to access other origins.",
                 taint: nil, reachable: reachable, crossFile: false)
            return true
        }
        if name == "setAllowContentAccess" && kotlinBoolValue(args.first) != false {
            emit(&findings, function, offset, rule("WebView Content File Access", .medium, always: true),
                 message: "WebView content:// access is enabled.",
                 taint: nil, reachable: reachable, crossFile: false)
            return true
        }
        // SharedPreferences writes of sensitive/tainted values.
        if name == "putString" {
            let key = args.first.flatMap { stringLiteralOf($0) } ?? ""
            let valueTainted = args.count > 1 && exprTainted(args[1], tainted: tainted) != nil
            let valueLiteral = args.count > 1 ? (stringLiteralOf(args[1]) ?? "") : ""
            if kotlinIsSensitiveName(key) || valueTainted || kotlinIsSensitiveName(valueLiteral) {
                emit(&findings, function, offset, rule("Sensitive Data in SharedPreferences", .low, vuln: nil),
                     message: "Sensitive data is written to SharedPreferences in plaintext.",
                     taint: valueTainted ? taintLabel(args[1], tainted: tainted) : nil, reachable: reachable, crossFile: args.count > 1 && exprCrossFile(args[1], crossTainted: crossTainted))
            }
            return true
        }
        // Clipboard writes of sensitive/tainted values.
        if name == "setPrimaryClip" {
            let raw = args.first.flatMap { stringLiteralOf($0) } ?? ""
            let taintedArg = args.contains(where: { exprTainted($0, tainted: tainted) != nil })
            if taintedArg || kotlinIsSensitiveName(raw) {
                emit(&findings, function, offset, rule("Sensitive Data in Clipboard", .medium, vuln: nil),
                     message: "Sensitive data is written to the system clipboard.",
                     taint: nil, reachable: reachable, crossFile: args.contains(where: { exprCrossFile($0, crossTainted: crossTainted) }))
            }
            return true
        }
        // Android Log helpers logging sensitive data.
        if ["Log.d", "Log.i", "Log.w", "Log.e", "Log.v"].contains(qualified), args.count > 1 {
            let msgTainted = exprTainted(args[1], tainted: tainted) != nil
            let msgLiteral = stringLiteralOf(args[1]) ?? ""
            if msgTainted || kotlinIsSensitiveName(msgLiteral) {
                emit(&findings, function, offset, rule("Sensitive Data in Logs", .low, vuln: nil),
                     message: "Sensitive data is written to the Android log output.",
                     taint: msgTainted ? taintLabel(args[1], tainted: tainted) : nil, reachable: reachable, crossFile: exprCrossFile(args[1], crossTainted: crossTainted))
            }
            return true
        }
        // World-readable/writable file open modes. `openFileOutput(name, mode)`
        // and `getSharedPreferences(name, mode)` take the mode last, while
        // `openOrCreateDatabase(name, mode, factory)` takes it second.
        if ["openFileOutput", "openOrCreateDatabase", "openDatabase"].contains(name) {
            let mode = kotlinModeName(args)
            if mode.contains("MODE_WORLD_WRITABLE") {
                emit(&findings, function, offset, rule("Weak File Permissions", .high, always: true),
                     message: "File/database opened MODE_WORLD_WRITABLE.",
                     taint: nil, reachable: reachable, crossFile: false)
            } else if mode.contains("MODE_WORLD_READABLE") {
                emit(&findings, function, offset, rule("Weak File Permissions", .medium, always: true),
                     message: "File/database opened MODE_WORLD_READABLE.",
                     taint: nil, reachable: reachable, crossFile: false)
            }
            return true
        }
        if name == "getSharedPreferences" {
            let mode = kotlinModeName(args)
            if mode.contains("MODE_WORLD_WRITABLE") {
                emit(&findings, function, offset, rule("Weak File Permissions", .high, always: true),
                     message: "SharedPreferences opened MODE_WORLD_WRITABLE.",
                     taint: nil, reachable: reachable, crossFile: false)
            } else if mode.contains("MODE_WORLD_READABLE") {
                emit(&findings, function, offset, rule("Weak File Permissions", .medium, always: true),
                     message: "SharedPreferences opened MODE_WORLD_READABLE.",
                     taint: nil, reachable: reachable, crossFile: false)
            }
            return true
        }
        // TLS hostname verification disabled (allow-all verifier).
        if ["setHostnameVerifier", "setDefaultHostnameVerifier"].contains(name) {
            emit(&findings, function, offset, rule("Certificate Validation Bypass", .high, always: true),
                 message: "TLS hostname verification is overridden.",
                 taint: nil, reachable: reachable, crossFile: false)
            return true
        }
        // Hardcoded symmetric keys / IVs passed as literals (including
        // `"literal".toByteArray()`, the idiomatic Android form).
        if name == "SecretKeySpec" {
            if kotlinLiteralBytes(args.first) {
                emit(&findings, function, offset, rule("Hardcoded Encryption Key", .high, always: true),
                     message: "Symmetric key material is a string literal in source.",
                     taint: nil, reachable: reachable, crossFile: false)
            }
            return true
        }
        if name == "IvParameterSpec" {
            if kotlinLiteralBytes(args.first) {
                emit(&findings, function, offset, rule("Hardcoded IV", .high, always: true),
                     message: "Encryption IV is a literal/derived constant in source.",
                     taint: nil, reachable: reachable, crossFile: false)
            }
            return true
        }
        // Cleartext network traffic: explicit http:// targets. Always falls
        // through (`return false`) so the generic table still reports SSRF for
        // tainted URLs and XSS for tainted loadUrl targets. The literal may sit
        // in an argument (`loadUrl("http://...")`) or in the receiver
        // (`URL("http://...").openConnection()`).
        if name == "loadUrl" || name == "openConnection" || name == "HttpGet" || name == "HttpPost" || name == "openStream" || name == "URLConnection" {
            var literals: [String] = []
            for a in args { kotlinStringLiterals(a, into: &literals) }
            if case .member(let base, _, _, _) = callee { kotlinStringLiterals(base, into: &literals) }
            if literals.contains(where: { $0.hasPrefix("http://") && !$0.hasPrefix("https://") }) {
                emit(&findings, function, offset, rule("Cleartext Network Traffic", .medium, always: true),
                     message: "Plaintext http:// endpoint used for network traffic.",
                     taint: nil, reachable: reachable, crossFile: false)
            }
            return false
        }
        // Unvalidated intent data inflating a target activity/destination.
        if ["startActivity", "startActivityForResult", "startActivityFromFragment"].contains(name),
           args.contains(where: { exprTainted($0, tainted: tainted) != nil }) {
            emit(&findings, function, offset, rule("Intent Redirection", .high, vuln: nil),
                 message: "startActivity passes data that flows from an untrusted Intent extra.",
                 taint: nil, reachable: reachable, crossFile: args.contains(where: { exprCrossFile($0, crossTainted: crossTainted) }))
            return true
        }
        // Mutable PendingIntents (no FLAG_IMMUTABLE).
        if qualified.hasPrefix("PendingIntent.") && ["getActivity", "getBroadcast", "getService", "getForegroundService"].contains(lastSeg(qualified)) {
            let hasImmutable = args.contains { e in
                let s = flatMemberText(e)
                return s.contains("IMMUTABLE")
            }
            if !hasImmutable {
                emit(&findings, function, offset, rule("PendingIntent Mutability", .medium, always: true),
                     message: "PendingIntent created without FLAG_IMMUTABLE.",
                     taint: nil, reachable: reachable, crossFile: false)
            }
            return true
        }
        // Telephony/privacy identifier access.
        if ["getDeviceId", "getImei", "getLine1Number", "getSubscriberId"].contains(name) {
            emit(&findings, function, offset, rule("Privacy Data Access", .low, always: true),
                 message: "Device/telephony identifier read.",
                 taint: nil, reachable: reachable, crossFile: false)
            return true
        }
        return false
    }

    /// Flattens an expression's text for flag matching (`PendingIntent.FLAG_IMMUTABLE`).
    private func flatMemberText(_ e: CExpr) -> String {
        switch e {
        case .identifier(let n, _): return n
        case .member(let b, let m, _, _): return flatMemberText(b) + "." + m
        case .call(let c, _, _): return flatMemberText(c)
        case .paren(let x, _): return flatMemberText(x)
        case .newExpr(let t, _, _): return t
        case .stringLiteral(let s, _): return s
        case .integerLiteral(let n, _): return n
        case .booleanLiteral(let b, _): return b ? "true" : "false"
        case .unary(_, let o, _): return flatMemberText(o)
        default: return ""
        }
    }

    /// Structural whole-function mobile checks: WebView settings property
    /// assignments (`.settings.javaScriptEnabled = true`), no-op trust managers,
    /// insecure Random standing in for SecureRandom, and tainted Intent objects
    /// routed to startActivity.
    func checkKotlinMobileStructural(fn: CFunctionDef, function: String, tainted: Set<String>, crossTainted: Set<String>, findings: inout [AstFinding], reachable: Bool) {
        // No-op X509 trust managers: `override fun checkServerTrusted(...) {}`.
        let lowName = function.lowercased()
        if lowName == "checkservertrusted" || lowName == "checkclienttrusted" {
            if case .block(let arr) = fn.body, arr.isEmpty {
                emit(&findings, function, fn.startOffset, rule("Certificate Validation Bypass", .high, always: true),
                     message: "Trust manager method is an empty no-op; all certificates are accepted.",
                     taint: nil, reachable: reachable, crossFile: false)
                return
            }
        }
        if lowName == "getacceptedissuers" {
            var returnsEmpty = false
            if case .block(let arr) = fn.body {
                for s in arr {
                    if case .returnStmt(let e, _) = s, let e = e,
                       flatMemberText(e).contains("arrayOf") {
                        returnsEmpty = true
                    }
                }
            }
            if returnsEmpty {
                emit(&findings, function, fn.startOffset, rule("Certificate Validation Bypass", .high, always: true),
                     message: "Trust manager returns an empty accepted-issuers set; all certificates are accepted.",
                     taint: nil, reachable: reachable, crossFile: false)
            }
            return
        }

        // WebView settings property assignment + insecure Random / tainted
        // Intent routing require a whole-body walk.
        var randomVar: String? = nil
        var cryptoParamsInFn = false
        var untrustedIntentVars = Set<String>()
        let propCats: [String: (String, ScanFinding.Severity)] = [
            "javaScriptEnabled": ("WebView JavaScript Enabled", .medium),
            "allowFileAccess": ("WebView File Access Enabled", .medium),
            "allowFileAccessFromFileURLs": ("WebView Local File Access", .medium),
            "allowUniversalAccessFromFileURLs": ("WebView Universal File Access", .high),
            "allowContentAccess": ("WebView Content File Access", .medium),
        ]

        func walkExpr(_ e: CExpr) {
            switch e {
            case .assign("=", let lhs, let rhs, let off):
                if let m = kotlinTrailingMember(lhs), let (cat, sev) = propCats[m] {
                    if kotlinBoolValue(rhs) == true {
                        emit(&findings, function, off, rule(cat, sev, always: true),
                             message: "WebView setting \(m) is explicitly enabled via property assignment.",
                             taint: nil, reachable: reachable, crossFile: false)
                    }
                }
                // `val rnd = Random(seed)` / `val rnd = Random()`.
                if let lhsName = simpleIdentifier(lhs), flatMemberText(rhs).hasPrefix("Random") {
                    randomVar = lhsName
                }
                if flatMemberText(rhs).contains("IvParameterSpec") || flatMemberText(rhs).contains("SecretKeySpec") {
                    cryptoParamsInFn = true
                }
                walkExpr(lhs)
                walkExpr(rhs)
            case .call(let callee, let cargs, let off):
                // Tainted data feeding an Intent's destination -> redirection.
                let cName = callName(callee)
                let recv = identifierReceiver(callee)
                if let cName = cName,
                   ["setData", "setDataAndType", "setClassName", "setClass", "setComponent", "putExtra"].contains(cName),
                   let recv = recv,
                   cargs.contains(where: { exprTainted($0, tainted: tainted) != nil }) {
                    untrustedIntentVars.insert(recv)
                }
                if cName == "startActivity", let intent = cargs.first.flatMap({ simpleIdentifier($0) }),
                   untrustedIntentVars.contains(intent) {
                    emit(&findings, function, off, rule("Intent Redirection", .high, vuln: nil),
                         message: "Activity launched with an Intent carrying attacker-controlled extras.",
                         taint: nil, reachable: reachable, crossFile: false)
                }
                // `rnd.nextBytes(buffer)` used as crypto IV/key material.
                if cName == "nextBytes", let rv = randomVar,
                   let recv = identifierReceiver(callee), recv == rv {
                    emit(&findings, function, off, rule("Insecure Random for Security", .medium, always: true),
                         message: "SecureRandom should drive IV/key generation instead of java.util.Random.",
                         taint: nil, reachable: reachable, crossFile: false)
                }
                walkExpr(callee)
                for a in cargs { walkExpr(a) }
            case .newExpr(let t, let nargs, let off):
                if t == "Random" { randomVar = "Random" }
                if t == "IvParameterSpec" || t == "SecretKeySpec" { cryptoParamsInFn = true }
                if t == "Random" { emit(&findings, function, off, rule("Insecure Random for Security", .medium, always: true), message: "Insecure java.util.Random for security-sensitive generation.", taint: nil, reachable: reachable, crossFile: false) }
                for a in nargs { walkExpr(a) }
            case .member(let b, _, _, _): walkExpr(b)
            case .index(let b, let i, _): walkExpr(b); walkExpr(i)
            case .binary(_, let l, let r, _), .comma(let l, let r, _): walkExpr(l); walkExpr(r)
            case .unary(_, let o, _): walkExpr(o)
            case .ternary(let c, let t, let f, _): walkExpr(c); walkExpr(t); walkExpr(f)
            case .cast(let x, _), .paren(let x, _): walkExpr(x)
            case .arrayInit(let arr, _): for a in arr { walkExpr(a) }
            default: break
            }
        }

        func walkStmt(_ s: CStmt) {
            switch s {
            case .block(let arr): for x in arr { walkStmt(x) }
            case .expr(let e): walkExpr(e)
            case .declaration(let d):
                if case .variable(_, let vn, let ie?) = d.kind {
                    let txt = flatMemberText(ie)
                    if txt.hasPrefix("Random") { randomVar = vn }
                    if txt.contains("IvParameterSpec") || txt.contains("SecretKeySpec") { cryptoParamsInFn = true }
                    walkExpr(ie)
                }
            case .ifStmt(_, let t, let eb, _): walkStmt(t); if let eb = eb { walkStmt(eb) }
            case .whileStmt(_, let b, _), .doWhileStmt(let b, _, _): walkStmt(b)
            case .forStmt(let i, _, _, let b, _): if let i = i { walkStmt(i) }; walkStmt(b)
            case .switchStmt(_, let cases, _): for c in cases { for x in c.body { walkStmt(x) } }
            case .labeledStmt(_, let inner, _): walkStmt(inner)
            case .returnStmt(let e?, _): walkExpr(e)
            default: break
            }
        }
        walkStmt(fn.body)
        _ = cryptoParamsInFn
    }

    /// Post-sink hardening for mobile categories. Each suppression is scoped to
    /// the *function* (via its body slice and AST) so a mitigation elsewhere in
    /// the same function — not the whole file — removes the finding.
    func applyKotlinMobileSuppressions(fn: CFunctionDef, findings: inout [AstFinding]) {
        let ns = source as NSString
        let lo = max(0, fn.startOffset)
        let hi = min(ns.length, fn.endOffset)
        let bodyText = hi > lo ? ns.substring(with: NSRange(location: lo, length: hi - lo)) : ""
        let lt = bodyText.lowercased()

        // WebView JS: disabled anywhere in the same function, or the bridge removed.
        let jsDisabled = lt.contains("setjavascriptenabled(false)") || lt.contains("javascriptenabled = false")
        if jsDisabled {
            findings.removeAll { $0.category == "WebView JavaScript Enabled" }
            findings.removeAll { $0.category == "WebView JavaScript Injection" }
        }
        if lt.contains("removejavascriptinterface") || lt.contains("removealljavascriptinterfaces") {
            findings.removeAll { $0.category == "WebView JavaScript Bridge" }
        }
        // WebView file-access toggles disabled later in the same function. The
        // property form (`allowFileAccessFromFileURLs = false`) and its setter
        // are matched per setting so each category is suppressed by its own
        // turn-off.
        let fileEnabledOff = lt.contains("setallowfileaccess(false)") || lt.contains("allowfileaccess = false")
        let localFileOff = lt.contains("setallowfileaccessfromfileurls(false)") || lt.contains("allowfileaccessfromfileurls = false")
        if fileEnabledOff || localFileOff {
            findings.removeAll { $0.category == "WebView File Access Enabled" }
            findings.removeAll { $0.category == "WebView Local File Access" }
        }
        if lt.contains("setallowuniversalaccessfromfileurls(false)") || lt.contains("allowuniversalaccessfromfileurls = false") {
            findings.removeAll { $0.category == "WebView Universal File Access" }
        }
        if lt.contains("setallowcontentaccess(false)") || lt.contains("allowcontentaccess = false") {
            findings.removeAll { $0.category == "WebView Content File Access" }
        }
        // WebView content injection / JS injection: sanitizer or CSP in scope.
        if lt.contains("sanitize") || lt.contains("content-security-policy") || lt.contains("contentsecuritypolicy") || lt.contains("escapehtml") {
            findings.removeAll { $0.category == "WebView Content Injection" }
            findings.removeAll { $0.category == "WebView JavaScript Injection" }
        }
        // Logs: isLoggable-gated logging is acceptable.
        if lt.contains("isloggable") {
            findings.removeAll { $0.category == "Sensitive Data in Logs" }
        }
        // Intent redirection: explicit allowlist/validation gates the extra.
        if lt.contains("allowed") || lt.contains("allowlist") || lt.contains("allowList")
            || lt.contains("validate") || lt.contains("istrusted") || lt.contains("sanitize") {
            findings.removeAll { $0.category == "Intent Redirection" }
        }
        // Privacy: runtime permission enforced before reading identifiers.
        if lt.contains("requestpermissions") || lt.contains("checkselfpermission")
            || lt.contains("haspermission") || lt.contains("enforcecallingpermission") {
            findings.removeAll { $0.category == "Privacy Data Access" }
        }
        // Certificates: a real verifier/chain validation exists in scope.
        if lt.contains("checkvalidity") || lt.contains("getpeercertificates")
            || lt.contains("certificatefactory")
            || lt.contains("verify") && lt.contains("chain") {
            findings.removeAll { $0.category == "Certificate Validation Bypass" }
        }
        // Hardcoded keys/IVs: sourced from a keystore/env/SecureRandom instead.
        if lt.contains("keystore") || lt.contains("system.getenv") || lt.contains("securerandom()") {
            findings.removeAll { $0.category == "Hardcoded Encryption Key" }
            findings.removeAll { $0.category == "Hardcoded IV" }
        }
        // Insecure Random: a SecureRandom instance is used in the function.
        if lt.contains("securerandom()") {
            findings.removeAll { $0.category == "Insecure Random for Security" }
        }
        // Weak file permissions: same store opened MODE_PRIVATE.
        if lt.contains("mode_private") {
            findings.removeAll { $0.category == "Weak File Permissions" }
        }
        // SharedPreferences: value is encrypted before storage.
        if lt.contains("cipher") || lt.contains("encrypt") || lt.contains("encryptor")
            || lt.contains("keystore") {
            findings.removeAll { $0.category == "Sensitive Data in SharedPreferences" }
        }
        // Cleartext: https is used in the same function (TLS in scope).
        if lt.contains("https://") {
            findings.removeAll { $0.category == "Cleartext Network Traffic" }
        }
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
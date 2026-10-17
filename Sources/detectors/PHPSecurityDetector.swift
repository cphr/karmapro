// by cipher.org.uk
// MARK: - PHP-specific AST security checks
// Extracted from AstSecurityDetector.swift to keep per-language
// vulnerability detection modular. Shared wire-up stays in
// AstSecurityDetector.swift (dispatch lines only).

import Foundation

extension AstSecurityDetector {

    /// Superglobals seeded as tainted when the AST walker processes a PHP file.
    /// They arrive as bare identifiers (`_GET`, `_POST`, ..., the `$` is a
    /// tokenizer artifact). Session values are typically attacker-written
    /// (stored request data), so `_SESSION` seeds like the rest.
    static let phpSuperglobalSeeds: Set<String> = ["_GET", "_POST", "_REQUEST", "_FILES", "_COOKIE", "_SERVER", "_ENV", "_SESSION", "php_input"]

    /// PHP superglobal names as they appear in the PHP token stream (the `$`
    /// prefix is a tokenizer artifact and is not part of the identifier).
    static let phpSuperglobalNames: Set<String> = ["_GET", "_POST", "_REQUEST", "_FILES", "_COOKIE", "_SERVER", "_ENV", "_SESSION", "php_input"]

    /// $_SERVER keys the server itself sets (protocol string, software banner,
    /// docroot). Reading one is configuration data; only HTTP_*/REQUEST_* keys
    /// are attacker-controlled.
    static let phpServerSetKeys: Set<String> = [
        "SERVER_PROTOCOL", "SERVER_SOFTWARE", "SERVER_ADMIN", "SERVER_ADDR",
        "SERVER_SIGNATURE", "DOCUMENT_ROOT", "SCRIPT_NAME", "SCRIPT_FILENAME",
        "SCRIPT_URI", "SCRIPT_URL", "GATEWAY_INTERFACE", "SERVER_PORT",
    ]

    /// True when a PHP `header()` value is genuinely attacker-sourced: the taint
    /// label is a superglobal (or `php_input`), a source/taint-returning API call,
    /// or a superglobal interpolated into a double-quoted string. Bare parameters
    /// and locals (whose root is unknown in the set-based AST taint model) are
    /// NOT treated as genuine so helper functions that build headers from their
    /// parameters do not spuriously fire; the heuristic pass still covers
    /// superglobal-rooted flows because it preserves the source root in its path.
    private func phpHeaderTaintedLabel(_ e: CExpr, tainted: Set<String>) -> String? {
        switch e {
        case .identifier(let n, _):
            return (tainted.contains(n) && Self.phpSuperglobalNames.contains(n)) ? n : nil
        case .call(let callee, let args, _):
            if let cname = callName(callee), isSeedFn(cname) { return cname }
            if let q = callQualifiedName(callee), isSeedFn(q) { return q }
            for a in args { if let t = phpHeaderTaintedLabel(a, tainted: tainted) { return t } }
            return nil
        case .member(let b, _, _, _):
            return phpHeaderTaintedLabel(b, tainted: tainted)
        case .index(let b, let idx, _):
            // Server-set $_SERVER keys are configuration, not request data.
            if case .identifier(let baseName, _) = b, baseName == "_SERVER",
               serverSetKeyText(idx) != nil {
                return nil
            }
            return phpHeaderTaintedLabel(b, tainted: tainted) ?? phpHeaderTaintedLabel(idx, tainted: tainted)
        case .unary(_, let o, _):
            return phpHeaderTaintedLabel(o, tainted: tainted)
        case .binary(_, let l, let r, _), .comma(let l, let r, _):
            return phpHeaderTaintedLabel(l, tainted: tainted) ?? phpHeaderTaintedLabel(r, tainted: tainted)
        case .assign(_, let l, let r, _):
            return phpHeaderTaintedLabel(l, tainted: tainted) ?? phpHeaderTaintedLabel(r, tainted: tainted)
        case .ternary(let c, let t, let f, _):
            return phpHeaderTaintedLabel(c, tainted: tainted) ?? phpHeaderTaintedLabel(t, tainted: tainted) ?? phpHeaderTaintedLabel(f, tainted: tainted)
        case .cast(let x, _), .paren(let x, _):
            return phpHeaderTaintedLabel(x, tainted: tainted)
        case .arrayInit(let arr, _):
            for a in arr { if let t = phpHeaderTaintedLabel(a, tainted: tainted) { return t } }
            return nil
        case .stringLiteral(let s, _):
            for global in Self.phpSuperglobalNames where global != "php_input" {
                if s.contains("$" + global + "[") || s.contains("${" + global + "[") {
                    if global == "_SERVER", literalServerKeysClean(s) { continue }
                    return global
                }
            }
            return nil
        default:
            return nil
        }
    }

    // MARK: - PHP sink checks

    func checkPHPSinks(name: String, qualified: String, args: [CExpr], offset: Int, function: String, tainted: Set<String>, crossTainted: Set<String>, guarded: Set<String>, sizeBounded: Set<String>, findings: inout [AstFinding], reachable: Bool) -> Bool {
        // `preg_replace` is only a code-injection sink with the `/e` modifier
        // (or an attacker-controlled pattern). A fixed allowlist pattern such
        // as `preg_replace('/[^A-Za-z0-9._-]/', '_', $name)` is *sanitization*,
        // not eval — report nothing for it.
        if name == "preg_replace", let first = args.first {
            if let pat = stringLiteralOf(first) {
                let flags = pat.split(separator: "/").last.map(String.init) ?? ""
                if !flags.contains("e") && exprTainted(first, tainted: tainted) == nil {
                    return true
                }
            } else if exprTainted(first, tainted: tainted) == nil {
                // Non-literal, untainted pattern (e.g. a config constant): no
                // attacker-crafted regex, no eval modifier → not a code sink.
                return true
            }
        }
        guard let rule = Self.phpSinks[qualified] ?? Self.phpSinks[name] else { return false }
        // PHP `header()`: only report when the value is genuinely attacker-sourced.
        // Function parameters are seeded tainted (they may be constants at each
        // call site), so a param-only flow inside a helper — e.g. the iGoat
        // `setHttpHeaders($contentType, $statusCode)` building `header(...)` from
        // them — is a false positive. Genuine sources are PHP superglobals, source
        // / taint-returning APIs, superglobal string interpolation, and cross-file
        // sources. (Direct superglobal flows also key the heuristic pass, which
        // tracks the source root, so suppressing bare-param label here keeps recall.)
        if name == "header", let vi = rule.vulnArgIndex, vi < args.count {
            if let label = phpHeaderTaintedLabel(args[vi], tainted: tainted),
               !isGuarded(args[vi], guarded: guarded, category: rule.category) {
                emit(&findings, function, offset, rule,
                     message: "Attacker-influenced data flows into header() from \(label); possible header injection.",
                     taint: label, reachable: reachable,
                     crossFile: exprCrossFile(args[vi], crossTainted: crossTainted))
            }
            return true
        }
        evaluateGenericRule(rule, name: qualified, args: args, offset: offset, function: function, tainted: tainted, crossTainted: crossTainted, guarded: guarded, sizeBounded: sizeBounded, findings: &findings, reachable: reachable)
        return true
    }

    /// Database write keywords inside a query literal (distinguishes a write
    /// helper from a read-only `SELECT`).
    static let phpSQLWriteRegex = try! NSRegularExpression(
        pattern: "\\b(INSERT|UPDATE|DELETE|REPLACE|DROP|ALTER|TRUNCATE)\\b",
        options: [.caseInsensitive])

    static let phpSinks: [String: AstSinkRule] = [
        // SQL Injection (procedural + PDO/mysqli member calls). The procedural
        // family leads with the connection handle, so the query is argument 1
        // (`mysqli_query($c, $q)`, `pg_query($c, $q)`); the one-arg member
        // style (`$db->query($q)`) keeps argument 0.
        "mysqli_query": .init(category: "SQL Injection", severity: .high, vulnArgIndex: 1, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "mysqli_multi_query": .init(category: "SQL Injection", severity: .high, vulnArgIndex: 1, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "mysqli_real_query": .init(category: "SQL Injection", severity: .high, vulnArgIndex: 1, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "mysqli_prepare": .init(category: "SQL Injection", severity: .high, vulnArgIndex: 1, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "pg_query": .init(category: "SQL Injection", severity: .high, vulnArgIndex: 1, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "pg_exec": .init(category: "SQL Injection", severity: .high, vulnArgIndex: 1, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "pg_query_params": .init(category: "SQL Injection", severity: .high, vulnArgIndex: 1, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "sqlite_query": .init(category: "SQL Injection", severity: .high, vulnArgIndex: 1, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "sqlite_exec": .init(category: "SQL Injection", severity: .high, vulnArgIndex: 1, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "query": .init(category: "SQL Injection", severity: .high, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "prepare": .init(category: "SQL Injection", severity: .high, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        // Command / Code Injection.
        "system": .init(category: "Command Injection", severity: .high, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "exec": .init(category: "Command Injection", severity: .high, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "shell_exec": .init(category: "Command Injection", severity: .high, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "passthru": .init(category: "Command Injection", severity: .high, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "proc_open": .init(category: "Command Injection", severity: .high, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "popen": .init(category: "Command Injection", severity: .high, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "pcntl_exec": .init(category: "Command Injection", severity: .high, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "eval": .init(category: "Code Injection", severity: .critical, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "assert": .init(category: "Code Injection", severity: .high, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "preg_replace": .init(category: "Code Injection", severity: .high, vulnArgIndex: 2, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "create_function": .init(category: "Code Injection", severity: .high, vulnArgIndex: 1, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        // Path / File Traversal.
        "file_get_contents": .init(category: "Path Traversal", severity: .medium, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "file_put_contents": .init(category: "Path Traversal", severity: .medium, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "fopen": .init(category: "Path Traversal", severity: .medium, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "readfile": .init(category: "Path Traversal", severity: .medium, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "unlink": .init(category: "Path Traversal", severity: .medium, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        // Laravel/CloudStorage-style `$storage->put($path, ...)` writes the
        // upload under a caller-influenced path.
        "put": .init(category: "Path Traversal", severity: .medium, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "mkdir": .init(category: "Path Traversal", severity: .medium, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "rmdir": .init(category: "Path Traversal", severity: .medium, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "rename": .init(category: "TOCTOU / Race Condition", severity: .medium, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "move_uploaded_file": .init(category: "Arbitrary File Write", severity: .high, vulnArgIndex: 1, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        // File inclusion / LFI.
        "include": .init(category: "Path Traversal (File Inclusion)", severity: .high, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "include_once": .init(category: "Path Traversal (File Inclusion)", severity: .high, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "require": .init(category: "Path Traversal (File Inclusion)", severity: .high, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "require_once": .init(category: "Path Traversal (File Inclusion)", severity: .high, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        // SSRF / Network.
        "curl_init": .init(category: "SSRF", severity: .high, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "curl_setopt": .init(category: "SSRF", severity: .high, vulnArgIndex: 2, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "fsockopen": .init(category: "SSRF", severity: .high, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "stream_socket_client": .init(category: "SSRF", severity: .high, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "get_headers": .init(category: "SSRF", severity: .high, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "socket_create": .init(category: "SSRF", severity: .high, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        // Insecure Deserialization.
        "unserialize": .init(category: "Insecure Deserialization", severity: .critical, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        // XSS (function-call forms; `echo`/`print` handled separately).
        "printf": .init(category: "XSS (HTML Injection)", severity: .high, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "vprintf": .init(category: "XSS (HTML Injection)", severity: .high, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "print": .init(category: "XSS (HTML Injection)", severity: .high, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "header": .init(category: "Header Injection", severity: .high, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        // Weak Cryptography / Randomness.
        "md5": .init(category: "Weak Cryptography", severity: .low, vulnArgIndex: 0, alwaysVulnerable: true, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "sha1": .init(category: "Weak Cryptography", severity: .low, vulnArgIndex: 0, alwaysVulnerable: true, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "crypt": .init(category: "Weak Cryptography", severity: .medium, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "rand": .init(category: "Weak Randomness", severity: .low, vulnArgIndex: 0, alwaysVulnerable: true, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "mt_rand": .init(category: "Weak Randomness", severity: .low, vulnArgIndex: 0, alwaysVulnerable: true, formatArgIndex: nil, bufferOverflowOnFormat: false),
    ]

    func checkPHPLooseAuthCompare(fn: CFunctionDef, function: String, params: Set<String>, findings: inout [AstFinding], reachable: Bool) {
        let low = function.lowercased()
        let authWords = ["authoriz", "authorise", "auth", "authenticat", "login", "logon",
                         "verify", "valid", "token", "permission", "permit", "isallowed",
                         "acl", "password", "passwd", "signin"]
        guard authWords.contains(where: { low.contains($0) }) else { return }
        // Hardening present anywhere is treated as the explicit remediation:
        // hash_equals / password_verify / strict `===` / is_string type checks.
        let fileLow = source.lowercased()
        guard !fileLow.contains("hash_equals") && !fileLow.contains("password_verify")
            && !fileLow.contains("is_string") && !fileLow.contains("strcmp")
            && !source.contains("===") else { return }
        let safeBases: Set<String> = ["_SESSION", "_COOKIE", "_POST", "_GET", "_REQUEST", "_SERVER"]
        func unwrap(_ e: CExpr) -> CExpr {
            if case .paren(let x, _) = e { return unwrap(x) }
            return e
        }
        func isUserValue(_ e: CExpr) -> Bool {
            switch unwrap(e) {
            case .identifier(let n, _): return params.contains(n) || safeBases.contains(n)
            case .member(let b, _, _, _): return isUserValue(b)
            case .index(let b, _, _): return isUserValue(b)
            default: return false
            }
        }
        func isPlainOperand(_ e: CExpr) -> Bool {
            switch unwrap(e) {
            case .identifier, .member, .index: return true
            default: return false
            }
        }
        var matchedOffset: Int? = nil
        func scanStmt(_ s: CStmt) {
            if matchedOffset != nil { return }
            switch s {
            case .block(let arr): for x in arr { scanStmt(x) }
            case .returnStmt(let e?, let off):
                if case .binary("==", let l, let r, _) = e,
                   isPlainOperand(l), isPlainOperand(r), isUserValue(l), isUserValue(r) {
                    matchedOffset = off
                }
            case .expr(let e): scanExpr(e)
            case .declaration(let d):
                if case .variable(_, _, let ie?) = d.kind { scanExpr(ie) }
            case .ifStmt(_, let t, let eb, _): scanStmt(t); if let eb = eb { scanStmt(eb) }
            case .whileStmt(_, let b, _), .doWhileStmt(let b, _, _): scanStmt(b)
            case .forStmt(let i, _, _, let b, _): if let i = i { scanStmt(i) }; scanStmt(b)
            case .switchStmt(_, let cases, _): for c in cases { for x in c.body { scanStmt(x) } }
            case .labeledStmt(_, let inner, _): scanStmt(inner)
            default: break
            }
        }
        func scanExpr(_ e: CExpr) {
            if matchedOffset != nil { return }
            switch e {
            case .binary("==", let l, let r, let off):
                if isPlainOperand(l), isPlainOperand(r), isUserValue(l), isUserValue(r) {
                    matchedOffset = off
                    return
                }
                scanExpr(l); scanExpr(r)
            case .binary(_, let l, let r, _), .comma(let l, let r, _): scanExpr(l); scanExpr(r)
            case .call(_, let args, _): for a in args { scanExpr(a) }
            case .member(let b, _, _, _): scanExpr(b)
            case .index(let b, let i, _): scanExpr(b); scanExpr(i)
            case .unary(_, let o, _): scanExpr(o)
            case .cast(let x, _), .paren(let x, _): scanExpr(x)
            case .ternary(let c, let t, let f, _): scanExpr(c); scanExpr(t); scanExpr(f)
            case .assign(_, let l, let r, _): scanExpr(l); scanExpr(r)
            case .newExpr(_, let args, _): for a in args { scanExpr(a) }
            default: break
            }
        }
        scanStmt(fn.body)
        if let off = matchedOffset {
            emit(&findings, function, off,
                 AstSinkRule(category: "PHP Loose Comparison Auth Bypass", severity: .high, vulnArgIndex: nil, alwaysVulnerable: true, formatArgIndex: nil, bufferOverflowOnFormat: false),
                 message: "Authorization decided by loose '==' comparison; type-juggling can bypass it. Use hash_equals / ===",
                 taint: nil, reachable: reachable, crossFile: false)
        }
    }

    /// AST-based state-change guard check. A handler that reads form/request
    /// input and then mutates server state (database write or file mutation)
    /// must validate a request-forgery token first. When the function performs
    /// such a mutation with no token / origin check anywhere in its body, the
    /// state change is reachable cross-site and is reported.
    func checkPHPAccessControl(fn: CFunctionDef, function: String, findings: inout [AstFinding], reachable: Bool) {
        // Token/origin identifiers whose presence anywhere in the body counts as
        // a request-forgery guard, regardless of the framework used.
        let guardMarkers = ["csrf", "nonce", "form_key", "formkey",
                            "requesttoken", "request_token", "xsrf",
                            "hash_equals", "check_admin", "check_ajax",
                            "verify_nonce", "check_referer", "referer",
                            "formtoken", "form_token", "captcha", "token"]
        func nameLooksGuarded(_ name: String) -> Bool {
            let low = name.lowercased()
            return guardMarkers.contains { low.contains($0) }
        }
        // A token key like `$_POST['token']` / `$_SESSION['csrf']` is a guard
        // even though the bare identifier `token` is too common to match on.
        // Single-quoted PHP strings are not always surfaced as string literals
        // by the shared parser, so accept identifier/char-literal nodes too.
        let tokenKeyMarkers = ["csrf", "nonce", "token", "xsrf", "form_key"]
        func keyLooksGuarded(_ e: CExpr) -> Bool {
            func texts(_ e: CExpr) -> [String] {
                switch e {
                case .stringLiteral(let s, _), .charLiteral(let s, _): return [s]
                case .identifier(let n, _): return [n]
                case .paren(let x, _), .cast(let x, _): return texts(x)
                default: return []
                }
            }
            for t in texts(e) {
                let low = t.lowercased()
                if tokenKeyMarkers.contains(where: { low.contains($0) }) { return true }
            }
            return false
        }
        func mentions(_ e: CExpr, _ names: Set<String>) -> Bool {
            switch e {
            case .identifier(let n, _): return names.contains(n)
            case .member(let b, _, _, _): return mentions(b, names)
            case .index(let b, let i, _): return mentions(b, names) || mentions(i, names)
            case .unary(_, let o, _): return mentions(o, names)
            case .binary(_, let l, let r, _), .comma(let l, let r, _): return mentions(l, names) || mentions(r, names)
            case .ternary(let c, let t, let f, _): return mentions(c, names) || mentions(t, names) || mentions(f, names)
            case .assign(_, let l, let r, _): return mentions(l, names) || mentions(r, names)
            case .cast(let x, _), .paren(let x, _): return mentions(x, names)
            case .arrayInit(let es, _): return es.contains { mentions($0, names) }
            case .call(_, let args, _): return args.contains { mentions($0, names) }
            default: return false
            }
        }
        let requestVars: Set<String> = ["_POST", "_GET", "_REQUEST"]
        let sessionVars: Set<String> = ["_SESSION", "_COOKIE", "_SERVER"]
        var readsRequest = false
        var mutates = false
        var guarded = false
        var mutateOffset: Int? = nil
        // Non-SQL state mutators. SQL writes are recognised from the literal
        // statement passed to a query helper (a SELECT helper is not a write).
        let mutationCalls: Set<String> = ["file_put_contents", "fwrite", "fputs",
                                           "move_uploaded_file", "unlink", "rename",
                                           "mkdir", "rmdir", "chmod", "chown", "touch",
                                           "truncate", "copy",
                                           "insert", "update", "delete", "save",
                                           "replace", "upsert", "store", "persist"]
        func walkExpr(_ e: CExpr) {
            switch e {
            case .identifier(let n, _):
                if Self.phpSuperglobalNames.contains(n) { readsRequest = true }
                if nameLooksGuarded(n) { guarded = true }
            case .call(let callee, let args, let off):
                let nm = callName(callee) ?? ""
                let q = callQualifiedName(callee) ?? nm
                if nameLooksGuarded(nm) || nameLooksGuarded(q) { guarded = true }
                if mutationCalls.contains(nm) || mutationCalls.contains(q) {
                    mutates = true
                    if mutateOffset == nil { mutateOffset = off }
                }
                for a in args {
                    if let s = stringLiteralOf(a), Self.phpSQLWriteRegex.firstMatch(
                        in: s, options: [], range: NSRange(s.startIndex..., in: s)) != nil {
                        mutates = true
                        if mutateOffset == nil { mutateOffset = off }
                    }
                }
                for a in args { walkExpr(a) }
            case .member(let b, let m, _, _):
                if nameLooksGuarded(m) { guarded = true }
                walkExpr(b)
            case .index(let b, let i, _):
                if keyLooksGuarded(i) { guarded = true }
                walkExpr(b); walkExpr(i)
            case .binary(let op, let l, let r, _):
                if op == "==" || op == "!=" || op == "===" || op == "!==" {
                    // Classic token check: a request value compared against a
                    // session/expected value.
                    if (mentions(l, requestVars) && mentions(r, sessionVars))
                        || (mentions(r, requestVars) && mentions(l, sessionVars)) {
                        guarded = true
                    }
                }
                walkExpr(l); walkExpr(r)
            case .comma(let l, let r, _): walkExpr(l); walkExpr(r)
            case .unary(_, let o, _): walkExpr(o)
            case .ternary(let c, let t, let f, _): walkExpr(c); walkExpr(t); walkExpr(f)
            case .assign(_, let l, let r, _): walkExpr(l); walkExpr(r)
            case .cast(let x, _), .paren(let x, _): walkExpr(x)
            case .arrayInit(let es, _): for x in es { walkExpr(x) }
            case .newExpr(_, let args, _): for a in args { walkExpr(a) }
            default: break
            }
        }
        func walkStmt(_ s: CStmt) {
            switch s {
            case .block(let arr): for x in arr { walkStmt(x) }
            case .expr(let e): walkExpr(e)
            case .declaration(let d):
                if case .variable(_, _, let ie?) = d.kind { walkExpr(ie) }
            case .returnStmt(let e?, _): walkExpr(e)
            case .ifStmt(let c, let t, let eb, _):
                // Classic token validation: the condition relates request input
                // to session/server state (e.g. comparing a submitted token to
                // `$_SESSION[...]`). Robust to the parser mis-shaping the
                // operand, so it is checked at the guard-statement level.
                if mentions(c, requestVars) && mentions(c, sessionVars) { guarded = true }
                walkExpr(c); walkStmt(t); if let eb = eb { walkStmt(eb) }
            case .whileStmt(let c, let b, _): walkExpr(c); walkStmt(b)
            case .doWhileStmt(let b, let c, _): walkStmt(b); walkExpr(c)
            case .forStmt(let i, let c, let inc, let b, _):
                if let i = i { walkStmt(i) }; if let c = c { walkExpr(c) }
                if let inc = inc { walkExpr(inc) }; walkStmt(b)
            case .switchStmt(let e, let cases, _):
                walkExpr(e); for cs in cases { for x in cs.body { walkStmt(x) } }
            case .labeledStmt(_, let inner, _): walkStmt(inner)
            default: break
            }
        }
        walkStmt(fn.body)
        // Report only a genuine cross-site-reachable state change: form/request
        // input drives a mutation and no request-forgery guard is present.
        if readsRequest, mutates, !guarded, let off = mutateOffset {
            emit(&findings, function, off,
                 AstSinkRule(category: "Cross-Site Request Forgery", severity: .medium, vulnArgIndex: nil, alwaysVulnerable: true, formatArgIndex: nil, bufferOverflowOnFormat: false),
                 message: "Request input drives a server state change without any request-forgery token or origin check; the action can be triggered cross-site.",
                 taint: "request", reachable: reachable, crossFile: false)
        }
    }

    /// Applies the PHP-specific file-level suppressions: when the file contains
    /// an allowlist / hardening guard for a category, drop that category's
    /// findings (command allowlist + escapeshellarg, path traversal canonical
    /// resolution, file-inclusion view allowlist, SSRF host/scheme allowlist,
    /// atomic rename pattern, upload MIME allowlist, unserialize
    /// allowed_classes). Logic moved verbatim from AstSecurityDetector's
    /// `scanFunction`.
    func applyPHPSuppressions(findings: inout [AstFinding]) {
        // PHP command allowlist: `ALLOWED_COMMANDS` / arg escaping
        // (escapeshellarg) before command execution means the command is not
        // attacker-controlled.
        let hasCmdGuard = source.contains("ALLOWED_COMMANDS") || source.contains("escapeshellarg")
        if hasCmdGuard {
            findings.removeAll { $0.category == "Command Injection" }
        }
        // PHP path containment: `safeResolve` / `realpath` canonicalization
        // with a base-dir prefix check is the canonical path-traversal
        // mitigation.
        let hasPathGuard = source.contains("safeResolve") || source.contains("realpath")
        if hasPathGuard {
            findings.removeAll { $0.category == "Path Traversal" }
        }
        // PHP file inclusion: allowlisted view/map lookup (`VIEWS`, `in_array`)
        // before include/require means the target is a server-side constant.
        let hasLfiGuard = source.contains("in_array") || source.contains("VIEW_DIR")
        if hasLfiGuard {
            findings.removeAll { $0.category == "Path Traversal (File Inclusion)" }
        }
        // PHP SSRF: scheme+host allowlist (`ALLOWED_HOSTS` + `ALLOWED_SCHEMES`
        // via parse_url/validatedUrl) is the standard egress gate.
        let hasUrlGuard = source.contains("ALLOWED_HOSTS") || source.contains("validatedUrl")
        if hasUrlGuard {
            findings.removeAll { $0.category == "SSRF" }
        }
        // PHP atomic save: writing a temp file with a random name then `rename`
        // is the canonical TOCTOU-free replace pattern.
        let hasAtomic = source.contains("atomicReplace") || (source.contains("random_bytes") && source.contains("rename"))
        if hasAtomic {
            findings.removeAll { $0.category == "TOCTOU / Race Condition" }
        }
        // PHP uploads: MIME allowlist (`ALLOWED_TYPES`), finfo sniffing and
        // is_uploaded_file() verification mean move_uploaded_file() only writes
        // server-chosen content.
        let hasUploadGuard = source.contains("ALLOWED_TYPES") || source.contains("is_uploaded_file")
        if hasUploadGuard {
            findings.removeAll { $0.category == "Arbitrary File Write" }
        }
        // PHP deserialization: `unserialize(..., ['allowed_classes' => ...])`
        // constrains object instantiation to an allowlist (or disables it) —
        // the standard harden-the-call pattern.
        let hasDeserGuard = source.contains("allowed_classes")
        if hasDeserGuard {
            findings.removeAll { $0.category == "Insecure Deserialization" }
        }
    }

} // end extension AstSecurityDetector

extension VulnerabilityScanner {

    /// PHP-specific per-file function classification for the heuristic pass.
    /// Distinguishes param-propagation taint-returning functions (whose tainted
    /// return derives only from their parameters, e.g. a serializer like
    /// `encodeJson($data)`) from true sources (which read a superglobal or
    /// system source-API internally, e.g. `getUntrusted()` returning
    /// `$_GET[$key]`). Propagation functions are demoted to *conditional* — they
    /// only taint their result when a call argument is tainted. Also computes the
    /// file-local PHP sanitizer set (functions whose bodies only reference
    /// sanitizer helpers). Returns the conditional set and the sanitizer list.
    /// Canonical set of PHP functions that themselves transform a value into a
    /// safe form. Content-preserving reshapers (trim, substr, implode, array_map,
    /// …) are deliberately excluded: a helper that only trims or re-slices its
    /// argument still returns attacker-controlled data.
    static let phpSanitizerFunctionSet: Set<String> = [
        "htmlspecialchars", "htmlentities",
        "preg_replace", "preg_quote", "escapeshellarg",
        // Database escape helpers: they return an escaped copy of their
        // argument, so a value built from one of these is safe for the engine
        // when the statement quotes it (unquoted numeric contexts still
        // evaluate as injectable by the call-site check on the literal).
        "mysqli_real_escape_string", "mysql_real_escape_string",
        "mysqli_escape_string", "mysql_escape_string",
        "pg_escape_string", "pg_escape_literal", "sqlite_escape_string",
        "urlencode", "rawurlencode", "strip_tags",
        "addcslashes", "bin2hex", "clean", "sanitize",
        "intval", "floatval", "boolval",
        "bindec", "hexdec", "octdec",
        "round", "abs", "number_format",
        "strlen", "strcmp", "strcasecmp",
        "str_contains", "str_starts_with", "str_ends_with",
        "preg_match", "preg_match_all",
        "array_key_exists"]

    static func phpClassifyFunctions(isPHP: Bool, source: String, tokens: [Token], localTaintReturning: Set<String>, projectIndex: ProjectIndex?) -> (conditionalTaintReturning: Set<String>, phpSanitizersLocal: Set<String>) {
        let phpSanitizerSet = Self.phpSanitizerFunctionSet
        var phpSanitizersLocal = projectIndex?.globalPHPSanitizers ?? []
        var conditionalTaintReturning: Set<String> = []
        if isPHP {
            let phpSuperglobals: Set<String> = ["_GET","_POST","_REQUEST","_FILES","_COOKIE","_SERVER","_ENV"]
            let phpDefs = ScriptMethodParser(language: .php, source: source).parseMethods()
            var sourceReading = Set<String>()
            // Transitive within-file fixpoint: source-reading if body references
            // a superglobal, calls a system taint-return function, or calls
            // another local source-reading function.
            var changed = true
            while changed {
                changed = false
                for def in phpDefs {
                    if sourceReading.contains(def.name) { continue }
                    let r = def.bodyRange
                    let body = Self.tokens(in: r, tokenList: tokens)
                    for tk in body where tk.kind == .identifier {
                        if phpSuperglobals.contains(tk.text) || taintReturnFunctions.contains(tk.text) || sourceReading.contains(tk.text) {
                            sourceReading.insert(def.name)
                            changed = true
                            break
                        }
                    }
                }
            }
            // Sanitizer functions: bodies that only reference sanitizer helpers
            // (preg_replace, htmlspecialchars, …) and never a superglobal or
            // taint-returning source. Calls to these produce clean values.
            let phpDefParams: [String: Set<String>] = Dictionary(uniqueKeysWithValues: phpDefs.compactMap { def -> (String, Set<String>)? in
                let params = def.params.compactMap { $0.name }
                return (def.name, Set(params))
            })
            changed = true
            while changed {
                changed = false
                for def in phpDefs {
                    if phpSanitizersLocal.contains(def.name) || sourceReading.contains(def.name) { continue }
                    let defParams = phpDefParams[def.name] ?? []
                    let r = def.bodyRange
                    let body = Self.tokens(in: r, tokenList: tokens)
                    var onlySanitizers = true
                    // A body that merely forwards its own parameters (a pure
                    // pass-through such as `function id($v){ return $v; }`)
                    // sanitises nothing, so it must not be treated as clean.
                    // Require at least one real sanitizer call.
                    var sawSanitizer = false
                    for tk in body where tk.kind == .identifier {
                        if phpSuperglobals.contains(tk.text) || taintReturnFunctions.contains(tk.text)
                           || sourceReading.contains(tk.text) {
                            onlySanitizers = false
                            break
                        }
                        if defParams.contains(tk.text) { continue }
                        if phpSanitizerSet.contains(tk.text) || phpSanitizersLocal.contains(tk.text) {
                            sawSanitizer = true
                            continue
                        }
                        onlySanitizers = false
                        break
                    }
                    if onlySanitizers && sawSanitizer {
                        phpSanitizersLocal.insert(def.name)
                        changed = true
                    }
                }
            }
            // Demote local taint-returning functions that are NOT source readers
            // to conditional (param-propagation only), excluding sanitizer fns.
            conditionalTaintReturning = localTaintReturning.filter { name in
                phpDefs.contains { $0.name == name } && !sourceReading.contains(name) && !taintReturnFunctions.contains(name) && !phpSanitizersLocal.contains(name)
            }
        }
        return (conditionalTaintReturning, phpSanitizersLocal)
    }

} // end extension VulnerabilityScanner

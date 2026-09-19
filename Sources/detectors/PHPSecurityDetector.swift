// by cipher.org.uk
// MARK: - PHP-specific AST security checks
// Extracted from AstSecurityDetector.swift to keep per-language
// vulnerability detection modular. Shared wire-up stays in
// AstSecurityDetector.swift (dispatch lines only).

import Foundation

extension AstSecurityDetector {

    /// Superglobals seeded as tainted when the AST walker processes a PHP file.
    /// They arrive as bare identifiers (`_GET`, `_POST`, ..., the `$` is a
    /// tokenizer artifact).
    static let phpSuperglobalSeeds: Set<String> = ["_GET", "_POST", "_REQUEST", "_FILES", "_COOKIE", "_SERVER", "_ENV", "php_input"]

    /// PHP superglobal names as they appear in the PHP token stream (the `$`
    /// prefix is a tokenizer artifact and is not part of the identifier).
    static let phpSuperglobalNames: Set<String> = ["_GET", "_POST", "_REQUEST", "_FILES", "_COOKIE", "_SERVER", "_ENV", "_SESSION", "php_input"]

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
                if s.contains("$" + global + "[") || s.contains("${" + global + "[") { return global }
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

    static let phpSinks: [String: AstSinkRule] = [
        // SQL Injection (procedural + PDO/mysqli member calls).
        "mysqli_query": .init(category: "SQL Injection", severity: .high, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "mysqli_multi_query": .init(category: "SQL Injection", severity: .high, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "mysqli_real_query": .init(category: "SQL Injection", severity: .high, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "mysqli_prepare": .init(category: "SQL Injection", severity: .high, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "pg_query": .init(category: "SQL Injection", severity: .high, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "pg_exec": .init(category: "SQL Injection", severity: .high, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "pg_query_params": .init(category: "SQL Injection", severity: .high, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "sqlite_query": .init(category: "SQL Injection", severity: .high, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "sqlite_exec": .init(category: "SQL Injection", severity: .high, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
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
    static func phpClassifyFunctions(isPHP: Bool, source: String, tokens: [Token], localTaintReturning: Set<String>, projectIndex: ProjectIndex?) -> (conditionalTaintReturning: Set<String>, phpSanitizersLocal: Set<String>) {
        let phpSanitizerSet: Set<String> = ["htmlspecialchars", "htmlentities", "preg_replace",
                                             "preg_quote", "escapeshellarg", "urlencode", "rawurlencode",
                                             "strip_tags", "addcslashes", "bin2hex", "clean",
                                             "strlen", "substr", "trim", "ltrim", "rtrim",
                                             "strtolower", "strtoupper", "str_replace", "str_ireplace",
                                             "preg_match", "preg_match_all", "preg_split", "preg_filter",
                                             "implode", "explode", "join", "sprintf", "number_format",
                                             "round", "abs", "intval", "floatval", "boolval",
                                             "bindec", "hexdec", "octdec", "decbin", "dechex", "decoct",
                                             "wordwrap", "strrev", "strtr", "chunk_split", "str_pad",
                                             "str_repeat", "strcmp", "strcasecmp", "str_contains",
                                             "str_starts_with", "str_ends_with",
                                             "array_filter", "array_map", "array_values", "array_keys",
                                             "sort", "rsort", "ksort", "asort", "array_unique",
                                             "array_merge", "array_slice", "array_splice",
                                             "array_change_key_case", "array_chunk", "array_column",
                                             "array_combine", "array_count_values", "array_diff",
                                             "array_fill", "array_fill_keys", "array_filter",
                                             "array_flip", "array_intersect", "array_key_exists",
                                             "array_key_first", "array_key_last", "array_keys",
                                             "array_map", "array_merge", "array_merge_recursive",
                                             "array_pad", "array_pop", "array_product", "array_push",
                                             "array_rand", "array_replace", "array_replace_recursive",
                                             "array_reverse", "array_search", "array_shift",
                                             "array_slice", "array_splice", "array_sum",
                                             "array_udiff", "array_unique", "array_unshift",
                                             "array_values", "array_walk", "arsort", "asort",
                                             "krsort", "ksort", "natcasesort", "natsort",
                                             "range", "uasort", "uksort", "usort",
                                             "array_slice", "array_splice"]
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
                    for tk in body where tk.kind == .identifier {
                        if phpSuperglobals.contains(tk.text) || taintReturnFunctions.contains(tk.text)
                           || sourceReading.contains(tk.text) {
                            onlySanitizers = false
                            break
                        }
                        if defParams.contains(tk.text) { continue }
                        if !phpSanitizerSet.contains(tk.text), !phpSanitizersLocal.contains(tk.text) {
                            onlySanitizers = false
                            break
                        }
                    }
                    if onlySanitizers {
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

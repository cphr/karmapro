// by cipher.org.uk
// MARK: - Rust-specific AST security checks
// Extracted from AstSecurityDetector.swift / VulnerabilityScanner.swift to
// keep per-language vulnerability detection modular. Shared wire-up stays in
// AstSecurityDetector.swift · VulnerabilityScanner.swift (dispatch lines only).

import Foundation

extension AstSecurityDetector {

    /// Rust sinks (mirrors the scanner's Rust table). Keyed on the dotted Rust
    /// API path (`Command.new`, `reqwest.get`) or a bare method name (`arg`,
    /// `prepare`, `query`) when it applies to any receiver of that method.

    static let rustSinks: [String: AstSinkRule] = [
        "Command.new": .init(category: "Command Injection", severity: .high, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        // NOTE: `Html` XSS below is gated on the absence of html-escape helpers.
        "sql_query": .init(category: "SQL Injection", severity: .high, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "one_off": .init(category: "Server-Side Template Injection", severity: .critical, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "deserialize": .init(category: "Insecure Deserialization", severity: .critical, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "NamedFile.open": .init(category: "Path Traversal", severity: .medium, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "Html": .init(category: "XSS (HTML Injection)", severity: .high, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "append_header": .init(category: "Open Redirect", severity: .medium, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "uri": .init(category: "SSRF", severity: .high, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "arg": .init(category: "Command Injection", severity: .high, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "args": .init(category: "Command Injection", severity: .high, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "prepare": .init(category: "SQL Injection", severity: .high, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "query": .init(category: "SQL Injection", severity: .high, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "execute": .init(category: "SQL Injection", severity: .high, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "execute_batch": .init(category: "SQL Injection", severity: .high, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "query_row": .init(category: "SQL Injection", severity: .high, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "File.open": .init(category: "Path Traversal", severity: .medium, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "File.create": .init(category: "Path Traversal", severity: .medium, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        // `PathBuf::from(base).join(user_controlled)` — joining a caller-
        // controlled segment escapes the base directory. Suppressed when the
        // function rejects ParentDir/RootDir components first.
        "join": .init(category: "Path Traversal", severity: .medium, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "fs.File.create": .init(category: "Path Traversal", severity: .medium, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "fs.write": .init(category: "Path Traversal", severity: .medium, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "write": .init(category: "Path Traversal", severity: .medium, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "read_to_string": .init(category: "Path Traversal", severity: .medium, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "create_dir": .init(category: "Path Traversal", severity: .medium, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "create_dir_all": .init(category: "Path Traversal", severity: .medium, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "remove_file": .init(category: "Path Traversal", severity: .medium, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "remove_dir": .init(category: "Path Traversal", severity: .medium, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "remove_dir_all": .init(category: "Path Traversal", severity: .medium, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "read_dir": .init(category: "Path Traversal", severity: .medium, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "symlink": .init(category: "Path Traversal", severity: .medium, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "hard_link": .init(category: "Path Traversal", severity: .medium, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "copy": .init(category: "Path Traversal", severity: .medium, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "rename": .init(category: "TOCTOU / Race Condition", severity: .medium, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "reqwest.get": .init(category: "SSRF", severity: .high, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "reqwest.post": .init(category: "SSRF", severity: .high, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "ureq.get": .init(category: "SSRF", severity: .high, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "ureq.post": .init(category: "SSRF", severity: .high, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "get": .init(category: "SSRF", severity: .high, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "post": .init(category: "SSRF", severity: .high, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "connect": .init(category: "SSRF", severity: .high, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "serde_yaml.from_str": .init(category: "Insecure Deserialization", severity: .high, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "bincode.deserialize": .init(category: "Insecure Deserialization", severity: .high, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "ron.from_str": .init(category: "Insecure Deserialization", severity: .high, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "md5.compute": .init(category: "Weak Cryptography", severity: .medium, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "Sha1.digest": .init(category: "Weak Cryptography", severity: .medium, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "sha1.digest": .init(category: "Weak Cryptography", severity: .medium, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "Md5.digest": .init(category: "Weak Cryptography", severity: .medium, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "Md5.new": .init(category: "Weak Cryptography", severity: .medium, vulnArgIndex: 0, alwaysVulnerable: true, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "rand.thread_rng": .init(category: "Weak Randomness", severity: .low, vulnArgIndex: 0, alwaysVulnerable: true, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "rand.random": .init(category: "Weak Randomness", severity: .low, vulnArgIndex: 0, alwaysVulnerable: true, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "StdRng.from_seed": .init(category: "Weak Randomness", severity: .low, vulnArgIndex: 0, alwaysVulnerable: true, formatArgIndex: nil, bufferOverflowOnFormat: false),
    ]


    func checkRustSinks(name: String, qualified: String, args: [CExpr], offset: Int, function: String, tainted: Set<String>, crossTainted: Set<String>, guarded: Set<String>, sizeBounded: Set<String>, findings: inout [AstFinding], reachable: Bool) -> Bool {
        guard let rule = Self.rustSinks[qualified] ?? Self.rustSinks[name] else { return false }
        // `Command::new(prog).arg(x)` — std/tokio process args are passed to the
        // OS directly (no shell), so plain `.arg(...)` chains are not command
        // injection. Injection needs a shell program (`sh`/`bash`/`cmd`/…)
        // or an explicit `-c`/`/c` flag anywhere in the file.
        // `Html(escaped)` after contextual html encoding is safe.
        if rule.category == "XSS (HTML Injection)", name == "Html",
           source.contains("html_escape") || source.contains("encode_text") || source.contains("encode_safe") {
            return true
        }
        if rule.category == "Command Injection", name == "arg" || name == "args" {
            let low = source.lowercased()
            let shellProgram = ["command::new(\"sh\"", "command::new(\"bash\"", "command::new(\"zsh\"",
                                "command::new(\"cmd\"", "command::new(\"powershell\"", "command::new(\"pwsh\"",
                                "command::new(&\"sh\"", "command::new(&\"bash\""].contains(where: { low.contains($0) })
            let shellFlag = low.contains(".arg(\"-c\")") || low.contains(".arg(\"/c\")")
            if !(shellProgram || shellFlag) { return true }
        }
        // Rust sqlx parameterized queries: `.bind(...)` chained after a
        // `query(...)` call is the standard secure idiom — the SQL template
        // is fixed and values travel as bound placeholders.
        if rule.category == "SQL Injection", source.contains(".bind(") {
            return true
        }
        evaluateGenericRule(rule, name: qualified, args: args, offset: offset, function: function, tainted: tainted, crossTainted: crossTainted, guarded: guarded, sizeBounded: sizeBounded, findings: &findings, reachable: reachable)
        return true
    }



    /// Rust hardening awareness:
    ///  - `PathBuf` joins guarded by a component-rejection walk
    ///    (`components()` / `starts_with(` / `canonicalize` / `file_name`)
    ///    stay inside the base directory,
    ///  - `ALLOWED_HOSTS` host allowlist gates SSRF egress.
    func applyRustSuppressions(fn: CFunctionDef, findings: inout [AstFinding]) {
        let low = source.lowercased()
        if source.contains("components()") || source.contains("starts_with(")
             || source.contains("canonicalize") || source.contains("file_name") {
            findings.removeAll { $0.category == "Path Traversal" }
        }
        if low.contains("allowed_hosts") {
            findings.removeAll { $0.category == "SSRF" }
        }
    }
} // end extension AstSecurityDetector

// by cipher.org.uk
// MARK: - Ruby-specific AST security checks
// Extracted from AstSecurityDetector.swift / VulnerabilityScanner.swift to
// keep per-language vulnerability detection modular. Shared wire-up stays in
// AstSecurityDetector.swift · VulnerabilityScanner.swift (dispatch lines only).

import Foundation

extension AstSecurityDetector {

    /// Ruby sinks (mirrors the scanner's Ruby table). Keyed on the dotted
    /// Ruby API path (`IO.popen`, `File.open`) or a bare method name
    /// (`system`, `exec`, `where`) when it applies to any receiver of that method.
    static let rubySinks: [String: AstSinkRule] = [
        "system": .init(category: "Command Injection", severity: .high, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "exec": .init(category: "Command Injection", severity: .high, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "spawn": .init(category: "Command Injection", severity: .high, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "IO.popen": .init(category: "Command Injection", severity: .high, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "IO.popen2": .init(category: "Command Injection", severity: .high, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "popen": .init(category: "Command Injection", severity: .high, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "Open3.capture2e": .init(category: "Command Injection", severity: .high, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "Open3.capture2": .init(category: "Command Injection", severity: .high, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "Open3.capture3": .init(category: "Command Injection", severity: .high, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "Open3.pipeline": .init(category: "Command Injection", severity: .high, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "Open3.popen2": .init(category: "Command Injection", severity: .high, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "Open3.popen3": .init(category: "Command Injection", severity: .high, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "Process.exec": .init(category: "Command Injection", severity: .high, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "open": .init(category: "Path Traversal", severity: .medium, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "File.open": .init(category: "Path Traversal", severity: .medium, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "File.read": .init(category: "Path Traversal", severity: .medium, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "File.readlines": .init(category: "Path Traversal", severity: .medium, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "File.write": .init(category: "Path Traversal", severity: .medium, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "File.delete": .init(category: "Path Traversal", severity: .medium, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "File.unlink": .init(category: "Path Traversal", severity: .medium, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "FileUtils.rm": .init(category: "Path Traversal", severity: .medium, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "FileUtils.rm_rf": .init(category: "Path Traversal", severity: .medium, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "FileUtils.cp": .init(category: "Path Traversal", severity: .medium, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "FileUtils.mv": .init(category: "Path Traversal", severity: .medium, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "FileUtils.mkdir_p": .init(category: "Path Traversal", severity: .medium, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "Dir.mkdir": .init(category: "Path Traversal", severity: .medium, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "Dir.delete": .init(category: "Path Traversal", severity: .medium, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "IO.read": .init(category: "Path Traversal", severity: .medium, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "IO.readlines": .init(category: "Path Traversal", severity: .medium, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "find_by_sql": .init(category: "SQL Injection", severity: .high, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "select_all": .init(category: "SQL Injection", severity: .high, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "exec_query": .init(category: "SQL Injection", severity: .high, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "execute": .init(category: "SQL Injection", severity: .high, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "YAML.load": .init(category: "Insecure Deserialization", severity: .critical, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "YAML.unsafe_load": .init(category: "Insecure Deserialization", severity: .critical, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "YAML.load_file": .init(category: "Insecure Deserialization", severity: .critical, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "Marshal.load": .init(category: "Insecure Deserialization", severity: .critical, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "Marshal.restore": .init(category: "Insecure Deserialization", severity: .critical, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "load": .init(category: "Insecure Deserialization", severity: .high, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "JSON.load": .init(category: "Insecure Deserialization", severity: .high, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "Oj.load": .init(category: "Insecure Deserialization", severity: .high, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "Psych.load": .init(category: "Insecure Deserialization", severity: .critical, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "URI.open": .init(category: "SSRF", severity: .high, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "Net.HTTP.get_response": .init(category: "SSRF", severity: .high, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "Net.HTTP.post_form": .init(category: "SSRF", severity: .high, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "Net.HTTP.start": .init(category: "SSRF", severity: .high, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "HTTParty.get": .init(category: "SSRF", severity: .high, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "HTTParty.post": .init(category: "SSRF", severity: .high, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "Faraday.get": .init(category: "SSRF", severity: .high, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "Faraday.post": .init(category: "SSRF", severity: .high, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "RestClient.get": .init(category: "SSRF", severity: .high, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "RestClient.post": .init(category: "SSRF", severity: .high, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "TCPSocket.new": .init(category: "Network Exposure", severity: .medium, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "Digest.MD5.hexdigest": .init(category: "Weak Cryptography", severity: .medium, vulnArgIndex: 0, alwaysVulnerable: true, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "Digest.MD5.digest": .init(category: "Weak Cryptography", severity: .medium, vulnArgIndex: 0, alwaysVulnerable: true, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "Digest.SHA1.hexdigest": .init(category: "Weak Cryptography", severity: .medium, vulnArgIndex: 0, alwaysVulnerable: true, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "Digest.SHA1.digest": .init(category: "Weak Cryptography", severity: .medium, vulnArgIndex: 0, alwaysVulnerable: true, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "OpenSSL.Digest.MD5.new": .init(category: "Weak Cryptography", severity: .medium, vulnArgIndex: 0, alwaysVulnerable: true, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "Random.new": .init(category: "Weak Randomness", severity: .medium, vulnArgIndex: 0, alwaysVulnerable: true, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "rand": .init(category: "Weak Randomness", severity: .low, vulnArgIndex: 0, alwaysVulnerable: true, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "instance_eval": .init(category: "Code Injection", severity: .high, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "class_eval": .init(category: "Code Injection", severity: .high, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "module_eval": .init(category: "Code Injection", severity: .high, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "send": .init(category: "Code Injection", severity: .medium, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "html_safe": .init(category: "XSS (HTML Injection)", severity: .high, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "raw": .init(category: "XSS (HTML Injection)", severity: .high, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
    ]

    /// Ruby hardening awareness:
    ///  - `ALLOWED_COMMANDS` / `allowed_commands` before command execution,
    ///  - `validate_path` / `sanitize_path` + `realpath` containment,
    ///  - `validate_url` / `sanitized_url` + `TRUSTED_HOSTS` / `ALLOWED_SCHEMES`,
    ///  - `ALLOWED_HOSTS` / `ALLOWED_PORTS` validation before `TCPSocket.new`.
    func applyRubySuppressions(fn: CFunctionDef, findings: inout [AstFinding]) {
        let hasAllowlist = source.contains("ALLOWED_COMMANDS") || source.contains("allowed_commands") || source.contains("allowedCommands")
        if hasAllowlist {
            findings.removeAll { $0.category == "Command Injection" }
        }
        let hasPathGuard = source.contains("validate_path") || source.contains("sanitize_path") || source.contains("realpath")
        if hasPathGuard {
            findings.removeAll { $0.category == "Path Traversal" }
        }
        let hasUrlGuard = source.contains("validate_url") || source.contains("sanitized_url") || source.contains("TRUSTED_HOSTS")
        if hasUrlGuard {
            findings.removeAll { $0.category == "SSRF" }
        }
        let hasSocketGuard = source.contains("ALLOWED_HOSTS") || source.contains("ALLOWED_PORTS")
        if hasSocketGuard {
            findings.removeAll { $0.category == "Network Exposure" }
        }
    }

    func checkRubySinks(name: String, qualified: String, args: [CExpr], offset: Int, function: String, params: Set<String>, tainted: Set<String>, crossTainted: Set<String>, guarded: Set<String>, sizeBounded: Set<String>, findings: inout [AstFinding], reachable: Bool) -> Bool {
        // Rails `where("<condition with #{user input}>")` string form: the SQL
        // fragment is built by interpolation. The hash form `where(email: x)`
        // is the parameterized/safe shape and never fires.
        if name == "where" {
            for a in args {
                if case .stringLiteral(let s, _) = a, s.contains("#{") {
                    emit(&findings, function, offset,
                         rule("SQL Injection", .high),
                         message: "Rails where() builds its condition by string interpolation of untrusted data (use the hash form).",
                         taint: nil, reachable: reachable, crossFile: false)
                    return true
                }
            }
        }
        guard let rule = Self.rubySinks[qualified] ?? Self.rubySinks[name] else { return false }
        evaluateGenericRule(rule, name: qualified, args: args, offset: offset, function: function, tainted: tainted, crossTainted: crossTainted, guarded: guarded, sizeBounded: sizeBounded, findings: &findings, reachable: reachable)
        return true
    }
} // end extension AstSecurityDetector
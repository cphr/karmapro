// by cipher.org.uk
// MARK: - Go-specific AST security checks
// Extracted from AstSecurityDetector.swift / VulnerabilityScanner.swift to
// keep per-language vulnerability detection modular. Shared wire-up stays in
// AstSecurityDetector.swift · VulnerabilityScanner.swift (dispatch lines only).

import Foundation

extension AstSecurityDetector {

    /// Go sinks (mirrors the scanner's Go table). Keyed on the dotted package
    /// path as written (`exec.Command`, `os.Open`) or a bare method name
    /// (`Query`, `Do`) when the rule applies to any receiver of that method.
    static let goSinks: [String: AstSinkRule] = [
        "exec.Command": .init(category: "Command Injection", severity: .high, vulnArgIndex: nil, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "exec.CommandContext": .init(category: "Command Injection", severity: .high, vulnArgIndex: nil, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "os.StartProcess": .init(category: "Command Injection", severity: .high, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "database/sql.Open": .init(category: "SQL Injection", severity: .medium, vulnArgIndex: 1, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "Query": .init(category: "SQL Injection", severity: .high, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "QueryRow": .init(category: "SQL Injection", severity: .high, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "Exec": .init(category: "SQL Injection", severity: .high, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        // The *Context variants take `(ctx, query, args...)`: the SQL statement
        // text is argument index 1 (index 0 is a context.Context), so `?`-bound
        // parameter values must never count as the statement itself.
        "QueryContext": .init(category: "SQL Injection", severity: .high, vulnArgIndex: 1, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "QueryRowContext": .init(category: "SQL Injection", severity: .high, vulnArgIndex: 1, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "ExecContext": .init(category: "SQL Injection", severity: .high, vulnArgIndex: 1, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "Raw": .init(category: "SQL Injection", severity: .high, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "os.Open": .init(category: "Path Traversal", severity: .medium, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "os.Create": .init(category: "Path Traversal", severity: .medium, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "os.Remove": .init(category: "Path Traversal", severity: .medium, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "os.RemoveAll": .init(category: "Path Traversal", severity: .medium, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "os.ReadFile": .init(category: "Path Traversal", severity: .medium, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "ioutil.ReadFile": .init(category: "Path Traversal", severity: .medium, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "os.Rename": .init(category: "Path Traversal", severity: .medium, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "os.OpenFile": .init(category: "Path Traversal", severity: .medium, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "os.ReadDir": .init(category: "Path Traversal", severity: .medium, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "os.Mkdir": .init(category: "Path Traversal", severity: .medium, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "os.MkdirAll": .init(category: "Path Traversal", severity: .medium, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "os.WriteFile": .init(category: "Path Traversal", severity: .medium, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "ioutil.WriteFile": .init(category: "Path Traversal", severity: .medium, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "os.Chmod": .init(category: "Path Traversal", severity: .medium, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "os.Symlink": .init(category: "Path Traversal", severity: .medium, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "os.Link": .init(category: "Path Traversal", severity: .medium, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "os.Truncate": .init(category: "Path Traversal", severity: .medium, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "http.Get": .init(category: "SSRF", severity: .high, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "http.Redirect": .init(category: "Open Redirect", severity: .medium, vulnArgIndex: 2, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "http.Post": .init(category: "SSRF", severity: .high, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "http.Head": .init(category: "SSRF", severity: .high, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "http.PostForm": .init(category: "SSRF", severity: .high, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "http.NewRequest": .init(category: "SSRF", severity: .high, vulnArgIndex: 1, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "Do": .init(category: "SSRF", severity: .high, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "net.Dial": .init(category: "SSRF", severity: .high, vulnArgIndex: 1, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "crypto/md5.New": .init(category: "Weak Cryptography", severity: .medium, vulnArgIndex: 0, alwaysVulnerable: true, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "crypto/sha1.New": .init(category: "Weak Cryptography", severity: .medium, vulnArgIndex: 0, alwaysVulnerable: true, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "md5.New": .init(category: "Weak Cryptography", severity: .medium, vulnArgIndex: 0, alwaysVulnerable: true, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "sha1.New": .init(category: "Weak Cryptography", severity: .medium, vulnArgIndex: 0, alwaysVulnerable: true, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "crypto.SHA1": .init(category: "Weak Cryptography", severity: .medium, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "des.NewCipher": .init(category: "Weak Cryptography", severity: .medium, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "rc4.NewCipher": .init(category: "Weak Cryptography", severity: .medium, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "sha1.Sum": .init(category: "Weak Cryptography", severity: .medium, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "md5.Sum": .init(category: "Weak Cryptography", severity: .medium, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "syscall.Exec": .init(category: "Command Injection", severity: .high, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "syscall.StartProcess": .init(category: "Command Injection", severity: .high, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "syscall.ForkExec": .init(category: "Command Injection", severity: .high, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "gob.NewDecoder": .init(category: "Insecure Deserialization", severity: .high, vulnArgIndex: 0, alwaysVulnerable: true, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "rand.Seed": .init(category: "Weak Randomness", severity: .low, vulnArgIndex: 0, alwaysVulnerable: true, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "rand.NewSource": .init(category: "Weak Randomness", severity: .low, vulnArgIndex: 0, alwaysVulnerable: true, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "log.Println": .init(category: "Log Injection", severity: .low, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "log.Printf": .init(category: "Log Injection", severity: .low, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "template.HTML": .init(category: "XSS (HTML Injection)", severity: .high, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
    ]

    /// Go hardening awareness:
    ///  - redirect targets validated with `strings.HasPrefix` anywhere in the
    ///    file are local redirects (the mitigation helper may live elsewhere),
    ///  - `filepath.Clean(join)` + `HasPrefix(safeDir)` containment is the
    ///    canonical path-traversal mitigation.
    func applyGoSuppressions(fn: CFunctionDef, findings: inout [AstFinding]) {
        if source.contains("HasPrefix") {
            findings.removeAll { $0.category == "Open Redirect" }
        }
        if bodyHasIdentifierStmt(fn.body, "Clean"), bodyHasIdentifierStmt(fn.body, "HasPrefix") {
            findings.removeAll { $0.category == "Path Traversal" }
        }
    }

    func checkGoSinks(name: String, qualified: String, args: [CExpr], offset: Int, function: String, params: Set<String>, tainted: Set<String>, crossTainted: Set<String>, guarded: Set<String>, sizeBounded: Set<String>, findings: inout [AstFinding], reachable: Bool) -> Bool {
        guard let rule = Self.goSinks[qualified] ?? Self.goSinks[name] else { return false }

        // Go `exec.Command*` hands argv straight to the OS (no shell layer), so
        // a non-shell program with separately-escaped argv is not command
        // injection on its own. Only a tainted program name, a shell program
        // (`sh`, `bash`, …) fed tainted data, or *confirmed* taint (an argument
        // that visibly reaches a taint source/transformer in this body, not just
        // a default-seeded function parameter) is reported.
        if rule.category == "Command Injection",
           qualified == "exec.Command" || qualified == "exec.CommandContext" {
            let progIdx = qualified == "exec.CommandContext" ? 1 : 0
            let progExpr = progIdx < args.count ? args[progIdx] : nil
            let rest = Array(args.dropFirst(progIdx + 1))
            let progTainted = progExpr.flatMap { exprTainted($0, tainted: tainted) } != nil
            let progName = progExpr.flatMap(stringLiteralOf)?.lowercased() ?? ""
            let isShellProgram = ["sh", "bash", "zsh", "dash", "ksh", "cmd", "powershell", "pwsh",
                                  "cmd.exe", "/bin/sh", "/bin/bash", "/bin/zsh", "/bin/dash"].contains(progName)
            // A bare identifier that is one of THIS function's parameters is only
            // seeded tainted by default seeding (the caller decides its actual
            // value); it is not confirmed taint inside this body.
            let confirmedTainted = rest.contains { arg in
                guard exprTainted(arg, tainted: tainted) != nil else { return false }
                if case .identifier(let n, _) = arg, params.contains(n), crossTainted.contains(n) == false { return false }
                return true
            }
            let shellTainted = isShellProgram && rest.contains { exprTainted($0, tainted: tainted) != nil }
            if progTainted || confirmedTainted || shellTainted {
                let cross = rest.contains { exprCrossFile($0, crossTainted: crossTainted) }
                emit(&findings, function, offset, rule, message: "\(qualified) called with potentially untrusted data.", taint: nil, reachable: reachable, crossFile: cross)
            }
            return true
        }

        // Go path loads through a bare caller-supplied parameter (`os.ReadFile(path)`
        // with `path` a parameter) are config/loader helpers: taint is only the
        // default seeding of the parameter, and the decision to read untrusted data
        // belongs to the caller, not to this read. The positive corpus keeps
        // confirmed taint (concatenation, cross-file sourced variables, and the
        // `os.Open`/`os.ReadDir`/write-sink family) firing.
        if rule.category == "Path Traversal",
           ["os.ReadFile", "ioutil.ReadFile"].contains(qualified),
           let first = args.first,
           case .identifier(let vn, _) = first,
           params.contains(vn),
           crossTainted.contains(vn) == false {
            return true
        }

        evaluateGenericRule(rule, name: qualified, args: args, offset: offset, function: function, tainted: tainted, crossTainted: crossTainted, guarded: guarded, sizeBounded: sizeBounded, findings: &findings, reachable: reachable)
        return true
    }
} // end extension AstSecurityDetector
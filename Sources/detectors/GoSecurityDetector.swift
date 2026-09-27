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
    /// `query` (lowercase) is the sqlmock-style custom driver method the
    /// review corpus uses for direct statement execution.
    static let goSinks: [String: AstSinkRule] = [
        "exec.Command": .init(category: "Command Injection", severity: .high, vulnArgIndex: nil, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "exec.CommandContext": .init(category: "Command Injection", severity: .high, vulnArgIndex: nil, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "os.StartProcess": .init(category: "Command Injection", severity: .high, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "database/sql.Open": .init(category: "SQL Injection", severity: .medium, vulnArgIndex: 1, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "Query": .init(category: "SQL Injection", severity: .high, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "QueryRow": .init(category: "SQL Injection", severity: .high, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "Exec": .init(category: "SQL Injection", severity: .high, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "query": .init(category: "SQL Injection", severity: .high, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
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
        // Patterns the generic sink table cannot resolve themselves (format
        // string classifier, template.Parse, FileServer root, ReadAll body,
        // zero-IV cipher streams, LIKE wildcard binding, forwarded-proxy trust).
        if goSpecialChecks(name: name, qualified: qualified, args: args, offset: offset, function: function, tainted: tainted, findings: &findings, reachable: reachable) {
            return true
        }

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

    // MARK: - Shared expression helpers

    private func goCleanStringLiteral(_ s: String) -> String {
        var v = s
        if v.hasPrefix("\"") && v.hasSuffix("\"") && v.count >= 2 {
            v = String(v.dropFirst().dropLast())
        }
        return v
    }

    /// All string-literal fragments of a binary `+` concatenation.
    private func goFlattenedLiterals(_ e: CExpr) -> [String] {
        switch e {
        case .stringLiteral(let s, _):
            return [goCleanStringLiteral(s)]
        case .binary(let op, let l, let r, _) where op == "+":
            return goFlattenedLiterals(l) + goFlattenedLiterals(r)
        case .paren(let x, _), .cast(let x, _):
            return goFlattenedLiterals(x)
        default:
            return []
        }
    }

    /// The identifier and member names mentioned anywhere in an expression.
    private func goExprNames(_ e: CExpr) -> Set<String> {
        var out = Set<String>()
        func walk(_ x: CExpr) {
            switch x {
            case .identifier(let n, _):
                out.insert(n.lowercased())
            case .binary(_, let l, let r, _), .comma(let l, let r, _):
                walk(l); walk(r)
            case .unary(_, let o, _), .cast(let o, _), .paren(let o, _):
                walk(o)
            case .ternary(let c, let t, let f, _):
                walk(c); walk(t); walk(f)
            case .assign(_, let l, let r, _):
                walk(l); walk(r)
            case .call(let callee, let args, _):
                walk(callee); args.forEach(walk)
            case .member(let b, let m, _, _):
                walk(b); out.insert(m.lowercased())
            case .index(let b, let i, _):
                walk(b); walk(i)
            case .arrayInit(let els, _), .newExpr(_, let els, _):
                els.forEach(walk)
            case .sizeOf(let x, _, _):
                if let x = x { walk(x) }
            case .lambda:
                break
            default:
                break
            }
        }
        walk(e)
        return out
    }

    /// Names of make-buffers in the function body (`iv := make([]byte, n)`).
    /// A zero-initialized buffer is what makes it a bad IV/nonce for
    /// block-cipher modes.
    func goZeroIVVars(in body: CStmt) -> Set<String> {
        var out = Set<String>()
        func exprMentionsMake(_ e: CExpr) -> Bool {
            switch e {
            case .call(let callee, let args, _):
                if case .identifier(let n, _) = callee, n == "make" { return true }
                if exprMentionsMake(callee) { return true }
                return args.contains { exprMentionsMake($0) }
            case .binary(_, let l, let r, _), .comma(let l, let r, _):
                return exprMentionsMake(l) || exprMentionsMake(r)
            case .unary(_, let o, _), .cast(let o, _), .paren(let o, _):
                return exprMentionsMake(o)
            case .member(let b, _, _, _):
                return exprMentionsMake(b)
            case .index(let b, let i, _):
                return exprMentionsMake(b) || exprMentionsMake(i)
            case .assign(_, let l, let r, _):
                return exprMentionsMake(l) || exprMentionsMake(r)
            case .arrayInit(let els, _), .newExpr(_, let els, _):
                return els.contains { exprMentionsMake($0) }
            case .ternary(let c, let t, let f, _):
                return exprMentionsMake(c) || exprMentionsMake(t) || exprMentionsMake(f)
            case .sizeOf(let x, _, _):
                return x.map { exprMentionsMake($0) } ?? false
            default:
                return false
            }
        }
        func walkStmt(_ s: CStmt) {
            switch s {
            case .block(let arr):
                arr.forEach(walkStmt)
            case .declaration(let d):
                if case .variable(_, let name, let ie?) = d.kind, exprMentionsMake(ie) {
                    out.insert(name)
                }
            case .expr(let e):
                if case .assign(let op, let lhs, let rhs, _) = e, op == "=", let n = simpleIdentifier(lhs), exprMentionsMake(rhs) {
                    out.insert(n)
                }
            case .ifStmt(_, let t, let elif, _):
                walkStmt(t); if let elif = elif { walkStmt(elif) }
            case .whileStmt(_, let b, _):
                walkStmt(b)
            case .doWhileStmt(let b, _, _):
                walkStmt(b)
            case .forStmt(let initS, _, let inc, let b, _):
                if let initS = initS { walkStmt(initS) }
                _ = inc
                walkStmt(b)
            case .switchStmt(_, let cases, _):
                for c in cases { for x in c.body { walkStmt(x) } }
            case .labeledStmt(_, let s, _):
                walkStmt(s)
            case .returnStmt, .breakStmt, .continueStmt, .gotoStmt, .empty:
                break
            }
        }
        walkStmt(body)
        return out
    }

    // MARK: - Call-site specials (single-call patterns the sink table misses)

    /// Specialized Go checks dispatched from `checkGoSinks` for call patterns
    /// that cannot be expressed as a plain `(name, argIndex)` rule. Returns true
    /// when this call was handled by a special (so the generic table is not
    /// consulted again).
    func goSpecialChecks(name: String, qualified: String, args: [CExpr], offset: Int, function: String, tainted: Set<String>, findings: inout [AstFinding], reachable: Bool) -> Bool {
        // ---- fmt format-string classifier -------------------------------------
        // `fmt.Sprintf/Fprintf("SELECT … %s …", tainted)`: SQL fused into a
        // format string; `… \r\n …`: CRLF in a format carrying untrusted data;
        // `… INFO … user=…`: log-injection style content.
        let fmtFormatters: Set<String> = ["Sprintf", "Fprintf", "Printf", "Sprintln", "Fprintln", "Println", "Sprint", "Fprint"]
        if qualified.hasPrefix("fmt."), let fmtName = qualified.split(separator: ".").last.map(String.init), fmtFormatters.contains(fmtName) {
            var formatText = ""
            for a in args {
                let parts = goFlattenedLiterals(a)
                if !parts.isEmpty { formatText = parts.joined(); break }
            }
            if !formatText.isEmpty,
               args.contains(where: { exprTainted($0, tainted: tainted) != nil }) {
                let up = formatText.uppercased()
                if formatText.contains("\\r\\n") || formatText.contains("\\n\\r") {
                    emit(&findings, function, offset, AstSinkRule(category: "CRLF / HTTP Response Splitting", severity: .high, vulnArgIndex: nil, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
                         message: "\(qualified) emits a CRLF (\\r\\n) sequence into a format string carrying untrusted data; header/body boundaries can be injected.",
                         taint: nil, reachable: reachable, crossFile: false)
                    return true
                }
                let sqlWords = ["SELECT ", "INSERT ", "UPDATE ", "DELETE FROM ", "CREATE TABLE ", "DROP TABLE ", "ALTER TABLE ", "CREATE ", "DROP ", "TRUNCATE "]
                if sqlWords.contains(where: { up.contains($0) }) {
                    emit(&findings, function, offset, AstSinkRule(category: "SQL Injection", severity: .high, vulnArgIndex: nil, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
                         message: "\(qualified) builds SQL statement text with a format string while interpolating untrusted data; use parameterized queries/bind placeholders.",
                         taint: nil, reachable: reachable, crossFile: false)
                    return true
                }
                let logMarkers = ["INFO", "WARN", "ERROR", "DEBUG", "USER=", "ACTION=", " AUTH", " LOGIN", "AUTHENTIC"]
                if logMarkers.contains(where: { up.contains($0) }) {
                    emit(&findings, function, offset, AstSinkRule(category: "Log Injection", severity: .low, vulnArgIndex: nil, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
                         message: "\(qualified) writes untrusted data into log-shaped output without sanitization of CR/LF or marking characters.",
                         taint: nil, reachable: reachable, crossFile: false)
                    return true
                }
            }
            return true
        }

        // ---- text/template Parse (server-side template injection) -------------
        if qualified == "template.New.Parse" {
            if let first = args.first, exprTainted(first, tainted: tainted) != nil {
                emit(&findings, function, offset, AstSinkRule(category: "Server-Side Template Injection", severity: .high, vulnArgIndex: nil, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
                     message: "template.New(...).Parse() evaluates a template string derived from untrusted data; template actions can execute arbitrary logic.",
                     taint: nil, reachable: reachable, crossFile: false)
            }
            return true
        }

        // ---- http.FileServer over a broad / dynamic root ----------------------
        if qualified == "http.FileServer" {
            var rootIsBroad = false
            var dirStr = ""
            if let first = args.first, case .call(let dcallee, let dargs, _) = first,
               let dq = callQualifiedName(dcallee), dq == "http.Dir" || dq.hasSuffix(".Dir") {
                if let lit = dargs.first.flatMap(stringLiteralOf) {
                    dirStr = lit
                    if lit == "/" || lit == "." || lit == ".." {
                        rootIsBroad = true
                    }
                } else {
                    rootIsBroad = true
                }
            }
            if rootIsBroad {
                emit(&findings, function, offset, AstSinkRule(category: "Information Disclosure (File Server on a Broad Root)", severity: .medium, vulnArgIndex: nil, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
                     message: "http.FileServer serves a broad or dynamic directory root (\(dirStr == "/" ? "/" : "non-literal")); any file under it is exposed verbatim.",
                     taint: nil, reachable: reachable, crossFile: false)
            }
            return true
        }

        // ---- Unbounded request-body read --------------------------------------
        if qualified == "io.ReadAll" || qualified == "ioutil.ReadAll" {
            if let first = args.first,
               case .member(let base, "Body", _, _) = first,
               case .identifier(let bname, _) = base,
               ["r", "req", "request"].contains(bname),
               !source.contains("MaxBytesReader"),
               !source.contains("SetReadLimit") {
                emit(&findings, function, offset, AstSinkRule(category: "Unbounded Request Body Read", severity: .high, vulnArgIndex: nil, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
                     message: "io.ReadAll reads the entire request body with no size cap; a hostile upload can exhaust memory (use http.MaxBytesReader).",
                     taint: nil, reachable: reachable, crossFile: false)
            }
            return true
        }

        // ---- Block-cipher stream with a zero/static IV ------------------------
        let ivCipherNames: Set<String> = ["NewCBCEncrypter", "NewCBCDecrypter", "NewCFBEncrypter", "NewCFBDecrypter", "NewCTR", "NewOFB"]
        if ivCipherNames.contains(name), args.count >= 2, case .identifier(let iv, _) = args[1], goZeroIVRef.vars.contains(iv) {
            emit(&findings, function, offset, AstSinkRule(category: "Weak Cryptography (static/zero IV)", severity: .high, vulnArgIndex: nil, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
                 message: "\(qualified) is initialized with an all-zero (make-allocated) IV. Two records sharing a prefix produce identical ciphertext; use a random per-message nonce.",
                 taint: nil, reachable: reachable, crossFile: false)
            return true
        }

        // ---- SQL LIKE wildcard binding ----------------------------------------
        let sqlSinkNames: Set<String> = ["query", "Query", "QueryRow", "Exec", "QueryContext", "QueryRowContext", "ExecContext"]
        if sqlSinkNames.contains(name) {
            for a in args {
                if case .binary("+", _, _, _) = a,
                   goFlattenedLiterals(a).contains(where: { $0.contains("%") }),
                   exprTainted(a, tainted: tainted) != nil {
                    emit(&findings, function, offset, AstSinkRule(category: "SQL Injection (LIKE wildcard)", severity: .medium, vulnArgIndex: nil, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
                         message: "\(qualified) binds an untrusted value into a LIKE pattern; wildcards (%) or escapes survive into the match.",
                         taint: nil, reachable: reachable, crossFile: false)
                    return true
                }
            }
        }

        // ---- Forwarded-proxy header trust -------------------------------------
        let forwardedHeaders: Set<String> = ["X-Forwarded-For", "X-Real-IP", "X-Client-IP", "True-Client-IP", "X-Forwarded-IP"]
        if name == "Get", let first = args.first, case .stringLiteral(let hdr, _) = first,
           forwardedHeaders.contains(goCleanStringLiteral(hdr)), qualified.contains(".Header.") {
            emit(&findings, function, offset, AstSinkRule(category: "Untrusted Client IP from Forwarded-Proxy Header", severity: .medium, vulnArgIndex: nil, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
                 message: "\(qualified) trusts \(goCleanStringLiteral(hdr)) without verifying a proxy in front; any client can forge its identity here.",
                 taint: nil, reachable: reachable, crossFile: false)
            return true
        }

        return false
    }

    // MARK: - Whole-function structural checks

    func checkGoStructural(fn: CFunctionDef, function: String, params: Set<String>, tainted: Set<String>, crossTainted: Set<String>, findings: inout [AstFinding], reachable: Bool) {
        let ns = self.source as NSString
        let funcSource = goFunctionSlice(ns: ns, fn: fn)
        let functionLow = function.lowercased()

        var headerHandles = Set<String>()
        var headerSetCalls: [(offset: Int, name: String, value: CExpr?)] = []
        var htmlContentType = false
        var credentialHeaderTrue = false
        var originStar = false
        var originReflected = false
        var xssWriteOffset: Int? = nil
        var bytesEqualOffset: Int? = nil
        var timingSecretEqOffset: Int? = nil
        var deferInLoopOffset: Int? = nil
        var passwordLogOffset: Int? = nil
        var execCommandOffset: Int? = nil
        var execStdinTainted = false

        let secretMemberWords = ["secret", "password", "token", "hash", "digest", "signature", "signing", "mac", "tag"]
        let authFunctionWords = ["auth", "verify", "check", "compare", "login", "sign", "valid", "equal", "digest"]

        func thenReturnsFalse(_ s: CStmt) -> Bool {
            func isFalseLiteral(_ e: CExpr?) -> Bool {
                if case .booleanLiteral(let v, _)? = e { return !v }
                return false
            }
            if case .returnStmt(let e, _) = s { return isFalseLiteral(e) }
            if case .block(let arr) = s, arr.count == 1, case .returnStmt(let e, _) = arr[0] { return isFalseLiteral(e) }
            return false
        }

        func exprHasCall(_ e: CExpr, _ target: Set<String>) -> Bool {
            switch e {
            case .call(let callee, let args, _):
                if let n = callName(callee), target.contains(n) { return true }
                return exprHasCall(callee, target) || args.contains { exprHasCall($0, target) }
            case .binary(_, let l, let r, _), .comma(let l, let r, _):
                return exprHasCall(l, target) || exprHasCall(r, target)
            case .unary(_, let o, _), .cast(let o, _), .paren(let o, _):
                return exprHasCall(o, target)
            case .member(let b, _, _, _):
                return exprHasCall(b, target)
            case .index(let b, let i, _):
                return exprHasCall(b, target) || exprHasCall(i, target)
            case .ternary(let c, let t, let f, _):
                return exprHasCall(c, target) || exprHasCall(t, target) || exprHasCall(f, target)
            case .assign(_, let l, let r, _):
                return exprHasCall(l, target) || exprHasCall(r, target)
            case .arrayInit(let els, _), .newExpr(_, let els, _):
                return els.contains { exprHasCall($0, target) }
            case .sizeOf(let x, _, _):
                return x.map { exprHasCall($0, target) } ?? false
            case .lambda:
                return false
            default:
                return false
            }
        }

        func walk(_ s: CStmt, inLoop: Bool) {
            switch s {
            case .block(let arr):
                for i in 0..<arr.count {
                    let st = arr[i]
                    if inLoop, deferInLoopOffset == nil,
                       case .expr(.identifier("defer", _)) = st,
                       i + 1 < arr.count,
                       case .expr(.call(let closeCallee, _, let closeOff)) = arr[i + 1],
                       callName(closeCallee) == "Close" {
                        deferInLoopOffset = closeOff
                    }
                    walk(st, inLoop: inLoop)
                }
            case .declaration(let d):
                if case .variable(_, let vname, let ie?) = d.kind,
                   case .call(let ccallee, _, _) = ie,
                   callQualifiedName(ccallee) == "Header" || callQualifiedName(ccallee)?.hasSuffix(".Header") == true {
                    headerHandles.insert(vname)
                }
                if case .variable(_, _, let ie?) = d.kind { walkExpr(ie) }
            case .expr(let e):
                walkExpr(e)
            case .ifStmt(let cond, let t, let elif, _):
                walkExpr(cond)
                walk(t, inLoop: inLoop)
                if let elif = elif { walk(elif, inLoop: inLoop) }
            case .whileStmt(let cond, let b, _):
                walkExpr(cond)
                walk(b, inLoop: inLoop)
            case .doWhileStmt(let b, let cond, _):
                walkExpr(cond)
                walk(b, inLoop: inLoop)
            case .forStmt(let initS, let condF, let incF, let b, _):
                if let initS = initS { walk(initS, inLoop: true) }
                if let condF = condF { walkExpr(condF) }
                if let incF = incF { walkExpr(incF) }
                walk(b, inLoop: true)
            case .switchStmt(let expr, let cases, _):
                walkExpr(expr)
                for c in cases { for x in c.body { walk(x, inLoop: inLoop) } }
            case .labeledStmt(_, let st, _):
                walk(st, inLoop: inLoop)
            case .returnStmt(let e, _):
                if let e = e { walkExpr(e) }
            case .breakStmt, .continueStmt, .gotoStmt, .empty:
                break
            }
        }

        func walkExpr(_ e: CExpr) {
            switch e {
            case .call(let callee, let args, let off):
                let cq = callQualifiedName(callee)
                let nameOnly = callName(callee) ?? ""
                if nameOnly == "Command" || nameOnly == "CommandContext" {
                    if execCommandOffset == nil { execCommandOffset = off }
                }
                if nameOnly == "Set", args.count >= 2, let hname = stringLiteralOf(args.first) {
                    let isHeaderTarget = (cq?.contains(".Header.") == true)
                        || (calleeBaseIdentifier(callee).map { headerHandles.contains($0) } ?? false)
                    if isHeaderTarget {
                        headerSetCalls.append((offset: off, name: goCleanStringLiteral(hname), value: args.count > 1 ? args[1] : nil))
                    }
                }
                if cq?.contains(".Header.") == true, nameOnly == "Set",
                   args.count > 1,
                   let ct = stringLiteralOf(args[1]), ct.lowercased().contains("text/html") {
                    htmlContentType = true
                }
                let fmtWriters: Set<String> = ["Fprintf", "Fprint", "Fprintln", "Printf", "WriteString"]
                if fmtWriters.contains(nameOnly), args.contains(where: { exprTainted($0, tainted: tainted) != nil }) {
                    if xssWriteOffset == nil { xssWriteOffset = off }
                }
                if nameOnly == "Equal" {
                    if bytesEqualOffset == nil { bytesEqualOffset = off }
                }
                let logNames: Set<String> = ["logf", "infof", "warnf", "errorf", "Printf", "Sprintf", "Println", "Fprintf", "Log", "log"]
                if logNames.contains(nameOnly) {
                    var format = ""
                    for a in args {
                        let parts = goFlattenedLiterals(a)
                        if !parts.isEmpty { format = parts.joined(); break }
                    }
                    if format.lowercased().contains("password"),
                       args.contains(where: { goExprNames($0).contains { $0.contains("password") } }) {
                        if passwordLogOffset == nil { passwordLogOffset = off }
                    }
                }
                for a in args { walkExpr(a) }
                walkExpr(callee)
            case .assign(let op, let lhs, let rhs, _):
                if op == "=", let vname = simpleIdentifier(lhs),
                   case .call(let hcallee, _, _) = rhs,
                   callQualifiedName(hcallee) == "Header" || callQualifiedName(hcallee)?.hasSuffix(".Header") == true {
                    headerHandles.insert(vname)
                }
                if op == "=", case .member(_, "Stdin", _, _) = lhs, exprTainted(rhs, tainted: tainted) != nil {
                    execStdinTainted = true
                }
                walkExpr(lhs)
                walkExpr(rhs)
            case .binary(let op, let l, let r, let off):
                if (op == "==" || op == "!="), timingSecretEqOffset == nil {
                    let namesL = goExprNames(l)
                    let namesR = goExprNames(r)
                    let secretNaming = namesL.union(namesR).contains { secretMemberWords.contains($0) }
                    if secretNaming,
                       (authFunctionWords.contains { functionLow.contains($0) }
                        || exprTainted(l, tainted: tainted) != nil
                        || exprTainted(r, tainted: tainted) != nil) {
                        timingSecretEqOffset = off
                    }
                }
                walkExpr(l)
                walkExpr(r)
            case .unary(_, let o, _):
                walkExpr(o)
            case .member(let b, _, _, _):
                walkExpr(b)
            case .index(let b, let i, _):
                walkExpr(b); walkExpr(i)
            case .ternary(let c, let t, let f, _):
                walkExpr(c); walkExpr(t); walkExpr(f)
            case .comma(let l, let r, _):
                walkExpr(l); walkExpr(r)
            case .arrayInit(let els, _), .newExpr(_, let els, _):
                els.forEach(walkExpr)
            case .sizeOf(let x, _, _):
                x.map { walkExpr($0) }
            case .cast(let x, _), .paren(let x, _):
                walkExpr(x)
            case .integerLiteral, .floatLiteral, .stringLiteral, .charLiteral, .booleanLiteral, .identifier, .lambda:
                break
            }
        }

        // Loop-return-false digest comparison (timing oracle via short-circuit).
        func detectLoopReturnFalse(_ stmt: CStmt) -> [Int] {
            var hits: [Int] = []
            func scan(_ s: CStmt) {
                switch s {
                case .forStmt(_, _, _, let b, let off):
                    if case .block(let arr) = b {
                        for st in arr {
                            if case .ifStmt(let cond, let thenB, _, _) = st,
                               case .binary("!=", _, _, _) = cond,
                               thenReturnsFalse(thenB),
                               (authFunctionWords.contains { functionLow.contains($0) }
                                || funcSource.contains("Sum256") || funcSource.contains("Sum512")
                                || funcSource.contains("sum256") || funcSource.contains("digest")) {
                                hits.append(off)
                            }
                            scan(st)
                        }
                    } else {
                        scan(b)
                    }
                case .block(let arr):
                    arr.forEach(scan)
                case .ifStmt(_, let t, let elif, _):
                    scan(t); if let elif = elif { scan(elif) }
                default:
                    break
                }
            }
            scan(stmt)
            return hits
        }

        // Manual ECB-style block loops: for body that calls block.Encrypt/Decrypt.
        func detectECBLoops(_ stmt: CStmt) -> [Int] {
            var hits: [Int] = []
            func scan(_ s: CStmt) {
                switch s {
                case .forStmt(_, _, _, let b, let off):
                    let target: Set<String> = ["Encrypt", "Decrypt"]
                    func bodyEncrypts(_ x: CStmt) -> Bool {
                        switch x {
                        case .expr(let e): return exprHasCall(e, target)
                        case .block(let arr): return arr.contains { bodyEncrypts($0) }
                        case .declaration(let d):
                            if case .variable(_, _, let ie?) = d.kind { return exprHasCall(ie, target) }
                            return false
                        case .ifStmt(_, let t, let elif, _): return bodyEncrypts(t) || (elif.map { bodyEncrypts($0) } ?? false)
                        case .whileStmt(_, let wb, _): return bodyEncrypts(wb)
                        case .doWhileStmt(let wb, _, _): return bodyEncrypts(wb)
                        case .forStmt(_, _, _, let nb, _): return bodyEncrypts(nb)
                        case .switchStmt(_, let cases, _):
                            return cases.contains { c in c.body.contains { bodyEncrypts($0) } }
                        case .labeledStmt(_, let ls, _): return bodyEncrypts(ls)
                        default: return false
                        }
                    }
                    if bodyEncrypts(b) { hits.append(off) }
                    scan(b)
                case .block(let arr):
                    arr.forEach(scan)
                case .ifStmt(_, let t, let elif, _):
                    scan(t); if let elif = elif { scan(elif) }
                case .whileStmt(_, let b, _), .doWhileStmt(let b, _, _):
                    scan(b)
                default:
                    break
                }
            }
            scan(stmt)
            return hits
        }

        walk(fn.body, inLoop: false)
        let loopTimingHits = detectLoopReturnFalse(fn.body)
        let ecbHits = detectECBLoops(fn.body)

        // XSS: HTML content-type on the response + tainted fmt-write.
        if htmlContentType, let off = xssWriteOffset {
            emit(&findings, function, off, AstSinkRule(category: "XSS (HTML Injection)", severity: .high, vulnArgIndex: nil, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
                 message: "Function renders text/html and formats untrusted data into it without escaping; injectable markup/scripts reach the browser.",
                 taint: nil, reachable: reachable, crossFile: false)
        }

        // CORS: credentialed responses with a wildcard or reflected origin.
        var corsEmitOffset: Int? = nil
        for hs in headerSetCalls {
            if hs.name == "Access-Control-Allow-Credentials", let v = hs.value, stringLiteralOf(v)?.lowercased() == "true" {
                credentialHeaderTrue = true
            }
            if hs.name == "Access-Control-Allow-Origin" {
                if let lit = hs.value.flatMap(stringLiteralOf), lit == "*" {
                    originStar = true
                } else if let v = hs.value, exprTainted(v, tainted: tainted) != nil {
                    originReflected = true
                }
                if corsEmitOffset == nil { corsEmitOffset = hs.offset }
            }
        }
        if credentialHeaderTrue && (originStar || originReflected), let off = corsEmitOffset {
            emit(&findings, function, off, AstSinkRule(category: "CORS Misconfiguration", severity: .high, vulnArgIndex: nil, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
                 message: "Access-Control-Allow-Origin is a wildcard or reflects the request Origin while Access-Control-Allow-Credentials is true; any site can read credentialed responses.",
                 taint: nil, reachable: reachable, crossFile: false)
        }

        // Timing-unsafe comparisons.
        if let off = bytesEqualOffset, source.contains("crypto/hmac") {
            emit(&findings, function, off, AstSinkRule(category: "Non-Constant-Time Comparison", severity: .medium, vulnArgIndex: nil, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
                 message: "bytes.Equal over an HMAC/digest returns at the first differing byte; use hmac.Equal or a constant-time compare.",
                 taint: nil, reachable: reachable, crossFile: false)
        }
        if let off = timingSecretEqOffset {
            emit(&findings, function, off, AstSinkRule(category: "Non-Constant-Time Comparison", severity: .medium, vulnArgIndex: nil, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
                 message: "Untrusted input is compared to a secret/deviation with ==/!=; the first differing byte leaks into timing.",
                 taint: nil, reachable: reachable, crossFile: false)
        }
        if let off = loopTimingHits.first {
            emit(&findings, function, off, AstSinkRule(category: "Non-Constant-Time Comparison", severity: .medium, vulnArgIndex: nil, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
                 message: "Digest compare loops return as soon as one byte differs; timing leaks how many leading bytes a guess matches.",
                 taint: nil, reachable: reachable, crossFile: false)
        }

        // JWT `alg: none`/missing-signature acceptance.
        if funcSource.contains("strings.Split("),
           funcSource.contains("\"none\""),
           (funcSource.contains("parts[2]") || funcSource.contains("Alg") || funcSource.contains("alg")) {
            emit(&findings, function, fn.bodyOffset, AstSinkRule(category: "JWT Algorithm Confusion (alg none)", severity: .high, vulnArgIndex: nil, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
                 message: "The token header's alg is accepted as \"none\" (or a missing signature passes); unverified claims are trusted.",
                 taint: nil, reachable: reachable, crossFile: false)
        }

        // Manual ECB-style block encryption loops (no chained mode in scope).
        if let off = ecbHits.first,
           !funcSource.contains("NewCBCEncrypter"), !funcSource.contains("NewCBCDecrypter"),
           !funcSource.contains("NewCTR"), !funcSource.contains("NewCFB"),
           !funcSource.contains("NewGCM"), !funcSource.contains("NewOFB") {
            emit(&findings, function, off, AstSinkRule(category: "Weak Cryptography (ECB-style block encryption)", severity: .high, vulnArgIndex: nil, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
                 message: "Block cipher invoked once per block in a loop (manual ECB); identical plaintext blocks produce identical ciphertext.",
                 taint: nil, reachable: reachable, crossFile: false)
        }

        // defer ... Close() inside a loop body.
        if let off = deferInLoopOffset {
            emit(&findings, function, off, AstSinkRule(category: "Resource Leak (deferred close inside loop)", severity: .medium, vulnArgIndex: nil, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
                 message: "defer f.Close() inside a loop defers until the enclosing function returns; every iteration leaks a descriptor.",
                 taint: nil, reachable: reachable, crossFile: false)
        }

        // Plaintext password written to a log.
        if let off = passwordLogOffset {
            emit(&findings, function, off, AstSinkRule(category: "Plaintext Password Storage/Logging", severity: .medium, vulnArgIndex: nil, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
                 message: "A password-named value is formatted into log output verbatim; clear-text secrets must never reach logs.",
                 taint: nil, reachable: reachable, crossFile: false)
        }

        // exec.Command with tainted data piped through .Stdin into a shell.
        if let off = execCommandOffset, execStdinTainted {
            emit(&findings, function, off, AstSinkRule(category: "Command Injection", severity: .high, vulnArgIndex: nil, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
                 message: "exec.Command launches a shell/program while untrusted data is piped into its standard input; the content is re-parsed as commands.",
                 taint: nil, reachable: reachable, crossFile: false)
        }

        let saltWord = try? NSRegularExpression(pattern: #"\bsalt\b"#)
        let hasSaltWord = saltWord.map { !$0.matches(in: source, range: NSRange(location: 0, length: ns.length)).isEmpty } ?? true
        if (funcSource.contains("sha256.Sum256") || funcSource.contains("sha256.New(")),
           !hasSaltWord,
           params.contains(where: { ["secret", "password", "pwd"].contains($0.lowercased()) }) {
            emit(&findings, function, fn.bodyOffset, AstSinkRule(category: "Weak Cryptography (unsalted hash)", severity: .medium, vulnArgIndex: nil, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
                 message: "A password/secret is hashed with a fast unsalted SHA-256; one leaked digest is a dictionary hit for every user (use bcrypt/argon2/PBKDF2).",
                 taint: nil, reachable: reachable, crossFile: false)
        }

        // Verbose error/everything (stack + internal details) in a handler.
        if funcSource.contains("err.Error()"),
           (functionLow.contains("handle") || functionLow.contains("serve") || funcSource.contains("debug.Stack")) {
            var searchAt = fn.bodyOffset
            let r = ns.range(of: "err.Error()", options: [], range: NSRange(location: fn.bodyOffset, length: max(0, ns.length - fn.bodyOffset)))
            if r.location != NSNotFound {
                searchAt = r.location
            }
            emit(&findings, function, searchAt, AstSinkRule(category: "Verbose Error Disclosure", severity: .medium, vulnArgIndex: nil, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
                 message: "Handler returns internal error text (and possibly a stack trace) to clients; internal addresses, paths and credentials leak.",
                 taint: nil, reachable: reachable, crossFile: false)
        }

        // Range-loop + deferred Close (parser flattens `for _, x := range` into
        // a spurious top-level block, so the structural defer-in-loop probe
        // never sees the loop; a function that both ranges and defers a Close
        // carries the same per-iteration descriptor leak).
        let deferLow = funcSource.lowercased()
        if deferInLoopOffset == nil, funcSource.contains("defer "), deferLow.contains("close"),
           let bodyRange = AstSecurityDetector.rangeLoopBodySpan(funcSource) {
            let bodyStart = bodyRange.lowerBound
            let bodyEnd = bodyRange.upperBound
            let inSpan = funcSource[bodyStart..<bodyEnd]
            if let dl = inSpan.range(of: "defer "), inSpan[dl.lowerBound...].lowercased().contains("close") {
                var pos = ns.range(of: "defer", options: [], range: NSRange(location: fn.bodyOffset, length: max(0, ns.length - fn.bodyOffset)))
                if pos.location == NSNotFound { pos = NSRange(location: fn.bodyOffset, length: 0) }
                emit(&findings, function, pos.location, AstSinkRule(category: "Resource Leak (deferred close inside loop)", severity: .medium, vulnArgIndex: nil, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
                     message: "defer f.Close() sits inside a loop carried by a range statement; every iteration defers the release until the enclosing function returns.",
                     taint: nil, reachable: reachable, crossFile: false)
            }
        }
    }

    // Returns the span of a `for ... range ... {}` loop body in the function
    // slice by brace-balancing from the loop's opening brace. The cfamily
    // parser flattens range-loop bodies to a spurious top-level block, so this
    // text probe is the only way to localize a defer inside the loop.
    private static func rangeLoopBodySpan(_ s: String) -> Range<String.Index>? {
        guard let re = try? NSRegularExpression(pattern: #"\bfor\b[^{]*\brange\b"#) else { return nil }
        let ns = s as NSString
        let full = NSRange(location: 0, length: ns.length)
        for m in re.matches(in: s, range: full) {
            let bodyFrom = s.index(s.startIndex, offsetBy: m.range.location + m.range.length)
            if let openIdx = s[bodyFrom...].firstIndex(of: "{") {
                var depth = 1
                var j = s.index(after: openIdx)
                while j < s.endIndex {
                    let c = s[j]
                    if c == "{" { depth += 1 } else if c == "}" { depth -= 1 }
                    if depth == 0 { return openIdx..<s.index(after: j) }
                    j = s.index(after: j)
                }
            }
        }
        return nil
    }

    // MARK: - Per-function source slice

    private func goFunctionSlice(ns: NSString, fn: CFunctionDef) -> String {
        let lo = min(max(0, fn.bodyOffset), ns.length)
        var hi = fn.endOffset
        if hi <= lo || hi > ns.length { hi = min(ns.length, lo + 800) }
        if hi <= lo { return "" }
        return ns.substring(with: NSRange(location: lo, length: hi - lo))
    }

    private func calleeBaseIdentifier(_ callee: CExpr) -> String? {
        if case .member(let base, _, _, _) = callee {
            if case .identifier(let n, _) = base { return n }
            return calleeBaseIdentifier(base)
        }
        if case .call(let inner, _, _) = callee { return calleeBaseIdentifier(inner) }
        return nil
    }
} // end extension AstSecurityDetector

// MARK: - File-level Go scans (called from VulnerabilityScanner)

extension AstSecurityDetector {

    /// File-wide Go heuristics that need no per-function AST context:
    /// cookie flag omissions, gzip bombs, nil-map writes, missing response-body
    /// closes, unbounded make allocations, unsynchronized map writes, and
    /// hardcoded AES keys.
    static func scanGoFileLevel(url: URL, source: String, scanningSource: String, functionRegions: [String: CFunctionDef]) -> [ScanFinding] {
        var findings: [ScanFinding] = []
        let ns = source as NSString
        let whole = NSRange(location: 0, length: ns.length)

        func line(at offset: Int) -> Int {
            var line = 1
            for i in 0..<min(max(0, offset), ns.length) where ns.character(at: i) == 0x0A { line += 1 }
            return line
        }
        func add(_ offset: Int, _ category: String, _ severity: ScanFinding.Severity, _ message: String) {
            findings.append(ScanFinding(fileURL: url, line: line(at: offset), function: "(file)",
                                        category: category, message: message, taint: nil,
                                        severity: severity, exploitability: severity,
                                        reachable: true, taintPath: nil, ignored: false,
                                        scanningSource: scanningSource))
        }

        // Insecure cookie flags: SetCookie literal without Secure/HttpOnly/SameSite.
        if let re = try? NSRegularExpression(pattern: #"http\.SetCookie\([^(}]*&http\.Cookie\{([^}]*)\}"#) {
            re.enumerateMatches(in: source, options: [], range: whole) { match, _, _ in
                guard let match = match, match.numberOfRanges > 1 else { return }
                let flds = ns.substring(with: match.range(at: 1))
                let up = flds.uppercased()
                if !up.contains("SECURE") && !up.contains("HTTPONLY") && !up.contains("SAMESITE") {
                    add(match.range.location, "Insecure Cookie Flags", .medium,
                        "Cookie is set without Secure/HttpOnly/SameSite; the session/identifier can be replayed over HTTP and read by scripts.")
                }
            }
        }

        // Gzip bomb: gzip.NewReader + io.ReadAll with no decompression ceiling.
        if source.contains("gzip.NewReader"),
           (source.contains("io.ReadAll(") || source.contains("ioutil.ReadAll(")),
           !source.contains("LimitReader"), !source.contains("MaxBytesReader"), !source.contains("SetReadLimit") {
            let r = ns.range(of: "gzip.NewReader", options: [], range: whole)
            if r.location != NSNotFound {
                add(r.location, "Denial of Service (Gzip Bomb)", .high,
                    "gzip stream is fully decompressed with no size ceiling; a tiny upload can expand without bound (use io.LimitReader/http.MaxBytesReader).")
            }
        }

        // Nil map write: `var m map[...]` never made, then written.
        if let re = try? NSRegularExpression(pattern: #"\bvar\s+(\w+)\s+map\[[^\]]+\]"#) {
            re.enumerateMatches(in: source, options: [], range: whole) { match, _, _ in
                guard let match = match, match.numberOfRanges > 1 else { return }
                let name = ns.substring(with: match.range(at: 1))
                let declLine = ns.substring(with: ns.lineRange(for: NSRange(location: match.range.location, length: 0)))
                if declLine.contains("make(") || declLine.contains("= map[") { return }
                let writeRe = try? NSRegularExpression(pattern: "\\b\(NSRegularExpression.escapedPattern(for: name))\\[[^\\]]*\\]\\s*(\\+\\+|--|\\+=|\\+\\=|\\-\\=|\\-\\-)")
                guard let writeRe = writeRe else { return }
                var firstWrite: Int? = nil
                writeRe.enumerateMatches(in: source, options: [], range: whole) { m, _, stop in
                    guard firstWrite == nil, let m = m else { return }
                    firstWrite = m.range.location
                    stop.pointee = true
                }
                if let off = firstWrite {
                    add(off, "Nil Map Write (panic on assignment)", .high,
                        "A map declared with var is nil until make(); the write at \(name)[...] panics at runtime.")
                }
            }
        }

        // Response body not closed: the Get/Post result is captured into a
        // variable whose Body is never closed. A bare call whose result is
        // discarded holds nothing open, so it is not flagged.
        for (fname, fdef) in functionRegions {
            let lo = fdef.bodyOffset
            var hi = fdef.endOffset
            if hi <= lo || hi > ns.length { hi = min(ns.length, lo + 800) }
            if hi <= lo { continue }
            let region = ns.substring(with: NSRange(location: lo, length: hi - lo))
            guard let callRE = try? NSRegularExpression(pattern: #"=\s*\S+\.(?:Get|Post|PostForm|NewRequest|Do)\("#) else { continue }
            let fullRegion = NSRange(location: 0, length: (region as NSString).length)
            var firstMatch = NSRange(location: NSNotFound, length: 0)
            callRE.enumerateMatches(in: region, options: [], range: fullRegion) { match, _, stop in
                guard let match = match else { return }
                let lineStart = region[..<region.index(region.startIndex, offsetBy: match.range.location)]
                    .lastIndex(of: "\n").map { region.index(after: $0) } ?? region.startIndex
                let lineSlice = region[lineStart...].prefix { $0 != "\n" }
                if lineSlice.contains(":=") {
                    if firstMatch.location == NSNotFound { firstMatch = match.range }
                    else { stop.pointee = true; return }
                }
            }
            guard firstMatch.location != NSNotFound else { continue }
            let closed = region.contains(".Body.Close")
            if !closed {
                let r1 = ns.range(of: "http.Get(", options: [], range: NSRange(location: lo, length: hi - lo))
                let r2 = ns.range(of: "http.Post(", options: [], range: NSRange(location: lo, length: hi - lo))
                let r3 = ns.range(of: "http.PostForm(", options: [], range: NSRange(location: lo, length: hi - lo))
                let r4 = ns.range(of: "client.Get(", options: [], range: NSRange(location: lo, length: hi - lo))
                let r5 = ns.range(of: "client.Post(", options: [], range: NSRange(location: lo, length: hi - lo))
                let r6 = ns.range(of: ".Client().Get(", options: [], range: NSRange(location: lo, length: hi - lo))
                let r7 = ns.range(of: ".Client().Post(", options: [], range: NSRange(location: lo, length: hi - lo))
                let chosen = [r1, r2, r3, r4, r5, r6, r7].filter { $0.location != NSNotFound }.sorted { $0.location < $1.location }.first
                if let chosen = chosen {
                    add(chosen.location, "Response Body Not Closed (resource leak)", .medium,
                        "\(fname) captures an HTTP response but never reads/closes resp.Body; connections are not returned to the pool.")
                }
            }
        }

        // Unbounded allocation from a converted size: make([]byte, 0, int(x)).
        if let re = try? NSRegularExpression(pattern: #"make\(\s*\[\][A-Za-z]+\s*,\s*0\s*,\s*(?:int|uint|uint8|uint16|uint32|uint64)\s*\("#) {
            re.enumerateMatches(in: source, options: [], range: whole) { match, _, _ in
                guard let match = match, match.range.location != NSNotFound else { return }
                add(match.range.location, "Denial of Service (Unbounded Allocation)", .high,
                    "make() preallocates a buffer sized from a converted runtime value with no ceiling; a hostile length can exhaust memory.")
            }
        }

        // Unsynchronized map writes shared with goroutines.
        if source.contains("go func("),
           let re = try? NSRegularExpression(pattern: #"type\s+(\w+)\s+struct\s*\{([^}]*)\}"#) {
            var mappedFields: [String] = []
            re.enumerateMatches(in: source, options: [], range: whole) { match, _, _ in
                guard let match = match, match.numberOfRanges > 2 else { return }
                let fields = ns.substring(with: match.range(at: 2))
                if fields.contains("map[") && !fields.contains("Mutex") && !fields.contains("atomic") && !fields.contains("sync.") && !fields.contains("RWMutex") {
                    // Collect map field names so the write probe hits `s.counters[...]`.
                    if let mre = try? NSRegularExpression(pattern: #"\b(\w+)\s+map\["#) {
                        mre.enumerateMatches(in: fields, options: [], range: NSRange(location: 0, length: (fields as NSString).length)) { fm, _, _ in
                            guard let fm = fm, fm.numberOfRanges > 1 else { return }
                            mappedFields.append((fields as NSString).substring(with: fm.range(at: 1)))
                        }
                    }
                }
            }
            if !mappedFields.isEmpty {
                for field in mappedFields {
                    let writeRe = try? NSRegularExpression(pattern: "\\b\\w+\\.\(NSRegularExpression.escapedPattern(for: field))\\[[^\\]]*\\]\\s*(\\+\\+|--|\\+=|\\+\\=|\\-\\=|\\-\\-)")
                    guard let writeRe = writeRe else { continue }
                    var firstWrite: Int? = nil
                    writeRe.enumerateMatches(in: source, options: [], range: whole) { m, _, stop in
                        guard firstWrite == nil, let m = m else { return }
                        firstWrite = m.range.location
                        stop.pointee = true
                    }
                    if let off = firstWrite {
                        add(off, "Concurrent Write Race (unsynchronized map)", .high,
                            "A map field is written without a mutex/atomic while goroutines run; concurrent writes can panic or race.")
                        break
                    }
                }
            }
        }

        // Hardcoded AES/encryption key literal (64 hex chars in a *Key* constant).
        if let re = try? NSRegularExpression(pattern: #"(?i)const\s+(?:\w+[Kk]ey\w*|\w*[Kk]ey\w+)\s*=\s*"[0-9a-fA-F]{64}""#) {
            re.enumerateMatches(in: source, options: [], range: whole) { match, _, _ in
                guard let match = match else { return }
                add(match.range.location, "Hardcoded Encryption Key", .high,
                    "A cryptographic key literal is embedded in source; anyone with the repository/binary can decrypt the data.")
            }
        }

        return findings
    }
}
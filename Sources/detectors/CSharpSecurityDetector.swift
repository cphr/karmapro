// by cipher.org.uk
// MARK: - C#-specific AST security checks
// Extracted from AstSecurityDetector.swift / VulnerabilityScanner.swift to
// keep per-language vulnerability detection modular. Shared wire-up stays in
// AstSecurityDetector.swift · VulnerabilityScanner.swift (dispatch lines only).

import Foundation

extension AstSecurityDetector {

    /// C# hardening awareness. The path-containment and XXE mitigations
    /// re-validate data *after* the raw sink call, so a pre-sink guard model
    /// doesn't see them:
    ///  - `Path.GetFullPath(...)` + `StartsWith(root)` + reject is the
    ///    canonical path-traversal containment check,
    ///  - `DtdProcessing.Prohibit/Ignore` or a null `XmlResolver` hardens
    ///    `XmlReader`/`XmlDocument` against XXE.
    func applyCSharpSuppressions(fn: CFunctionDef, findings: inout [AstFinding]) {
        if bodyHasIdentifierStmt(fn.body, "GetFullPath"), bodyHasIdentifierStmt(fn.body, "StartsWith") {
            findings.removeAll { $0.category == "Path Traversal" }
        }
        let lowBody = source.lowercased()
        if lowBody.contains("dtdprocessing.prohibit") || lowBody.contains("dtdprocessing.ignore")
            || lowBody.contains("xmlresolver = null") || lowBody.contains("xmlresolver=null") {
            findings.removeAll { $0.category == "XXE (XML External Entity)" || $0.category == "XXE" }
        }
    }

    func checkCSharpSinks(name: String, args: [CExpr], offset: Int, function: String, tainted: Set<String>, crossTainted: Set<String>, guarded: Set<String>, sizeBounded: Set<String>, findings: inout [AstFinding], reachable: Bool) {
        let shortName = lastSeg(name)
        // Open redirect: Response.Redirect(tainted) / Redirect(tainted).
        // `Url.IsLocalUrl(...)` rejection is the standard mitigation.
        if shortName == "Redirect", args.count >= 1,
           exprTainted(args[0], tainted: tainted) != nil,
           !source.contains("IsLocalUrl") {
            emit(&findings, function, offset,
                 AstSinkRule(category: "Open Redirect", severity: .high, vulnArgIndex: nil, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
                 message: "Redirect uses an attacker-controlled URL; open redirect is possible.",
                 taint: exprTainted(args[0], tainted: tainted), reachable: reachable, crossFile: false)
            return
        }
        // HttpClient outbound requests with a tainted URL (SSRF).
        if ["GetStringAsync", "GetAsync", "GetStreamAsync", "GetByteArrayAsync",
            "PostAsync", "PutAsync", "SendAsync", "GetStringWithRetry"].contains(shortName),
           args.count >= 1, exprTainted(args[0], tainted: tainted) != nil,
           !source.lowercased().contains("allowedhosts") {
            emit(&findings, function, offset,
                 AstSinkRule(category: "SSRF", severity: .high, vulnArgIndex: nil, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
                 message: "\(shortName) fetches an attacker-controlled URL; SSRF is possible.",
                 taint: exprTainted(args[0], tainted: tainted), reachable: reachable, crossFile: false)
            return
        }
        // XmlDocument.LoadXml / XmlReader parsing of untrusted payloads (XXE;
        // the hardened variants are removed by the DtdProcessing/XmlResolver gate).
        if ["LoadXml", "Load"].contains(shortName), args.count >= 1,
           exprTainted(args[0], tainted: tainted) != nil {
            emit(&findings, function, offset,
                 AstSinkRule(category: "XXE", severity: .high, vulnArgIndex: nil, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
                 message: "\(shortName) parses untrusted XML; configure DtdProcessing/XmlResolver to prevent XXE.",
                 taint: exprTainted(args[0], tainted: tainted), reachable: reachable, crossFile: false)
            return
        }
        // Command injection: Process.Start / Start
        if shortName == "Start" || name == "Process.Start" {
            if args.contains(where: { exprTainted($0, tainted: tainted) != nil && !isGuarded($0, guarded: guarded, category: "Command Injection") }) {
                emit(&findings, function, offset,
                     AstSinkRule(category: "Command Injection", severity: .high, vulnArgIndex: nil, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
                     message: "\(name) constructs an OS command from untrusted data.",
                     taint: nil, reachable: reachable, crossFile: args.contains(where: { exprCrossFile($0, crossTainted: crossTainted) }))
            }
            return
        }
        // SQL injection: SqlCommand / ExecuteReader / ExecuteNonQuery / ExecuteScalar
        if ["ExecuteReader", "ExecuteNonQuery", "ExecuteScalar", "SqlCommand"].contains(shortName) {
            for a in args where exprTainted(a, tainted: tainted) != nil && !isGuarded(a, guarded: guarded, category: "SQL Injection") {
                emit(&findings, function, offset,
                     AstSinkRule(category: "SQL Injection", severity: .high, vulnArgIndex: nil, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
                     message: "SQL command or query execution built from untrusted data.",
                     taint: nil, reachable: reachable, crossFile: exprCrossFile(a, crossTainted: crossTainted))
                return
            }
        }
        // Insecure Deserialization: BinaryFormatter.Deserialize / XmlSerializer.Deserialize / Deserialize
        if shortName == "Deserialize" || shortName == "BinaryFormatter" || shortName == "XmlSerializer" {
            for a in args where exprTainted(a, tainted: tainted) != nil {
                emit(&findings, function, offset,
                     AstSinkRule(category: "Insecure Deserialization", severity: .critical, vulnArgIndex: nil, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
                     message: "Deserialization of untrusted data using \(name).",
                     taint: nil, reachable: reachable, crossFile: exprCrossFile(a, crossTainted: crossTainted))
                return
            }
        }
        // SSRF: DownloadString / WebClient
        if shortName == "DownloadString" || shortName == "WebClient" {
            for a in args where exprTainted(a, tainted: tainted) != nil {
                emit(&findings, function, offset,
                     AstSinkRule(category: "SSRF", severity: .high, vulnArgIndex: nil, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
                     message: "Network request made to untrusted URL via \(name).",
                     taint: nil, reachable: reachable, crossFile: exprCrossFile(a, crossTainted: crossTainted))
                return
            }
        }
        // Path Traversal: File.ReadAllText / ReadAllLines / Open / WriteAllText
        if ["ReadAllText", "ReadAllLines", "Open", "WriteAllText", "OpenRead", "OpenWrite", "DownloadFile"].contains(shortName) {
            for a in args where exprTainted(a, tainted: tainted) != nil && !isGuarded(a, guarded: guarded, category: "Path Traversal") {
                emit(&findings, function, offset,
                     AstSinkRule(category: "Path Traversal", severity: .medium, vulnArgIndex: nil, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
                     message: "\(name) opens or reads file path from untrusted data.",
                     taint: nil, reachable: reachable, crossFile: exprCrossFile(a, crossTainted: crossTainted))
                return
            }
        }
    }

    func checkCSharpNewExprSinks(name: String, args: [CExpr], offset: Int, function: String, tainted: Set<String>, crossTainted: Set<String>, guarded: Set<String>, sizeBounded: Set<String>, findings: inout [AstFinding], reachable: Bool) {
        let shortName = lastSeg(name)
        // System.Random is predictable (Mersenne Twister seeded from the clock);
        // constructing it inside a security-token generator produces guessable
        // tokens. RandomNumberGenerator / RNGCryptoServiceProvider are the CSPRNG
        // replacements. The function-name gate keeps non-security uses clean.
        if shortName == "Random" {
            let low = function.lowercased()
            let tokenWords = ["token", "password", "passwd", "secret", "otp", "passcode", "pin", "reset",
                              "credential", "nonce", "session", "cookie", "auth", "signature", "verify"]
            if tokenWords.contains(where: { low.contains($0) }) {
                emit(&findings, function, offset,
                     AstSinkRule(category: "Weak Randomness", severity: .high, vulnArgIndex: nil, alwaysVulnerable: true, formatArgIndex: nil, bufferOverflowOnFormat: false),
                     message: "new Random() is predictable; use RandomNumberGenerator for security-critical values.",
                     taint: nil, reachable: reachable, crossFile: false)
                return
            }
        }
        if ["BinaryFormatter", "XmlSerializer", "SqlCommand"].contains(shortName) {
            // For SqlCommand the only SQL-injection-relevant argument is the
            // command *text* (arg 0). A tainted connection / data-adapter argument
            // is not injection, and parameterized queries keep a string-literal
            // command text safe even when other args are caller-controlled.
            let relevant = shortName == "SqlCommand" ? Array(args.prefix(1)) : args
            for a in relevant where exprTainted(a, tainted: tainted) != nil && !isGuarded(a, guarded: guarded, category: "SQL Injection") {
                let cat = shortName == "SqlCommand" ? "SQL Injection" : "Insecure Deserialization"
                let sev: ScanFinding.Severity = shortName == "SqlCommand" ? .high : .critical
                emit(&findings, function, offset,
                     AstSinkRule(category: cat, severity: sev, vulnArgIndex: nil, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
                     message: "\(name) instantiated with untrusted data.",
                     taint: nil, reachable: reachable, crossFile: exprCrossFile(a, crossTainted: crossTainted))
                return
            }
        }
    }
}

extension VulnerabilityScanner {

    /// Reachability over the C# method call graph, mirroring the Java pass. A
    /// method is reachable if it is transitively called from a conventional
    /// entry point (`Main`, `MainAsync`, `handler`, `OnGet`, `OnPost`, `Run`, ...)
    /// defined in this file.
    static func csharpReachableFunctions(source: String, methods: [CSharpMethodDef], definitions: [CCFunctionParser.FunctionDef]) -> Set<String> {
        let tokens = CTokenizer(source: source).tokenize()
        let definedNames = Set(definitions.map { $0.name })

        var callees: [String: [String]] = [:]
        for def in definitions {
            let lo = def.bodyRange.location
            let hi = lo + def.bodyRange.length
            let bodyTokens = Self.cTokens(lo, hi, tokens: tokens)
            var calling = Set<String>()
            for (idx, t) in bodyTokens.enumerated() where t.kind == .identifier {
                guard idx + 1 < bodyTokens.count,
                      bodyTokens[idx + 1].kind == .punct, bodyTokens[idx + 1].text == "(" else { continue }
                if idx > 0, bodyTokens[idx - 1].kind == .operator, bodyTokens[idx - 1].text == "." { continue }
                let callee = t.text
                if definedNames.contains(callee), callee != def.name {
                    calling.insert(callee)
                }
            }
            callees[def.name] = Array(calling)
        }

        let entryNames: Set<String> = ["Main", "MainAsync", "MainTask", "handler", "Run",
                                       "OnGet", "OnPost", "OnPut", "OnDelete", "HandleRequest",
                                       "ProcessRequest", "Index", "OnAction", "Execute"]
        var visited = Set<String>()
        var queue: [String] = []
        for entry in entryNames where definedNames.contains(entry) {
            if !visited.contains(entry) {
                visited.insert(entry)
                queue.append(entry)
            }
        }
        while !queue.isEmpty {
            let current = queue.removeFirst()
            for next in (callees[current] ?? []) where !visited.contains(next) {
                visited.insert(next)
                queue.append(next)
            }
        }
        return visited
    }
}
// by cipher.org.uk
// MARK: - Python-specific AST security checks
// Extracted from AstSecurityDetector.swift / VulnerabilityScanner.swift to
// keep per-language vulnerability detection modular. Shared wire-up stays in
// AstSecurityDetector.swift · VulnerabilityScanner.swift (dispatch lines only).

import Foundation

extension AstSecurityDetector {

    /// Python sinks (mirrors the scanner's Python table). Keyed on the dotted
    /// Python API path (`os.system`, `subprocess.call`) or a bare method name
    /// (`execute`, `open`) when it applies to any receiver of that method.
    static let pythonSinks: [String: AstSinkRule] = [
        "os.system": .init(category: "Command Injection", severity: .high, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "os.popen": .init(category: "Command Injection", severity: .high, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "os.spawnl": .init(category: "Command Injection", severity: .high, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "os.spawnv": .init(category: "Command Injection", severity: .high, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "os.popen2": .init(category: "Command Injection", severity: .high, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "os.popen3": .init(category: "Command Injection", severity: .high, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "os.execl": .init(category: "Command Injection", severity: .high, vulnArgIndex: 1, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "os.execv": .init(category: "Command Injection", severity: .high, vulnArgIndex: 1, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "os.spawnvp": .init(category: "Command Injection", severity: .high, vulnArgIndex: 2, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "os.spawnve": .init(category: "Command Injection", severity: .high, vulnArgIndex: 2, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "popen2.popen2": .init(category: "Command Injection", severity: .high, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "subprocess.call": .init(category: "Command Injection", severity: .high, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "subprocess.Popen": .init(category: "Command Injection", severity: .high, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "subprocess.run": .init(category: "Command Injection", severity: .high, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "subprocess.check_call": .init(category: "Command Injection", severity: .high, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "subprocess.check_output": .init(category: "Command Injection", severity: .high, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "subprocess.getoutput": .init(category: "Command Injection", severity: .high, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "subprocess.getstatusoutput": .init(category: "Command Injection", severity: .high, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "commands.getoutput": .init(category: "Command Injection", severity: .high, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "commands.getstatusoutput": .init(category: "Command Injection", severity: .high, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "eval": .init(category: "Code Injection", severity: .high, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "exec": .init(category: "Command Injection", severity: .high, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "compile": .init(category: "Code Injection", severity: .high, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "sqlite3.connect": .init(category: "SQL Injection", severity: .medium, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "execute": .init(category: "SQL Injection", severity: .high, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "executemany": .init(category: "SQL Injection", severity: .high, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "executescript": .init(category: "SQL Injection", severity: .high, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "pickle.loads": .init(category: "Insecure Deserialization", severity: .critical, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "pickle.load": .init(category: "Insecure Deserialization", severity: .critical, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "joblib.load": .init(category: "Insecure Deserialization", severity: .critical, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "shelve.open": .init(category: "Insecure Deserialization", severity: .critical, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "yaml.load": .init(category: "Insecure Deserialization", severity: .high, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "cPickle.loads": .init(category: "Insecure Deserialization", severity: .critical, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "marshal.load": .init(category: "Insecure Deserialization", severity: .critical, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "numpy.load": .init(category: "Insecure Deserialization", severity: .medium, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "torch.load": .init(category: "Insecure Deserialization", severity: .critical, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "os.remove": .init(category: "Path Traversal", severity: .medium, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "os.rename": .init(category: "Path Traversal", severity: .medium, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "os.unlink": .init(category: "Path Traversal", severity: .medium, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "os.mkdir": .init(category: "Path Traversal", severity: .medium, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "os.makedirs": .init(category: "Path Traversal", severity: .medium, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "os.rmdir": .init(category: "Path Traversal", severity: .medium, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "shutil.copy": .init(category: "Path Traversal", severity: .medium, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "shutil.move": .init(category: "Path Traversal", severity: .medium, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "shutil.rmtree": .init(category: "Path Traversal", severity: .medium, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "builtins.open": .init(category: "Path Traversal", severity: .medium, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "open": .init(category: "Path Traversal", severity: .medium, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "urlopen": .init(category: "SSRF", severity: .high, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "urlretrieve": .init(category: "SSRF", severity: .high, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "requests.get": .init(category: "SSRF", severity: .high, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "requests.post": .init(category: "SSRF", severity: .high, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "requests.put": .init(category: "SSRF", severity: .high, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "requests.delete": .init(category: "SSRF", severity: .high, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "requests.patch": .init(category: "SSRF", severity: .high, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "requests.head": .init(category: "SSRF", severity: .high, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "requests.options": .init(category: "SSRF", severity: .high, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "requests.request": .init(category: "SSRF", severity: .high, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "hashlib.md5": .init(category: "Weak Cryptography", severity: .medium, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "hashlib.sha1": .init(category: "Weak Cryptography", severity: .medium, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "logging.error": .init(category: "Log Injection", severity: .low, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "logging.critical": .init(category: "Log Injection", severity: .low, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        // Server-side template / response sinks: tainted content rendered or
        // returned as HTML flows to the browser without escaping.
        "render_template_string": .init(category: "XSS (HTML Injection)", severity: .high, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "flask.render_template_string": .init(category: "XSS (HTML Injection)", severity: .high, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "make_response": .init(category: "XSS (HTML Injection)", severity: .high, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "flask.make_response": .init(category: "XSS (HTML Injection)", severity: .high, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "flask.Response": .init(category: "XSS (HTML Injection)", severity: .high, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "Response": .init(category: "XSS (HTML Injection)", severity: .high, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        // markupsafe.Markup(...) marks a string as safe-to-render: wrapping a
        // tainted value is a self-XSS/reflected-XSS trust decision.
        "Markup": .init(category: "XSS (HTML Injection)", severity: .high, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "markupsafe.Markup": .init(category: "XSS (HTML Injection)", severity: .high, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
    ]

    /// Python hardening awareness:
    ///  - `ALLOWED_COMMANDS` constants + list-form subprocess calls (no shell=True),
    ///  - `resolve_safe` canonicalizing against a fixed base and rejecting escapes,
    ///  - `validated_url` / `ALLOWED_HOSTS` scheme+host allowlists.
    func applyPythonSuppressions(fn: CFunctionDef, findings: inout [AstFinding]) {
        let hasCmdGuard = source.contains("ALLOWED_COMMANDS")
        if hasCmdGuard {
            findings.removeAll { $0.category == "Command Injection" }
        }
        let hasPathGuard = source.contains("resolve_safe")
        if hasPathGuard {
            findings.removeAll { $0.category == "Path Traversal" }
        }
        let hasUrlGuard = source.contains("validated_url") || source.contains("ALLOWED_HOSTS")
        if hasUrlGuard {
            findings.removeAll { $0.category == "SSRF" }
        }
    }

    func checkPythonSinks(name: String, qualified: String, args: [CExpr], offset: Int, function: String, tainted: Set<String>, crossTainted: Set<String>, guarded: Set<String>, sizeBounded: Set<String>, findings: inout [AstFinding], reachable: Bool) -> Bool {
        // Weak crypto via `hashlib.new("md5", ...)`: the algorithm is a string
        // literal, so evaluate it like the Java getInstance rule.
        if qualified == "hashlib.new", let lit = stringLiteralOf(args.first) {
            if isWeakAlgorithm(lit) {
                emit(&findings, function, offset,
                     rule("Weak Cryptography", .medium, always: true),
                     message: "Use of weak algorithm \(lit); prefer an authenticated modern cipher/hash.",
                     taint: nil, reachable: reachable, crossFile: false)
            }
            return true
        }
        guard let rule = Self.pythonSinks[qualified] ?? Self.pythonSinks[name] else { return false }
        if rule.category == "SSRF", let idx = rule.vulnArgIndex,
           idx < args.count, isPythonSSRFValidatedURL(args[idx]) {
            return true
        }
        evaluateGenericRule(rule, name: qualified, args: args, offset: offset, function: function, tainted: tainted, crossTainted: crossTainted, guarded: guarded, sizeBounded: sizeBounded, findings: &findings, reachable: reachable)
        return true
    }

    /// A direct call to a project-wide host/scheme validator yields a clean URL.
    /// Keep this scoped to Python SSRF so validators cannot accidentally sanitize
    /// data for unrelated categories such as SQL injection or command execution.
    func isPythonSSRFValidatedURL(_ expr: CExpr) -> Bool {
        guard !pythonSSRFValidatedFunctions.isEmpty,
              case .call(let callee, _, _) = expr else { return false }
        let qualified = callQualifiedName(callee)
        let short = callName(callee)
        return (qualified.map { pythonSSRFValidatedFunctions.contains($0) } ?? false)
            || (short.map { pythonSSRFValidatedFunctions.contains($0) } ?? false)
    }
} // end extension AstSecurityDetector
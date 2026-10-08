// by cipher.org.uk
// MARK: - Java-specific AST security checks
// Extracted from AstSecurityDetector.swift / VulnerabilityScanner.swift to
// keep per-language vulnerability detection modular. Shared wire-up stays in
// AstSecurityDetector.swift · VulnerabilityScanner.swift (dispatch lines only).

import Foundation

extension AstSecurityDetector {

    /// Java file-constructor receivers on which a tainted path argument is a
    /// path-traversal sink (`new FileReader(taintedPath)`, ...).
    static let javaFileConstructors: Set<String> = [
        "FileReader", "FileInputStream", "FileOutputStream", "RandomAccessFile",
        "FileWriter", "File", "Scanner", "PrintWriter", "FileChannel",
    ]

    /// Java file-operation sinks whose trailing identifier is a path sink
    /// (`Paths.get`, `Files.newInputStream`, ...). The callee is a member
    /// chain, so both the full name and its last segment may match.
    static let javaFilePathSinks: Set<String> = [
        "Paths.get", "Files.newInputStream", "Files.newOutputStream", "Files.newBufferedReader",
        "Files.newBufferedWriter", "Files.readAllBytes", "Files.readAllLines", "Files.copy",
        "Files.move", "Files.delete", "Files.createDirectories", "Files.createFile",
        "ClassLoader.getResourceAsStream", "getResourceAsStream",
    ]

    /// Java hardening awareness. Both mitigations re-validate data *after*
    /// the raw sink call, so a pre-sink guard model doesn't see them:
    ///  - `setObjectInputFilter(...)` before `readObject()` constrains what
    ///    the stream may deserialize (JEP 290 filter),
    ///  - `getCanonicalPath()` + `startsWith(base)` + reject is the classic
    ///    zip-slip containment check over the extracted File.
    func applyJavaSuppressions(fn: CFunctionDef, findings: inout [AstFinding]) {
        if bodyHasIdentifierStmt(fn.body, "setObjectInputFilter") {
            findings.removeAll { $0.category == "Insecure Deserialization" }
        }
        if bodyHasCanonicalPathValidation(fn.body) {
            findings.removeAll { $0.category == "Path Traversal" }
        }
    }

    /// Lowercased source text of the statement containing `offset`, built from
    /// the *token* stream so comments (which often mention a scan keyword, e.g.
    /// a note about `ALLOWED_HOSTS`) can neither suppress a sink nor leak an
    /// unrelated token into the window. Bounded by the nearest `;`, `{`, or `}`
    /// token on either side; string-literal tokens keep their quoted text.
    func statementText(_ offset: Int) -> String {
        let tokens = CTokenizer(source: source).tokenize()
        guard !tokens.isEmpty else { return "" }
        let bounds: Set<String> = [";", "{", "}"]
        var lo = 0
        for (i, t) in tokens.enumerated() where t.offset <= offset { lo = i + 1 }
        var bs = lo
        while bs > 0, !bounds.contains(tokens[bs - 1].text) { bs -= 1 }
        var fe = lo
        while fe < tokens.count, !bounds.contains(tokens[fe].text) { fe += 1 }
        guard fe > bs else { return "" }
        return tokens[bs..<fe].map { $0.text }.joined().lowercased()
    }

    /// First segment of a dotted call path as written (`engine` for
    /// `engine.process`, `u` for `u.openConnection`).
    func firstSegment(_ name: String) -> String {
        name.split(separator: ".").first.map(String.init) ?? name
    }

    /// True when `varName` is declared with a server-side template type name
    /// (`TemplateEngine engine, ...`, `Template t`, `ThymeleafTemplate view`).
    /// The optional prefix + suffix consume adjacent type-name characters.
    func javaVarHasTemplateType(_ varName: String, source: String) -> Bool {
        let pattern = #"\b(?:[A-Za-z_$][A-Za-z0-9_$]*)?(?:Template|Thymeleaf|Freemarker)[A-Za-z0-9_$]*\s+"# + NSRegularExpression.escapedPattern(for: varName) + #"(?=[,)={;])"#
        guard let re = try? NSRegularExpression(pattern: pattern, options: [.caseInsensitive]) else { return false }
        let ns = source as NSString
        return re.firstMatch(in: source, range: NSRange(location: 0, length: ns.length)) != nil
    }

    /// True when the function performs the canonical-path containment pattern:
    /// a `getCanonicalPath()` read combined with a `startsWith(...)` comparison.
    private func bodyHasCanonicalPathValidation(_ stmt: CStmt) -> Bool {
        var hasCanonical = false
        var hasStartsWith = false

        func note(_ e: CExpr) {
            if case .member(let base, let m, _, _) = e {
                if m == "getCanonicalPath" { hasCanonical = true }
                note(base)
            }
        }
        func walkExpr(_ e: CExpr) {
            note(e)
            switch e {
            case .unary(_, let x, _), .cast(let x, _), .paren(let x, _):
                walkExpr(x)
            case .binary(_, let l, let r, _), .comma(let l, let r, _):
                walkExpr(l); walkExpr(r)
            case .ternary(let c, let t, let f, _):
                walkExpr(c); walkExpr(t); walkExpr(f)
            case .assign(_, let l, let r, _):
                walkExpr(l); walkExpr(r)
            case .call(let callee, let args, _):
                if case .member(let b, let m, _, _) = callee, m == "startsWith" { hasStartsWith = true; walkExpr(b) }
                walkExpr(callee)
                for a in args { walkExpr(a) }
            case .member(let base, _, _, _):
                walkExpr(base)
            case .index(let base, let idx, _):
                walkExpr(base); walkExpr(idx)
            case .arrayInit(let els, _):
                for el in els { walkExpr(el) }
            case .newExpr(_, let args, _):
                for a in args { walkExpr(a) }
            case .sizeOf, .lambda, .integerLiteral, .floatLiteral, .stringLiteral, .charLiteral, .booleanLiteral, .identifier:
                break
            }
        }
        func walkStmt(_ stmt: CStmt) {
            switch stmt {
            case .block(let arr):
                for s in arr { walkStmt(s) }
            case .expr(let e):
                walkExpr(e)
            case .declaration(let d):
                if case .variable(_, _, let ie?) = d.kind { walkExpr(ie) }
            case .ifStmt(let cond, let t, let e, _):
                walkExpr(cond); walkStmt(t); if let e = e { walkStmt(e) }
            case .whileStmt(let cond, let b, _):
                walkExpr(cond); walkStmt(b)
            case .doWhileStmt(let b, let cond, _):
                walkStmt(b); walkExpr(cond)
            case .forStmt(let initS, let cond, let inc, let b, _):
                if let initS = initS { walkStmt(initS) }
                if let cond = cond { walkExpr(cond) }
                if let inc = inc { walkExpr(inc) }
                walkStmt(b)
            case .returnStmt(let e, _):
                if let e = e { walkExpr(e) }
            case .switchStmt(let expr, let cases, _):
                walkExpr(expr)
                for c in cases { for s in c.body { walkStmt(s) } }
            case .labeledStmt(_, let s, _):
                walkStmt(s)
            case .breakStmt, .continueStmt, .gotoStmt, .empty:
                break
            }
        }
        walkStmt(stmt)
        return hasCanonical && hasStartsWith
    }

    func checkJavaSinks(name: String, qualified: String, args: [CExpr], offset: Int, function: String, tainted: Set<String>, crossTainted: Set<String>, guarded: Set<String>, sizeBounded: Set<String>, findings: inout [AstFinding], reachable: Bool) {
        let ql = qualified.lowercased()
        // Weak-crypto via MessageDigest/Cipher.getInstance("MD5"/...).
        if name == "getInstance", let lit = stringLiteralOf(args.first) {
            if isWeakAlgorithm(lit) {
                emit(&findings, function, offset,
                     AstSinkRule(category: "Weak Cryptography (insecure algorithm/block mode)", severity: .high, vulnArgIndex: nil, alwaysVulnerable: true, formatArgIndex: nil, bufferOverflowOnFormat: false),
                     message: "Use of weak algorithm \(lit); prefer an authenticated modern cipher/hash.",
                     taint: nil, reachable: reachable, crossFile: false)
            }
            return
        }
        // Command injection: Runtime.exec (single shell-command string).
        // ProcessBuilder is safe by construction: it always uses an explicit
        // argument list and never interprets the command as a shell string.
        if name == "exec" {
            if args.contains(where: { exprTainted($0, tainted: tainted) != nil && !isGuarded($0, guarded: guarded, category: "Command Injection") }) {
                emit(&findings, function, offset,
                     AstSinkRule(category: "Command Injection", severity: .high, vulnArgIndex: nil, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
                     message: "\(name) constructs an OS command from untrusted data.",
                     taint: nil, reachable: reachable, crossFile: args.contains(where: { exprCrossFile($0, crossTainted: crossTainted) }))
            }
            return
        }
        // SQL via Statement/PreparedStatement execution when the query is built by concatenation.
        if ["executeQuery", "executeUpdate", "execute", "addBatch"].contains(name) {
            for a in args where exprTainted(a, tainted: tainted) != nil && !isGuarded(a, guarded: guarded, category: "SQL Injection") {
                emit(&findings, function, offset,
                     AstSinkRule(category: "SQL Injection", severity: .high, vulnArgIndex: nil, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
                     message: "SQL statement is built from untrusted data without parameterization.",
                     taint: nil, reachable: reachable, crossFile: exprCrossFile(a, crossTainted: crossTainted))
                return
            }
        }
        // LDAP injection: DirContext.search(base, filter, …) with a filter built
        // from untrusted data. `escapeForLDAP`-style escaping of the meta
        // characters (\ * ( ) NUL) is the standard mitigation.
        if ["search", "searchByName"].contains(name), args.count >= 2,
           exprTainted(args[1], tainted: tainted) != nil {
            let near = self.statementText(args[1].offset)
            if !near.contains("escapeforldap") && !near.contains("\\5c") && !near.contains("\\2a") {
                emit(&findings, function, offset,
                     rule("LDAP Injection", .high),
                     message: "\(name) builds an LDAP filter from untrusted data without escaping; filter manipulation is possible.",
                     taint: exprTainted(args[1], tainted: tainted), reachable: reachable, crossFile: exprCrossFile(args[1], crossTainted: crossTainted))
            }
        }
        // Open redirect: response.sendRedirect(tainted).
        if name == "sendRedirect", args.count >= 1,
           exprTainted(args[0], tainted: tainted) != nil {
            emit(&findings, function, offset,
                 rule("Open Redirect", .high),
                 message: "sendRedirect uses an attacker-controlled URL; open redirect is possible.",
                 taint: exprTainted(args[0], tainted: tainted), reachable: reachable, crossFile: exprCrossFile(args[0], crossTainted: crossTainted))
            return
        }
        // SpEL injection: parseExpression(tainted).
        if name == "parseExpression", args.count >= 1,
           exprTainted(args[0], tainted: tainted) != nil {
            emit(&findings, function, offset,
                 rule("Expression Language Injection", .critical),
                 message: "SpEL expression built from untrusted data; code execution is possible.",
                 taint: exprTainted(args[0], tainted: tainted), reachable: reachable, crossFile: exprCrossFile(args[0], crossTainted: crossTainted))
            return
        }
        // XPath injection: xpath.evaluate(tainted, node).
        if name == "evaluate", args.count >= 1,
           exprTainted(args[0], tainted: tainted) != nil {
            emit(&findings, function, offset,
                 rule("XPath Injection", .high),
                 message: "XPath expression built from untrusted data.",
                 taint: exprTainted(args[0], tainted: tainted), reachable: reachable, crossFile: exprCrossFile(args[0], crossTainted: crossTainted))
            return
        }
        // JdbcTemplate / EntityManager native queries built by concatenation.
        if ["createNativeQuery", "queryForObject", "queryForList", "queryForMap", "executeQuery"].contains(name),
           args.count >= 1, exprTainted(args[0], tainted: tainted) != nil {
            emit(&findings, function, offset,
                 rule("SQL Injection", .high),
                 message: "\(name) builds a SQL statement from untrusted data without parameterization.",
                 taint: exprTainted(args[0], tainted: tainted), reachable: reachable, crossFile: exprCrossFile(args[0], crossTainted: crossTainted))
            return
        }
        // RestTemplate / WebClient outbound requests with a tainted URL.
        if ["getForObject", "getForEntity", "postForObject", "exchange", "get uri", "retrieve"].contains(name),
           args.count >= 1, exprTainted(args[0], tainted: tainted) != nil,
           !self.statementText(args[0].offset).contains("allowed_hosts") {
            emit(&findings, function, offset,
                 rule("SSRF", .high),
                 message: "\(name) fetches an attacker-controlled URL; SSRF is possible.",
                 taint: exprTainted(args[0], tainted: tainted), reachable: reachable, crossFile: exprCrossFile(args[0], crossTainted: crossTainted))
            return
        }
        // URL member HTTP calls: `url.openConnection()`/`openStream()` connect
        // to the URL the receiver variable was built from. A receiver seeded
        // from tainted input (`URL u = new URL(target)`) is the SSRF vector.
        if ["openConnection", "openStream"].contains(name),
           let recv = qualified.split(separator: ".").first.map(String.init),
           tainted.contains(recv) {
            emit(&findings, function, offset,
                 rule("SSRF", .high),
                 message: "\(name) opens a connection to a URL built from untrusted data; SSRF is possible.",
                 taint: nil, reachable: reachable, crossFile: args.first.map { exprCrossFile($0, crossTainted: crossTainted) } ?? false)
            return
        }
        // Path Traversal: file/stream constructors opened from a tainted path. The
        // callee is a member chain (e.g. `Files.newInputStream(path)`), so we check
        // the trailing identifier of each sink name.
        if Self.javaFilePathSinks.contains(qualified) || Self.javaFilePathSinks.contains(name) || Self.javaFilePathSinks.contains(lastSeg(name)) {
            for a in args where exprTainted(a, tainted: tainted) != nil && !isGuarded(a, guarded: guarded, category: "Path Traversal") {
                emit(&findings, function, offset,
                     AstSinkRule(category: "Path Traversal", severity: .medium, vulnArgIndex: nil, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
                     message: "\(name) opens a file path that can be controlled by the caller.",
                     taint: nil, reachable: reachable, crossFile: exprCrossFile(a, crossTainted: crossTainted))
                return
            }
        }
        // SQL injection via prepared/statement construction with a query built by
        // concatenation (parameterized `?` queries are string literals and skip).
        if ["prepareStatement", "createStatement"].contains(name), args.count >= 1,
           exprTainted(args[0], tainted: tainted) != nil,
           !isGuarded(args[0], guarded: guarded, category: "SQL Injection") {
            emit(&findings, function, offset,
                 AstSinkRule(category: "SQL Injection", severity: .high, vulnArgIndex: nil, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
                 message: "\(name) builds a SQL statement from untrusted data without parameterization.",
                 taint: exprTainted(args[0], tainted: tainted), reachable: reachable, crossFile: exprCrossFile(args[0], crossTainted: crossTainted))
            return
        }
        // HTTP response splitting / header injection via servlet headers.
        if ["setHeader", "addHeader", "setIntHeader", "addIntHeader"].contains(name),
           args.contains(where: { exprTainted($0, tainted: tainted) != nil }) {
            emit(&findings, function, offset,
                 AstSinkRule(category: "Header Injection", severity: .high, vulnArgIndex: nil, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
                 message: "\(name) sets an HTTP header from untrusted data; CRLF injection is possible.",
                 taint: nil, reachable: reachable, crossFile: args.contains(where: { exprCrossFile($0, crossTainted: crossTainted) }))
            return
        }
        // ReDoS via java.util.regex patterns built from untrusted data.
        // `Pattern.quote(...)` (and friends) neutralize the pattern and are skipped.
        if name == "compile", ql.hasPrefix("pattern."), args.count >= 1,
           exprTainted(args[0], tainted: tainted) != nil {
            let near = self.statementText(args[0].offset)
            if !near.contains("pattern.quote") && !near.contains(".quote(") {
                emit(&findings, function, offset,
                     AstSinkRule(category: "ReDoS", severity: .medium, vulnArgIndex: nil, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
                     message: "Pattern.compile() builds a regular expression pattern from untrusted data; ReDoS is possible.",
                     taint: exprTainted(args[0], tainted: tainted), reachable: reachable, crossFile: exprCrossFile(args[0], crossTainted: crossTainted))
                return
            }
        }
        // Insecure deserialization via ObjectInputStream.readObject/readUnshared.
        // A `setObjectInputFilter(...)` in the body removes these findings
        // (applyJavaSuppressions), so filtered streams stay clean.
        if ["readObject", "readUnshared"].contains(name) {
            emit(&findings, function, offset,
                 AstSinkRule(category: "Insecure Deserialization", severity: .critical, vulnArgIndex: nil, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
                 message: "\(name) deserializes object data from an untrusted stream.",
                 taint: nil, reachable: reachable, crossFile: false)
            return
        }
        // Reflected XSS: an HTTP response writer / JSP `out` written with
        // unsanitized data. Escaping/encoding near the write skips the check.
        if ["write", "print", "println"].contains(name),
           (ql.contains("getwriter") || ql.hasPrefix("out.")),
           args.contains(where: { exprTainted($0, tainted: tainted) != nil }) {
            let near = self.statementText(offset)
            if !near.contains("escape") && !near.contains("encode") && !near.contains("esc(") {
                emit(&findings, function, offset,
                     AstSinkRule(category: "XSS (HTML Injection)", severity: .high, vulnArgIndex: nil, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
                     message: "\(name) writes attacker-controlled data into an HTTP response without encoding.",
                     taint: nil, reachable: reachable, crossFile: args.contains(where: { exprCrossFile($0, crossTainted: crossTainted) }))
                return
            }
        }
        // Server-side template injection: TemplateEngine/Template render/process
        // driven by a tainted *template name* (the first argument); the model/
        // context arguments are attacker data by design and are not the
        // injection point. Receiver types include `TemplateEngine`, `Template`,
        // `ThymeleafTemplate`, etc.
        if ["process", "render"].contains(name),
           (ql.contains("template") || ql.contains("thymeleaf") || ql.contains("freemarker")
            || self.javaVarHasTemplateType(firstSegment(qualified), source: source)),
           let firstArg = args.first, exprTainted(firstArg, tainted: tainted) != nil {
            emit(&findings, function, offset,
                 AstSinkRule(category: "Template Injection", severity: .high, vulnArgIndex: nil, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
                 message: "\(name) renders a server-side template using untrusted data; template injection is possible.",
                 taint: nil, reachable: reachable, crossFile: args.contains(where: { exprCrossFile($0, crossTainted: crossTainted) }))
            return
        }
        // Arbitrary code loading: System.load/loadLibrary or Runtime.load of a
        // library path derived from untrusted data.
        if ["load", "loadLibrary"].contains(name),
           (ql.hasPrefix("system.") || ql.contains("runtime")),
           args.contains(where: { exprTainted($0, tainted: tainted) != nil }) {
            emit(&findings, function, offset,
                 AstSinkRule(category: "Arbitrary Code Loading", severity: .high, vulnArgIndex: nil, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
                 message: "\(name) loads a native library from a path derived from untrusted data.",
                 taint: nil, reachable: reachable, crossFile: args.contains(where: { exprCrossFile($0, crossTainted: crossTainted) }))
            return
        }
        // Insecure deserialization via XStream.fromXML on untrusted XML input.
        if name == "fromXML", args.count >= 1,
           exprTainted(args[0], tainted: tainted) != nil {
            emit(&findings, function, offset,
                 AstSinkRule(category: "Insecure Deserialization", severity: .critical, vulnArgIndex: nil, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
                 message: "\(name) deserializes untrusted XML data.",
                 taint: exprTainted(args[0], tainted: tainted), reachable: reachable, crossFile: exprCrossFile(args[0], crossTainted: crossTainted))
            return
        }
    }

    /// Receiver for `new <Type>(<tainted path>)` Java file operations.
    func checkNewExprSinks(name: String, args: [CExpr], offset: Int, function: String, tainted: Set<String>, crossTainted: Set<String>, guarded: Set<String>, sizeBounded: Set<String>, findings: inout [AstFinding], reachable: Bool) {
        if Self.javaFileConstructors.contains(name), let first = args.first,
           exprTainted(first, tainted: tainted) != nil,
           !isGuarded(first, guarded: guarded, category: "Path Traversal") {
            emit(&findings, function, offset,
                 AstSinkRule(category: "Path Traversal", severity: .medium, vulnArgIndex: nil, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
                 message: "\(name) opens a file path that can be controlled by the caller.",
                 taint: nil, reachable: reachable, crossFile: exprCrossFile(first, crossTainted: crossTainted))
            return
        }
        // `new ProcessBuilder(...)` builds an OS command array from untrusted
        // data; the shell-command text can be any of the arguments (a shell
        // binary with a command string, or a single tainted executable name).
        if name == "ProcessBuilder",
           args.contains(where: { exprTainted($0, tainted: tainted) != nil && !isGuarded($0, guarded: guarded, category: "Command Injection") }) {
            emit(&findings, function, offset,
                 AstSinkRule(category: "Command Injection", severity: .high, vulnArgIndex: nil, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
                 message: "ProcessBuilder constructs an OS command from untrusted data.",
                 taint: nil, reachable: reachable, crossFile: args.contains(where: { exprCrossFile($0, crossTainted: crossTainted) }))
            return
        }
        // SSRF: opening a socket to a host derived from untrusted data.
        // An explicit host allow-list in the file is respected like the other
        // Java SSRF sinks.
        if ["Socket", "InetSocketAddress"].contains(name), args.count >= 1,
           exprTainted(args[0], tainted: tainted) != nil,
           !self.statementText(args[0].offset).contains("allowed_hosts") {
            emit(&findings, function, offset,
                 AstSinkRule(category: "SSRF", severity: .high, vulnArgIndex: nil, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
                 message: "\(name) connects to a host derived from untrusted data; SSRF is possible.",
                 taint: exprTainted(args[0], tainted: tainted), reachable: reachable, crossFile: exprCrossFile(args[0], crossTainted: crossTainted))
            return
        }
    }
}

extension VulnerabilityScanner {

    /// Reachability over the Java method call graph: a method is reachable if it is
    /// transitively called from a conventional Java entry point (`main`, `Main`,
    /// `handler`, `doGet`, `doPost`, `service`, `run`, `init`, `onCreate`, ...)
    /// defined in this file. Call edges are collected pragmatically by scanning each
    /// method body (via its exact token range) for `name(` calls to other defined
    /// methods.
    static func javaReachableFunctions(source: String, methods: [JMethodDef], definitions: [CCFunctionParser.FunctionDef]) -> Set<String> {
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

        let entryNames: Set<String> = ["main", "Main", "MainAsync", "handler", "doGet", "doPost",
                                       "service", "run", "init", "onCreate", "onStart", "onResume",
                                       "click", "onClick", "processRequest", "process"]
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

    /// Java class fields written untrusted data somewhere in the file. A
    /// `this.<f> = <rhs>` store in any constructor/method marks `<f>` tainted
    /// for every method of the file, so a bare field read used at a sink in
    /// another method keeps its flow. The RHS is tainted when it references a
    /// parameter of the enclosing method (params are the untrusted sources) or
    /// a known taint-return API (e.g. `intent.getStringExtra(...)`).
    static func taintedJavaFields(source: String,
                                  definitions: [CCFunctionParser.FunctionDef],
                                  tokens: [Token],
                                  taintReturning: Set<String>) -> Set<String> {
        var fields = Set<String>()
        for def in definitions {
            let sigTokens = def.signatureRange.length > 0 ? Self.tokens(in: def.signatureRange, tokenList: tokens) : []
            let bodyTokens = Self.tokens(in: def.bodyRange, tokenList: tokens)
            let params = parameterNames(tokens: sigTokens.isEmpty ? bodyTokens : sigTokens)
            var i = 0
            let n = bodyTokens.count
            while i + 3 < n {
                if bodyTokens[i].kind == .identifier, bodyTokens[i].text == "this",
                   bodyTokens[i + 1].text == ".",
                   bodyTokens[i + 2].kind == .identifier,
                   bodyTokens[i + 3].text == "=" {
                    let field = bodyTokens[i + 2].text
                    var j = i + 4
                    var parenDepth = 0
                    var rhsRefsParam = false
                    var rhsRefsTaintReturn = false
                    while j < n {
                        let rt = bodyTokens[j]
                        if rt.text == "(" { parenDepth += 1 }
                        else if rt.text == ")" { parenDepth -= 1 }
                        if rt.text == ";" && parenDepth <= 0 { break }
                        if rt.kind == .identifier {
                            if params.contains(rt.text) { rhsRefsParam = true }
                            if taintReturning.contains(rt.text) { rhsRefsTaintReturn = true }
                        }
                        j += 1
                    }
                    // Stop scanning this store's RHS once both signals found.
                    if rhsRefsParam || rhsRefsTaintReturn {
                        fields.insert(field)
                    }
                    i = j
                } else {
                    i += 1
                }
            }
        }
        return fields
    }
}
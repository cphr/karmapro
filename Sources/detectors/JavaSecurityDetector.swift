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

    // MARK: - Java value-bounds analysis

    /// Java arithmetic/bounds faults: silent integer wraparound, division by an
    /// unchecked zero divisor, and array indexes that reach a tainted or
    /// out-of-range offset. Java has no buffer memory-unsafety, so these model
    /// the value fault itself (wrapped result, `ArithmeticException`,
    /// `ArrayIndexOutOfBoundsException`), not a memory overwrite.
    ///
    /// A value is "risky" when it derives from untrusted input, was seeded with a
    /// type-extreme constant, or was assigned a negative literal. A value is
    /// treated as safe when the body proves a bound on it: a MAX/MIN comparison
    /// (wraparound), a non-zero guard (division), or both a `>= 0` and a
    /// `< length` check (array index).
    func checkJavaNumeric(fn: CFunctionDef, function: String, tainted: Set<String>, findings: inout [AstFinding], reachable: Bool) {
        var atBound = Set<String>()
        var negative = Set<String>()
        var zeroed = Set<String>()
        var boundGuarded = Set<String>()
        var nonZero = Set<String>()
        var lowerBounded = Set<String>()
        var upperBounded = Set<String>()
        var numUpperBounded = Set<String>()
        func isNumericLit(_ e: CExpr) -> Bool {
            switch e {
            case .integerLiteral, .floatLiteral: return true
            case .paren(let x, _), .cast(let x, _): return isNumericLit(x)
            default: return false
            }
        }
        func collectIds(_ e: CExpr, into ids: inout Set<String>) {
            switch e {
            case .identifier(let n, _): ids.insert(n)
            case .call(let c, let args, _):
                collectIds(c, into: &ids); for a in args { collectIds(a, into: &ids) }
            case .member(let b, _, _, _): collectIds(b, into: &ids)
            case .index(let b, let i, _): collectIds(b, into: &ids); collectIds(i, into: &ids)
            case .unary(_, let x, _), .cast(let x, _), .paren(let x, _): collectIds(x, into: &ids)
            case .binary(_, let l, let r, _), .comma(let l, let r, _):
                collectIds(l, into: &ids); collectIds(r, into: &ids)
            case .ternary(let c, let t, let f, _):
                collectIds(c, into: &ids); collectIds(t, into: &ids); collectIds(f, into: &ids)
            case .arrayInit(let els, _): for el in els { collectIds(el, into: &ids) }
            case .newExpr(_, let args, _): for a in args { collectIds(a, into: &ids) }
            default: break
            }
        }

        func isLengthRef(_ e: CExpr) -> Bool {
            switch e {
            case .member(_, let m, _, _): return m == "length" || m == "size"
            case .call(let c, _, _): return callName(c) == "length" || callName(c) == "size"
            case .binary(_, let l, let r, _): return isLengthRef(l) || isLengthRef(r)
            case .paren(let x, _), .cast(let x, _): return isLengthRef(x)
            default: return false
            }
        }
        func isZeroLit(_ e: CExpr) -> Bool {
            switch e {
            case .integerLiteral(let s, _): return s == "0" || s == "0L" || s == "0l"
            case .paren(let x, _), .cast(let x, _): return isZeroLit(x)
            default: return false
            }
        }
        func isNonZeroLit(_ e: CExpr) -> Bool {
            switch e {
            case .integerLiteral(let s, _): return s != "0" && s != "0L" && s != "0l"
            case .floatLiteral(let s, _): return Double(s) != 0
            case .paren(let x, _), .cast(let x, _): return isNonZeroLit(x)
            default: return false
            }
        }
        // `Math.abs(x) > <positive literal>` or `abs(x) >= ...` proves `x` is
        // bounded away from zero, so a division/modulo by it cannot throw.
        func absArg(_ e: CExpr) -> String? {
            guard case .call(let c, let args, _) = e, callName(c) == "abs",
                  args.count == 1, let n = simpleIdentifier(args[0]) else { return nil }
            return n
        }
        func isNegLit(_ e: CExpr) -> Bool {
            switch e {
            case .integerLiteral(let s, _): return s.hasPrefix("-")
            case .unary("-", let x, _):
                if case .integerLiteral = x { return true }
                return false
            case .paren(let x, _), .cast(let x, _): return isNegLit(x)
            default: return false
            }
        }
        func isBoundConstant(_ e: CExpr) -> Bool {
            switch e {
            case .member(_, let m, _, _): return m == "MAX_VALUE" || m == "MIN_VALUE"
            case .binary(_, let l, let r, _): return isBoundConstant(l) || isBoundConstant(r)
            case .paren(let x, _), .cast(let x, _): return isBoundConstant(x)
            default: return false
            }
        }

        func flip(_ op: String) -> String {
            switch op {
            case "<": return ">"
            case "<=": return ">="
            case ">": return "<"
            case ">=": return "<="
            default: return op
            }
        }

        func noteBounds(_ op: String, _ a: CExpr, _ b: CExpr) {
            if isBoundConstant(a) { collectIds(b, into: &boundGuarded) }
            if isBoundConstant(b) { collectIds(a, into: &boundGuarded) }
            if isZeroLit(b) {
                if op == "!=" { collectIds(a, into: &nonZero) }
                if op == ">" || op == "<" { collectIds(a, into: &nonZero) }
                if op == ">" || op == ">=" { collectIds(a, into: &lowerBounded) }
            } else if isZeroLit(a) {
                if op == "!=" { collectIds(b, into: &nonZero) }
                if op == ">" || op == "<" { collectIds(b, into: &nonZero) }
                if op == ">" || op == ">=" { collectIds(b, into: &lowerBounded) }
            }
            if op == ">" || op == ">=" {
                if let n = absArg(a), isNonZeroLit(b) { nonZero.insert(n) }
                if let n = absArg(b), isNonZeroLit(a) { nonZero.insert(n) }
            }
            if isLengthRef(b) && (op == "<" || op == "<=") { collectIds(a, into: &upperBounded) }
            if isLengthRef(a) && (op == ">" || op == ">=") { collectIds(b, into: &upperBounded) }
            // A comparison against a numeric literal upper-bounds the other
            // operand (`if (count <= 20)`), which caps a loop driven by it.
            if isNumericLit(b) && (op == "<" || op == "<=") { collectIds(a, into: &numUpperBounded) }
            if isNumericLit(a) && (op == ">" || op == ">=") { collectIds(b, into: &numUpperBounded) }
        }

        func walkExpr(_ e: CExpr, _ visit: (CExpr) -> Void) {
            visit(e)
            switch e {
            case .call(let c, let args, _):
                walkExpr(c, visit); for a in args { walkExpr(a, visit) }
            case .member(let b, _, _, _): walkExpr(b, visit)
            case .index(let b, let i, _): walkExpr(b, visit); walkExpr(i, visit)
            case .unary(_, let x, _), .cast(let x, _), .paren(let x, _): walkExpr(x, visit)
            case .binary(_, let l, let r, _), .comma(let l, let r, _): walkExpr(l, visit); walkExpr(r, visit)
            case .ternary(let c, let t, let f, _): walkExpr(c, visit); walkExpr(t, visit); walkExpr(f, visit)
            case .assign(_, let l, let r, _): walkExpr(l, visit); walkExpr(r, visit)
            case .arrayInit(let arr, _): for a in arr { walkExpr(a, visit) }
            case .newExpr(_, let args, _): for a in args { walkExpr(a, visit) }
            default: break
            }
        }

        func evalConstInt(_ e: CExpr) -> Int? {
            switch e {
            case .integerLiteral(let s, _): return Int(s)
            case .identifier(let n, _): return javaIntConst[n]
            case .member(let b, let m, _, _):
                if case .identifier(let base, _) = b, let v = javaIntConst["\(base).\(m)"] { return v }
                return nil
            case .paren(let x, _), .cast(let x, _): return evalConstInt(x)
            case .unary(let op, let x, _) where op == "-" || op == "+":
                return evalConstInt(x).map { op == "-" ? -$0 : $0 }
            default: return nil
            }
        }
        func evalConstCond(_ e: CExpr) -> Bool? {
            switch e {
            case .booleanLiteral(let b, _): return b
            case .identifier(let n, _): return javaBoolConst[n]
            case .member(let b, let m, _, _):
                if case .identifier(let base, _) = b { return javaBoolConst["\(base).\(m)"] }
                return nil
            case .paren(let x, _), .cast(let x, _): return evalConstCond(x)
            case .unary("!", let x, _): return evalConstCond(x).map { !$0 }
            case .binary(let op, let l, let r, _):
                guard let a = evalConstInt(l), let b = evalConstInt(r) else { return nil }
                switch op {
                case "==": return a == b
                case "!=": return a != b
                case ">": return a > b
                case "<": return a < b
                case ">=": return a >= b
                case "<=": return a <= b
                default: return nil
                }
            default: return nil
            }
        }

        func walkStmt(_ s: CStmt, _ visit: (CExpr) -> Void) {
            switch s {
            case .block(let arr): for x in arr { walkStmt(x, visit) }
            case .expr(let e): walkExpr(e, visit)
            case .declaration(let d): if case .variable(_, _, let ie?) = d.kind { walkExpr(ie, visit) }
            case .ifStmt(let c, let t, let eb, _):
                if let cond = evalConstCond(c) {
                    if cond { walkStmt(t, visit) } else if let eb = eb { walkStmt(eb, visit) }
                } else {
                    walkExpr(c, visit); walkStmt(t, visit); if let eb = eb { walkStmt(eb, visit) }
                }
            case .whileStmt(let c, let b, _): walkExpr(c, visit); walkStmt(b, visit)
            case .doWhileStmt(let b, let c, _): walkStmt(b, visit); walkExpr(c, visit)
            case .forStmt(let initS, let c, let inc, let b, _):
                if let initS = initS { walkStmt(initS, visit) }
                if let c = c { walkExpr(c, visit) }
                if let inc = inc { walkExpr(inc, visit) }
                walkStmt(b, visit)
            case .switchStmt(let e, let cases, _):
                walkExpr(e, visit)
                // A `switch` on a compile-time constant selects one arm; the
                // other arms are dead and only hold compiler-satisfying
                // initializers (`data = 0`), so walking them invents a flow
                // that can never execute.
                if let v = evalConstInt(e) {
                    let match = cases.first { cs in
                        !cs.isDefault && cs.values.contains { evalConstInt($0) == v }
                    }
                    if let chosen = match ?? cases.first(where: { $0.isDefault }) {
                        for x in chosen.body { walkStmt(x, visit) }
                    }
                } else {
                    for cs in cases { for x in cs.body { walkStmt(x, visit) } }
                }
            case .returnStmt(let e, _): if let e = e { walkExpr(e, visit) }
            case .labeledStmt(_, let x, _): walkStmt(x, visit)
            default: break
            }
        }

        let compareOps: Set<String> = ["<", "<=", ">", ">=", "==", "!="]
        walkStmt(fn.body) { e in
            switch e {
            case .assign(_, let lhs, let rhs, _):
                if let n = simpleIdentifier(lhs) {
                    if isBoundConstant(rhs) { atBound.insert(n) }
                    if isNegLit(rhs) { negative.insert(n) }
                    if isZeroLit(rhs) { zeroed.insert(n) }
                }
            case .binary(let op, let l, let r, _) where compareOps.contains(op):
                noteBounds(op, l, r)
            default:
                break
            }
        }

        let risky = tainted.union(atBound).union(negative)
        let divisorRisk = tainted.union(atBound).union(zeroed)

        // An operand participates in string concatenation when it is a string
        // literal, a `+` chain that reaches one, or a stringification call. The
        // whole chain must be skipped so `"n=" + x + " = " + (a % b)` is not read
        // as integer overflow on each nested `+`.
        func isStringOperand(_ e: CExpr) -> Bool {
            switch e {
            case .stringLiteral:
                return true
            case .paren(let x, _), .cast(let x, _):
                return isStringOperand(x)
            case .binary("+", let l, let r, _):
                return isStringOperand(l) || isStringOperand(r)
            case .call(let c, _, _):
                if let n = callName(c) {
                    return n == "valueOf" || n == "toString" || n == "format" || n == "concat" || n == "append"
                }
                return false
            default:
                return false
            }
        }
        func riskyIds(_ e: CExpr) -> Set<String> {
            var ids = Set<String>()
            collectIds(e, into: &ids)
            return ids.filter { risky.contains($0) && !boundGuarded.contains($0) }
        }

        walkStmt(fn.body) { e in
            switch e {
            case .binary(let op, let l, let r, let off) where op == "+" || op == "-" || op == "*":
                if isStringOperand(l) || isStringOperand(r) { break }
                if !riskyIds(l).isEmpty || !riskyIds(r).isEmpty {
                    let category = op == "-" ? "Integer Underflow" : "Integer Overflow"
                    emit(&findings, function, off, rule(category, .medium),
                         message: "Arithmetic on a caller-influenced value can wrap past the numeric range without a bound check.",
                         taint: riskyIds(l).first ?? riskyIds(r).first, reachable: reachable, crossFile: false)
                }
            case .binary(let op, let l, let r, let off) where op == "/" || op == "%":
                _ = l
                let riskyDivisor: Bool
                if isZeroLit(r) { riskyDivisor = true }
                else if let n = simpleIdentifier(r), divisorRisk.contains(n), !nonZero.contains(n) { riskyDivisor = true }
                else { riskyDivisor = false }
                if riskyDivisor {
                    emit(&findings, function, off, rule("Possible Division by Zero", .medium),
                         message: "Division by a value that can be zero throws at runtime.",
                         taint: simpleIdentifier(r), reachable: reachable, crossFile: false)
                }
            case .unary(let op, let x, let off) where op == "++" || op == "--":
                if let n = simpleIdentifier(x), risky.contains(n), !boundGuarded.contains(n) {
                    let category = op == "--" ? "Integer Underflow" : "Integer Overflow"
                    emit(&findings, function, off, rule(category, .medium),
                         message: "Increment/decrement of a caller-influenced value can wrap past the numeric range.",
                         taint: n, reachable: reachable, crossFile: false)
                }
            case .assign(let op, let lhs, let rhs, let off) where op == "+=" || op == "-=" || op == "*=":
                _ = rhs
                if let n = simpleIdentifier(lhs), risky.contains(n), !boundGuarded.contains(n) {
                    let category = op == "-=" ? "Integer Underflow" : "Integer Overflow"
                    emit(&findings, function, off, rule(category, .medium),
                         message: "Compound arithmetic on a caller-influenced value can wrap past the numeric range.",
                         taint: n, reachable: reachable, crossFile: false)
                }
            case .index(let base, let idx, let off):
                _ = base
                if isNegLit(idx) {
                    emit(&findings, function, off, rule("Array Index Out of Bounds", .medium),
                         message: "A negative constant array index reads or writes outside the array bounds.",
                         taint: nil, reachable: reachable, crossFile: false)
                } else if let n = simpleIdentifier(idx), risky.contains(n),
                          !(lowerBounded.contains(n) && upperBounded.contains(n)) {
                    emit(&findings, function, off, rule("Array Index Out of Bounds", .medium),
                         message: "Array index derives from caller-influenced data without both lower- and upper-bound checks.",
                         taint: n, reachable: reachable, crossFile: false)
                }
            case .cast(let inner, let off):
                // Numeric truncation: a narrowing cast (`(byte)`/`(short)`/
                // `(char)`) of a caller-influenced integer silently loses the
                // high-order bits.
                if let n = riskyIds(inner).first {
                    let st = self.statementText(off)
                    if st.contains("(byte)") || st.contains("(short)") || st.contains("(char)") {
                        emit(&findings, function, off, rule("Numeric Truncation Error", .medium),
                             message: "Narrowing cast truncates a caller-influenced value; a numeric truncation error is possible.",
                             taint: n, reachable: reachable, crossFile: false)
                    }
                }
            case .newExpr(let typeName, let args, let off):
                let leaf = typeName.split(separator: ".").last.map(String.init) ?? typeName
                let sizedCollections: Set<String> = ["ArrayList", "HashMap", "HashSet", "Hashtable",
                                                     "Vector", "StringBuilder", "StringBuffer",
                                                     "ConcurrentHashMap", "LinkedHashMap",
                                                     "LinkedHashSet", "TreeMap", "TreeSet",
                                                     "ByteArrayOutputStream", "PriorityQueue"]
                if sizedCollections.contains(leaf), let first = args.first,
                   let n = riskyIds(first).first {
                    emit(&findings, function, off, rule("Uncontrolled Memory Allocation", .medium),
                         message: "\(leaf) is sized from untrusted data and can exhaust memory.",
                         taint: n, reachable: reachable, crossFile: false)
                }
            default:
                break
            }
        }

        // Uncontrolled resource consumption: a loop whose iteration bound is a
        // caller-influenced value with no upper-bound validation, and
        // Thread.sleep(tainted) which stalls for an attacker-chosen duration.
        func loopTaintedBound(_ cond: CExpr, _ bounded: Set<String>) -> String? {
            guard case .binary(let op, let l, let r, _) = cond, op == "<" || op == "<=" else { return nil }
            _ = l
            if isLengthRef(r) { return nil }
            if let n = simpleIdentifier(r), risky.contains(n), !boundGuarded.contains(n),
               !numUpperBounded.contains(n), !bounded.contains(n) { return n }
            return nil
        }
        func upperBoundVars(_ e: CExpr) -> Set<String> {
            var out = Set<String>()
            func scan(_ e: CExpr) {
                switch e {
                case .binary(let op, let l, let r, _):
                    if op == "<" || op == "<=" {
                        if isNumericLit(r) || isLengthRef(r) { collectIds(l, into: &out) }
                    }
                    if op == ">" || op == ">=" {
                        if isNumericLit(l) || isLengthRef(l) { collectIds(r, into: &out) }
                    }
                    scan(l); scan(r)
                case .unary(_, let x, _), .paren(let x, _), .cast(let x, _): scan(x)
                default: break
                }
            }
            scan(e)
            return out
        }
        func scanResource(_ s: CStmt, _ bounded: Set<String>) {
            switch s {
            case .block(let arr):
                for x in arr { scanResource(x, bounded) }
            case .forStmt(_, let cond, _, let body, let off):
                if let cond = cond, let n = loopTaintedBound(cond, bounded) {
                    emit(&findings, function, off, rule("Uncontrolled Resource Consumption", .medium),
                         message: "Loop iteration count derives from untrusted data without an upper bound; resource exhaustion is possible.",
                         taint: n, reachable: reachable, crossFile: false)
                }
                scanResource(body, bounded)
            case .whileStmt(_, let body, _), .doWhileStmt(let body, _, _):
                scanResource(body, bounded)
            case .ifStmt(let c, let t, let e, _):
                let b2 = bounded.union(upperBoundVars(c))
                scanResource(t, b2); if let e = e { scanResource(e, bounded) }
            case .switchStmt(_, let cases, _):
                for c in cases { for x in c.body { scanResource(x, bounded) } }
            case .labeledStmt(_, let x, _):
                scanResource(x, bounded)
            case .expr(let e):
                if case .call(let callee, let args, let off) = e, callName(callee) == "sleep",
                   args.count == 1, let n = riskyIds(args[0]).first,
                   !boundGuarded.contains(n), !numUpperBounded.contains(n), !bounded.contains(n) {
                    emit(&findings, function, off, rule("Uncontrolled Resource Consumption", .medium),
                         message: "Thread.sleep() uses an attacker-controlled duration; resource exhaustion is possible.",
                         taint: n, reachable: reachable, crossFile: false)
                }
            default:
                break
            }
        }
        scanResource(fn.body, [])
    }

    // MARK: - Java code-quality and null-safety checks

    /// Structural quality checks (empty branches, switch defects, always-true
    /// conditions, off-by-one bounds) plus a null-dereference pass, and a small
    /// amount of comment-stripped source slicing for the try/catch/finally
    /// shapes the parser flattens away.
    func checkJavaQuality(fn: CFunctionDef, function: String, tainted: Set<String>,
                          findings: inout [AstFinding], reachable: Bool) {
        func emitQ(_ off: Int, _ cat: String, _ sev: ScanFinding.Severity, _ msg: String) {
            emit(&findings, function, off, rule(cat, sev), message: msg, taint: nil, reachable: reachable, crossFile: false)
        }

        func stripParen(_ e: CExpr) -> CExpr {
            switch e {
            case .paren(let x, _), .cast(let x, _): return stripParen(x)
            default: return e
            }
        }
        func walkExpr(_ e: CExpr, _ visit: (CExpr) -> Void) {
            visit(e)
            switch e {
            case .call(let c, let args, _): walkExpr(c, visit); for a in args { walkExpr(a, visit) }
            case .member(let b, _, _, _): walkExpr(b, visit)
            case .index(let b, let i, _): walkExpr(b, visit); walkExpr(i, visit)
            case .unary(_, let x, _), .cast(let x, _), .paren(let x, _): walkExpr(x, visit)
            case .binary(_, let l, let r, _), .comma(let l, let r, _): walkExpr(l, visit); walkExpr(r, visit)
            case .ternary(let c, let t, let f, _): walkExpr(c, visit); walkExpr(t, visit); walkExpr(f, visit)
            case .assign(_, let l, let r, _): walkExpr(l, visit); walkExpr(r, visit)
            case .arrayInit(let a, _): for x in a { walkExpr(x, visit) }
            case .newExpr(_, let a, _): for x in a { walkExpr(x, visit) }
            default: break
            }
        }
        func walkAllStmts(_ s: CStmt, _ visit: (CStmt) -> Void) {
            visit(s)
            switch s {
            case .block(let a): for x in a { walkAllStmts(x, visit) }
            case .ifStmt(_, let t, let e, _): walkAllStmts(t, visit); if let e = e { walkAllStmts(e, visit) }
            case .whileStmt(_, let b, _): walkAllStmts(b, visit)
            case .doWhileStmt(let b, _, _): walkAllStmts(b, visit)
            case .forStmt(let i, _, _, let b, _): if let i = i { walkAllStmts(i, visit) }; walkAllStmts(b, visit)
            case .switchStmt(_, let cs, _): for c in cs { for x in c.body { walkAllStmts(x, visit) } }
            case .labeledStmt(_, let st, _): walkAllStmts(st, visit)
            default: break
            }
        }
        func eachExpr(_ f: (CExpr) -> Void) {
            walkAllStmts(fn.body) { s in
                switch s {
                case .expr(let e): walkExpr(e, f)
                case .declaration(let d): if case .variable(_, _, let ie?) = d.kind { walkExpr(ie, f) }
                case .ifStmt(let c, _, _, _): walkExpr(c, f)
                case .whileStmt(let c, _, _): walkExpr(c, f)
                case .doWhileStmt(_, let c, _): walkExpr(c, f)
                case .forStmt(_, let c, _, _, _): if let c = c { walkExpr(c, f) }
                case .switchStmt(let e, _, _): walkExpr(e, f)
                case .returnStmt(let e, _): if let e = e { walkExpr(e, f) }
                default: break
                }
            }
        }
        var localInt: [String: Int] = [:]
        var localBool: [String: Bool] = [:]
        func evalInt(_ e: CExpr) -> Int? {
            switch stripParen(e) {
            case .integerLiteral(let s, _): return Int(s)
            case .identifier(let n, _): return localInt[n] ?? javaIntConst[n]
            case .member(let b, let m, _, _):
                if case .identifier(let base, _) = stripParen(b) { return javaIntConst["\(base).\(m)"] }
                return nil
            case .unary(let op, let x, _) where op == "-" || op == "+":
                return evalInt(x).map { op == "-" ? -$0 : $0 }
            case .binary(let op, let l, let r, _):
                guard let a = evalInt(l), let b = evalInt(r) else { return nil }
                switch op {
                case "+": return a + b
                case "-": return a - b
                case "*": return a * b
                case "/": return b != 0 ? a / b : nil
                case "%": return b != 0 ? a % b : nil
                default: return nil
                }
            default: return nil
            }
        }
        func evalBool(_ e: CExpr) -> Bool? {
            switch stripParen(e) {
            case .booleanLiteral(let b, _): return b
            case .identifier(let n, _): return localBool[n] ?? javaBoolConst[n]
            case .member(let b, let m, _, _):
                if case .identifier(let base, _) = stripParen(b) { return javaBoolConst["\(base).\(m)"] }
                return nil
            case .unary("!", let x, _): return evalBool(x).map { !$0 }
            case .binary(let op, let l, let r, _):
                guard let a = evalInt(l), let b = evalInt(r) else { return nil }
                switch op {
                case "==": return a == b
                case "!=": return a != b
                case ">": return a > b
                case "<": return a < b
                case ">=": return a >= b
                case "<=": return a <= b
                default: return nil
                }
            default: return nil
            }
        }
        func isBoolLit(_ e: CExpr) -> Bool { if case .booleanLiteral = stripParen(e) { return true }; return false }
        // Locals declared final/never-reassigned with a literal initializer act as
        // compile-time constants for the structural checks below.
        do {
            var decls: [(String, CExpr)] = []
            var reassigned = Set<String>()
            walkAllStmts(fn.body) { s in
                switch s {
                case .declaration(let d):
                    if case .variable(_, let n, let ie?) = d.kind { decls.append((n, ie)) }
                case .expr(let e):
                    if case .assign(_, let l, _, _) = e, let n = simpleIdentifier(l) { reassigned.insert(n) }
                case .forStmt(_, _, let inc, _, _):
                    if let inc = inc, case .assign(_, let l, _, _) = inc, let n = simpleIdentifier(l) { reassigned.insert(n) }
                default: break
                }
            }
            for (n, ie) in decls where !reassigned.contains(n) {
                switch stripParen(ie) {
                case .integerLiteral(let s, _): if let v = Int(s) { localInt[n] = v }
                case .booleanLiteral(let b, _): localBool[n] = b
                case .unary("-", let x, _):
                    if case .integerLiteral(let s, _) = stripParen(x), let v = Int(s) { localInt[n] = -v }
                default: break
                }
            }
        }
        func isNullLit(_ e: CExpr) -> Bool {
            if case .identifier(let n, _) = stripParen(e), n == "null" { return true }
            return false
        }
        func isLengthRef(_ e: CExpr) -> Bool {
            switch stripParen(e) {
            case .member(_, let m, _, _): return m == "length" || m == "size"
            case .call(let c, _, _): return callName(c) == "length" || callName(c) == "size"
            default: return false
            }
        }
        func isEmptyBody(_ s: CStmt) -> Bool {
            switch s { case .empty: return true; case .block(let a): return a.isEmpty; default: return false }
        }
        func containsCall(_ e: CExpr) -> Bool {
            var found = false
            walkExpr(e) { x in if case .call = stripParen(x) { found = true } }
            return found
        }
        func isBreak(_ s: CStmt) -> Bool { if case .breakStmt = s { return true }; return false }
        func isTerminating(_ s: CStmt) -> Bool {
            switch s { case .breakStmt, .returnStmt, .continueStmt: return true; default: return false }
        }
        func bodyHasExit(_ s: CStmt) -> Bool {
            var found = false
            func walk(_ s: CStmt) {
                if found { return }
                switch s {
                case .breakStmt, .returnStmt, .continueStmt: found = true
                case .block(let a): for x in a { walk(x) }
                case .ifStmt(_, let t, let e, _): walk(t); if let e = e { walk(e) }
                case .whileStmt(_, let b, _): walk(b)
                case .doWhileStmt(let b, _, _): walk(b)
                case .forStmt(_, _, _, let b, _): walk(b)
                case .switchStmt(_, let cs, _): for c in cs { for x in c.body { walk(x) } }
                default: break
                }
            }
            walk(s); return found
        }
        // A comparison whose result is itself compared to a boolean literal is
        // the classic "compared where assigned" shape.
        func compareOfCompare(_ e: CExpr) -> Bool {
            if case .binary(let op, let l, let r, _) = stripParen(e), op == "==" || op == "!=" {
                let other = isBoolLit(l) ? r : (isBoolLit(r) ? l : nil)
                if let o = other, case .binary = stripParen(o) { return true }
            }
            return false
        }
        func isOffByOne(_ e: CExpr) -> Bool {
            if case .binary(let op, let l, let r, _) = stripParen(e), op == "<=" {
                return isLengthRef(r) || isLengthRef(l)
            }
            return false
        }

        walkAllStmts(fn.body) { s in
            switch s {
            case .ifStmt(let c, let t, let eb, let off):
                if isEmptyBody(t) || (eb.map(isEmptyBody) ?? false) {
                    emitQ(off, "Empty Code Block", .low, "Empty branch body has no effect.")
                    if containsCall(c) {
                        emitQ(off, "Error Condition Without Action", .low, "Result of a call is tested but no action is taken on failure.")
                    }
                }
                if case .assign = stripParen(c) {
                    emitQ(off, "Assigning Instead of Comparing", .medium, "Assignment used as a condition; a comparison was likely intended.")
                }
                if evalBool(c) == true {
                    emitQ(off, "Expression Always True", .low, "Condition always evaluates to true.")
                }
                if compareOfCompare(c) {
                    emitQ(off, "Comparing Instead of Assigning", .low, "Comparison result compared to a boolean literal.")
                }
            case .whileStmt(let c, let b, let off):
                if isEmptyBody(b) { emitQ(off, "Empty Code Block", .low, "Empty loop body has no effect.") }
                if case .assign = stripParen(c) {
                    emitQ(off, "Assigning Instead of Comparing", .medium, "Assignment used as a loop condition.")
                }
                if evalBool(c) == true && !bodyHasExit(b) {
                    emitQ(off, "Infinite Loop", .medium, "Loop condition is always true and the body has no exit.")
                }
                if isOffByOne(c) {
                    emitQ(off, "Off-by-One Error", .medium, "Loop bound uses <= against a length/size and can overrun by one.")
                }
            case .doWhileStmt(let b, let c, let off):
                if isEmptyBody(b) { emitQ(off, "Empty Code Block", .low, "Empty loop body has no effect.") }
                if evalBool(c) == true && !bodyHasExit(b) {
                    emitQ(off, "Infinite Loop", .medium, "Loop condition is always true and the body has no exit.")
                }
                if isOffByOne(c) {
                    emitQ(off, "Off-by-One Error", .medium, "Loop bound uses <= against a length/size and can overrun by one.")
                }
            case .forStmt(_, let c, _, let b, let off):
                if isEmptyBody(b) { emitQ(off, "Empty Code Block", .low, "Empty loop body has no effect.") }
                if c == nil || (c.map { evalBool($0) == true } ?? false) {
                    if !bodyHasExit(b) { emitQ(off, "Infinite Loop", .medium, "Loop has no terminating condition and no exit in the body.") }
                }
                if let c = c {
                    if case .assign = stripParen(c) {
                        emitQ(off, "Assigning Instead of Comparing", .medium, "Assignment used as a loop condition.")
                    }
                    if isOffByOne(c) {
                        emitQ(off, "Off-by-One Error", .medium, "Loop bound uses <= against a length/size and can overrun by one.")
                    }
                }
            case .switchStmt(_, let cases, let off):
                if !cases.contains(where: { $0.isDefault }) {
                    emitQ(off, "Missing Default Case in Switch", .low, "Switch has no default case.")
                }
                for (i, cs) in cases.enumerated() {
                    if cs.body.isEmpty || (cs.body.count == 1 && isBreak(cs.body[0])) {
                        emitQ(off, "Empty Code Block", .low, "Empty case body has no effect.")
                        continue
                    }
                    if i < cases.count - 1, let last = cs.body.last, !isTerminating(last) {
                        emitQ(off, "Omitted Break Statement in Switch", .low, "Case falls through into the next case; a break was likely intended.")
                    }
                }
            case .block(let a):
                if a.isEmpty { emitQ(s.offset, "Empty Code Block", .low, "Empty block has no effect.") }
            case .empty:
                emitQ(0, "Empty Code Block", .low, "Empty statement has no effect.")
            default: break
            }
        }

        eachExpr { e in
            if case .call(let c, _, let off) = e, callName(c) == "printStackTrace" {
                emitQ(off, "Information Leak Through Error Message", .low, "Stack trace written to output can leak implementation details.")
            }
        }

        // Calling Thread.run() executes on the current thread; start() is intended.
        // The anonymous-subclass form defeats the AST path, so this is checked
        // against the comment-stripped source slice below.

        let configSinks: Set<String> = ["setCatalog", "setSchema", "setTransactionIsolation", "setNetworkTimeout", "setReadOnly"]
        eachExpr { e in
            if case .call(let c, let args, let off) = e, let n = callName(c), configSinks.contains(n),
               args.contains(where: { exprTainted($0, tainted: tainted) != nil }) {
                emitQ(off, "External Control of Configuration Setting", .high, "Untrusted data controls a database or configuration setting.")
            }
        }

        // Null dereference: a value explicitly set to null, or returned by an
        // API that may return null, then dereferenced without a null check.
        let nullableAPIs: Set<String> = ["getProperty", "getenv", "getParameter", "getParameterValues",
            "getHeader", "getQueryString", "getPathInfo", "getServletPath", "getRequestURI", "getRequestURL",
            "getRemoteUser", "getUserPrincipal", "getAttribute", "getInitParameter", "getResource",
            "getResourceAsStream", "getCookies", "getSession", "readLine", "getText", "getRawValue", "getUserInput"]
        func isNullableCall(_ e: CExpr) -> Bool {
            if case .call(let c, _, _) = stripParen(e), let n = callName(c) { return nullableAPIs.contains(n) }
            return false
        }
        var nullAssigned = Set<String>()
        var nullableFrom = Set<String>()
        var nullGuarded = Set<String>()
        // Mark `x` guarded when it is the subject of a null comparison. Only a
        // top-level condition or an operand of a short-circuit `&&` chain
        // actually prevents the later dereference; a plain `&` evaluates both
        // sides and does not.
        func insertNullCheck(_ e: CExpr) -> Bool {
            guard case .binary(let op, let l, let r, _) = stripParen(e), op == "==" || op == "!=" else { return false }
            var hit = false
            if isNullLit(l), let n = simpleIdentifier(stripParen(r)) { nullGuarded.insert(n); hit = true }
            if isNullLit(r), let n = simpleIdentifier(stripParen(l)) { nullGuarded.insert(n); hit = true }
            return hit
        }
        func collectNullChecks(_ e: CExpr) {
            if insertNullCheck(e) { return }
            if case .binary(_, let l, let r, _) = stripParen(e) {
                collectNullChecks(l); collectNullChecks(r)
            }
        }
        func noteNullGuards(_ e: CExpr, topLevel: Bool) {
            if topLevel, insertNullCheck(e) { return }
            if case .binary(let op, let l, let r, _) = stripParen(e) {
                if op == "&&" { collectNullChecks(l) }
                noteNullGuards(l, topLevel: false)
                noteNullGuards(r, topLevel: false)
            }
        }
        func collectNullFacts(_ s: CStmt) {
            switch s {
            case .block(let a): for x in a { collectNullFacts(x) }
            case .declaration(let d):
                if case .variable(_, let name, let initExpr) = d.kind, let ie = initExpr {
                    if isNullLit(ie) { nullAssigned.insert(name) }
                    else if isNullableCall(ie) { nullableFrom.insert(name) }
                }
            case .expr(.assign(_, .identifier(let name, _), let rhs, _)):
                if isNullLit(rhs) { nullAssigned.insert(name) } else { nullAssigned.remove(name) }
                if isNullableCall(rhs) { nullableFrom.insert(name) }
            case .ifStmt(let c, let t, let eb, _):
                noteNullGuards(c, topLevel: true)
                if let v = evalBool(c) {
                    if v { collectNullFacts(t) } else if let eb = eb { collectNullFacts(eb) }
                } else {
                    // Both paths can run, so a variable is null afterwards only
                    // if every path leaves it null.
                    let savedNull = nullAssigned, savedNB = nullableFrom
                    collectNullFacts(t)
                    let thenNull = nullAssigned, thenNB = nullableFrom
                    nullAssigned = savedNull; nullableFrom = savedNB
                    if let eb = eb { collectNullFacts(eb) }
                    nullAssigned = thenNull.intersection(nullAssigned)
                    nullableFrom = thenNB.union(nullableFrom)
                }
            case .whileStmt(let c, let b, _): noteNullGuards(c, topLevel: true); collectNullFacts(b)
            case .doWhileStmt(let b, let c, _): collectNullFacts(b); noteNullGuards(c, topLevel: true)
            case .forStmt(let i, let c, _, let b, _):
                if let i = i { collectNullFacts(i) }
                if let c = c { noteNullGuards(c, topLevel: true) }
                collectNullFacts(b)
            case .switchStmt(let e, let cs, _):
                // A `switch` on a compile-time constant selects a single arm;
                // the other arms only hold compiler-satisfying initializers.
                if let v = evalInt(e) {
                    let match = cs.first { c in
                        !c.isDefault && c.values.contains { evalInt($0) == v }
                    }
                    if let chosen = match ?? cs.first(where: { $0.isDefault }) {
                        for x in chosen.body { collectNullFacts(x) }
                    }
                } else {
                    let savedNull = nullAssigned, savedNB = nullableFrom
                    var mergedNull: Set<String>? = nil
                    var unionNB = savedNB
                    for c in cs {
                        nullAssigned = savedNull; nullableFrom = savedNB
                        for x in c.body { collectNullFacts(x) }
                        mergedNull = mergedNull.map { $0.intersection(nullAssigned) } ?? nullAssigned
                        unionNB = unionNB.union(nullableFrom)
                    }
                    nullAssigned = mergedNull ?? savedNull
                    nullableFrom = unionNB
                }
            default: break
            }
        }
        collectNullFacts(fn.body)
        let nullable = nullAssigned.union(nullableFrom).subtracting(nullGuarded)
        if !nullable.isEmpty {
            eachExpr { e in
                switch e {
                case .member(let base, let m, _, let off):
                    if let v = simpleIdentifier(stripParen(base)), nullable.contains(v), m != "class" {
                        emitQ(off, "NULL Pointer Dereference", .high, "Possible null dereference of '\(v)'.")
                    }
                case .index(let base, _, let off):
                    if let v = simpleIdentifier(stripParen(base)), nullable.contains(v) {
                        emitQ(off, "NULL Pointer Dereference", .high, "Possible null index dereference of '\(v)'.")
                    }
                default: break
                }
            }
        }

        // try/catch/finally are flattened by the parser, so their shapes are
        // read from the comment-stripped source slice of the function body.
        let ns = source as NSString
        let lo = fn.bodyOffset, hi = fn.endOffset
        guard hi > lo, lo >= 0, hi <= ns.length else { return }
        let body = stripJavaComments(ns.substring(with: NSRange(location: lo, length: hi - lo)))
        if let r = firstJavaPattern(in: body, pattern: #"catch\s*\(\s*NullPointerException\b"#) {
            emitQ(lo + r, "Catch of NullPointerException", .low, "Catching NullPointerException hides a null-dereference defect.")
        }
        if firstJavaPattern(in: body, pattern: #"catch\s*\(\s*(?:Exception|Throwable)\b"#) != nil {
            emitQ(lo, "Catch of Generic Exception", .low, "Catching a broad Exception/Throwable class hides failures.")
        }
        if firstJavaPattern(in: body, pattern: #"catch\s*\([^)]*\)\s*\{\s*\}"#) != nil {
            emitQ(lo, "Error Condition Without Action", .low, "Empty catch block silently ignores an error.")
        }
        if javaReturnInFinally(body) {
            emitQ(lo, "Return in Finally Block", .medium, "Return inside finally discards the pending exception or return value.")
        }
        if firstJavaPattern(in: body, pattern: #"new\s+Thread\b"#) != nil,
           firstJavaPattern(in: body, pattern: #"\.\s*run\s*\(\s*\)"#) != nil {
            emitQ(lo, "Call to Thread.run Instead of start", .medium, "Calling run() executes on the caller thread; use start() to run concurrently.")
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

    /// Java class fields written untrusted data somewhere in the file. A store
    /// to a declared field — `this.<f> = <rhs>` or a bare `<f> = <rhs>` — in any
    /// constructor/method marks `<f>` tainted for every method of the file, so a
    /// bare field read used at a sink in another method keeps its flow. The RHS
    /// is tainted when it references a parameter of the enclosing method, a
    /// known taint-return API (e.g. `intent.getStringExtra(...)`), a source API,
    /// or a local already tracked as tainted (so `data = <source>; field = data`
    /// propagates).
    static func taintedJavaFields(source: String,
                                  definitions: [CCFunctionParser.FunctionDef],
                                  tokens: [Token],
                                  taintReturning: Set<String>) -> Set<String> {
        let fieldNames = declaredJavaFieldNames(source: source, definitions: definitions)
        guard !fieldNames.isEmpty else { return [] }
        var fields = Set<String>()
        for def in definitions {
            let sigTokens = def.signatureRange.length > 0 ? Self.tokens(in: def.signatureRange, tokenList: tokens) : []
            let bodyTokens = Self.tokens(in: def.bodyRange, tokenList: tokens)
            let params = parameterNames(tokens: sigTokens.isEmpty ? bodyTokens : sigTokens)
            var taintedLocals = Set(params)
            var i = 0
            let n = bodyTokens.count
            while i < n {
                var lhs: String?
                var lhsIsField = false
                var rhsStart = 0
                if bodyTokens[i].kind == .identifier, bodyTokens[i].text == "this",
                   i + 3 < n, bodyTokens[i + 1].text == ".",
                   bodyTokens[i + 2].kind == .identifier, bodyTokens[i + 3].text == "=" {
                    lhs = bodyTokens[i + 2].text
                    lhsIsField = true
                    rhsStart = i + 4
                } else if bodyTokens[i].kind == .identifier,
                          i + 1 < n, bodyTokens[i + 1].text == "=" {
                    lhs = bodyTokens[i].text
                    lhsIsField = fieldNames.contains(bodyTokens[i].text)
                    rhsStart = i + 2
                }
                guard let name = lhs else { i += 1; continue }
                var j = rhsStart
                var parenDepth = 0
                var taintedRHS = false
                while j < n {
                    let rt = bodyTokens[j]
                    if rt.text == "(" { parenDepth += 1 }
                    else if rt.text == ")" { parenDepth -= 1 }
                    if (rt.text == ";" || rt.text == ",") && parenDepth <= 0 { break }
                    if rt.kind == .identifier,
                       taintedLocals.contains(rt.text)
                        || taintReturning.contains(rt.text)
                        || javaSourceAPIs.contains(rt.text) {
                        taintedRHS = true
                    }
                    j += 1
                }
                if taintedRHS {
                    if lhsIsField { fields.insert(name) } else { taintedLocals.insert(name) }
                }
                i = rhsStart
            }
        }
        return fields
    }

    /// Names of fields declared at class scope. Method signatures and bodies are
    /// blanked first, so only class-body member declarations remain; the name is
    /// the last identifier before the terminating `;` or the declarator before
    /// `=`.
    /// Class fields assigned exactly once to a literal (at class-body scope) and
    /// never mutated — effectively constants. Juliet's flow-variant testcases
    /// guard dead code behind `if (PRIVATE_STATIC_FINAL_FALSE)` or
    /// `if (privateFive != 5)`, where the field is never reassigned; folding
    /// those conditions removes the dead `data = 0` initializer that would
    /// otherwise look like a zero divisor.
    static func constantScalarFields(source: String) -> (bools: [String: Bool], ints: [String: Int]) {
        constantScalarFields(tokens: CTokenizer(source: source).tokenize())
    }

    static func constantScalarFields(tokens: [CAstToken]) -> (bools: [String: Bool], ints: [String: Int]) {
        var depth = 0
        var assignCount: [String: Int] = [:]
        var assignLit: [String: String] = [:]
        var mutable = Set<String>()
        let mutateOps: Set<String> = ["++", "--", "+=", "-=", "*=", "/=", "%=", "&=", "|=", "^="]
        var i = 0
        while i < tokens.count {
            let t = tokens[i]
            if t.text == "{" { depth += 1; i += 1; continue }
            if t.text == "}" { depth -= 1; i += 1; continue }
            if t.kind == .identifier, i + 1 < tokens.count {
                let nx = tokens[i + 1].text
                if mutateOps.contains(nx) { mutable.insert(t.text) }
                else if nx == "=", depth == 1 {
                    assignCount[t.text, default: 0] += 1
                    if i + 2 < tokens.count {
                        let lit = tokens[i + 2]
                        let isLiteral = lit.kind == .number
                            || (lit.kind == .keyword && (lit.text == "true" || lit.text == "false"))
                        if isLiteral { assignLit[t.text] = lit.text }
                        else { assignLit.removeValue(forKey: t.text) }
                    }
                }
            }
            i += 1
        }
        var bools: [String: Bool] = [:]
        var ints: [String: Int] = [:]
        for (name, count) in assignCount where count == 1 && !mutable.contains(name) {
            guard let lit = assignLit[name] else { continue }
            if lit == "true" || lit == "false" { bools[name] = (lit == "true") }
            else if let value = Int(lit) { ints[name] = value }
        }
        return (bools, ints)
    }

    static func declaredJavaFieldNames(source: String,
                                       definitions: [CCFunctionParser.FunctionDef]) -> Set<String> {
        var chars = Array(source.utf16)
        func blank(_ r: NSRange) {
            guard r.location >= 0, r.length > 0, r.location + r.length <= chars.count else { return }
            for k in r.location..<(r.location + r.length) where chars[k] != 0x0A { chars[k] = 0x20 }
        }
        for def in definitions { blank(def.signatureRange); blank(def.bodyRange) }
        let tokens = CTokenizer(source: String(decoding: chars, as: UTF16.self)).tokenize()
        var fields = Set<String>()
        var depth = 0
        var parenDepth = 0
        var lastIdent: String?
        var assignLhs: String?
        for t in tokens {
            switch t.text {
            case "{":
                depth += 1; lastIdent = nil; assignLhs = nil
            case "}":
                depth -= 1; lastIdent = nil; assignLhs = nil
            case "(":
                parenDepth += 1
            case ")":
                if parenDepth > 0 { parenDepth -= 1 }
            case ";":
                if depth == 1, parenDepth == 0, let n = assignLhs ?? lastIdent { fields.insert(n) }
                lastIdent = nil; assignLhs = nil
            case "=":
                if depth == 1, parenDepth == 0 { assignLhs = lastIdent }
            default:
                if t.kind == .identifier, parenDepth == 0 { lastIdent = t.text }
            }
        }
        return fields
    }
}

/// Blanks `//` and `/* */` comments in Java source, preserving string-literal
/// contents and replacing comment characters with spaces so byte offsets and
/// line structure stay intact.
private func stripJavaComments(_ s: String) -> String {
    var out = Array(s.unicodeScalars)
    let n = out.count
    var i = 0
    func blank(_ j: Int) { if out[j] != "\n" && out[j] != "\r" { out[j] = " " } }
    while i < n {
        let c = out[i]
        if c == "\"" {
            i += 1
            while i < n {
                if out[i] == "\\" { i += 2; continue }
                if out[i] == "\"" { i += 1; break }
                i += 1
            }
        } else if c == "/" && i + 1 < n && out[i + 1] == "/" {
            while i < n && out[i] != "\n" { blank(i); i += 1 }
        } else if c == "/" && i + 1 < n && out[i + 1] == "*" {
            blank(i); blank(i + 1); i += 2
            while i + 1 < n && !(out[i] == "*" && out[i + 1] == "/") { blank(i); i += 1 }
            if i + 1 < n { blank(i); blank(i + 1); i += 2 }
        } else {
            i += 1
        }
    }
    return String(String.UnicodeScalarView(out))
}

private func firstJavaPattern(in s: String, pattern: String) -> Int? {
    guard let re = try? NSRegularExpression(pattern: pattern) else { return nil }
    let ns = s as NSString
    return re.firstMatch(in: s, range: NSRange(location: 0, length: ns.length))?.range.location
}

private func javaReturnInFinally(_ s: String) -> Bool {
    guard let re = try? NSRegularExpression(pattern: #"finally\s*\{"#) else { return false }
    let ns = s as NSString
    let matches = re.matches(in: s, range: NSRange(location: 0, length: ns.length))
    for m in matches {
        let brace = m.range.location + m.range.length - 1
        var depth = 0
        var i = brace
        while i < ns.length {
            let ch = ns.character(at: i)
            if ch == 123 { depth += 1 }
            else if ch == 125 { depth -= 1; if depth == 0 { break } }
            i += 1
        }
        if i >= ns.length { continue }
        let inner = ns.substring(with: NSRange(location: brace + 1, length: max(0, i - brace - 1)))
        if firstJavaPattern(in: inner, pattern: #"\breturn\b"#) != nil { return true }
    }
    return false
}
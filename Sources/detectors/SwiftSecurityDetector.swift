// by cipher.org.uk
import Foundation

// MARK: - Swift three-walk security analysis
//
// Three analysis layers run over the SwiftExpr/SwiftStmt AST built by
// SwiftExprParser, mirroring JSSecurityDetector but for Swift / Foundation /
// UIKit / AppKit APIs:
//
// Walk 1 (taint): value-based data flow over the Swift-native AST — every
//   expression evaluates to a TaintVal (clean / tainted(origin, crossFile)).
//   Source APIs (UserDefaults, CommandLine, FileManager reads, URLSession,
//   decoders, pasteboard, NotificationCenter.userInfo) seed taint; the same
//   source/returning sets power the sink rules (command injection, SQLi, SSRF,
//   deserialization, weak crypto…) and the mobile rules (storage, keychain,
//   WebView, clipboard, deep links, pinning…).
// Walk 2 (bounds): array/string index accesses correlated with loop headers,
//   ranges (`0...arr.count`), and branch guards (`if i < arr.count`, `guard
//   i < arr.count else return`).
// Walk 3 (boundary): division by zero, force-unwraps of possibly-nil subscripts,
//   integer overflow operators, unsafe pointers, and mutation of an array
//   while iterating it.
//
// Generic categories target macOS command-line / server tooling; the mobile
// categories target iOS/macOS app data handling. Findings carry taint paths and
// cross-file attribution like the other AST engines.

// MARK: - Platform inputs

/// Sanitizers specific to Swift: values passed through these are considered
/// neutralised (no arbitrary markup / shell metacharacters).
let swiftSanitizers: Set<String> = [
    "htmlEncode", "stringByAddingPercentEncoding", "addingPercentEncoding(withAllowedCharacters:)",
    "replacingOccurrences(of:with:)", "filtered", "escape", "escaped",
]

/// Force-unwrap of standard data-conversion accessors is idiomatic (their
/// optional covers degenerate encodings / byte views, not absent data).
let swiftForceUnwrapSafeLeaves: Set<String> = [
    "data", "data(using:)", "data(using:allowLossyConversion:)", "bytes", "utf8", "utf16", "string",
]

/// Methods that preserve the taint of their base receiver.
let swiftTaintPropagators: Set<String> = [
    "trimmingCharacters", "trim", "lowercased", "uppercased", "capitalized",
    "replacingCharacters", "replacingOccurrences", "split", "components",
    "joined", "flatMap", "compactMap", "map", "filter", "reduce", "prefix",
    "suffix", "dropFirst", "dropLast", "drop", "first", "last", "enumerated",
    "data(using:)", "data(using:allowLossyConversion:)", "base64EncodedString",
    "appendingPathComponent", "appendingPathExtension", "absoluteString",
    "description", "text", "stringValue", "utf8", "utf16",
]

// MARK: - Taint value

private struct TaintVal {
    var tainted: Bool
    var origin: String?
    var crossFile: Bool

    static let clean = TaintVal(tainted: false, origin: nil, crossFile: false)
    static func tainted(_ origin: String, crossFile: Bool = false) -> TaintVal {
        TaintVal(tainted: true, origin: origin, crossFile: crossFile)
    }
    func union(_ other: TaintVal) -> TaintVal {
        if !tainted { return other }
        if !other.tainted { return self }
        return TaintVal(tainted: true,
                        origin: origin.map { "\($0), \(other.origin ?? "?")" },
                        crossFile: crossFile || other.crossFile)
    }
}

private func unionAll(_ vals: [TaintVal]) -> TaintVal {
    vals.reduce(TaintVal.clean) { $0.union($1) }
}

private final class WalkContext {
    var vars: [String: TaintVal] = [:]
    var boundsGuards: Set<String> = []      // "index\u{1}base" pairs proven in-range
    var zeroChecked: Set<String> = []       // vars proven non-zero on this path
    var callbackTaintedParams: Set<String> = []
    var loopVar: String? = nil
    var loopBase: String? = nil
    var loopInclusive: Bool = false
    var dictLitVars: Set<String> = []   // vars declared as [K: V] keyed lookup tables

    func child() -> WalkContext {
        let c = WalkContext()
        c.vars = vars
        c.boundsGuards = boundsGuards
        c.zeroChecked = zeroChecked
        c.callbackTaintedParams = callbackTaintedParams
        c.loopVar = loopVar
        c.loopBase = loopBase
        c.loopInclusive = loopInclusive
        c.dictLitVars = dictLitVars
        return c
    }
}

// MARK: - Detector

struct SwiftSecurityDetector {

    struct SwiftFinding {
        let function: String
        let offset: Int
        let category: String
        let severity: ScanFinding.Severity
        let message: String
        let taintPath: String?
        let reachable: Bool
        var crossFile: Bool = false
    }

    private let source: String
    private let ns: NSString
    private let defs: [SwiftDef]
    private let tokens: [CAstToken]
    private let reachableNames: Set<String>
    private let taintReturning: Set<String>
    private let crossFileSources: Set<String>

    init(source: String, defs: [SwiftDef], tokens: [CAstToken]? = nil,
         reachableNames: Set<String> = [],
         taintReturning: Set<String> = [],
         crossFileSources: Set<String> = []) {
        self.source = source
        self.ns = source as NSString
        self.defs = defs
        self.tokens = tokens ?? CTokenizer(source: source).tokenize()
        self.reachableNames = reachableNames
        self.taintReturning = taintReturning
        self.crossFileSources = crossFileSources
    }

    func detect() -> [SwiftFinding] {
        var findings: [SwiftFinding] = []
        for def in defs {
            let body = bodyTokens(of: def)
            guard !body.isEmpty else { continue }
            findings.append(contentsOf: analyzeFunction(def, body: body))
        }
        // Cross-file: a finding is cross-file when its taint path originates
        // from a taint-returning function defined in another file.
        for i in findings.indices {
            if let root = findings[i].taintPath?.components(separatedBy: " → ").first,
               crossFileSources.contains(root) {
                findings[i].crossFile = true
            }
        }
        return findings
    }

    // MARK: - File-level scans

    /// File-level (non-function) Swift rules: transport security config,
    /// credentials embedded in URLs, deprecated APIs, plaintext transports.
    static func scanFileLevel(url: URL, source: String, scanningSource: String) -> [ScanFinding] {
        var findings: [ScanFinding] = []
        let ns = source as NSString
        let lower = source.lowercased()

        func line(at offset: Int) -> Int {
            var line = 1
            let upto = min(offset, ns.length)
            var i = 0
            while i < upto {
                if ns.character(at: i) == 0x0A { line += 1 }
                i += 1
            }
            return line
        }

        func add(_ offset: Int, _ category: String, _ severity: ScanFinding.Severity, _ message: String) {
            findings.append(ScanFinding(fileURL: url, line: line(at: offset), function: "(file)",
                                        category: category, message: message, taint: nil,
                                        severity: severity, exploitability: severity,
                                        reachable: true, taintPath: nil, ignored: false,
                                        scanningSource: scanningSource))
        }

        func find(_ probe: String) -> Int {
            let r = ns.range(of: probe, options: .caseInsensitive)
            return r.location != NSNotFound ? r.location : 0
        }

        // Line-aware occurrence scan: skips comment lines and XML/HTML
        // DOCTYPE lines (whose `http://www.w3.org/…` DTD URLs are not
        // network transport) so plaintext-transport findings only fire on
        // real endpoints.
        func scanOccurrence(_ probe: String, _ category: String, _ severity: ScanFinding.Severity, _ message: String) {
            var searchRange = NSRange(location: 0, length: ns.length)
            while searchRange.location < ns.length {
                let r = ns.range(of: probe, options: .caseInsensitive, range: searchRange)
                if r.location == NSNotFound { break }
                let lineStart = ns.lineRange(for: NSRange(location: r.location, length: 0)).location
                let lineLength = min(120, ns.length - lineStart)
                let lineText = ns.substring(with: NSRange(location: lineStart, length: lineLength))
                    .trimmingCharacters(in: .whitespaces)
                if !lineText.hasPrefix("//") && !lineText.hasPrefix("/*") && !lineText.hasPrefix("*")
                    && !lineText.hasPrefix("<") && !lineText.contains("DOCTYPE") {
                    add(r.location, category, severity, message)
                    return
                }
                searchRange = NSRange(location: r.location + r.length, length: ns.length - r.location - r.length)
            }
        }

        // App Transport Security Bypass: NSAllowsArbitraryLoads turned on.
        let atsRange = ns.range(of: "NSAllowsArbitraryLoads", options: .caseInsensitive)
        if atsRange.location != NSNotFound {
            let r = atsRange
            let aroundLo = max(0, r.location - 100)
            let aroundLen = max(0, min(ns.length, r.location + 300) - aroundLo)
            let around = ns.substring(with: NSRange(location: aroundLo, length: aroundLen))
            if around.lowercased().contains("true") {
                add(r.location, "App Transport Security Bypass", .high,
                    "NSAllowsArbitraryLoads = true disables App Transport Security for all connections, including plain HTTP.")
            }
        }

        // Embedded Credentials in URL (https://user:pass@host/…).
        let credRange = ns.range(of: #"https?://[^\s:@/]+:[^@\s]+@"#, options: .regularExpression)
        if credRange.location != NSNotFound {
            add(credRange.location, "Embedded Credentials in URL", .medium,
                "URL embeds credentials in the userinfo component; they leak through logs, history and referrers.")
        }

        // Deprecated Insecure API.
        if lower.contains("nsurlconnection") {
            add(find("NSURLConnection"), "Deprecated Insecure API", .medium,
                "NSURLConnection is deprecated and its TLS stack is outdated; use URLSession.")
        }

        // Insecure WebSocket.
        scanOccurrence("ws://", "Insecure WebSocket", .medium,
                       "Plain ws:// WebSocket transport is unencrypted; use wss://.")

        // Insecure Transport.
        scanOccurrence("http://", "Insecure Transport", .medium,
                       "Plain http:// transport sends data unencrypted; prefer https://.")

        return findings
    }

    // MARK: - Per-function analysis

    private func analyzeFunction(_ def: SwiftDef, body: [CAstToken]) -> [SwiftFinding] {
        let stmts = SwiftExprParser.parseStatements(body)
        let ctx = WalkContext()
        ctx.dictLitVars = dictLiteralVarNames()
        // Walk 1 seed: parameters are the initial untrusted inputs.
        for p in def.params.compactMap({ $0.name }) {
            ctx.vars[p] = .tainted("parameter \(p)")
        }
        var findings: [SwiftFinding] = []
        applyBodyTextualScans(def: def, body: body, ctx: ctx, into: &findings)
        walkAll(stmts, ctx: ctx, def: def, into: &findings)
        return findings
    }

    /// Body-level textual rules that reason about configuration / policy code
    /// inside a function body (WebView data stores, file protection, biometric
    /// policies, location and privacy-data pipelines, crash-report panics, cookie
    /// storage and TLS validation overrides).
    private func applyBodyTextualScans(def: SwiftDef, body: [CAstToken], ctx: WalkContext,
                                       into findings: inout [SwiftFinding]) {
        let reachable = isReachable(def)
        let lo = def.bodyRange.location
        let hi = lo + def.bodyRange.length
        guard lo >= 0, lo < ns.length, hi > lo else { return }
        let len = min(hi, ns.length) - lo
        guard len > 0 else { return }
        let bodyNS = ns.substring(with: NSRange(location: lo, length: len)) as NSString
        let lower = bodyNS.lowercased

        func offset(of probe: String) -> Int {
            let r = bodyNS.range(of: probe, options: .caseInsensitive)
            return r.location != NSNotFound ? lo + r.location : lo
        }
        func hasSensitive(_ t: String) -> Bool {
            let tl = t.lowercased()
            return swiftSensitiveDataNames.contains { tl.contains($0.lowercased()) }
        }

        // Persistent WebView Data Store: WKWebView + persistent WKWebsiteDataStore
        // leaves cookies / JS caches on disk across launches.
        if lower.contains("wkwebview") && lower.contains("wkwebsitedatastore")
            && !lower.contains("nonpersistent") {
            findings.append(finding(def: def, offset: offset(of: "WKWebsiteDataStore"),
                                    category: "Persistent WebView Data Store",
                                    severity: .low, reachable: reachable,
                                    message: "WKWebView backed by the persistent WKWebsiteDataStore keeps cookies and caches on disk across launches.",
                                    taint: nil))
        }

        // Insecure File Protection: writes with no data-protection class.
        if lower.contains("fileprotectiontype.none") || lower.contains(".nofileprotection") {
            findings.append(finding(def: def, offset: offset(of: "FileProtectionType"),
                                    category: "Insecure File Protection",
                                    severity: .medium, reachable: reachable,
                                    message: "File written without data protection (FileProtectionType.none) is readable before first unlock.",
                                    taint: nil))
        }

        // Weak Biometric Policy.
        if lower.contains("ksecaccesscontrolbiometryany") || lower.contains("devicepasscode") {
            findings.append(finding(def: def, offset: offset(of: "BiometryAny"),
                                    category: "Weak Biometric Policy",
                                    severity: .medium, reachable: reachable,
                                    message: "Biometric policy accepts any-enrolled biometrics or a passcode fallback, weakening the presence check.",
                                    taint: nil))
        }

        // Sensitive Location Usage.
        if lower.contains("cllocation")
            && (lower.contains("startupdatinglocation") || lower.contains("startmonitoring")) {
            findings.append(finding(def: def, offset: offset(of: "CLLocation"),
                                    category: "Sensitive Location Usage",
                                    severity: .medium, reachable: reachable,
                                    message: "Continuous location tracking without a clear purpose or retention policy.",
                                    taint: nil))
        }

        // Privacy Data Access: contacts / health data read then sent or logged.
        if (lower.contains("cncontact") || lower.contains("abaddressbook") || lower.contains("hkhealthstore"))
            && (lower.contains("urlsession") || lower.contains("http") || lower.contains("print") || lower.contains("os_log")) {
            findings.append(finding(def: def, offset: offset(of: "CNContact:"),
                                    category: "Privacy Data Access",
                                    severity: .medium, reachable: reachable,
                                    message: "Sensitive user data (contacts / health) is accessed and then transmitted or logged.",
                                    taint: nil))
        }

        // Sensitive Data in Crash Reports. Token-based so panics mentioned only
        // in comments (the tokenizer drops comments) and English words that merely
        // *contain* a sensitive name ("shipping" vs `pin`, "password" in docs)
        // don't fire: only a real identifier whose name is a sensitive label counts.
        if (bodyHasIdentifier(body, "fatalError") || bodyHasIdentifier(body, "preconditionFailure")) && bodyHasSensitiveToken(in: body) {
            findings.append(finding(def: def, offset: offset(of: "fatalError"),
                                    category: "Sensitive Data in Crash Reports",
                                    severity: .low, reachable: reachable,
                                    message: "Panic / precondition path may embed sensitive values in the crash report.",
                                    taint: nil))
        }

        // Insecure Cookie Storage: only when the body actually WRITES cookies
        // (`setCookies`); merely reading them (`cookies(for:)`) is not a sink.
        if lower.contains("httpcookiestorage") && (lower.contains("setcookies") || lower.contains("setcookie"))
            && hasSensitive(bodyNS as String) {
            findings.append(finding(def: def, offset: offset(of: "HTTPCookieStorage"),
                                    category: "Insecure Cookie Storage",
                                    severity: .medium, reachable: reachable,
                                    message: "Session / sensitive cookies set into HTTPCookieStorage without scoping or encryption.",
                                    taint: nil))
        }

        // Insecure TLS Validation.
        if lower.contains("kcfstreamsslallowsanyroot")
            || lower.contains("nsstreamsocketsecuritylevelnone")
            || lower.contains("allowsanyhttpsscertificatehosts") {
            findings.append(finding(def: def, offset: offset(of: "kCFStreamSSLAllowsAnyRoot"),
                                    category: "Insecure TLS Validation",
                                    severity: .high, reachable: reachable,
                                    message: "TLS certificate validation disabled or configured to trust any root.",
                                    taint: nil))
        }
    }

    private func walkAll(_ stmts: [SwiftStmt], ctx: WalkContext, def: SwiftDef,
                         into findings: inout [SwiftFinding]) {
        let current = ctx
        for s in stmts {
            walkStatement(s, ctx: current, def: def, into: &findings)
        }
    }

    private func walkStatement(_ stmt: SwiftStmt, ctx: WalkContext, def: SwiftDef,
                               into findings: inout [SwiftFinding]) {
        switch stmt {
        case .block(let inner, _):
            walkAll(inner, ctx: ctx, def: def, into: &findings)

        case .varDecl(let decls, _):
            for d in decls {
                guard let e = d.initExpr else { continue }
                let val = evalExpr(e, ctx: ctx, def: def, into: &findings)
                ctx.vars[d.name] = val
            }

        case .exprStmt(let e, _):
            _ = evalExpr(e, ctx: ctx, def: def, into: &findings)

        case .ifStmt(let cond, let thenBody, let elseBody, _):
            _ = evalExpr(cond, ctx: ctx, def: def, into: &findings)
            let thenCtx = ctx.child()
            refineGuards(cond: cond, ctx: thenCtx)
            walkAll(thenBody, ctx: thenCtx, def: def, into: &findings)
            if let eb = elseBody {
                walkAll(eb, ctx: ctx.child(), def: def, into: &findings)
            }
            // `guard`-style early exit (`if (i >= n) return`) guards the
            // statements that follow.
            if thenBody.contains(where: exits) {
                applyPositiveGuards(cond: cond, ctx: ctx)
            }

        case .guardStmt(cond: let cond, body: let body, _):
            _ = evalExpr(cond, ctx: ctx, def: def, into: &findings)
            // The body runs only when the condition fails.
            let bodyCtx = ctx.child()
            walkAll(body, ctx: bodyCtx, def: def, into: &findings)
            // Past the guard the condition holds.
            applyPositiveGuards(cond: cond, ctx: ctx)

        case .forStmt(loopVar: let lv, iterable: let iterable, body: let body, let o):
            if let it = iterable { _ = evalExpr(it, ctx: ctx, def: def, into: &findings) }
            let bodyCtx = ctx.child()
            var loopBaseName: String? = nil
            var inclusive = false
            if case .range(let bound, _, let rhs, _)? = iterable {
                inclusive = (bound == "...")
                loopBaseName = countBaseName(of: rhs)
            }
            if let lname = lv {
                bodyCtx.loopVar = lname
                bodyCtx.loopInclusive = inclusive
                if let b = loopBaseName { bodyCtx.loopBase = b }
            }
            // Walk 3: mutation of the iterated array while iterating it.
            if let it = iterable, case .ident(let arrName, _) = it, !arrName.isEmpty {
                if bodyContainsMutation(of: arrName, body: body, tokens: tokens, def: def) {
                    findings.append(finding(def: def, offset: o,
                                            category: "Array Mutation During Iteration",
                                            severity: .medium, reachable: isReachable(def),
                                            message: "Array '\(arrName)' is mutated while being iterated; Swift traps if the index shifts.",
                                            taint: nil))
                }
            }
            walkAll(body, ctx: bodyCtx, def: def, into: &findings)

        case .whileStmt(cond: let cond, body: let body, _):
            _ = evalExpr(cond, ctx: ctx, def: def, into: &findings)
            walkAll(body, ctx: ctx.child(), def: def, into: &findings)

        case .switchStmt(expr: let e, cases: let cases, _):
            _ = evalExpr(e, ctx: ctx, def: def, into: &findings)
            for c in cases {
                walkAll(c.body, ctx: ctx.child(), def: def, into: &findings)
            }

        case .returnStmt(let e, _):
            if let e = e { _ = evalExpr(e, ctx: ctx, def: def, into: &findings) }

        case .throwStmt(let e, _):
            if let e = e { _ = evalExpr(e, ctx: ctx, def: def, into: &findings) }

        case .repeatStmt(body: let body, cond: _, _):
            walkAll(body, ctx: ctx.child(), def: def, into: &findings)

        case .deferStmt(let body, _):
            walkAll(body, ctx: ctx.child(), def: def, into: &findings)
        }
    }

    private var exits: (SwiftStmt) -> Bool {
        { s in
            if case .returnStmt = s { return true }
            if case .throwStmt = s { return true }
            return false
        }
    }

    // MARK: - Walk 1: value-based taint evaluation (+ sink rules)

    private func evalExpr(_ e: SwiftExpr, ctx: WalkContext, def: SwiftDef,
                          into findings: inout [SwiftFinding]) -> TaintVal {
        switch e {
        case .ident(let n, _):
            if let v = ctx.vars[n] { return v }
            if swiftSourceAPIs.contains(n) { return .tainted(n) }
            return .clean

        case .literal:
            return .clean

        case .member(let base, let name, _):
            let baseVal = evalExpr(base, ctx: ctx, def: def, into: &findings)
            let dotted = base.dottedName.isEmpty ? name : "\(base.dottedName).\(name)"
            if swiftSourceAPIs.contains(dotted) { return .tainted(dotted) }
            // NOTE: a bare receiving member name (e.g. `.data` on a String) is
            // deliberately NOT a taint source of its own — only the full dotted
            // source API (`URLSession.data`, `UserDefaults.standard.data`) is.
            return baseVal

        case .index(let base, let idx, _):
            let baseVal = evalExpr(base, ctx: ctx, def: def, into: &findings)
            let idxVal = evalExpr(idx, ctx: ctx, def: def, into: &findings)
            applyBoundsRules(base: base, index: idx, idxVal: idxVal,
                             offset: e.offset, ctx: ctx, def: def, into: &findings)
            return baseVal.union(idxVal)

        case .call(callee: let callee, args: let args, let offset):
            return evalCall(callee: callee, args: args, offset: offset,
                            ctx: ctx, def: def, into: &findings, isNew: false)

        case .newExpr(typeName: let tn, args: let args, let offset):
            return evalNew(typeName: tn, args: args, offset: offset,
                           ctx: ctx, def: def, into: &findings)

        case .unary(_, let operand, _):
            return evalExpr(operand, ctx: ctx, def: def, into: &findings)

        case .binary(let op, let l, let r, let offset):
            let lv = evalExpr(l, ctx: ctx, def: def, into: &findings)
            let rv = evalExpr(r, ctx: ctx, def: def, into: &findings)
            // Walk 3: division / modulo without a zero guard.
            if op == "/" || op == "%" {
                if isZeroRisky(r, ctx: ctx) {
                    findings.append(finding(def: def, offset: offset,
                                            category: "Possible Division by Zero",
                                            severity: .medium, reachable: isReachable(def),
                                            message: "Division by '\(r.dottedName.isEmpty ? "unchecked expression" : r.dottedName)' without a zero check crashes (or yields NaN/Inf on floats).",
                                            taint: rv.tainted ? taintPath(rv) : nil))
                }
            }
            // Walk 3: Swift overflow operators (&+, &-, &*, &%).
            if ["&+", "&-", "&*", "&/", "&%", "&<<", "&>>"].contains(op) {
                findings.append(finding(def: def, offset: offset,
                                        category: "Integer Overflow",
                                        severity: .medium, reachable: isReachable(def),
                                        message: "Overflow operator '\(op)' silently wraps integer arithmetic; values can wrap and defeat validation.",
                                        taint: nil))
            }
            return lv.union(rv)

        case .assign(let op, let lhs, let rhs, let offset):
            let rhsVal = evalExpr(rhs, ctx: ctx, def: def, into: &findings)
            var val = rhsVal
            if op != "=", case .ident(let n, _) = lhs, let prev = ctx.vars[n] {
                val = prev.union(rhsVal)
            }
            if case .ident(let n, _) = lhs {
                ctx.vars[n] = val
            }
            applyAssignmentRules(target: lhs, value: rhs, valueTaint: rhsVal,
                                 offset: offset, ctx: ctx, def: def, into: &findings)
            return val

        case .ternary(let c, let t, let f, _):
            // The condition is evaluated for its side-effect sinks but its
            // taint is not part of the result: `busy ? A : B` is either A or B,
            // never a poisoned value just because the predicate was tainted.
            _ = evalExpr(c, ctx: ctx, def: def, into: &findings)
            let tv = evalExpr(t, ctx: ctx, def: def, into: &findings)
            let fv = evalExpr(f, ctx: ctx, def: def, into: &findings)
            return tv.union(fv)

        case .arrayLit(let elems, _):
            return unionAll(elems.map { evalExpr($0, ctx: ctx, def: def, into: &findings) })

        case .dictLit(let pairs, _):
            var val = TaintVal.clean
            for (k, v) in pairs {
                val = val.union(evalExpr(k, ctx: ctx, def: def, into: &findings))
                val = val.union(evalExpr(v, ctx: ctx, def: def, into: &findings))
            }
            return val

        case .paren(let x, _):
            return evalExpr(x, ctx: ctx, def: def, into: &findings)

        case .closure(params: let params, body: let body, _):
            let closureCtx = ctx.child()
            for p in params where ctx.callbackTaintedParams.contains(p) {
                closureCtx.vars[p] = .tainted("callback \(p)")
            }
            walkAll(body, ctx: closureCtx, def: def, into: &findings)
            return .clean

        case .forceUnwrap(let x, let offset):
            let val = evalExpr(x, ctx: ctx, def: def, into: &findings)
            // Walk 3: force-unwrapping a subscript/member access or a tainted
            // optional traps when nil. Subscript access is reported regardless
            // (the base is countable but unchecked); member/call unwraps only
            // report when the value is tainted, and benign data-conversion
            // accessors (`.data(using:)`, `.utf8`…) are exempt because their
            // optional covers degenerate encodings rather than absent data.
            let exemptLeaf: (String) -> Bool = { swiftForceUnwrapSafeLeaves.contains($0) }
            switch x {
            case .index(let base, _, _):
                findings.append(finding(def: def, offset: offset,
                                        category: "Unsafe Force Unwrap",
                                        severity: .medium, reachable: isReachable(def),
                                        message: "Force-unwrapped '\(base.dottedName.isEmpty ? "subscript" : base.dottedName)[…]' traps when the index is out of range; prefer guarded unwrap.",
                                        taint: val.tainted ? taintPath(val) : nil))
            case .member(_, let name, _):
                if val.tainted && !exemptLeaf(name) {
                    findings.append(finding(def: def, offset: offset,
                                            category: "Unsafe Force Unwrap",
                                            severity: .medium, reachable: isReachable(def),
                                            message: "Force-unwrapped '\(x.dottedName.isEmpty ? "expression" : x.dottedName)' traps when nil; prefer guarded unwrap.",
                                            taint: taintPath(val)))
                }
            case .call(callee: let c, _, _):
                if val.tainted && !exemptLeaf(c.leafName) {
                    findings.append(finding(def: def, offset: offset,
                                            category: "Unsafe Force Unwrap",
                                            severity: .medium, reachable: isReachable(def),
                                            message: "Force-unwrapped '\(x.dottedName.isEmpty ? "expression" : x.dottedName)' traps when nil; prefer guarded unwrap.",
                                            taint: taintPath(val)))
                }
            default:
                if val.tainted {
                    findings.append(finding(def: def, offset: offset,
                                            category: "Unsafe Force Unwrap",
                                            severity: .medium, reachable: isReachable(def),
                                            message: "Force-unwrapped tainted optional traps when nil.",
                                            taint: taintPath(val)))
                }
            }
            return val

        case .optional(let x, _):
            return evalExpr(x, ctx: ctx, def: def, into: &findings)

        case .interpolation(exprs: let exprs, _):
            return unionAll(exprs.map { evalExpr($0, ctx: ctx, def: def, into: &findings) })

        case .range(_, let l, let r, _):
            let lv = evalExpr(l, ctx: ctx, def: def, into: &findings)
            let rv = evalExpr(r, ctx: ctx, def: def, into: &findings)
            return lv.union(rv)

        case .cast(let op, let operand, let offset):
            let val = evalExpr(operand, ctx: ctx, def: def, into: &findings)
            if op == "as!" {
                findings.append(finding(def: def, offset: offset,
                                        category: "Unsafe Type Cast",
                                        severity: .low, reachable: isReachable(def),
                                        message: "Forced cast 'as!' traps on failure; use optional 'as?' when the type is untrusted.",
                                        taint: nil))
            }
            return val

        case .placeholder:
            return .clean
        }
    }

    // MARK: - Call sink rules + mobile rules

    private func evalCall(callee: SwiftExpr, args: [SwiftExpr], offset: Int,
                          ctx: WalkContext, def: SwiftDef,
                          into findings: inout [SwiftFinding], isNew: Bool) -> TaintVal {
        let name = callee.dottedName
        let leaf = callee.leafName
        let reachable = isReachable(def)

        // Bind callback parameters as tainted when the callee is a source or
        // write-through API (`URLSession.dataTask { data, response, error in }`).
        let isSourceish = swiftSourceAPIs.contains(name) || swiftSourceAPIs.contains(leaf)
            || swiftWriteThroughSinks.contains(leaf)
        if isSourceish {
            for a in args {
                if case .closure(params: let params, body: _, _) = a {
                    for p in params { ctx.callbackTaintedParams.insert(p) }
                }
            }
        }

        let calleeVal = evalExpr(callee, ctx: ctx, def: def, into: &findings)
        var argVals: [TaintVal] = []
        for a in args {
            argVals.append(evalExpr(a, ctx: ctx, def: def, into: &findings))
        }
        let argTainted = argVals.contains(where: { $0.tainted })
        let anySensitiveArg = args.contains { sensitiveName(for: $0) }
        let near = nearText(center: offset)
        let lowName = name.lowercased()

        // MARK: -- Walk 1 sink rules (generic)

        // Command Injection: shell process control.
        if leaf == "system" {
            if argTainted {
                findings.append(finding(def: def, offset: offset, category: "Command Injection",
                                        severity: .critical, reachable: reachable,
                                        message: "system() runs a shell; tainted input enables command injection.",
                                        taint: taintPath(argVals.first).map { "\($0) → system()" }))
            }
        } else if ["launchedProcess", "run", "launch", "start", "execute", "exec", "execve", "posix_spawn"].contains(leaf) {
            if argTainted && (lowName.contains("process") || lowName.contains("task") || lowName.contains("shell")) && !bodyHasCommandAllowlistGate(def) {
                findings.append(finding(def: def, offset: offset, category: "Command Injection",
                                        severity: .critical, reachable: reachable,
                                        message: "Tainted argument into an OS process / shell launcher.",
                                        taint: taintPath(argVals.first(where: { $0.tainted })).map { "\($0) → \(name)" }))
            }
        }

        // SQL Injection.
        if sqlFamily(leaf: leaf, name: lowName) && (argTainted || anySensitiveArg) {
            findings.append(finding(def: def, offset: offset, category: "SQL Injection",
                                    severity: .critical, reachable: reachable,
                                    message: "SQL statement built from untrusted input without parameterization.",
                                    taint: argTainted ? "\(taintPath(argVals.first(where: { $0.tainted })) ?? "?") → SQL" : nil))
        }

        // SSRF.
        let urlSessionLeafs: Set<String> = ["dataTask", "downloadTask", "uploadTask", "dataTaskPublisher"]
        if lowName.contains("urlsession") || lowName.contains("http") || urlSessionLeafs.contains(leaf) {
            let networkLeafs = urlSessionLeafs.union(["data", "get", "post", "put", "delete", "request", "fetch", "init"])
            if networkLeafs.contains(leaf) && argTainted {
                findings.append(finding(def: def, offset: offset, category: "SSRF",
                                        severity: .high, reachable: reachable,
                                        message: "Tainted URL in outbound request (\(name)).",
                                        taint: "\(taintPath(argVals.first(where: { $0.tainted })) ?? "?") → \(name)"))
            }
        }

        // Path Traversal (reads) / Arbitrary File Write / Deletion.
        if lowName.contains("filemanager") || lowName.contains("filehandle") {
            if ["contentsOfDirectory", "contentsAtPath", "contents", "dataWithContentsOfFile", "contentsOfFile", "subpathsOfDirectory", "enumerator", "dataWithContentsOfURL", "readFile", "open", "read"].contains(leaf) && argTainted {
                findings.append(finding(def: def, offset: offset, category: "Path Traversal",
                                        severity: .high, reachable: reachable,
                                        message: "Tainted file path in \(name) allows access outside the intended directory.",
                                        taint: "\(taintPath(argVals.first(where: { $0.tainted })) ?? "?") → \(name)"))
            }
            if ["writeToFile", "writeToURL", "createFile", "createDirectory", "copyItem", "moveItem"].contains(leaf) && argTainted && !anySensitiveArg {
                findings.append(finding(def: def, offset: offset, category: "Arbitrary File Write",
                                        severity: .high, reachable: reachable,
                                        message: "Tainted destination in \(name) writes outside the intended directory.",
                                        taint: "\(taintPath(argVals.first(where: { $0.tainted })) ?? "?") → \(name)"))
            }
            if leaf == "removeItem" && argTainted {
                findings.append(finding(def: def, offset: offset, category: "Arbitrary File Deletion",
                                        severity: .high, reachable: reachable,
                                        message: "Tainted path deleted via \(name); an attacker may remove arbitrary files.",
                                        taint: "\(taintPath(argVals.first(where: { $0.tainted })) ?? "?") → \(name)"))
            }
        }

        // Unsafe Deserialization.
        if lowName.contains("unarchive") || lowName.contains("unarchiver") || lowName == "decodeTopLevelObject" || leaf == "unarchiveObject" || leaf == "unarchiveObjectWithData" {
            if argTainted {
                findings.append(finding(def: def, offset: offset, category: "Unsafe Deserialization",
                                        severity: .critical, reachable: reachable,
                                        message: "Deserializing untrusted NSKeyedArchiver data can execute Objective-C initializers.",
                                        taint: taintPath(argVals.first(where: { $0.tainted })).map { "\($0) → \(leaf)" }))
            }
        }

        // Weak Cryptography.
        if weakCrypto(leaf: leaf, name: lowName) {
            findings.append(finding(def: def, offset: offset, category: "Weak Cryptography",
                                    severity: .high, reachable: reachable,
                                    message: "Weak/deprecated cryptographic primitive '\(name)' (MD5/SHA1/DES/RC4).",
                                    taint: argTainted ? taintPath(argVals.first(where: { $0.tainted })) : nil))
        }

        // Insecure Random.
        if ["arc4random", "arc4random_uniform", "drand48", "randomNumber", "rand", "srand"].contains(leaf) || lowName.contains("arc4random") {
            findings.append(finding(def: def, offset: offset, category: "Insecure Random",
                                    severity: .low, reachable: reachable,
                                    message: "'\(leaf)' is not cryptographically secure; use SecRandomCopyBytes / CryptoKit.",
                                    taint: nil))
        }

        // WebView XSS / Dynamic Code Execution.
        if leaf == "evaluateJavaScript" || leaf == "evaluateScript" || leaf == "executeJavaScript" {
            // Only attacker-influenced scripts are reported. `evaluateJavaScript`
            // with a compile-time constant or a typed bridge payload (the
            // message-bridge idiom) is not externally exploitable, so it stays
            // silent rather than firing a blanket "Dynamic Code Execution".
            if argTainted {
                findings.append(finding(def: def, offset: offset, category: "WebView XSS",
                                        severity: .high, reachable: reachable,
                                        message: "Tainted string evaluated in a WebView (\(leaf)) — XSS / script injection.",
                                        taint: "\(taintPath(argVals.first(where: { $0.tainted })) ?? "?") → \(leaf)"))
            }
        }
        if leaf == "performSelector" || lowName.contains("nsexpression") && leaf == "init" {
            findings.append(finding(def: def, offset: offset, category: "Dynamic Code Execution",
                                    severity: .high, reachable: reachable,
                                    message: "Dynamic selector/expression evaluation can lead to arbitrary method invocation.",
                                    taint: argTainted ? taintPath(argVals.first(where: { $0.tainted })) : nil))
        }

        // Open Redirect.
        if (leaf == "open" || leaf == "openURL" || leaf == "canOpenURL") && (lowName.contains("uiapplication") || lowName.contains("openurl") || lowName.contains("lsapplication")) && argTainted {
            findings.append(finding(def: def, offset: offset, category: "Open Redirect",
                                    severity: .high, reachable: reachable,
                                    message: "Tainted URL opened by an external app.",
                                    taint: "\(taintPath(argVals.first(where: { $0.tainted })) ?? "?") → \(name)"))
        }

        // Zip Slip.
        if (lowName.contains("unzip") || lowName.contains("archive")) && ["extract", "unzip", "writeFile", "write", "extractFiles"].contains(leaf) && argTainted {
            findings.append(finding(def: def, offset: offset, category: "Zip Slip",
                                    severity: .high, reachable: reachable,
                                    message: "Archive entry paths are written unvalidated; '../' entries escape the extraction root.",
                                    taint: taintPath(argVals.first(where: { $0.tainted })).map { "\($0) → \(leaf)" }))
        }

        // HTTP Header Injection.
        if (leaf == "setValue" || leaf == "set") && lowName.contains("http") && near.contains("forHTTPHeaderField") && argTainted {
            findings.append(finding(def: def, offset: offset, category: "HTTP Header Injection",
                                    severity: .medium, reachable: reachable,
                                    message: "Tainted value assigned to an HTTP header can inject CRLF headers.",
                                    taint: taintPath(argVals.first(where: { $0.tainted })).map { "\($0) → header" }))
        }

        // Weak File Permissions.
        if leaf == "createFile" {
            let permText = nearText(center: offset, before: 120, after: 480)
            if permText.contains("0o777") || permText.contains("0x1ff") || permText.contains("438") {
                findings.append(finding(def: def, offset: offset, category: "Weak File Permissions",
                                        severity: .medium, reachable: reachable,
                                        message: "File created with world-writable permissions (0o777).",
                                        taint: nil))
            } else if permText.contains("0o666") {
                findings.append(finding(def: def, offset: offset, category: "Weak File Permissions",
                                        severity: .low, reachable: reachable,
                                        message: "File created with world-writable permissions (0o666).",
                                        taint: nil))
            }
        }

        // Timing Attack (non-constant-time comparison of secrets).
        if ["isEqual", "isEqualToString", "compare", "localizedStandardCompare", "localizedCaseInsensitiveCompare", "hasPrefix", "hasSuffix"].contains(leaf) && anySensitiveArg {
            findings.append(finding(def: def, offset: offset, category: "Timing Attack",
                                    severity: .medium, reachable: reachable,
                                    message: "Secret compared with non-constant-time '\(leaf)'; an attacker can time side-channels.",
                                    taint: nil))
        }

        // Log Injection.
        if ["print", "debugPrint", "NSLog", "os_log"].contains(leaf) && argTainted {
            findings.append(finding(def: def, offset: offset, category: "Log Injection",
                                    severity: .low, reachable: reachable,
                                    message: "Tainted value written to a log can forge entries or crash parsers.",
                                    taint: taintPath(argVals.first(where: { $0.tainted })).map { "\($0) → \(leaf)" }))
        }

        // MARK: -- Mobile rules

        // Insecure Local Storage / App Group Storage via UserDefaults.set.
        if leaf == "set" || leaf == "setValue" || leaf == "setObject" {
            let isUserDefaults = lowName.contains("userdefaults") || near.contains("UserDefaults")
            if isUserDefaults, anySensitiveArg || argTainted {
                let suite = near.contains("suiteName")
                findings.append(finding(def: def, offset: offset,
                                        category: suite ? "Insecure App Group Storage" : "Insecure Local Storage",
                                        severity: .high, reachable: reachable,
                                        message: suite ? "Sensitive data stored in an App Group UserDefaults volume readable by every app in the group."
                                                       : "Sensitive data persisted via UserDefaults without encryption.",
                                        taint: taintPath(argVals.first(where: { $0.tainted }))))
            }
            if lowName.contains("keychain") || leaf == "SecItemAdd" {
                // window into keychain handled below.
            }
        }

        // Insecure Keychain Accessibility.
        if ["SecItemAdd", "SecItemUpdate", "SecItemCopyMatching", "SecItemDelete"].contains(leaf) || lowName.contains("seckeychain") {
            let kcNear = nearText(center: offset, before: 700, after: 140)
            if kcNear.contains("kSecAttrAccessibleAlways") || kcNear.contains("kSecAttrAccessibleAlwaysThisDeviceOnly") {
                findings.append(finding(def: def, offset: offset, category: "Insecure Keychain Accessibility",
                                        severity: .high, reachable: reachable,
                                        message: "Keychain items marked kSecAttrAccessibleAlways are readable when the device is locked.",
                                        taint: nil))
            }
        }

        // WebView JavaScript Bridge (message handler registration).
        if leaf == "add" && (lowName.contains("usercontentcontroller") || near.contains("WKScriptMessageHandler")) {
            findings.append(finding(def: def, offset: offset, category: "WebView JavaScript Bridge",
                                    severity: .high, reachable: reachable,
                                    message: "WKScriptMessageHandler bridge exposes app methods to page JavaScript with no origin allowlist.",
                                    taint: nil))
        }

        // WebView Loads Remote Content (http traffic in WebView).
        if ["load", "loadHTMLString", "loadHTMLData", "loadRequest"].contains(leaf),
           (lowName.contains("webview") || lowName.contains("web") || near.contains("WKWebView") || near.contains("UIWebView")) {
            let argText = args.map { sourceText(from: $0) }.joined()
            if argText.contains("http://") || near.contains("http://") {
                findings.append(finding(def: def, offset: offset, category: "WebView Loads Remote Content",
                                        severity: .medium, reachable: reachable,
                                        message: "WebView loads remote/plain-HTTP content; verify TLS and content trust.",
                                        taint: argTainted ? taintPath(argVals.first(where: { $0.tainted })) : nil))
            }
        }

        // Sensitive Data in Clipboard.
        if lowName.contains("pasteboard") && ["setString", "setValue", "setData", "setObjects", "setPropertyList", "set"].contains(leaf) {
            if anySensitiveArg || argTainted {
                findings.append(finding(def: def, offset: offset, category: "Sensitive Data in Clipboard",
                                        severity: .high, reachable: reachable,
                                        message: "Sensitive data written to the system pasteboard readable by any app.",
                                        taint: taintPath(argVals.first(where: { $0.tainted }))))
            }
        }

        // Certificate Pinning Bypass.
        if ["performDefaultHandling", "useCredential", "continueWithoutCredential", "rejectProtectionSpaceAndContinueWithPrerequisitesOnly"].contains(leaf)
            && (lowName.contains("sender") || lowName.contains("challenge") || lowName.contains("trust")) {
            findings.append(finding(def: def, offset: offset, category: "Certificate Pinning Bypass",
                                    severity: .high, reachable: reachable,
                                    message: "\(leaf) in a serverTrust challenge skips pin validation.",
                                    taint: nil))
        }

        // Sensitive Data in Logs.
        if ["print", "debugPrint", "NSLog", "os_log", "fputs"].contains(leaf) && anySensitiveArg {
            findings.append(finding(def: def, offset: offset, category: "Sensitive Data in Logs",
                                    severity: .medium, reachable: reachable,
                                    message: "Sensitive named data (password/token/secret) written to a log.",
                                    taint: nil))
        }

        // Insecure Inter-App Communication via extension context.
        if lowName.contains("extensioncontext") || lowName == "NSExtensionContext" || leaf == "loadItem" {
            if argTainted {
                findings.append(finding(def: def, offset: offset, category: "Insecure Inter-App Communication",
                                        severity: .medium, reachable: reachable,
                                        message: "Untrusted data from another app (extension context) drives sensitive logic.",
                                        taint: taintPath(argVals.first(where: { $0.tainted }))))
            }
        }

        // Unvalidated Notification Data.
        if lowName.contains("notificationcenter") && (leaf.hasPrefix("post") || leaf == "post") {
            if anySensitiveArg || argTainted {
                findings.append(finding(def: def, offset: offset, category: "Unvalidated Notification Data",
                                        severity: .medium, reachable: reachable,
                                        message: "Untrusted userInfo posted through NotificationCenter; observers can be tricked.",
                                        taint: argTainted ? taintPath(argVals.first(where: { $0.tainted })) : nil))
            }
        }

        // Unsolicited Message Send (SMS/iMessage/Mail).
        if lowName.contains("mfmessagecompose") || lowName.contains("mfmailcompose") {
            if argTainted {
                findings.append(finding(def: def, offset: offset, category: "Unsolicited Message Send",
                                        severity: .medium, reachable: reachable,
                                        message: "Message body/content composed from untrusted data may send attacker content.",
                                        taint: taintPath(argVals.first(where: { $0.tainted }))))
            }
        }

        // Notification Injection.
        if lowName.contains("unmutablenotificationcontent") && argTainted {
            findings.append(finding(def: def, offset: offset, category: "Notification Injection",
                                    severity: .medium, reachable: reachable,
                                    message: "Local notification body built from untrusted data can phish the user.",
                                    taint: taintPath(argVals.first(where: { $0.tainted }))))
        }

        // Sensitive Data in URL. Base64/encode/decode URL helpers
        // (`encodeBase64URL`, `base64EncodedString`) are character-set
        // transformations, not URL construction; the rule targets embedding a
        // secret into an actual URL (query/fragment).
        if lowName.contains("url") || lowName.contains("urlcomponents") {
            let isEncodingBypass = lowName.contains("base64") || lowName.contains("encode") || lowName.contains("decode")
            if !isEncodingBypass {
                let urlSensitive = args.contains { arg in
                    if anyInterpolatedSensitive(arg) { return true }
                    return sensitiveName(for: arg)
                }
                if urlSensitive {
                    findings.append(finding(def: def, offset: offset, category: "Sensitive Data in URL",
                                            severity: .medium, reachable: reachable,
                                            message: "Sensitive data embedded in a URL (query/fragment); it leaks to logs, caches and referrers.",
                                            taint: nil))
                }
            }
        }

        // Unsafe Pointer usage. The standard keychain idiom
        // `withUnsafeMutablePointer` / `UnsafeMutablePointer($0)` is exempt;
        // only risky memory-aliasing / bit-cast APIs are reported.
        if leaf == "unsafeBitCast" || leaf == "bindMemory" || leaf == "assumingMemoryBound" || lowName == "unsafebitcast" {
            findings.append(finding(def: def, offset: offset, category: "Unsafe Pointer",
                                    severity: .low, reachable: reachable,
                                    message: "Unsafe memory-aliasing / bit-cast API '\(name)' bypasses bounds/type checks.",
                                    taint: nil))
        }

        // ---- Call taint value ----
        if swiftSanitizers.contains(name) || swiftSanitizers.contains(leaf) || swiftSanitizers.contains("sanitize") {
            return .clean
        }
        // Local path-sanitizer guards (`guard PathGuard.isContained(...)` inside a
        // helper that resolves/validates a candidate path) make the result clean:
        // the caller's tainted input was contained-checked before being returned.
        if localDefNamed(leaf).map({ isPathSanitizer($0) }) == true {
            return .clean
        }
        if taintReturning.contains(leaf) {
            return .tainted(leaf, crossFile: crossFileSources.contains(leaf))
        }
        if case .member(_, let prop, _) = callee, swiftTaintPropagators.contains(prop) {
            if calleeVal.tainted { return calleeVal }
        }
        return unionAll(argVals).union(calleeVal)
    }

    /// Constructor-call rules: `Type(...)`. Several mobile/generic sinks are
    /// Type constructions (WebView, expression parsers, message composer…).
    private func evalNew(typeName: String, args: [SwiftExpr], offset: Int,
                         ctx: WalkContext, def: SwiftDef,
                         into findings: inout [SwiftFinding]) -> TaintVal {
        var argVals: [TaintVal] = []
        for a in args { argVals.append(evalExpr(a, ctx: ctx, def: def, into: &findings)) }
        let argTainted = argVals.contains(where: { $0.tainted })
        let reachable = isReachable(def)
        let near = nearText(center: offset)
        let low = typeName.lowercased()

        // File reads: `Data(contentsOf:)` / `String(contentsOf:)`.
        // The old check used nearText which can span a 280-char window and match
        // `contentsOf` from a completely unrelated later call in the same file.
        // We now restrict to this constructor's own argument slice.
        if ["data", "string", "nsdata", "nsstring"].contains(low) && argTainted && callArgumentSlice(from: offset).contains("contentsOf") {
            findings.append(finding(def: def, offset: offset, category: "Path Traversal",
                                    severity: .high, reachable: reachable,
                                    message: "File contents read from a tainted path (\(typeName)).",
                                    taint: "\(taintPath(argVals.first(where: { $0.tainted })) ?? "?") → \(typeName)"))
        }

        // ReDoS via user-controlled regular expression.
        if (low == "nsregularexpression" || low.contains("regex")) && argTainted {
            findings.append(finding(def: def, offset: offset, category: "ReDoS Pattern",
                                    severity: .medium, reachable: reachable,
                                    message: "Regular expression compiled from untrusted input can cause ReDoS.",
                                    taint: taintPath(argVals.first(where: { $0.tainted }))))
        }

        // NSExpression evaluates arbitrary expressions.
        if low == "nsexpression" && argTainted {
            findings.append(finding(def: def, offset: offset, category: "Dynamic Code Execution",
                                    severity: .critical, reachable: reachable,
                                    message: "NSExpression evaluates untrusted predicate/expression strings.",
                                    taint: taintPath(argVals.first(where: { $0.tainted }))))
        }

// Format String via String(format:).
        if low == "string" && argTainted && near.contains("format:") {
            findings.append(finding(def: def, offset: offset, category: "Format String",
                                    severity: .medium, reachable: reachable,
                                    message: "String(format:) with untrusted format string; % directives can misparse.",
                                    taint: taintPath(argVals.first(where: { $0.tainted }))))
        }

        // Deprecated insecure WebView.
        if low.contains("uiwebview") {
            findings.append(finding(def: def, offset: offset, category: "Deprecated Insecure WebView",
                                    severity: .medium, reachable: reachable,
                                    message: "UIWebView is deprecated and historically vulnerable; use WKWebView.",
                                    taint: nil))
        }

        // Unsafe pointers constructed directly. The keychain sample builds
        // `UnsafeMutablePointer($0)` for SecItemCopyMatching — benign idiom;
        // only genuinely raw/unowned constructions are worth reporting.
        if low.contains("uncopiedmemory") || low.contains("unsaferawbufferpointer") {
            findings.append(finding(def: def, offset: offset, category: "Unsafe Pointer",
                                    severity: .low, reachable: reachable,
                                    message: "Unsafe pointer type \(typeName) bypasses bounds/type checks.",
                                    taint: nil))
        }

        // Unsolicited message compose.
        if low.contains("mfmessagecompose") || low.contains("mfmailcompose") {
            if argTainted {
                findings.append(finding(def: def, offset: offset, category: "Unsolicited Message Send",
                                        severity: .medium, reachable: reachable,
                                        message: "Message composed from untrusted data.",
                                        taint: taintPath(argVals.first(where: { $0.tainted }))))
            }
        }

        // Notification content.
        if low.contains("unmutablenotificationcontent") && argTainted {
            findings.append(finding(def: def, offset: offset, category: "Notification Injection",
                                    severity: .medium, reachable: reachable,
                                    message: "Notification content from untrusted data.",
                                    taint: taintPath(argVals.first(where: { $0.tainted }))))
        }

        // Capitalized bare calls are often C-style function APIs (SecItemAdd,
        // CFRelease, SSL_* …) rather than type constructors. Run the generic
        // call sink rules for them so Command/SQL/Keychain/etc. detection applies.
        _ = evalCall(callee: .ident(typeName, offset), args: args, offset: offset,
                     ctx: ctx, def: def, into: &findings, isNew: true)

        return unionAll(argVals)
    }

    // MARK: - Assignment / member-write rules

    private func applyAssignmentRules(target: SwiftExpr, value: SwiftExpr, valueTaint: TaintVal,
                                      offset: Int, ctx: WalkContext, def: SwiftDef,
                                      into findings: inout [SwiftFinding]) {
        let reachable = isReachable(def)
        guard case .member(_, let tail, _) = target else { return }
        let targetText = assignmentTargetText(target)
        let lowTarget = targetText.lowercased()
        let near = nearText(center: offset)

        // Command injection via Process configuration.
        if ["launchPath", "executableURL", "arguments"].contains(tail),
           (lowTarget.contains("process") || lowTarget.contains("task") || near.lowercased().contains("process")) {
            if valueTaint.tainted {
                if bodyHasCommandAllowlistGate(def) { return }
                findings.append(finding(def: def, offset: value.offset, category: "Command Injection",
                                        severity: .critical, reachable: reachable,
                                        message: "Tainted value assigned to \(targetText) — attacker controlled process invocation.",
                                        taint: "\(taintPath(valueTaint) ?? "?") → \(targetText)"))
            }
        }

        // XML External Entity resolution.
        if tail == "shouldResolveExternalEntities" || tail == "shouldProcessExternalEntities" {
            if valueIsTrueLiteral(value) {
                findings.append(finding(def: def, offset: value.offset, category: "XML External Entity",
                                        severity: .high, reachable: reachable,
                                        message: "\(targetText) = true lets the XML parser resolve external entities (XXE).",
                                        taint: nil))
            }
        }

        // WebView configuration.
        if tail == "allowUniversalAccessFromFileURLs" || tail == "allowFileAccessFromFileURLs" {
            if valueIsTrueLiteral(value) {
                findings.append(finding(def: def, offset: value.offset, category: "WebView Universal File Access",
                                        severity: .high, reachable: reachable,
                                        message: "\(targetText) allows a WebView to read arbitrary local files.",
                                        taint: nil))
            }
        }
        if tail == "allowsArbitraryLoads" {
            if valueIsTrueLiteral(value) {
                findings.append(finding(def: def, offset: value.offset, category: "App Transport Security Bypass",
                                        severity: .high, reachable: reachable,
                                        message: "WebView ATS disabled: all loads permitted, incl. plain HTTP.",
                                        taint: nil))
            }
        }

        // Weak File Permissions via attributes.
        if tail == "posixPermissions" {
            if case .literal(let t, _) = value {
                let v = t.lowercased()
                if v.contains("0o777") || v == "511" || v.contains("0x1ff") {
                    findings.append(finding(def: def, offset: value.offset, category: "Weak File Permissions",
                                            severity: .medium, reachable: reachable,
                                            message: "File permissions set to 0o777 — world writable.",
                                            taint: nil))
                }
            }
        }
    }

    // MARK: - Walk 2: bounds rules at index accesses

    /// Finds the base name of a `X.count` / `X.endIndex` member as the loop
    /// upper bound (range RHS: `0...arr.count`, `0..<arr.count - 1`).
    private func countBaseName(of e: SwiftExpr) -> String? {
        switch e {
        case .member(let b, let m, _):
            if m == "count" || m == "endIndex" || m == "length" {
                let n = b.dottedName
                return n.isEmpty ? nil : n
            }
            return nil
        case .binary(_, let l, _, _):
            return countBaseName(of: l)
        case .paren(let x, _):
            return countBaseName(of: x)
        default:
            return nil
        }
    }

    private func applyBoundsRules(base: SwiftExpr, index: SwiftExpr, idxVal: TaintVal,
                                  offset: Int, ctx: WalkContext, def: SwiftDef,
                                  into findings: inout [SwiftFinding]) {
        let reachable = isReachable(def)
        let baseName = base.dottedName
        guard !baseName.isEmpty else { return }

        // arr[arr.count] / arr[arr.endIndex] — always out of bounds.
        if case .member(let ib, let m, _) = index, (m == "count" || m == "endIndex" || m == "length"), ib.dottedName == baseName {
            findings.append(finding(def: def, offset: offset,
                                    category: "Array Index Out of Bounds",
                                    severity: .high, reachable: reachable,
                                    message: "'\(baseName)[\(baseName).\(m)]' is always out of bounds (valid indices end at count - 1).",
                                    taint: nil))
            return
        }

        guard case .ident(let idxName, _) = index else { return }

        // Loop correlation: `for i in 0...arr.count { arr[i] }`.
        if let lv = ctx.loopVar, idxName == lv,
           let lb = ctx.loopBase, lb == baseName {
            if ctx.loopInclusive {
                findings.append(finding(def: def, offset: offset,
                                        category: "Loop Off-by-One",
                                        severity: .high, reachable: reachable,
                                        message: "Range \(lv) in 0...\(lb).count visits index \(lb).count, which is past the end of the array.",
                                        taint: nil))
            }
            return // loop-bounded access is in range otherwise
        }

        // Tainted index without a bounds guard.
        if idxVal.tainted, !ctx.boundsGuards.contains("\(idxName)\u{1}\(baseName)") {
            // Keyed dictionary lookups (`dict[key]`) are projection lookups, not
            // positional index arithmetic: every key is in-bounds by construction.
            if ctx.dictLitVars.contains(baseName) { return }
            findings.append(finding(def: def, offset: offset,
                                    category: "Unvalidated Array Index",
                                    severity: .medium, reachable: reachable,
                                    message: "Tainted index '\(idxName)' used to access '\(baseName)' without a bounds check.",
                                    taint: taintPath(idxVal).map { "\($0) → \(baseName)[\(idxName)]" }))
        }
    }

    // MARK: - Walk 3: guards

    /// Refines in-branch guards derived from a condition.
    private func refineGuards(cond: SwiftExpr, ctx: WalkContext) {
        switch cond {
        case .binary(let op, let l, let r, _):
            if ["<", "<=", ">", ">="].contains(op) {
                if case .ident(let idxName, _) = l, case .member(let base, let m, _) = r {
                    if m == "count" || m == "endIndex" || m == "length" {
                        ctx.boundsGuards.insert("\(idxName)\u{1}\(base.dottedName)")
                    }
                }
                if case .ident(let idxName, _) = r, case .member(let base, let m, _) = l {
                    if m == "count" || m == "endIndex" || m == "length" {
                        ctx.boundsGuards.insert("\(idxName)\u{1}\(base.dottedName)")
                    }
                }
            }
            if [">", "!=", "!=="].contains(op) {
                if case .ident(let n, _) = l, isZeroLiteral(r) { ctx.zeroChecked.insert(n) }
                if case .ident(let n, _) = r, isZeroLiteral(l) { ctx.zeroChecked.insert(n) }
            }
            if op == "&&" {
                refineGuards(cond: l, ctx: ctx)
                refineGuards(cond: r, ctx: ctx)
            }
        case .call(_, _, _):
            applyCallBoundsGuard(cond, ctx: ctx)
        default:
            break
        }
    }

    /// Guards that hold past an early-exit `if`/`guard` (`if i >= arr.count { return }`).
    private func applyPositiveGuards(cond: SwiftExpr, ctx: WalkContext) {
        switch cond {
        case .binary(let op, let l, let r, _):
            if op == ">=" || op == ">" {
                if case .ident(let idxName, _) = l, case .member(let base, let m, _) = r,
                   m == "count" || m == "endIndex" || m == "length" {
                    ctx.boundsGuards.insert("\(idxName)\u{1}\(base.dottedName)")
                }
            }
            if op == "<=" || op == "<" {
                if case .ident(let idxName, _) = l, case .member(let base, let m, _) = r,
                   m == "count" || m == "endIndex" || m == "length" {
                    ctx.boundsGuards.insert("\(idxName)\u{1}\(base.dottedName)")
                }
                if case .ident(let idxName, _) = r, case .member(let base, let m, _) = l,
                   m == "count" || m == "endIndex" || m == "length" {
                    ctx.boundsGuards.insert("\(idxName)\u{1}\(base.dottedName)")
                }
            }
            if op == "!=" || op == "!==" {
                if case .ident(let n, _) = l, isZeroLiteral(r) { ctx.zeroChecked.insert(n) }
                if case .ident(let n, _) = r, isZeroLiteral(l) { ctx.zeroChecked.insert(n) }
            }
            if op == ">" || op == ">=" {
                // `guard 0 < divisor`, `guard divisor > 0` — divisor becomes non-zero.
                if case .ident(let n, _) = l, isZeroLiteral(r) { ctx.zeroChecked.insert(n) }
                if case .ident(let n, _) = r, isZeroLiteral(l) { ctx.zeroChecked.insert(n) }
            }
            if op == "<" || op == "<=" {
                // `guard divisor >= 1` via the `<`/`<=` mirror: divisor is non-zero.
                if case .ident(let n, _) = r, isZeroLiteral(l) { ctx.zeroChecked.insert(n) }
                if case .ident(let n, _) = l, isZeroLiteral(r) { ctx.zeroChecked.insert(n) }
            }
            if op == "&&" {
                applyPositiveGuards(cond: l, ctx: ctx)
                applyPositiveGuards(cond: r, ctx: ctx)
            } else if op == "||" {
                // `if a || b { return }` — past the early exit both negations hold.
                applyPositiveGuards(cond: negatedBinary(l), ctx: ctx)
                applyPositiveGuards(cond: negatedBinary(r), ctx: ctx)
            }
        case .call(_, _, _):
            applyCallBoundsGuard(cond, ctx: ctx)
        default:
            break
        }
    }

    // MARK: - Call-based bounds guards

    /// A call in a guard/if-condition can bound an index variable:
    ///   - `arr.indices.contains(i)` / `arr.bounds.contains(i)`
    ///   - `Validator.bounded(i, within: arr.count)` / `isValidIndex(i, arr)`
    /// Recognized in both refineGuards (in-branch) and applyPositiveGuards
    /// (early-exit protected) so either phrasing silences false positives.
    private func applyCallBoundsGuard(_ expr: SwiftExpr, ctx: WalkContext) {
        guard case .call(let callee, let args, _) = expr, let idx = args.first,
              case .ident(let idxName, _) = idx else { return }
        let leaf = callee.leafName
        let full = callee.dottedName.lowercased()

        if leaf == "contains" {
            // `arr.indices.contains(i)` / `bounds.contains(i)`.
            if case .member(let base, _, _) = callee {
                let bn = base.dottedName
                for suffix in [".indices", ".bounds"] where bn.hasSuffix(suffix) {
                    let baseName = String(bn.dropLast(suffix.count))
                    if !baseName.isEmpty {
                        ctx.boundsGuards.insert("\(idxName)\u{1}\(baseName)")
                    }
                }
            }
        }
        if full.contains("bounded") || full.contains("validated") || full.contains(".validindex") {
            // `Validator.bounded(i, within: arr.count)` — the bound base shows
            // up as a `x.count` / `x.count - 1` argument.
            for a in args {
                if case .member(let b, let m, _) = a, m == "count" || m == "length" || m == "endIndex" {
                    ctx.boundsGuards.insert("\(idxName)\u{1}\(b.dottedName)")
                }
            }
        }
    }

    /// Inverts a binary comparison (`>=` becomes `<` etc.) so the negated
    /// branches of a `||` early-exit can be fed back through the guard rules.
    private func negatedBinary(_ e: SwiftExpr) -> SwiftExpr {
        guard case .binary(let op, let l, let r, let o) = e else { return e }
        switch op {
        case "<": return .binary(op: ">=", lhs: l, rhs: r, o)
        case "<=": return .binary(op: ">", lhs: l, rhs: r, o)
        case ">": return .binary(op: "<=", lhs: l, rhs: r, o)
        case ">=": return .binary(op: "<", lhs: l, rhs: r, o)
        case "==": return .binary(op: "!=", lhs: l, rhs: r, o)
        case "!=": return .binary(op: "==", lhs: l, rhs: r, o)
        default: return e
        }
    }

    // MARK: - Walk 3: boundary checks

    private func isZeroLiteral(_ e: SwiftExpr) -> Bool {
        if case .literal(let t, _) = e { return t == "0" || t == "0.0" }
        return false
    }

    private func isZeroRisky(_ e: SwiftExpr, ctx: WalkContext) -> Bool {
        switch e {
        case .literal(let t, _):
            return t == "0" || t == "0.0"
        case .ident(let n, _):
            if ctx.zeroChecked.contains(n) { return false }
            if let v = ctx.vars[n] {
                return v.tainted || v.origin?.hasPrefix("parameter") == true
            }
            return true // untracked global/outer value
        case .member:
            return true
        default:
            return false
        }
    }

    // MARK: - Body mutation scan (Array Mutation During Iteration)

    private func bodyContainsMutation(of name: String, body: [SwiftStmt],
                                      tokens: [CAstToken], def: SwiftDef) -> Bool {
        var found = false
        func scanStmt(_ s: SwiftStmt) {
            if found { return }
            switch s {
            case .block(let inner, _):
                for x in inner { scanStmt(x) }
            case .ifStmt(_, let t, let e, _):
                for x in t { scanStmt(x) }
                if let e = e { for x in e { scanStmt(x) } }
            case .guardStmt(_, let body, _):
                for x in body { scanStmt(x) }
            case .forStmt(_, _, let b, _), .whileStmt(_, let b, _):
                for x in b { scanStmt(x) }
            case .repeatStmt(let b, _, _), .deferStmt(let b, _):
                for x in b { scanStmt(x) }
            case .switchStmt(_, let cases, _):
                for c in cases { for x in c.body { scanStmt(x) } }
            case .exprStmt(let e, _):
                scanExpr(e)
            case .varDecl(let decls, _):
                for d in decls { if let e = d.initExpr { scanExpr(e) } }
            case .returnStmt(let e, _):
                if let e = e { scanExpr(e) }
            case .throwStmt(let e, _):
                if let e = e { scanExpr(e) }
            }
        }
        func scanExpr(_ e: SwiftExpr) {
            if found { return }
            switch e {
            case .call(let callee, let args, _):
                var baseName = ""
                if case .member(let b, _, _) = callee { baseName = b.dottedName }
                let leaf = callee.leafName
                if baseName == name,
                   ["append", "append(contentsOf:)", "remove", "removeAll", "removeLast", "removeFirst", "removeSubrange", "insert", "popLast", "swapAt", "shuffle", "sort", "reverse", "replaceSubrange"].contains(leaf) {
                    found = true
                }
                for a in args { scanExpr(a) }
                scanExpr(callee)
            case .assign(_, let l, let r, _):
                if case .index(let b, _, _) = l, b.dottedName == name { found = true }
                scanExpr(l); scanExpr(r)
            case .member(let b, _, _):
                scanExpr(b)
            case .index(let b, let i, _):
                scanExpr(b); scanExpr(i)
            case .binary(_, let l, let r, _), .range(_, let l, let r, _):
                scanExpr(l); scanExpr(r)
            case .ternary(let c, let t, let f, _):
                scanExpr(c); scanExpr(t); scanExpr(f)
            case .unary(_, let o, _):
                scanExpr(o)
            case .arrayLit(let els, _):
                for el in els { scanExpr(el) }
            case .dictLit(let pairs, _):
                for (k, v) in pairs { scanExpr(k); scanExpr(v) }
            case .paren(let x, _), .forceUnwrap(let x, _), .optional(let x, _):
                scanExpr(x)
            case .cast(_, let x, _):
                scanExpr(x)
            case .closure(_, let body, _):
                for x in body { scanStmt(x) }
            case .interpolation(let exprs, _):
                for x in exprs { scanExpr(x) }
            case .ident, .literal, .newExpr, .placeholder:
                break
            }
        }
        for s in body { scanStmt(s) }
        return found
    }

    // MARK: - Helpers

    private func taintPath(_ v: TaintVal?) -> String? {
        guard let v = v, v.tainted else { return nil }
        return v.origin
    }

    private func isReachable(_ def: SwiftDef) -> Bool {
        reachableNames.contains(def.name) || reachableNames.isEmpty
    }

    private func bodyTokens(of def: SwiftDef) -> [CAstToken] {
        let lo = def.bodyRange.location
        let hi = lo + def.bodyRange.length
        return tokens.filter { $0.offset >= lo && $0.offset < hi && $0.kind != .eof }
    }

    private func sourceText(from e: SwiftExpr) -> String {
        let start = e.offset
        guard start >= 0, start < ns.length else { return "" }
        return ns.substring(with: NSRange(location: start, length: min(160, ns.length - start)))
    }

    private func nearText(center: Int, before: Int = 120, after: Int = 160) -> String {
        let lo = max(0, center - before)
        let hi = min(ns.length, center + after)
        guard hi > lo else { return "" }
        return ns.substring(with: NSRange(location: lo, length: hi - lo))
    }

    /// True when an expression's flattened text mentions a sensitive name
    /// (password, token, secret, key, auth…).
    private func sensitiveName(for e: SwiftExpr) -> Bool {
        var names: [String] = []
        collectNames(e, into: &names)
        return names.contains { swiftSensitiveDataNames.contains($0.lowercased()) }
    }

    private func anyInterpolatedSensitive(_ e: SwiftExpr) -> Bool {
        guard case .interpolation(let exprs, _) = e else { return false }
        return exprs.contains { sensitiveName(for: $0) }
    }

    private func collectNames(_ e: SwiftExpr, into names: inout [String]) {
        switch e {
        case .ident(let n, _): names.append(n)
        case .member(let b, let m, _):
            collectNames(b, into: &names)
            names.append(m)
        case .interpolation(let exprs, _):
            for x in exprs { collectNames(x, into: &names) }
        default:
            for c in e.children { collectNames(c, into: &names) }
        }
    }

    private func assignmentTargetText(_ e: SwiftExpr) -> String {
        switch e {
        case .member(let base, let name, _):
            let b = assignmentTargetText(base)
            return b.isEmpty ? name : "\(b).\(name)"
        case .index(let base, let idx, _):
            return "\(assignmentTargetText(base))[\(assignmentTargetText(idx))]"
        case .ident(let n, _):
            return n
        default:
            return ""
        }
    }

    private func valueIsTrueLiteral(_ e: SwiftExpr) -> Bool {
        if case .literal(let t, _) = e { return t == "true" }
        return false
    }

    private func dottedLast(_ e: SwiftExpr) -> String {
        e.dottedName.components(separatedBy: ".").last ?? ""
    }

    /// True when the body's token stream contains the given identifier. The
    /// tokenizer excludes comments, so names appearing only in comment text
    /// never match here.
    func bodyHasIdentifier(_ tokens: [CAstToken], _ name: String) -> Bool {
        tokens.contains { $0.kind == .identifier && $0.text == name }
    }

    /// True when a real body identifier is named after a sensitive data label
    /// (password, token, keychain, credit card, …). Token-exact, so harmless
    /// substrings inside other words ("shipping") never match.
    func bodyHasSensitiveToken(in tokens: [CAstToken]) -> Bool {
        let names = swiftSensitiveDataNames.map { $0.lowercased() }
        return tokens.contains { $0.kind == .identifier && names.contains($0.text.lowercased()) }
    }

    private func finding(def: SwiftDef, offset: Int, category: String,
                         severity: ScanFinding.Severity, reachable: Bool,
                         message: String, taint: String?) -> SwiftFinding {
        SwiftFinding(function: def.name, offset: offset, category: category,
                     severity: severity, message: message, taintPath: taint,
                     reachable: reachable)
    }

    /// A file-local function definition with the given name.
    private func localDefNamed(_ name: String) -> SwiftDef? {
        defs.first { $0.name == name }
    }

    /// True when a local function body applies an explicit containment /
    /// sanitizer gate (`PathGuard.isContained`, `isAllowedPath`, …). Such
    /// helpers return already-validated paths, so callers of them are clean.
    private func isPathSanitizer(_ def: SwiftDef) -> Bool {
        let lo = def.bodyRange.location
        let hi = lo + def.bodyRange.length
        guard lo >= 0, lo < ns.length, hi > lo, hi <= ns.length else { return false }
        let body = ns.substring(with: NSRange(location: lo, length: hi - lo))
        return body.contains("isContained") || body.contains("contained")
            || body.contains("isAllowed") || body.contains("allowedPath")
    }

    /// True when a function body gates process invocations behind an explicit
    /// allowlist (allowed binaries / command allow-list). Tainted args assigned
    /// inside such a gated helper are not an injection vector.
    private func bodyHasCommandAllowlistGate(_ def: SwiftDef) -> Bool {
        let lo = def.bodyRange.location
        let hi = lo + def.bodyRange.length
        guard lo >= 0, lo < ns.length, hi > lo, hi <= ns.length else { return false }
        let body = ns.substring(with: NSRange(location: lo, length: hi - lo)).lowercased()
        return body.contains("allowedbin") || body.contains("allowlist") || body.contains("allowedcommand")
            || body.contains("allowedbinary")
    }

    /// The balanced argument-slice text of a call whose opening `(` begins at
    /// (or after) `offset`. Limits `contentsOf`-style rules to the constructor
    /// they appear in instead of a wide line window.
    private func callArgumentSlice(from offset: Int) -> String {
        guard offset >= 0, offset < ns.length else { return "" }
        var open = -1
        var i = offset
        while i < ns.length {
            let c = ns.character(at: i)
            if c == 0x28 { open = i; break }
            if c == 0x0A { break }
            i += 1
        }
        guard open >= 0 else { return "" }
        var depth = 0
        var j = open
        while j < ns.length {
            let c = ns.character(at: j)
            if c == 0x28 { depth += 1 }
            else if c == 0x29 { depth -= 1; if depth == 0 { break } }
            j += 1
        }
        guard j < ns.length else { return "" }
        return ns.substring(with: NSRange(location: open, length: j - open + 1))
    }

    /// Variable names declared as dictionary / keyed-map lookups:
    /// `let x: [String: V]` or `let x = ["k": v, …]`. Tainted key lookups on
    /// these are projection reads, never positional index overruns.
    private func dictLiteralVarNames() -> Set<String> {
        var names = Set<String>()
        // Typed declarations: `let policies: [String: Access]`.
        if let re = try? NSRegularExpression(pattern: "(?:let|var)\\s+([A-Za-z_$][\\w$]*)\\s*:\\s*\\[[^\\]]+\\s*:[^\\]]+\\]") {
            for m in re.matches(in: source, range: NSRange(location: 0, length: ns.length)) {
                names.insert(ns.substring(with: m.range(at: 1)))
            }
        }
        // Literal initializers: `let policies = ["read": …]`.
        if let re = try? NSRegularExpression(pattern: "(?:let|var)\\s+([A-Za-z_$][\\w$]*)\\s*(?::\\s*\\[[^\\]]*\\])?\\s*=\\s*\\[[^\\]]*\\s*:[^\\]]") {
            for m in re.matches(in: source, range: NSRange(location: 0, length: ns.length)) {
                names.insert(ns.substring(with: m.range(at: 1)))
            }
        }
        return names
    }
}

// MARK: - Helper predicates (file-internal)

/// SQL sinks: the callee name or a nearby statement looks like a database
/// execution path. Parameterised / read-only sqlite3 helpers (binding values,
/// reading columns, finalising, stepping a prepared statement) are safe and
/// excluded so that `sqlite3_bind_text` never counts as an injection sink.
private func sqlFamily(leaf: String, name: String) -> Bool {
    if name.hasPrefix("sqlite3_bind") || name.hasPrefix("sqlite3_column")
        || name == "sqlite3_finalize" || name == "sqlite3_step" { return false }
    let sqlLeaves = Set(["execute", "executeQuery", "executeUpdate", "exec", "run", "prepare", "query", "sqlite3_exec", "sqlite3_prepare_v2"])
    if sqlLeaves.contains(leaf) { return true }
    if name.contains("sqlite") || name.contains("fmdb") || name.contains("executeQuery") || name.contains("executeUpdate") { return true }
    return false
}

/// Identifier-style tokens of a lowercased call name: split on non-alphanumeric
/// delimiters and camelCase boundaries (`setSideShadow` → [set, side, shadow],
/// `insertNewObject` → [insert, new, object]).
private func identifierTokens(of low: String) -> [String] {
    var tokens: [String] = []
    for word in low.components(separatedBy: CharacterSet.alphanumerics.inverted) where !word.isEmpty {
        var current = ""
        var prev: Character? = nil
        for ch in word {
            if let p = prev, ch.isUppercase, !p.isUppercase, !current.isEmpty {
                tokens.append(current.lowercased())
                current = ""
            }
            current.append(ch)
            prev = ch
        }
        if !current.isEmpty { tokens.append(current.lowercased()) }
    }
    return tokens
}

private let weakAlgorithmTokens: Set<String> = ["md5", "md2", "md4", "sha1", "des", "desede", "rc2", "rc4"]

private func weakCrypto(leaf: String, name: String) -> Bool {
    let weakAvailable = swiftWeakCryptoNames
    if weakAvailable.contains(leaf) || weakAvailable.contains(name) { return true }
    let low = name.lowercased()
    if low.contains("insecure.") || low.contains("cc_md5") || low.contains("cc_sha1")
        || low.contains("commoncrypto") { return true }
    return identifierTokens(of: low).contains(where: { weakAlgorithmTokens.contains($0) })
}
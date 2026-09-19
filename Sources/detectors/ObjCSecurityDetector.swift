// by cipher.org.uk
import Foundation

// MARK: - ObjC three-walk security analysis
//
// Native AST detector for Cocoa/ObjC, structurally mirroring
// SwiftSecurityDetector. ObjC files no longer ride the C-AST frontend: this
// detector owns ObjC (and the C subset inside it) over ObjCParser's AST.
//
// Walk 1 (taint): value-flow over method bodies — parameters and known
//   source APIs seed taint; message arguments and C-call arguments are
//   checked against taint-configured sinks (Command Injection, SQL
//   Injection, Path Traversal, SSRF, Log Injection, Dynamic Code Execution).
// Walk 2 (bounds): fixed-size buffer locals (`char buf[64]`) correlated with
//   unbounded copies (strcpy/strcat/wcscpy), size-derived copies
//   (memcpy/memmove) and sprintf-family writes.
// Walk 3 (boundary): configuration and API-surface markers reasoned over the
//   AST — Keychain accessibility constants, ATS bypass selectors, deprecated
//   webviews, privacy APIs, location trackers, messaging/clipboard surfaces —
//   plus the file-level transport scans.

final class ObjCSecurityDetector {

    struct ObjCFinding {
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
    private let defs: [ObjCMethodDef]
    private let bodies: [Int: [ObjCStmt]]
    private let reachableNames: Set<String>
    private let taintReturning: Set<String>
    private let crossFileSources: Set<String>
    /// True when the file disables JavaScript support somewhere (`webView.javaScriptEnabled = NO`).
    /// A webview with JavaScript disabled cannot execute injected markup, so
    /// legacy `loadHTMLString:`/`loadRequest:` content surfaces are config load
    /// points rather than in-process script execution. Only used to suppress
    /// the "XSS (HTML Injection)" content-surface markers — files that never
    /// disable JS are unaffected, so JS-enabled vulnerable webviews still fire.
    private let fileDisablesJS: Bool
    /// Local variable names (within the function currently analyzed) that were
    /// initialized or assigned from a dictionary literal whose keychain
    /// accessibility is a secure when-unlocked/after-first-unlock value.
    /// `SecItemAdd` calls passing such a dictionary are already protected and
    /// must not fire the storage-policy marker.
    private var secureKeychainDicts: Set<String> = []
    /// Root identifier names in the function currently analyzed that passed a
    /// validation/sanitization guard (`if (!CorpusIsValidPathComponent(x)) return NO;`).
    /// Sinks fed by a guard-validated root are suppressed: the path/selector/command
    /// only flows further when the check allowed it.
    private var guardValidated: Set<String> = []
    /// Variable names bound to HTTPS-normalized URL values (via
    /// `stringByReplacingOccurrencesOfString:withString:` to an https:// literal,
    /// or a URL built from such a value). Feeding such a value to an SSRF sink is
    /// a no-op and must not fire.
    private var httpsSafeVars: Set<String> = []

    init(source: String,
         defs: [ObjCMethodDef],
         bodies: [Int: [ObjCStmt]],
         reachableNames: Set<String> = [],
         taintReturning: Set<String> = [],
         crossFileSources: Set<String> = []) {
        self.source = source
        self.ns = source as NSString
        self.defs = defs
        self.bodies = bodies
        self.reachableNames = reachableNames
        self.taintReturning = taintReturning
        self.crossFileSources = crossFileSources
        let jsDisable = try? NSRegularExpression(pattern: "\\.javaScriptEnabled\\s*=\\s*(NO|false|0)\\b",
                                                 options: [.caseInsensitive])
        self.fileDisablesJS = jsDisable?.firstMatch(in: source,
                                                   options: [],
                                                   range: NSRange(location: 0, length: (source as NSString).length)) != nil
    }

    func detect() -> [ObjCFinding] {
        var findings: [ObjCFinding] = []
        for def in defs {
            guard let stmts = bodies[def.bodyOpenOffset], !stmts.isEmpty else { continue }
            var defFindings = analyzeFunction(def, statements: stmts)
            // A bare `NSUserDefaults` identifier (or class-use as receiver) is a
            // marker only for the insecure *storage* pattern: the method actually
            // persisting data to standard defaults. Reading standard defaults for
            // configuration (`NSUserDefaults.standardUserDefaults;` in an init or
            // a plain lookup) is not storing secrets unencrypted.
            if !statementsWriteUserDefaults(stmts) {
                defFindings.removeAll { $0.category == "Insecure UserDefaults Storage" }
            }
            if fileDisablesJS {
                defFindings.removeAll { $0.category == "XSS (HTML Injection)" }
            }
            findings.append(contentsOf: defFindings)
        }
        for i in findings.indices {
            if let root = findings[i].taintPath?.components(separatedBy: " → ").first,
               crossFileSources.contains(root) {
                findings[i].crossFile = true
            }
        }
        return findings
    }

    /// Walk 3 entry-point classification: a method is attacker-reachable when
    /// it is a top-level C function or a public (non-underscore-prefixed) ObjC
    /// method — the standard ObjC privacy convention. Taint-based sinks fire
    /// only from entry points; configuration markers and bounds findings are
    /// facts about the code and fire everywhere.
    private func isEntryPoint(_ def: ObjCMethodDef) -> Bool {
        if def.isCFunction { return true }
        return !def.selector.hasPrefix("_")
    }

    // MARK: - Walk 1 + 2 + 3 per function

    private func analyzeFunction(_ def: ObjCMethodDef, statements: [ObjCStmt]) -> [ObjCFinding] {
        let reachable = reachableNames.contains(def.selector)
        let entryPoint = isEntryPoint(def)
        var findings: [ObjCFinding] = []
        var tainted: [String: [String]] = [:]
        var bufferSizes: [String: Int] = [:]
        secureKeychainDicts = []
        guardValidated = []
        httpsSafeVars = []

        // Walk 1 seed: parameters are the initial untrusted inputs.
        for p in def.params { tainted[p.name] = [p.name] }

        for stmt in statements {
            switch stmt.kind {
            case .declaration(let type, let name, _, let arraySize, let initExpr):
                if let sz = arraySize { bufferSizes[name] = sz }
                // Walk 3: declaration types can themselves be markers
                // (e.g. `NSUserDefaults *d;`, `ABAddressBookRef book;`).
                if let marker = identifierMarker(type) {
                    findings.append(ObjCFinding(function: def.selector,
                                                offset: stmt.offset,
                                                category: marker.category,
                                                severity: marker.severity,
                                                message: marker.message,
                                                taintPath: nil,
                                                reachable: reachable))
                }
                if let e = initExpr {
                    findings.append(contentsOf: scanExpr(e,
                                                         function: def.selector,
                                                         tainted: tainted,
                                                         bufferSizes: bufferSizes,
                                                         reachable: reachable,
                                                         entryPoint: entryPoint))
                    if exprHasSecureKeychainAccessibility(e) {
                        secureKeychainDicts.insert(name)
                    }
                    if exprTransportsToHTTPS(e, tracked: httpsSafeVars) {
                        httpsSafeVars.insert(name)
                    }
                    if let path = exprTaintPath(e, tainted: tainted) {
                        tainted[name] = path
                    } else {
                        tainted.removeValue(forKey: name)
                    }
                    // A fresh value replaces whatever the guard validated.
                    guardValidated.remove(name)
                } else {
                    tainted.removeValue(forKey: name)
                }
            case .assignment(let target, let value):
                findings.append(contentsOf: scanExpr(target,
                                                     function: def.selector,
                                                     tainted: tainted,
                                                     bufferSizes: bufferSizes,
                                                     reachable: reachable,
                                                     entryPoint: entryPoint))
                findings.append(contentsOf: scanExpr(value,
                                                     function: def.selector,
                                                     tainted: tainted,
                                                     bufferSizes: bufferSizes,
                                                     reachable: reachable,
                                                     entryPoint: entryPoint))
                if let name = targetTrailingName(target) {
                    if exprHasSecureKeychainAccessibility(value) {
                        secureKeychainDicts.insert(name)
                    }
                    if exprTransportsToHTTPS(value, tracked: httpsSafeVars) {
                        httpsSafeVars.insert(name)
                    }
                    if let path = exprTaintPath(value, tainted: tainted) {
                        tainted[name] = path
                    } else {
                        tainted.removeValue(forKey: name)
                    }
                    // A fresh value replaces whatever the guard validated.
                    guardValidated.remove(name)
                }
            case .expression(let e):
                findings.append(contentsOf: scanExpr(e,
                                                     function: def.selector,
                                                     tainted: tainted,
                                                     bufferSizes: bufferSizes,
                                                     reachable: reachable,
                                                     entryPoint: entryPoint))
            case .condition(let e):
                // Guard analysis: a condition gating execution past a
                // validation/sanitization call validates that call's arguments.
                guardExprDetectGuards(e)
                findings.append(contentsOf: scanExpr(e,
                                                     function: def.selector,
                                                     tainted: tainted,
                                                     bufferSizes: bufferSizes,
                                                     reachable: reachable,
                                                     entryPoint: entryPoint))
            case .returnStmt(let e):
                if let e = e {
                    findings.append(contentsOf: scanExpr(e,
                                                         function: def.selector,
                                                         tainted: tainted,
                                                         bufferSizes: bufferSizes,
                                                         reachable: reachable,
                                                         entryPoint: entryPoint))
                }
            }
        }
        return findings
    }

    // MARK: - Expression scan (sinks + markers, all walks)

    private func scanExpr(_ e: ObjCExpr,
                          function: String,
                          tainted: [String: [String]],
                          bufferSizes: [String: Int],
                          reachable: Bool,
                          entryPoint: Bool,
                          inMessageArg: Bool = false,
                          messageSelector: String = "") -> [ObjCFinding] {
        var out: [ObjCFinding] = []

        switch e {
        case .identifier(let name, let offset):
            // Walk 3: bare configuration/privacy markers.
            if let marker = identifierMarker(name) {
                // NSFileProtectionNone is only a defect when it WRITES the weak
                // protection level; using it in a comparison/read (e.g. an
                // `isEqualToString:` validation) is not insecure.
                let weakProtectionComparison = name == "NSFileProtectionNone"
                    && inMessageArg && !isWriteSelector(messageSelector)
                if !weakProtectionComparison {
                    out.append(ObjCFinding(function: function,
                                           offset: offset,
                                           category: marker.category,
                                           severity: marker.severity,
                                           message: marker.message,
                                           taintPath: nil,
                                           reachable: reachable))
                }
            }

        case .call(let name, let args, let offset):
            out.append(contentsOf: scanCCall(name: name,
                                             args: args,
                                             offset: offset,
                                             function: function,
                                             tainted: tainted,
                                             bufferSizes: bufferSizes,
                                             reachable: reachable,
                                             entryPoint: entryPoint))
            for a in args {
                out.append(contentsOf: scanExpr(a,
                                                function: function,
                                                tainted: tainted,
                                                bufferSizes: bufferSizes,
                                                reachable: reachable,
                                                entryPoint: entryPoint))
            }

        case .message(let receiver, let parts, let offset):
            // Walk 1: format-string flaw — the FORMAT argument must itself be
            // attacker-influenced. A literal format with tainted arguments is
            // safe (the arguments are data the format consumes). Variadic
            // continuations are comma-folded; only the first item is the format.
            if parts.first?.selector == "stringWithFormat:",
               let fmt = parts.first?.arg {
                let formatExpr = firstFoldedItem(fmt)
                if !isStringLiteral(formatExpr),
                   let path = exprTaintPath(formatExpr, tainted: tainted) {
                    out.append(ObjCFinding(function: function,
                                           offset: formatExpr.offset,
                                           category: "Format String",
                                           severity: .high,
                                           message: "stringWithFormat uses a format string derived from untrusted data.",
                                           taintPath: path.joined(separator: " → "),
                                           reachable: reachable))
                }
            }
            // Walk 3: receiver class markers.
            // The Insecure Deserialization marker tracks data that truly flows
            // from an untrusted source into a dangerous unarchive. Local blobs,
            // secure unarchivers (`unarchivedObjectOfClass:forKey:` /
            // `unarchivedObjectOfClasses:fromData:error:`), plists (inert
            // containers) and the archiver writer are all safe to elide.
            var suppressDeserialization = false
            if let r0 = receiver, let recv0 = staticReceiverName(r0) {
                guard let part0 = parts.first else { break }
                switch recv0 {
                case "NSKeyedUnarchiver":
                    if part0.selector == "unarchiveObjectWithData:" {
                        // Legacy unarchiver: only suppress when the blob is
                        // clearly not attacker-influenced.
                        if let rawArg = part0.arg,
                           exprTaintPath(rawArg, tainted: tainted) == nil {
                            suppressDeserialization = true
                        }
                    } else if part0.selector == "unarchivedObjectOfClass:" || part0.selector == "unarchivedObjectOfClasses:" {
                        // The secure variants require an explicit class
                        // allowlist — their use IS the mitigation, whatever
                        // the blob's provenance.
                        suppressDeserialization = true
                    }
                case "NSKeyedArchiver":
                    if part0.selector == "archivedDataWithRootObject:" {
                        // Archiving is a safe write; the "tamper" advisory
                        // belongs to the read site, not here.
                        suppressDeserialization = true
                    }
                case "NSPropertyListSerialization":
                    // Plists are inert containers — no dynamic classes.
                    suppressDeserialization = true
                default:
                    break
                }
            }
            if let r = receiver, let recvName = staticReceiverName(r),
               let marker = receiverMarker(recvName),
               !(suppressDeserialization && marker.category == "Insecure Deserialization") {
                out.append(ObjCFinding(function: function,
                                       offset: r.offset,
                                       category: marker.category,
                                       severity: marker.severity,
                                       message: marker.message,
                                       taintPath: nil,
                                       reachable: reachable))
            }
            // Walk 3 + Walk 1: selector-based rules.
            // [NSURLSession sharedSession] has no per-request URL to validate —
            // the session accessor is the SSRF surface itself.
            if let r = receiver, staticReceiverName(r) == "NSURLSession",
               let sel = parts.first?.selector, sel == "sharedSession" {
                out.append(ObjCFinding(function: function,
                                       offset: offset,
                                       category: "SSRF",
                                       severity: .high,
                                       message: "[NSURLSession sharedSession] creates a default session with no per-request transport restrictions.",
                                       taintPath: nil,
                                       reachable: reachable))
            }
            for part in parts {
                if let marker = selectorMarker(part.selector) {
                    out.append(ObjCFinding(function: function,
                                           offset: offset,
                                           category: marker.category,
                                           severity: marker.severity,
                                           message: marker.message,
                                           taintPath: nil,
                                           reachable: reachable))
                }
                if let rule = selectorTaintSink(part.selector),
                   let rawArg = part.arg, let arg = nonNil(rawArg),
                   entryPoint,
                   let path = exprTaintPath(arg, tainted: tainted),
                   !isGuardValidated(root: path.first),
                   !isGuardValidated(root: rootIdentifier(arg)) {
                    out.append(ObjCFinding(function: function,
                                           offset: arg.offset,
                                           category: rule.category,
                                           severity: rule.severity,
                                           message: rule.message(part.selector),
                                           taintPath: path.joined(separator: " → "),
                                           reachable: reachable))
                }
            }
            if let r = receiver {
                // A suppressed unarchive round-trip also must not re-fire through the
                // bare-identifier marker scan of the receiver class name.
                if !(suppressDeserialization
                    && ["NSKeyedUnarchiver", "NSKeyedArchiver", "NSPropertyListSerialization"].contains(staticReceiverName(r) ?? "")) {
                    out.append(contentsOf: scanExpr(r,
                                                    function: function,
                                                    tainted: tainted,
                                                    bufferSizes: bufferSizes,
                                                    reachable: reachable,
                                                    entryPoint: entryPoint))
                }
            }
            for part in parts {
                if let arg = part.arg {
                    out.append(contentsOf: scanExpr(arg,
                                                    function: function,
                                                    tainted: tainted,
                                                    bufferSizes: bufferSizes,
                                                    reachable: reachable,
                                                    entryPoint: entryPoint,
                                                    inMessageArg: true,
                                                    messageSelector: part.selector))
                }
            }

        case .member(let base, _, _):
            out.append(contentsOf: scanExpr(base,
                                            function: function,
                                            tainted: tainted,
                                            bufferSizes: bufferSizes,
                                            reachable: reachable,
                                            entryPoint: entryPoint))

        case .index(let base, let index, _):
            out.append(contentsOf: scanExpr(base,
                                            function: function,
                                            tainted: tainted,
                                            bufferSizes: bufferSizes,
                                            reachable: reachable,
                                            entryPoint: entryPoint))
            out.append(contentsOf: scanExpr(index,
                                            function: function,
                                            tainted: tainted,
                                            bufferSizes: bufferSizes,
                                            reachable: reachable,
                                            entryPoint: entryPoint))

        case .binary(_, let lhs, let rhs, _):
            out.append(contentsOf: scanExpr(lhs,
                                            function: function,
                                            tainted: tainted,
                                            bufferSizes: bufferSizes,
                                            reachable: reachable,
                                            entryPoint: entryPoint))
            out.append(contentsOf: scanExpr(rhs,
                                            function: function,
                                            tainted: tainted,
                                            bufferSizes: bufferSizes,
                                            reachable: reachable,
                                            entryPoint: entryPoint))

        case .ternary(let cond, let thenE, let elseE, _):
            for sub in [cond, thenE, elseE] {
                out.append(contentsOf: scanExpr(sub,
                                                function: function,
                                                tainted: tainted,
                                                bufferSizes: bufferSizes,
                                                reachable: reachable,
                                                entryPoint: entryPoint))
            }

        case .unary(_, let operand, _):
            out.append(contentsOf: scanExpr(operand,
                                            function: function,
                                            tainted: tainted,
                                            bufferSizes: bufferSizes,
                                            reachable: reachable,
                                            entryPoint: entryPoint))

        case .paren(let inner, _):
            out.append(contentsOf: scanExpr(inner,
                                            function: function,
                                            tainted: tainted,
                                            bufferSizes: bufferSizes,
                                            reachable: reachable,
                                            entryPoint: entryPoint))

        case .arrayLiteral(let items, _):
            for item in items {
                out.append(contentsOf: scanExpr(item,
                                                function: function,
                                                tainted: tainted,
                                                bufferSizes: bufferSizes,
                                                reachable: reachable,
                                                entryPoint: entryPoint))
            }

        case .dictLiteral(let entries, _):
            for entry in entries {
                out.append(contentsOf: scanExpr(entry.key,
                                                function: function,
                                                tainted: tainted,
                                                bufferSizes: bufferSizes,
                                                reachable: reachable,
                                                entryPoint: entryPoint))
                out.append(contentsOf: scanExpr(entry.value,
                                                function: function,
                                                tainted: tainted,
                                                bufferSizes: bufferSizes,
                                                reachable: reachable,
                                                entryPoint: entryPoint))
            }

        case .string, .number, .unknown:
            break
        }
        return out
    }

    // MARK: - Walk 1: C-call sinks

    private func scanCCall(name: String,
                           args: [ObjCExpr],
                           offset: Int,
                           function: String,
                           tainted: [String: [String]],
                           bufferSizes: [String: Int],
                           reachable: Bool,
                           entryPoint: Bool) -> [ObjCFinding] {
        var out: [ObjCFinding] = []

        // Walk 1 taint findings fire only from attacker-reachable entry
        // points; internal helpers would taint-flag on library-internal data.
        func emitTaint(_ category: String, _ severity: ScanFinding.Severity, _ message: String, path: [String]?) {
            guard entryPoint else { return }
            // A sink fed by a guard-validated root (validated/sanitized before
            // use) is already processed; the check is the mitigation.
            if let root = path?.first, guardValidated.contains(root) { return }
            out.append(ObjCFinding(function: function,
                                   offset: offset,
                                   category: category,
                                   severity: severity,
                                   message: message,
                                   taintPath: path?.joined(separator: " → "),
                                   reachable: reachable))
        }
        func emit(_ category: String, _ severity: ScanFinding.Severity, _ message: String, path: [String]?) {
            out.append(ObjCFinding(function: function,
                                   offset: offset,
                                   category: category,
                                   severity: severity,
                                   message: message,
                                   taintPath: path?.joined(separator: " → "),
                                   reachable: reachable))
        }
        func taintedArg(_ idx: Int) -> [String]? {
            guard idx < args.count else { return nil }
            return exprTaintPath(args[idx], tainted: tainted)
        }
        func anyTaintedArg() -> [String]? {
            for a in args {
                if let p = exprTaintPath(a, tainted: tainted) { return p }
            }
            return nil
        }
        func argsHasSecureKeychainAccessibility() -> Bool {
            for a in args {
                if let n = leafIdentifierName(a) {
                    if secureKeychainDicts.contains(n) { return true }
                }
                if exprHasSecureKeychainAccessibility(a) { return true }
            }
            return false
        }
        func fixedDst(_ idx: Int) -> Bool {
            guard idx < args.count else { return false }
            if case .identifier(let n, _) = args[idx] { return bufferSizes[n] != nil }
            return false
        }

        switch name {
        // Walk 1: command injection.
        case "system", "popen":
            if let p = taintedArg(0) {
                emitTaint("Command Injection", .high,
                     "\(name) executes an OS command built from untrusted data.", path: p)
            }
        case "execl", "execlp", "execle", "execv", "execvp", "execvpe", "posix_spawn", "posix_spawnp":
            if let p = anyTaintedArg() {
                emitTaint("Command Injection", .high,
                     "\(name) launches a process influenced by untrusted data.", path: p)
            }

        // Walk 1: SQL injection.
        case "sqlite3_exec":
            if let p = taintedArg(1) {
                emitTaint("SQL Injection", .high,
                     "sqlite3_exec runs a SQL statement assembled from untrusted data.", path: p)
            }
        case "sqlite3_prepare", "sqlite3_prepare_v2":
            if let p = taintedArg(1) {
                emitTaint("SQL Injection", .high,
                     "\(name) prepares a SQL statement assembled from untrusted data; use bound parameters.", path: p)
            }

        // Walk 1: path traversal.
        case "fopen", "open", "creat", "remove", "mkdir", "unlink", "stat",
             "access", "chmod", "truncate", "lstat", "sqlite3_open":
            if let p = taintedArg(0) {
                emitTaint("Path Traversal", .medium,
                     "\(name) operates on a file path controlled by untrusted data.", path: p)
            }

        // Walk 2: unbounded copies into fixed buffers.
        case "strcpy", "strcat", "wcscpy":
            let srcTainted = taintedArg(1) ?? taintedArg(0)
            if fixedDst(0) {
                emitTaint("Buffer Overflow", .high,
                     "\(name) copies into a fixed-size buffer without a bounds check; a long source overflows it.",
                     path: srcTainted)
            } else if let p = srcTainted {
                emitTaint("Buffer Overflow", .high,
                     "\(name) copies untrusted data with no bounds check.", path: p)
            }
        case "strncpy", "strncat":
            let sizeTainted = taintedArg(2)
            // A fixed-size local buffer combined with an attacker-influenced or
            // oversized bound is a provable overflow. Copying into a caller-
            // supplied buffer with a parameter-derived bound (`bufSize - 1`) is
            // the caller's own sizing contract, not a defect in this function.
            if fixedDst(0) {
                var literalOversize = false
                if case .number(let n, _) = args[2], let v = Int(n), let cap = bufferSizes[bufferName(args[0])], v > cap {
                    literalOversize = true
                }
                if let p = sizeTainted {
                    emitTaint("Buffer Overflow", .high,
                         "\(name) writes an attacker-influenced number of bytes into a fixed-size buffer.", path: p)
                } else if literalOversize {
                    emitTaint("Buffer Overflow", .high,
                         "\(name) writes more bytes than the fixed-size buffer can hold.", path: nil)
                }
            }
        case "memcpy", "memmove":
            let sizeTainted = taintedArg(2)
            if fixedDst(0) {
                var literalOversize = false
                if case .number(let n, _) = args[2], let v = Int(n), let cap = bufferSizes[bufferName(args[0])], v > cap {
                    literalOversize = true
                }
                if sizeTainted != nil || literalOversize {
                    emitTaint("Buffer Overflow", .high,
                         "\(name) writes \(sizeTainted != nil ? "attacker-influenced" : "oversized") bytes into a fixed-size buffer.",
                         path: sizeTainted)
                }
            }

        // Walk 2 + format string.
        case "sprintf", "vsprintf":
            // A fixed-size destination alone is not decisive (an internal
            // `char buf[16]; sprintf(buf, "%d", n);` is safe); only a format
            // string derived from untrusted data is a defect.
            if let fmtTainted = taintedArg(1) {
                emitTaint("Buffer Overflow / Format String", .high,
                     "\(name) writes formatted output into a buffer with no size limit.",
                     path: fmtTainted)
            }
        case "CFStringAppendFormat":
            if let p = taintedArg(2) {
                emitTaint("Format String", .high,
                     "CFStringAppendFormat appends output formatted from untrusted data.", path: p)
            }
        case "printf", "fprintf", "snprintf", "vsnprintf":
            // fprintf(FILE *, fmt) and syslog(priority, fmt) put the format at index 1.
            let fmtIdx = (name == "fprintf" || name == "syslog") ? 1 : 0
            if let p = taintedArg(fmtIdx) {
                emitTaint("Format String", .medium,
                     "\(name) uses a format string derived from untrusted data.", path: p)
            }

        // Walk 1: weak cryptography (always).
        case "MD5", "MD5_Init", "MD5_Update", "MD5_Final", "EVP_md5",
             "SHA1", "SHA1_Init", "SHA1_Update", "SHA1_Final", "EVP_sha1",
             "DES_ecb_encrypt", "DES_cbc_encrypt", "EVP_des_ecb", "RC4":
            emit("Weak Cryptography", .medium,
                 "\(name) is a broken or deprecated primitive; use SHA-256+ via CommonCrypto or CryptoKit.", path: nil)

        // Walk 1: log injection. Mirrors the `stringWithFormat:` rule above:
        // NSLog's FIRST argument is the format string. A literal `@"..."` format
        // with tainted data arguments is safe (the args are data the format
        // consumes). Only a format string derived from untrusted data can forge
        // log entries, so only that case fires.
        case "NSLog":
            if let fmt = args.first {
                let formatExpr = firstFoldedItem(fmt)
                if !isStringLiteral(formatExpr),
                   let p = exprTaintPath(formatExpr, tainted: tainted) {
                    emitTaint("Log Injection", .low,
                         "NSLog uses a format string derived from untrusted data; forgeable entries can mislead triage.", path: p)
                }
            }
        case "syslog":
            // syslog(priority, fmt): a tainted format argument is both a
            // forged log entry and a format-string flaw.
            if let p = taintedArg(1) {
                emitTaint("Log Injection", .low,
                     "syslog writes untrusted data to the log; forgeable entries can mislead triage.", path: p)
                emitTaint("Format String", .medium,
                     "syslog uses a format string derived from untrusted data.", path: p)
            }

        // Walk 3: keychain write (configuration-free marker).
        case "SecItemAdd":
            if !argsHasSecureKeychainAccessibility() {
                emit("Insecure Keychain Accessibility", .medium,
                     "SecItemAdd persists an item; verify kSecAttrAccessible is a when-unlocked value.", path: nil)
            }

        // Walk 3: weak randomness / temporary files (configuration facts).
        case "srand", "random", "rand":
            emit("Weak Randomness", .low,
                 "\(name) is a predictable PRNG; use SecRandomCopyBytes for security-sensitive values.", path: nil)
        case "tmpnam", "tempnam":
            emit("Insecure Temporary File", .medium,
                 "\(name) creates predictable temporary files in a world-readable directory.", path: nil)

        // Walk 1: weak cryptography (always — broken primitives).
        case "CC_MD5", "CC_MD4", "CC_SHA1", "crypt":
            emit("Weak Cryptography", .medium,
                 "\(name) is a broken or deprecated primitive; use SHA-256+ via CommonCrypto or CryptoKit.", path: nil)

        // Walk 1: dynamic code execution surfaces (taint-gated).
        case "objc_msgSend":
            if let p = anyTaintedArg() {
                emitTaint("Code Injection", .high,
                          "objc_msgSend dispatches to a caller-influenced target/selector.", path: p)
            }
        case "dlopen":
            if let p = taintedArg(0) {
                emitTaint("Code Injection", .high,
                          "dlopen loads a library from an attacker-influenced path.", path: p)
            }
        case "dlsym":
            if let p = anyTaintedArg() {
                emitTaint("Code Injection", .high,
                          "dlsym resolves a caller-influenced symbol.", path: p)
            }
        case "predicateWithFormat":
            if let p = taintedArg(0) {
                emitTaint("Code Injection", .high,
                          "predicateWithFormat builds a predicate from untrusted data (format-injection risk).", path: p)
            }
        case "valueForKeyPath":
            if let p = taintedArg(0) {
                emitTaint("Code Injection", .high,
                          "valueForKeyPath traverses a caller-influenced key path.", path: p)
            }
        case "NSClassFromString", "NSSelectorFromString":
            if let p = taintedArg(0) {
                emitTaint("Code Injection", .high,
                          "\(name) resolves a caller-influenced class/selector for dynamic dispatch.", path: p)
            }

        // Walk 1: TOCTOU on renames.
        case "rename":
            if let p = taintedArg(0) {
                emitTaint("TOCTOU / Race Condition", .medium,
                          "rename operates on a path that can change between check and use.", path: p)
            }

        default:
            break
        }
        return out
    }

    // MARK: - Walk 3: marker tables

    private struct Marker {
        let category: String
        let severity: ScanFinding.Severity
        let message: String
    }

    private func identifierMarker(_ name: String) -> Marker? {
        switch name {
        case "kSecAttrAccessibleAlways", "kSecAttrAccessibleAlwaysThisDeviceOnly":
            return Marker(category: "Insecure Keychain Accessibility", severity: .medium,
                          message: "Keychain item stays readable while the device is locked.")
        case "NSFileProtectionNone":
            return Marker(category: "Insecure File Protection", severity: .medium,
                          message: "File data is stored without at-rest encryption.")
        case "NSAllowsArbitraryLoads":
            return Marker(category: "App Transport Security Bypass", severity: .medium,
                          message: "ATS is globally disabled; plaintext HTTP traffic is permitted.")
        case "UIWebView":
            return Marker(category: "Deprecated Insecure WebView", severity: .medium,
                          message: "UIWebView is deprecated and lacks WebKit process isolation.")
        case "NSUserDefaults":
            return Marker(category: "Insecure UserDefaults Storage", severity: .medium,
                          message: "UserDefaults stores data unencrypted and is readable by backups/other tooling.")
        case "MFMessageComposeViewController":
            return Marker(category: "Unsolicited Message Send", severity: .medium,
                          message: "App composes SMS on the user's behalf; verify recipient and body are user-initiated.")
        case "MFMailComposeViewController":
            return Marker(category: "Unsolicited Message Send", severity: .medium,
                          message: "App composes mail on the user's behalf; verify content provenance.")
        case "CNContactStore", "ABAddressBook", "ABAddressBookRef":
            return Marker(category: "Privacy Data Access", severity: .medium,
                          message: "Address-book access surfaces personal contact data.")
        case "UIPasteboard":
            return Marker(category: "Sensitive Data in Clipboard", severity: .medium,
                          message: "Clipboard is readable system-wide by other apps.")
        case "UNMutableNotificationContent":
            return Marker(category: "Notification Injection", severity: .low,
                          message: "Notification content should be validated before display.")
        case "NSKeyedArchiver":
            return Marker(category: "Insecure Deserialization", severity: .high,
                          message: "Keyed archiver output can be tampered with; validate on read-back.")
        case "NSKeyedUnarchiver", "NSPropertyListSerialization":
            return Marker(category: "Insecure Deserialization", severity: .high,
                          message: "Deserializing stored objects executes their classes; validate provenance first.")
        default:
            return nil
        }
    }

    private func receiverMarker(_ name: String) -> Marker? {
        // Same taxonomy as bare identifiers: class names used as receivers.
        return identifierMarker(name)
    }

    private func selectorMarker(_ selector: String) -> Marker? {
        switch selector {
        case "setAllowsArbitraryLoads:", "setAllowsArbitraryLoadsForMedia:",
             "setAllowsArbitraryLoadsInWebContent:":
            return Marker(category: "App Transport Security Bypass", severity: .medium,
                          message: "ATS relaxation enabled at runtime.")
        case "startUpdatingLocation", "requestWhenInUseAuthorization",
             "requestAlwaysAuthorization", "startMonitoringSignificantLocationChanges":
            return Marker(category: "Sensitive Location Usage", severity: .low,
                          message: "Location tracking surface; ensure purpose strings and minimization.")
        case "openURL:", "openURL:options:completionHandler:":
            return Marker(category: "Open Redirect / URL Scheme Exposure", severity: .medium,
                          message: "Opens an externally-controlled URL; validate the destination scheme/host.")
        case "evaluateJavaScript:", "evaluateJavaScript:completionHandler:":
            return Marker(category: "WebView JavaScript Injection", severity: .high,
                          message: "Runs JavaScript in the webview; content must not be attacker-controlled.")
        case "loadHTMLString:", "loadRequest:", "stringByEvaluatingJavaScriptFromString:":
            return Marker(category: "XSS (HTML Injection)", severity: .high,
                          message: "Legacy webview content surface; attacker-influenced content executes in-process.")
        default:
            return nil
        }
    }

    private struct TaintSinkRule {
        let category: String
        let severity: ScanFinding.Severity
        let message: (String) -> String
    }

    private func selectorTaintSink(_ selector: String) -> TaintSinkRule? {
        switch selector {
        case "loadHTMLString:":
            return TaintSinkRule(category: "XSS (HTML Injection)", severity: .high) { sel in
                "loadHTMLString renders untrusted HTML in the webview (\(sel))."
            }
        case "dataWithContentsOfURL:", "stringWithContentsOfURL:":
            return TaintSinkRule(category: "SSRF", severity: .high) { sel in
                "\(sel) fetches an externally-influenced URL from the device."
            }
        case "requestWithURL:", "requestWithURL:cachePolicy:",
             "connectionWithRequest:", "connectionWithURL:",
             "dataTaskWithURL:", "dataTaskWithRequest:",
             "downloadTaskWithURL:", "downloadTaskWithRequest:",
             "uploadTaskWithRequest:":
            return TaintSinkRule(category: "SSRF", severity: .high) { sel in
                "\(sel) builds a network request from an externally-influenced URL."
            }
        case "performSelector:":
            return TaintSinkRule(category: "Code Injection", severity: .high) { sel in
                "\(sel) invokes a caller-influenced selector."
            }
        case "predicateWithFormat:":
            return TaintSinkRule(category: "Code Injection", severity: .high) { sel in
                "\(sel) builds a predicate from untrusted data (format-injection risk)."
            }
        case "valueForKeyPath:":
            return TaintSinkRule(category: "Code Injection", severity: .high) { sel in
                "\(sel) traverses a caller-influenced key path."
            }
        default:
            return nil
        }
    }

    // MARK: - Walk 1: taint evaluation

    /// Returns the taint path when the expression *yields* untrusted data.
    private func exprTaintPath(_ e: ObjCExpr, tainted: [String: [String]]) -> [String]? {
        switch e {
        case .identifier(let name, _):
            return tainted[name]
        case .paren(let inner, _):
            return exprTaintPath(inner, tainted: tainted)
        case .string, .number:
            return nil
        case .member(let base, _, _):
            return exprTaintPath(base, tainted: tainted)
        case .index(let base, _, _):
            return exprTaintPath(base, tainted: tainted)
        case .unary(_, let operand, _):
            return exprTaintPath(operand, tainted: tainted)
        case .binary(_, let lhs, let rhs, _):
            return exprTaintPath(lhs, tainted: tainted) ?? exprTaintPath(rhs, tainted: tainted)
        case .ternary(_, let thenE, let elseE, _):
            return exprTaintPath(thenE, tainted: tainted) ?? exprTaintPath(elseE, tainted: tainted)
        case .call(let name, let args, _):
            // Validation/sanitization helpers return an allowlisted copy (or nil);
            // their result is clean even when a parameter is passed in.
            if isSanitizerFunctionName(name) { return nil }
            if taintReturning.contains(name) { return [name] }
            for a in args {
                if let p = exprTaintPath(a, tainted: tainted) { return p }
            }
            return nil
        case .message(let receiver, let parts, _):
            // A message whose selector names a taint-returning method (defined in
            // another file, or locally) taints its result exactly like the `.call`
            // rule above: `[obj fetchUnsafe]` propagates like `fetchUnsafe()`, so a
            // cross-file ObjC method returning attacker-controlled data is treated
            // as a source at the call site. Method keys are the bare first selector
            // segment, so strip the trailing ':'. Framework methods are never in the
            // set (only methods defined in the scanned project are), so this cannot
            // mask the always-source/conditional rules below.
            if let sel = parts.first?.selector {
                let base = sel.hasSuffix(":") ? String(sel.dropLast()) : sel
                if isSanitizerFunctionName(base) { return nil }
                if taintReturning.contains(base) || crossFileSources.contains(base) {
                    return [base]
                }
            }
            // Conditional sources: URLWithString: propagates its argument — unless
            // the argument is the result of an https normalization (the original
            // url's scheme has already been forced to HTTPS at this point).
            for part in parts {
                if part.selector == "URLWithString:", let arg = part.arg {
                    if exprIsHTTPSNormalized(arg) { return nil }
                    if case .identifier(let n, _) = arg, httpsSafeVars.contains(n) { return nil }
                    if let p = exprTaintPath(arg, tainted: tainted) {
                        return p
                    }
                }
            }
            // Always-sources: reading external content taints the result.
            let sel = parts.first?.selector ?? ""
            if sel == "dataWithContentsOfURL:" || sel == "stringWithContentsOfURL:" ||
               sel == "dataWithContentsOfFile:" || sel == "stringWithContentsOfFile:" {
                let root = sel.hasSuffix("OfURL:")
                    ? (parts.first?.arg.flatMap { exprTaintPath($0, tainted: tainted) } ?? nil) ?? ["\(sel)"]
                    : ["\(sel)"]
                return root
            }
            // `[[X alloc] initWith...:t]` style flows.
            for part in parts {
                if let arg = part.arg, let p = exprTaintPath(arg, tainted: tainted) {
                    return p
                }
            }
            if let r = receiver, let p = exprTaintPath(r, tainted: tainted) {
                return p
            }
            return nil
        case .arrayLiteral(let items, _):
            for i in items {
                if let p = exprTaintPath(i, tainted: tainted) { return p }
            }
            return nil
        case .dictLiteral(let entries, _):
            for entry in entries {
                if let p = exprTaintPath(entry.value, tainted: tainted) { return p }
            }
            return nil
        case .unknown:
            return nil
        }
    }

    // MARK: - Helpers

    private func nonNil(_ e: ObjCExpr) -> ObjCExpr? {
        if case .identifier(let n, _) = e, n == "nil" || n == "NULL" || n == "Nil" { return nil }
        return e
    }

    /// True when the expression is a plain string literal (`@"..."`).
    private func isStringLiteral(_ e: ObjCExpr) -> Bool {
        if case .string = e { return true }
        return false
    }

    /// Unwraps variadic comma-folds (`a, b, c` → `a`): the first item of a
    /// message argument list is the format; the rest are its data.
    private func firstFoldedItem(_ e: ObjCExpr) -> ObjCExpr {
        if case .binary(let op, let lhs, _, _) = e, op == "," {
            return firstFoldedItem(lhs)
        }
        return e
    }

    /// True when the taint path's root identifier was guard-validated in this
    /// function — the value passed a validation/sanitization guard before use.
    private func isGuardValidated(root: String?) -> Bool {
        guard let root = root else { return false }
        return guardValidated.contains(root)
    }

    /// True when the message selector writes a value into a container — the
    /// contexts in which a weak file-protection constant is actually applied.
    private func isWriteSelector(_ selector: String) -> Bool {
        switch selector {
        case "setObject:forKey:", "setObject:forKeyedSubscript:",
             "setObject:atIndexedSubscript:", "setValue:forKey:",
             "setValue:forUndefinedKey:", "setFileProtection:",
             "addObject:", "insertObject:atIndex:", "setValue:forKeyPath:":
            return true
        default:
            return false
        }
    }

    /// The underlying identifier when `e` is a plain identifier or a C-style
    /// cast wrapping one (`(__bridge id)kSecAttrAccessible`); nil otherwise.
    private func leafIdentifierName(_ e: ObjCExpr) -> String? {
        switch e {
        case .identifier(let name, _):
            return name
        case .paren(let inner, _):
            return leafIdentifierName(inner)
        case .call(let name, let args, _):
            // __bridge / __bridge_retained / __bridge_transfer casts of a
            // constant appear as a call named after the cast keyword.
            let bridgeCasts: Set<String> = ["__bridge", "__bridge_retained", "__bridge_transfer"]
            if bridgeCasts.contains(name), let arg = args.first {
                return leafIdentifierName(arg)
            }
            return nil
        default:
            return nil
        }
    }

    /// True when a dictionary literal expressly sets the keychain accessibility
    /// key to a secure when-unlocked / after-first-unlock value — the case in
    /// which `SecItemAdd` should NOT warrant the storage-policy marker.
    private func dictHasSecureKeychainAccessibility(_ entries: [(key: ObjCExpr, value: ObjCExpr)]) -> Bool {
        let secureValues: Set<String> = [
            "kSecAttrAccessibleWhenUnlocked",
            "kSecAttrAccessibleWhenUnlockedThisDeviceOnly",
            "kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly",
            "kSecAttrAccessibleAfterFirstUnlock",
            "kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly",
        ]
        for entry in entries {
            guard leafIdentifierName(entry.key) == "kSecAttrAccessible",
                  let v = leafIdentifierName(entry.value),
                  secureValues.contains(v) else { continue }
            return true
        }
        return false
    }

    /// True when `e` is (or wraps, through casts/parens) a dictionary literal
    /// with a secure keychain accessibility value.
    private func exprHasSecureKeychainAccessibility(_ e: ObjCExpr) -> Bool {
        switch e {
        case .dictLiteral(let entries, _):
            return dictHasSecureKeychainAccessibility(entries)
        case .paren(let inner, _):
            return exprHasSecureKeychainAccessibility(inner)
        case .call(_, let args, _):
            return args.contains { exprHasSecureKeychainAccessibility($0) }
        case .member(let base, _, _):
            return exprHasSecureKeychainAccessibility(base)
        default:
            return false
        }
    }

    // MARK: - Guard-clause analysis

    /// The root variable identifier in an expression (the leftmost name after
    /// stripping member chains, message receivers, casts and parens).
    private func rootIdentifier(_ e: ObjCExpr) -> String? {
        switch e {
        case .identifier(let n, _): return n
        case .member(let base, _, _): return rootIdentifier(base)
        case .message(let receiver, _, _): return receiver.flatMap(rootIdentifier)
        case .paren(let inner, _): return rootIdentifier(inner)
        case .call(_, let args, _): return args.first.flatMap(rootIdentifier)
        default: return nil
        }
    }

    /// Scan a guard-clause expression (`if (!IsValid(x)) return NO;`) and
    /// register every root identifier passed to a sanitizer-named call as
    /// guard-validated.  Sinks fed by a guard-validated root are suppressed.
    private func guardExprDetectGuards(_ e: ObjCExpr) {
        switch e {
        case .unary(_, let operand, _):
            guardExprDetectGuards(operand)
        case .binary(_, let lhs, let rhs, _):
            guardExprDetectGuards(lhs)
            guardExprDetectGuards(rhs)
            if let root = isHTTPSValidatingCondition(e) {
                guardValidated.insert(root)
            }
        case .call(let name, let args, _):
            if isSanitizerFunctionName(name) {
                for a in args {
                    if let root = rootIdentifier(a) {
                        self.guardValidated.insert(root)
                    }
                }
            }
case .message(let receiver, let parts, _):
            if let r = receiver { guardExprDetectGuards(r) }
            for p in parts { if let a = p.arg { guardExprDetectGuards(a) } }
            if let root = isHTTPSValidatingCondition(e) {
                guardValidated.insert(root)
            }
        case .paren(let inner, _):
            guardExprDetectGuards(inner)
        default:
            break
        }
    }

    /// The unquoted content of a string-literal token (the parser keeps the
    /// surrounding `"` characters in the token text).
    private func unquote(_ s: String) -> String {
        var t = s
        if t.hasPrefix("\""), t.hasSuffix("\"") && t.count >= 2 {
            t.removeFirst()
            t.removeLast()
        }
        return t
    }

    /// True when `e` is the result of an https/wss protocol normalization —
    /// e.g. `stringByReplacingOccurrencesOfString:@"http://" withString:@"https://"`.
    /// A URL created from such a string is scheme-validated by construction.
    private func exprIsHTTPSNormalized(_ e: ObjCExpr) -> Bool {
        if case .message(_, let parts, _) = e {
            if parts.first?.selector == "stringByReplacingOccurrencesOfString:" {
                for p in parts where p.selector == "withString:" {
                    if case .string(let s, _)? = p.arg, unquote(s).hasPrefix("https") {
                        return true
                    }
                }
            }
        }
        return false
    }

    /// Whether `e` is an https-normalizing expression itself, or a URL built
    /// (`URLWithString:`) from a tracked https-safe value. Used to register
    /// variable names in `httpsSafeVars`.
    private func exprTransportsToHTTPS(_ e: ObjCExpr, tracked: Set<String>) -> Bool {
        if exprIsHTTPSNormalized(e) { return true }
        if case .message(_, let parts, _) = e, parts.first?.selector == "URLWithString:" {
            if let a = parts.first?.arg {
                if let root = rootIdentifier(a), tracked.contains(root) { return true }
                if exprTransportsToHTTPS(a, tracked: tracked) { return true }
            }
        }
        return false
    }

    /// The root variable when `e` is a transport-protection condition: a
    /// `hasPrefix:@"https://"` / `@"wss://"` check on a URL, or an
    /// `isEqualToString:@"https"` check on its `.scheme` member, or a
    /// bare `==` on `.scheme`.
    private func isHTTPSValidatingCondition(_ e: ObjCExpr) -> String? {
        switch e {
        case .message(let receiver, let parts, _):
            guard let sel = parts.first?.selector else { return nil }
            if sel == "hasPrefix:" {
                guard let r = receiver, let root = rootIdentifier(r) else { return nil }
                if case .string(let s, _)? = parts.first?.arg,
                   unquote(s) == "https://" || unquote(s) == "wss://" {
                    return root
                }
            }
            if sel == "isEqualToString:" {
                // Receiver should be `x.scheme`; check that and confirm literal.
                if let r = receiver, let root = schemeRootForHTTPSCheck(r) {
                    if case .string(let s, _)? = parts.first?.arg,
                       unquote(s) == "https" || unquote(s) == "wss" {
                        return root
                    }
                }
            }
            return nil
        case .binary(let op, let lhs, let rhs, _):
            if op == "==" {
                if let root = schemeRootForHTTPSCheck(lhs),
                   isHTTPSStringLiteral(rhs) { return root }
                if let root = schemeRootForHTTPSCheck(rhs),
                   isHTTPSStringLiteral(lhs) { return root }
            }
            return nil
        default:
            return nil
        }
    }

    /// Root identifier when `e` is `x.scheme` (member `.scheme` of a name).
    private func schemeRootForHTTPSCheck(_ e: ObjCExpr) -> String? {
        if case .member(let base, let name, _) = e, name == "scheme" {
            return rootIdentifier(base)
        }
        return nil
    }

    /// True when `e` is a string literal whose value is `https` or `wss`.
    private func isHTTPSStringLiteral(_ e: ObjCExpr) -> Bool {
        if case .string(let s, _) = e { return unquote(s) == "https" || unquote(s) == "wss" }
        return false
    }

    /// True when the method's bodies perform a keyed write into an
    /// NSUserDefaults-style preference store. Used to keep the insecure-storage
    /// marker only on methods that actually persist data.
    private func exprWritesUserDefaults(_ e: ObjCExpr) -> Bool {
        switch e {
        case .message(let receiver, let parts, _):
            let sels = parts.map { $0.selector }
            if sels.contains("removeObjectForKey:") || sels.contains("removePersistentDomainForName:") { return true }
            // `[defaults setObject:x forKey:k]` parses as two selector parts
            // (`setObject:` + `forKey:`); a keyed setter pasting into defaults
            // is the actionable write. (Other keyed containers like dictionaries
            // also match — that only ever keeps a marker, never wrongly suppresses.)
            let hasKeyedSet = sels.contains(where: { $0.hasSuffix("forKey:") || $0.hasSuffix("forKeyedSubscript:") || $0.hasSuffix("forKeyPath:") })
                && sels.contains(where: { $0.hasPrefix("set") && $0.hasSuffix(":") })
            if hasKeyedSet { return true }
            if let r = receiver, exprWritesUserDefaults(r) { return true }
            for p in parts {
                if let a = p.arg, exprWritesUserDefaults(a) { return true }
            }
            return false
        case .member(let base, _, _):
            return exprWritesUserDefaults(base)
        case .call(_, let args, _):
            return args.contains { exprWritesUserDefaults($0) }
        case .index(let base, let index, _):
            return exprWritesUserDefaults(base) || exprWritesUserDefaults(index)
        case .binary(_, let lhs, let rhs, _):
            return exprWritesUserDefaults(lhs) || exprWritesUserDefaults(rhs)
        case .ternary(let cond, let thenE, let elseE, _):
            return exprWritesUserDefaults(cond) || exprWritesUserDefaults(thenE) || exprWritesUserDefaults(elseE)
        case .unary(_, let operand, _):
            return exprWritesUserDefaults(operand)
        case .paren(let inner, _):
            return exprWritesUserDefaults(inner)
        case .arrayLiteral(let items, _):
            return items.contains { exprWritesUserDefaults($0) }
        case .dictLiteral(let entries, _):
            return entries.contains { exprWritesUserDefaults($0.key) || exprWritesUserDefaults($0.value) }
        case .identifier, .string, .number, .unknown:
            return false
        }
    }

    private func statementsWriteUserDefaults(_ stmts: [ObjCStmt]) -> Bool {
        for s in stmts {
            switch s.kind {
            case .declaration(_, _, _, _, let initExpr):
                if let e = initExpr, exprWritesUserDefaults(e) { return true }
            case .assignment(_, let value):
                if exprWritesUserDefaults(value) { return true }
            case .expression(let e), .condition(let e):
                if exprWritesUserDefaults(e) { return true }
            case .returnStmt(let e):
                if let e = e, exprWritesUserDefaults(e) { return true }
            }
        }
        return false
    }

    private func targetTrailingName(_ target: ObjCExpr) -> String? {
        switch target {
        case .identifier(let n, _):
            return n
        case .index(let base, _, _):
            return targetTrailingName(base)
        case .member(let base, _, _):
            return targetTrailingName(base)
        case .paren(let inner, _):
            return targetTrailingName(inner)
        default:
            return nil
        }
    }

    private func bufferName(_ e: ObjCExpr) -> String {
        if case .identifier(let n, _) = e { return n }
        return ""
    }

    /// The receiver's class/variable name when it is a bare identifier or a
    /// chain rooted at one — used for receiver class markers.
    private func staticReceiverName(_ r: ObjCExpr) -> String? {
        switch r {
        case .identifier(let n, _):
            return n
        case .member(let base, _, _):
            return staticReceiverName(base)
        default:
            return nil
        }
    }

    // MARK: - File-level scans

    /// Transport plaintext and websocket scheme literals in ObjC files.
    static func scanFileLevel(url: URL, source: String, scanningSource: String) -> [ScanFinding] {
        var out: [ScanFinding] = []
        let ns = source as NSString
        func lineOf(_ location: Int) -> Int {
            let prefix = ns.substring(to: min(location, ns.length))
            return prefix.components(separatedBy: "\n").count
        }
        func scan(_ needle: String, _ category: String, _ severity: ScanFinding.Severity, _ message: String) {
            var searchRange = NSRange(location: 0, length: ns.length)
            while searchRange.location < ns.length {
                let found = ns.range(of: needle, options: [], range: searchRange)
                if found.location == NSNotFound { break }
                // Bare scheme tokens (`@"http://"` used as a replacement/label
                // operand) carry no host and are text, not a transport endpoint.
                let afterLoc = found.location + found.length
                let isBareSchemeLiteral = afterLoc < ns.length
                    && (ns.character(at: afterLoc) == 0x22 || ns.character(at: afterLoc) == 0x27) // " '
                // Skip comment lines.
                let lineStart = (source as NSString).lineRange(for: NSRange(location: found.location, length: 0)).location
                let lineText = ns.substring(with: NSRange(location: lineStart,
                                                          length: min(120, ns.length - lineStart)))
                    .trimmingCharacters(in: .whitespaces)
                if !isBareSchemeLiteral,
                   !lineText.hasPrefix("//") && !lineText.hasPrefix("*") && !lineText.hasPrefix("/*") {
                    out.append(ScanFinding(fileURL: url,
                                           line: lineOf(found.location),
                                           function: "",
                                           category: category,
                                           message: message,
                                           taint: nil,
                                           severity: severity,
                                           exploitability: severity,
                                           reachable: false,
                                           taintPath: nil,
                                           ignored: false,
                                           scanningSource: scanningSource))
                }
                searchRange = NSRange(location: found.location + max(found.length, 1),
                                      length: ns.length - (found.location + max(found.length, 1)))
            }
        }
        scan("http://", "Insecure Transport", .medium,
             "Plaintext HTTP transport in an ObjC source; use HTTPS/ATS.")
        scan("ws://", "Insecure WebSocket", .medium,
             "Unencrypted WebSocket endpoint in an ObjC source; use wss://.")
        return out
    }
}

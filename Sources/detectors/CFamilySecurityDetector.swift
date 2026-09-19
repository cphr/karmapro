// by cipher.org.uk
// MARK: - C/C++-specific AST security checks
// Extracted from AstSecurityDetector.swift to keep per-language vulnerability
// detection modular. Shared wire-up stays in AstSecurityDetector.swift
// (dispatch lines only). Rust lives in RustSecurityDetector.swift.

import Foundation

extension AstSecurityDetector {

    /// C-family sinks (C / C++ / ObjC). Lowercase library functions such as
    /// `strcpy`, `printf` and `fopen`. Kernel categories are owned by the
    /// dedicated KernelAstDetector and are intentionally absent here.

    static let cSinks: [String: AstSinkRule] = [
        "strcpy": .init(category: "Buffer Overflow", severity: .high, vulnArgIndex: 1, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "strcat": .init(category: "Buffer Overflow", severity: .high, vulnArgIndex: 1, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "wcscpy": .init(category: "Buffer Overflow", severity: .high, vulnArgIndex: 1, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "gets": .init(category: "Buffer Overflow", severity: .critical, vulnArgIndex: 0, alwaysVulnerable: true, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "sprintf": .init(category: "Buffer Overflow / Format String", severity: .high, vulnArgIndex: 1, alwaysVulnerable: true, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "vsprintf": .init(category: "Buffer Overflow / Format String", severity: .high, vulnArgIndex: 1, alwaysVulnerable: true, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "printf": .init(category: "Format String", severity: .medium, vulnArgIndex: nil, alwaysVulnerable: false, formatArgIndex: 0, bufferOverflowOnFormat: false),
        "fprintf": .init(category: "Format String", severity: .medium, vulnArgIndex: nil, alwaysVulnerable: false, formatArgIndex: 1, bufferOverflowOnFormat: false),
        "syslog": .init(category: "Format String", severity: .medium, vulnArgIndex: nil, alwaysVulnerable: false, formatArgIndex: 1, bufferOverflowOnFormat: false),
        "system": .init(category: "Command Injection", severity: .high, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "popen": .init(category: "Command Injection", severity: .high, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "open": .init(category: "Path Traversal", severity: .medium, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "fopen": .init(category: "Path Traversal", severity: .medium, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "creat": .init(category: "Path Traversal", severity: .medium, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "remove": .init(category: "Path Traversal", severity: .medium, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "sqlite3_exec": .init(category: "SQL Injection", severity: .high, vulnArgIndex: 1, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "sqlite3_prepare": .init(category: "SQL Injection", severity: .high, vulnArgIndex: 1, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "sqlite3_prepare_v2": .init(category: "SQL Injection", severity: .high, vulnArgIndex: 1, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "scanf": .init(category: "Buffer Overflow", severity: .high, vulnArgIndex: nil, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: true),
        "sscanf": .init(category: "Buffer Overflow", severity: .medium, vulnArgIndex: nil, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: true),
        "fscanf": .init(category: "Buffer Overflow", severity: .medium, vulnArgIndex: nil, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: true),
        "MD5": .init(category: "Weak Cryptography (MD5 / SHA-1 / DES / RC4)", severity: .high, vulnArgIndex: nil, alwaysVulnerable: true, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "MD5_Init": .init(category: "Weak Cryptography (MD5 / SHA-1 / DES / RC4)", severity: .medium, vulnArgIndex: nil, alwaysVulnerable: true, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "MD5_Update": .init(category: "Weak Cryptography (MD5 / SHA-1 / DES / RC4)", severity: .medium, vulnArgIndex: nil, alwaysVulnerable: true, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "MD5_Final": .init(category: "Weak Cryptography (MD5 / SHA-1 / DES / RC4)", severity: .medium, vulnArgIndex: nil, alwaysVulnerable: true, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "EVP_md5": .init(category: "Weak Cryptography (MD5 / SHA-1 / DES / RC4)", severity: .medium, vulnArgIndex: nil, alwaysVulnerable: true, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "SHA1": .init(category: "Weak Cryptography (MD5 / SHA-1 / DES / RC4)", severity: .high, vulnArgIndex: nil, alwaysVulnerable: true, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "SHA1_Init": .init(category: "Weak Cryptography (MD5 / SHA-1 / DES / RC4)", severity: .medium, vulnArgIndex: nil, alwaysVulnerable: true, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "EVP_sha1": .init(category: "Weak Cryptography (MD5 / SHA-1 / DES / RC4)", severity: .medium, vulnArgIndex: nil, alwaysVulnerable: true, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "DES_ecb_encrypt": .init(category: "Weak Cryptography (MD5 / SHA-1 / DES / RC4)", severity: .high, vulnArgIndex: nil, alwaysVulnerable: true, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "DES_cbc_encrypt": .init(category: "Weak Cryptography (MD5 / SHA-1 / DES / RC4)", severity: .high, vulnArgIndex: nil, alwaysVulnerable: true, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "EVP_des_ecb": .init(category: "Weak Cryptography (MD5 / SHA-1 / DES / RC4)", severity: .medium, vulnArgIndex: nil, alwaysVulnerable: true, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "RC4": .init(category: "Weak Cryptography (MD5 / SHA-1 / DES / RC4)", severity: .high, vulnArgIndex: nil, alwaysVulnerable: true, formatArgIndex: nil, bufferOverflowOnFormat: false),
        // Kernel categories are owned by the dedicated KernelAstDetector (taint,
        // bounds and boundary walks), so they are intentionally not registered as
        // generic C sinks here.
        "snprintf": .init(category: "Format String / Buffer Overflow", severity: .medium, vulnArgIndex: 2, alwaysVulnerable: false, formatArgIndex: 2, bufferOverflowOnFormat: true),
        "vsnprintf": .init(category: "Format String", severity: .medium, vulnArgIndex: 2, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "strncpy": .init(category: "Buffer Overflow", severity: .low, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "strncat": .init(category: "Buffer Overflow", severity: .low, vulnArgIndex: 2, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "memcpy": .init(category: "Buffer Overflow", severity: .medium, vulnArgIndex: 2, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
        "memmove": .init(category: "Buffer Overflow", severity: .medium, vulnArgIndex: 2, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
    ]



    /// C-family sink evaluation. Also shared by the Java/C# paths (their
    /// detector files layer the language-specific tables on top of this one).
    func checkCSinks(name: String, args: [CExpr], offset: Int, function: String, tainted: Set<String>, crossTainted: Set<String>, guarded: Set<String>, sizeBounded: Set<String>, findings: inout [AstFinding], reachable: Bool, calleeIsMember: Bool) {

        guard let rule = Self.cSinks[name] else { return }
        // C/C++/ObjC: a bare-name free-function sink reached through a member
        // access (`->`/`.`) is a struct/ops-table callback or object method
        // dispatch (`h5->vnd->open(h5)`, `p->read(buf)`), not a call to the C
        // library function of the same name. Bare-name rules never apply to
        // member calls. (Java/C# method sinks such as `stmt.execute(...)` must
        // keep flowing through this table.)
        if calleeIsMember, !isJava, !isCSharp,
           !name.contains("."), !name.contains("::") {
            return
        }
        // A bare, unqualified sink name that is also a user-defined function in
        // the project shadows the C library symbol at the call site:
        // `Session::open(id)` (via a local `open(...)` call inside a namespace)
        // must not be treated as the POSIX `open()` path-traversal sink. Keep the
        // `::`-qualified and library member forms intact.
        if !isJava, !isCSharp, !name.contains("."), !name.contains("::"),
           userDefinedFunctions.contains(name) {
            return
        }
        if rule.alwaysVulnerable {
            // sprintf/vsprintf with a *constant* format string that has no
            // unbounded `%s` specifier produces a bounded number of characters
            // (numeric/char specifiers have a known max width) and cannot
            // overflow a destination sized for the format. Only a non-literal
            // format or an unbounded `%s` is a real overflow risk.
            if (name == "sprintf" || name == "vsprintf"), args.count > 1,
               let lit = stringLiteralOf(args[1]),
               !containsUnboundedFormatSpecifier(lit) {
                return
            }
            emit(&findings, function, offset, rule, message: "\(name) is unbounded and can overflow the destination buffer.", taint: nil, reachable: reachable, crossFile: false)
            return
        }
        if rule.category == "Buffer Overflow" {
            // Bounded string copies (strncpy / strncat / strlcpy / strlcat / *_s)
            // cap the output at an explicit count, so a tainted source or
            // destination is not an overflow on its own.
            if isBoundedStringCopy(name) { return }
            // Exact-byte copies (memcpy / memmove) are safe when their count is
            // provably bounded by an explicit guard or a `cap - 1` form.
            if isExactByteCopy(name), let szIdx = exactByteCountIndex(name),
               szIdx < args.count, sizeArgSafe(args[szIdx], sizeBounded: sizeBounded) {
                return
            }
        }
        if rule.bufferOverflowOnFormat, let fmt = stringLiteralOf(args.first),
           containsUnboundedFormatSpecifier(fmt) {
            emit(&findings, function, offset, rule, message: "\(name) uses an unbounded %s specifier and can overflow the destination buffer.", taint: nil, reachable: reachable, crossFile: false)
            return
        }
        if let fmt = rule.formatArgIndex, fmt < args.count {
            if case .stringLiteral = args[fmt] {} else if case .identifier(let fmtVar, _) = args[fmt],
               constantStringRef.vars.contains(fmtVar) || stringMacros[fmtVar] != nil
                || globalConstantFormats.contains(fmtVar) {
                // The format argument is a variable only ever assigned string
                // literals, an object-like macro expanding to a string literal,
                // or a project-wide global `const char*` constant — a constant
                // format string in all three cases.
            } else {
                emit(&findings, function, offset, rule, message: "Non-constant \(name) format string.", taint: nil, reachable: reachable, crossFile: false)
                return
            }
            // A constant format string is safe regardless of how tainted the
            // remaining arguments are (`printf("%s", argv[1])` is correct C) —
            // don't fall through to the generic taint evaluation below.
            return
        }
        if let vi = rule.vulnArgIndex, vi < args.count {
            if exprTainted(args[vi], tainted: tainted) != nil,
               !isGuarded(args[vi], guarded: guarded, category: rule.category) {
                emit(&findings, function, offset, rule, message: "\(name) receives data that flows from an untrusted source.", taint: taintLabel(args[vi], tainted: tainted), reachable: reachable, crossFile: exprCrossFile(args[vi], crossTainted: crossTainted))
            }
        } else {
            // Evaluate all args generically.
            if args.contains(where: { exprTainted($0, tainted: tainted) != nil && !isGuarded($0, guarded: guarded, category: rule.category) }) {
                let cross = args.contains(where: { exprCrossFile($0, crossTainted: crossTainted) })
                emit(&findings, function, offset, rule, message: "\(name) called with potentially untrusted data.", taint: nil, reachable: reachable, crossFile: cross)
            }
        }
    }

    /// True for bounded-length string-copy sinks whose explicit count caps the
    /// destination write (`strncpy`, `strncat`, `strlcpy`, `strlcat`, `*_s`).
    private func isBoundedStringCopy(_ name: String) -> Bool {
        let prefixes = ["strncpy", "strncat", "strlcpy", "strlcat"]
        for p in prefixes where name == p || name.hasSuffix("_" + p) { return true }
        return name.hasSuffix("_s")
    }

    /// True for exact-byte copy sinks (`memcpy` / `memmove`).
    private func isExactByteCopy(_ name: String) -> Bool {
        name == "memcpy" || name == "memmove"
    }

    /// The argument index holding the byte count for an exact-byte copy.
    private func exactByteCountIndex(_ name: String) -> Int? {
        isExactByteCopy(name) ? 2 : nil
    }

    /// True if a scanf-style format string contains an unbounded `%s` (a `%s`
    /// not bounded by a maximum width like `%10s`, `%[Ns]` or `%15s`).
    private func containsUnboundedFormatSpecifier(_ format: String) -> Bool {
        let chars = Array(format)
        var i = 0
        while i < chars.count {
            if chars[i] == "%" {
                var j = i + 1
                if j < chars.count && chars[j] == "%" { i += 2; continue }
                var sawBounded = false
                var sawS = false
                while j < chars.count {
                    let c = chars[j]
                    if c == "s" {
                        sawS = true
                        break
                    }
                    if CharacterSet.decimalDigits.contains(c.unicodeScalars.first!) {
                        sawBounded = true
                    }
                    if c == "[" { sawBounded = true }
                    j += 1
                    if c == " " || c.isLetter && c != "s" && c != "h" && c != "l" && c != "L" && c != "z" && c != "j" && c != "t" && c != "*" { break }
                }
                if sawS && !sawBounded { return true }
            }
            i += 1
        }
        return false
    }


    // MARK: - Userspace memory safety (double free / use after free / leak)

    /// Linear per-function walk that tracks heap pointers in execution order to
    /// report (a) double `free`/`delete`, (b) use of a freed pointer, and (c)
    /// allocations that never escape and are never released. Kernel-shaped
    /// files are excluded (the KernelAstDetector owns those categories).

    func checkMemorySafety(fn: CFunctionDef, function: String, findings: inout [AstFinding], reachable: Bool) {
        // Functions whose body returns a directly-malloc'd local: calls to them
        // yield heap pointers, so `x = heapReturningFn()` seeds an allocation.
        let heapReturners = heapReturningFunctionNames()
        var allocs: [String: Int] = [:]     // local -> allocation offset
        var freed: [String: Int] = [:]      // local -> free offset
        var reportedUAF = Set<String>()
        var paramFreed: [String: Int] = [:]
        var escapedVars = Set<String>()
        // Allocations stored into member/index targets (`outerArray[i] = malloc(...)`,
        // `p->innerArray = malloc(...)`). Keyed by the structured LHS text so the
        // matching `free(outerArray[i])` releases them and a missing release is
        // reported as a leak (the struct outer array is freed, its inner arrays not).
        var keyAllocs: [String: Int] = [:]
        var keyFreed = Set<String>()
        // Names already reported as leaking (branch leak + fallthrough guard), so
        // one path-specific leak is not reported twice per allocation.
        var leakReported = Set<String>()

        func markAlloc(_ name: String, _ offset: Int) {
            allocs[name] = offset
            freed[name] = nil
            paramFreed[name] = nil
        }

        // Collect the plain identifiers used inside an expression.
        func usedIdents(_ e: CExpr, into out: inout [(String, Int)]) {
            switch e {
            case .identifier(let n, let o): out.append((n, o))
            case .unary(_, let x, _), .cast(let x, _), .paren(let x, _):
                usedIdents(x, into: &out)
            case .binary(_, let l, let r, _), .comma(let l, let r, _):
                usedIdents(l, into: &out); usedIdents(r, into: &out)
            case .ternary(let c, let t, let f, _):
                usedIdents(c, into: &out); usedIdents(t, into: &out); usedIdents(f, into: &out)
            case .assign(_, let l, let r, _):
                usedIdents(l, into: &out); usedIdents(r, into: &out)
            case .call(let callee, let args, _):
                usedIdents(callee, into: &out)
                for a in args { usedIdents(a, into: &out) }
            case .member(let base, _, _, _):
                usedIdents(base, into: &out)
            case .index(let base, let idx, _):
                usedIdents(base, into: &out); usedIdents(idx, into: &out)
            case .arrayInit(let els, _):
                for el in els { usedIdents(el, into: &out) }
            case .newExpr(_, let args, _):
                for a in args { usedIdents(a, into: &out) }
            case .sizeOf, .lambda:
                break
            case .integerLiteral, .floatLiteral, .stringLiteral, .charLiteral, .booleanLiteral:
                break
            }
        }

        func isHeapAllocCall(_ e: CExpr) -> Bool {
            switch e {
            case .cast(let x, _), .paren(let x, _):
                return isHeapAllocCall(x)
            case .call(let callee, _, _):
                if case .identifier(let n, _) = callee {
                    if ["malloc", "calloc", "realloc", "strdup", "strndup"].contains(n) { return true }
                    // A call to an in-file function that returns a directly
                    // allocated local also yields a heap pointer.
                    if heapReturners.contains(n) { return true }
                }
                return false
            case .newExpr:
                return true
            default:
                return false
            }
        }

        // Returns true when the statement consumes identifiers (use check).
        func checkUses(_ e: CExpr) {
            var idents: [(String, Int)] = []
            usedIdents(e, into: &idents)
            for (n, o) in idents {
                guard let freeOff = freed[n] ?? paramFreed[n] else { continue }
                if reportedUAF.contains(n) { continue }
                reportedUAF.insert(n)
                findings.append(AstFinding(function: function, offset: o,
                                           category: "Use After Free",
                                           severity: .critical,
                                           message: "\(n) is used after being freed (freed at offset \(freeOff)); the pointer may reference reclaimed memory.",
                                           taintPath: nil, reachable: reachable, crossFile: false))
            }
        }

        // A `Session* session = ...` declaration parses (C++ lacking type-aware
        // grammar) as an assignment whose LHS is the "multiplication"
        // `Session * session`. Recover the declared name from
        // pointer/reference-declaration shapes so `new Session(user)` seeding
        // and the escape test treat it as a local variable, not a member store.
        func assignedDeclName(_ e: CExpr) -> String? {
            switch e {
            case .identifier(let n, _): return n
            case .cast(let x, _), .paren(let x, _): return assignedDeclName(x)
            case .binary(let op, let l, let r, _) where op == "*" || op == "&":
                return assignedDeclName(r) ?? assignedDeclName(l)
            default: return nil
            }
        }

        // Name of a plain identifier target only — `x`, `(x)`, `(T)x` — with no
        // dereference/address-of chain. A statement parsed as `**MyStruct = malloc`
        // (a `T** p = malloc` declaration the parser does not recognize) must NOT
        // mark `MyStruct` as a heap allocation: the address it dereferences is the
        // fake variable name, not a real ownership target.
        func plainAssignedName(_ e: CExpr) -> String? {
            switch e {
            case .identifier(let n, _): return n
            case .cast(let x, _), .paren(let x, _): return plainAssignedName(x)
            default: return nil
            }
        }

        // Stable text key for a structured assignment target / free argument
        // (`outerArray[i]`, `p->innerArray`, `arr[k].field`). Two occurrences of
        // the same key are the same memory object; a free only releases its exact
        // key, so an alias mismatch (outer vs inner arrays) surfaces as a leak.
        func exprKey(_ e: CExpr) -> String? {
            switch e {
            case .identifier(let n, _): return n
            case .paren(let x, _), .cast(let x, _): return exprKey(x)
            case .index(let b, let i, _):
                guard let bk = exprKey(b), let ik = exprKey(i) else { return nil }
                return "\(bk)[\(ik)]"
            case .member(let b, let m, _, _):
                guard let bk = exprKey(b) else { return nil }
                return "\(bk).\(m)"
            default:
                return nil
            }
        }

        // Statement-level assignment handling so free → NULL rebinding clears state.
        func handleAssign(_ e: CExpr) {
            guard case .assign(let op, let lhs, let rhs, _) = e else { return }
            // Use check on the RHS first (reading freed memory).
            checkUses(rhs)
            let lhsName = assignedDeclName(lhs)
            if let name = lhsName {
                if op == "=" {
                    if plainAssignedName(lhs) != nil, isHeapAllocCall(rhs) {
                        markAlloc(name, rhs.offset)
                    } else {
                        // Reassignment breaks the freed state (free→NULL idiom or
                        // fresh ownership); the old pointer is no longer readable.
                        freed[name] = nil
                        paramFreed[name] = nil
                        allocs[name] = nil
                    }
                }
                if case .newExpr = rhs { markAlloc(name, rhs.offset) }
            } else {
                // Storing into a member/global transfers or consumes values —
                // treat reads of freed pointers there as uses (already covered
                // by checkUses on the RHS above).
                checkUses(lhs)
                if op == "=", isHeapAllocCall(rhs), let key = exprKey(lhs) {
                    // `outerArray[i] = malloc(...)`, `p->innerArray = malloc(...)`.
                    keyAllocs[key] = rhs.offset
                    keyFreed.remove(key)
                }
            }
            // Escaped allocations: returned or stored elsewhere.
            var rhsIdents: [(String, Int)] = []
            usedIdents(rhs, into: &rhsIdents)
            for (n, _) in rhsIdents where allocs[n] != nil {
                if lhsName == nil { escapedVars.insert(n) }
            }
        }

        // Reports leaks of allocations (in `allocs`) still unreleased (not in
        // `freed`) on a branch that definitely returns — those paths never
        // reach the function's end-of-path free, so a later `free()` on the
        // main line does not cover them (`if (!f) return -1;` leaks `buffer`).
        // A NULL-guard of the very allocation (`if (x == NULL) return;` after
        // `x = malloc(...)`) is the allocation-failure bail-out, not a leak.
        func reportBranchLeaks(allocs: [String: Int], freed: [String: Int],
                               escaped: Set<String>, nullChecked: String?,
                               reported: inout Set<String>) {
            for (name, off) in allocs.sorted(by: { $0.value < $1.value }) {
                guard freed[name] == nil, !escaped.contains(name),
                      name != nullChecked, reported.insert(name).inserted else { continue }
                findings.append(AstFinding(function: function, offset: off,
                                           category: "Memory Leak",
                                           severity: .medium,
                                           message: "\(name) is allocated on the heap but this early-return path leaves it unreleased; the pointer does not escape.",
                                           taintPath: nil, reachable: reachable, crossFile: false))
            }
        }

        /// The variable tested for NULL/0 in a guard condition, e.g. `x == NULL`
        /// or `!x` (used to suppress allocation-failure bail-out paths).
        func nullCheckedVariable(_ cond: CExpr) -> String? {
            switch cond {
            case .binary(let op, let l, let r, _) where op == "==":
                if case .identifier(let n, _) = unwrapExpr(l), isNullOrZero(r) { return n }
                if case .identifier(let n, _) = unwrapExpr(r), isNullOrZero(l) { return n }
                return nil
            case .unary("!", let operand, _):
                if case .identifier(let n, _) = unwrapExpr(operand) { return n }
                return nil
            default:
                return nil
            }
        }

        func isNullOrZero(_ e: CExpr) -> Bool {
            switch unwrapExpr(e) {
            case .identifier(let n, _): return n == "NULL" || n == "nullptr"
            case .integerLiteral(let v, _): return v == "0"
            default: return false
            }
        }

        func unwrapExpr(_ e: CExpr) -> CExpr {
            switch e {
            case .paren(let x, _), .cast(let x, _): return unwrapExpr(x)
            default: return e
            }
        }

        func walk(_ stmt: CStmt) {
            switch stmt {
            case .block(let arr):
                for s in arr { walk(s) }
            case .expr(let e):
                if case .call(let callee, let args, let offset) = e {
                    if case .identifier(let n, _) = callee, n == "free", let first = args.first {
                        if case .identifier(let target, _) = first {
                            if freed[target] != nil {
                                findings.append(AstFinding(function: function, offset: offset,
                                                           category: "Double Free",
                                                           severity: .high,
                                                           message: "\(target) is freed a second time; double free corrupts the heap allocator.",
                                                           taintPath: nil, reachable: reachable, crossFile: false))
                            } else if paramFreed[target] != nil {
                                findings.append(AstFinding(function: function, offset: offset,
                                                           category: "Double Free",
                                                           severity: .high,
                                                           message: "\(target) is freed a second time; double free corrupts the heap allocator.",
                                                           taintPath: nil, reachable: reachable, crossFile: false))
                            } else {
                                freed[target] = offset
                            }
                        } else if let key = exprKey(first) {
                            // Structured target: `free(outerArray[i])`. Releases
                            // exactly this key (never an inner array stored in
                            // it). No double-free finding here: indexes alias
                            // across loop iterations/exclusive branches, so the
                            // same spelled key can legitimately be freed on
                            // disjoint paths — track it only for leak math.
                            keyFreed.insert(key)
                            keyAllocs.removeValue(forKey: key)
                        }
                    } else if case .identifier(let n, _) = callee, ["delete"].contains(n) {
                        // C++ `delete` parsed as a plain call (defensive).
                        if let first = args.first, case .identifier(let target, _) = first {
                            if freed[target] != nil || paramFreed[target] != nil {
                                findings.append(AstFinding(function: function, offset: offset,
                                                           category: "Double Free",
                                                           severity: .high,
                                                           message: "\(target) is deleted a second time; double free corrupts the heap.",
                                                           taintPath: nil, reachable: reachable, crossFile: false))
                            } else {
                                freed[target] = offset
                            }
                        } else if let first = args.first, let key = exprKey(first) {
                            // Structured `delete obj[i]` target — alias-safe
                            // bookkeeping only (see free above).
                            keyFreed.insert(key)
                            keyAllocs.removeValue(forKey: key)
                        }
                    } else {
                        // Any other call: arguments that read freed pointers are UAF.
                        for a in args { checkUses(a) }
                        // Ownership hand-off: passing an allocation to another
                        // function escapes it (conservative for leak reporting).
                        // Only in-file callees count — libc-style helpers
                        // (puts/printf/strlen/…) never take ownership.
                        var calleeIsLocal = false
                        if case .identifier(let cn, _) = callee, astFns[cn] != nil { calleeIsLocal = true }
                        if calleeIsLocal {
                            for a in args {
                                var ids: [(String, Int)] = []
                                usedIdents(a, into: &ids)
                                for (n, _) in ids where allocs[n] != nil { escapedVars.insert(n) }
                            }
                        }
                    }
                    // The callee expression itself may read freed memory.
                    checkUses(callee)
                } else {
                    handleAssign(e)
                }
            case .declaration(let d):
                if case .variable(_, let name, let initExpr?) = d.kind {
                    let initE = initExpr
                    if isHeapAllocCall(initE) {
                        markAlloc(name, initE.offset)
                    } else {
                            checkUses(initE)
                            // `T* x = otherPtr;` after otherPtr was freed → UAF.
                            var ids: [(String, Int)] = []
                            usedIdents(initE, into: &ids)
                            for (n, _) in ids where freed[n] != nil || paramFreed[n] != nil {
                                if reportedUAF.insert(name).inserted {
                                    findings.append(AstFinding(function: function, offset: d.offset,
                                                               category: "Use After Free",
                                                               severity: .critical,
                                                               message: "\(name) is initialized from freed pointer \(n).",
                                                               taintPath: nil, reachable: reachable, crossFile: false))
                                }
                            }
                        }
                    }
                case .returnStmt(let e, _):
                if let e = e {
                    checkUses(e)
                    var ids: [(String, Int)] = []
                    usedIdents(e, into: &ids)
                    for (n, _) in ids where allocs[n] != nil { escapedVars.insert(n) }
                }
            case .ifStmt(let cond, let t, let e, _):
                checkUses(cond)
                // A free inside a branch that definitely returns (the classic
                // `if (!ok) { free(p); return NULL; }` cleanup) must not poison
                // the flow AFTER the branch — walk it with a snapshot of the
                // freed state and discard changes when it returns.
                let freedSnap = freed
                let paramFreedSnap = paramFreed
                let returnsThen = definitelyReturns(t)
                walk(t)
                if returnsThen {
                    // Early-return path leaks: heap allocations live at branch
                    // entry that were not released inside the returning branch
                    // leak on exactly this path (the main path may free them
                    // later — e.g. `if (!file) return -1;` after `malloc`).
                    reportBranchLeaks(allocs: allocs, freed: freed, escaped: escapedVars,
                                      nullChecked: nullCheckedVariable(cond),
                                      reported: &leakReported)
                    for k in freed.keys where freedSnap[k] == nil { freed[k] = nil }
                    for k in paramFreed.keys where paramFreedSnap[k] == nil { paramFreed[k] = nil }
                }
                if let e = e {
                    let returnsElse = definitelyReturns(e)
                    walk(e)
                    if returnsElse {
                        reportBranchLeaks(allocs: allocs, freed: freed, escaped: escapedVars,
                                          nullChecked: nullCheckedVariable(cond),
                                          reported: &leakReported)
                        for k in freed.keys where freedSnap[k] == nil { freed[k] = nil }
                        for k in paramFreed.keys where paramFreedSnap[k] == nil { paramFreed[k] = nil }
                    }
                }
            case .whileStmt(let cond, let body, _):
                checkUses(cond)
                walk(body)
            case .doWhileStmt(let body, let cond, _):
                walk(body)
                checkUses(cond)
            case .forStmt(let initS, let cond, let inc, let body, _):
                if let initS = initS { walk(initS) }
                if let cond = cond { checkUses(cond) }
                if let inc = inc { checkUses(inc) }
                walk(body)
            case .switchStmt(let expr, let cases, _):
                checkUses(expr)
                for c in cases { for s in c.body { walk(s) } }
            case .labeledStmt(_, let s, _):
                walk(s)
            case .breakStmt, .continueStmt, .gotoStmt, .empty:
                break
            }
        }

        walk(fn.body)

        // Leak report: allocations that never escaped (return/store/call) and
        // were never freed inside the function.
        for (name, offset) in allocs.sorted(by: { $0.value < $1.value }) {
            guard freed[name] == nil, !escapedVars.contains(name),
                  leakReported.insert(name).inserted else { continue }
            findings.append(AstFinding(function: function, offset: offset,
                                       category: "Memory Leak",
                                       severity: .medium,
                                       message: "\(name) is allocated on the heap but never released on this path and does not escape the function.",
                                       taintPath: nil, reachable: reachable, crossFile: false))
        }
        // Structured leak report: allocations stored into member/index targets
        // (`outerArray[i]->innerArray = malloc(...)`) whose exact key was never
        // freed — the surrounding array/struct being freed does not release them.
        for (key, offset) in keyAllocs.sorted(by: { $0.value < $1.value })
        where !keyFreed.contains(key) {
            findings.append(AstFinding(function: function, offset: offset,
                                       category: "Memory Leak",
                                       severity: .medium,
                                       message: "\(key) is allocated on the heap but never released on this path; freeing the containing object does not free this allocation.",
                                       taintPath: nil, reachable: reachable, crossFile: false))
        }
    }



    /// Names of in-file functions that `return` a directly-allocated local
    /// (`malloc`/`calloc`/`strdup`/`new`). Calls to them produce heap pointers.
    private func heapReturningFunctionNames() -> Set<String> {
        var out = Set<String>()
        for (name, fn) in astFns {
            if functionReturnsAllocatedLocal(fn) { out.insert(name) }
        }
        return out
    }

    private func functionReturnsAllocatedLocal(_ fn: CFunctionDef) -> Bool {
        var allocs = Set<String>()
        var found = false

        func isAllocCall(_ e: CExpr) -> Bool {
            if case .call(let callee, _, _) = e, case .identifier(let n, _) = callee {
                return ["malloc", "calloc", "realloc", "strdup", "strndup"].contains(n)
            }
            if case .newExpr = e { return true }
            return false
        }

        func walk(_ stmt: CStmt) {
            if found { return }
            switch stmt {
            case .block(let arr):
                for s in arr { walk(s) }
            case .expr(let e):
                if case .assign(_, let lhs, let rhs, _) = e,
                   case .identifier(let n, _) = lhs, isAllocCall(rhs) {
                    allocs.insert(n)
                }
            case .declaration(let d):
                if case .variable(_, let name, let ie?) = d.kind,
                   isAllocCall(ie) {
                    allocs.insert(name)
                }
            case .returnStmt(let e, _):
                if let e = e, case .identifier(let n, _) = e, allocs.contains(n) {
                    found = true
                }
            case .ifStmt(_, let t, let e, _):
                walk(t); if let e = e { walk(e) }
            case .whileStmt(_, let b, _):
                walk(b)
            case .doWhileStmt(let b, _, _):
                walk(b)
            case .forStmt(_, _, _, let b, _):
                walk(b)
            case .switchStmt(_, let cases, _):
                for c in cases { for s in c.body { walk(s) } }
            case .labeledStmt(_, let s, _):
                walk(s)
            case .breakStmt, .continueStmt, .gotoStmt, .empty:
                break
            }
        }
        walk(fn.body)
        return found
    }

    /// C++-shaped structural checks that the C sink table cannot reach because
    /// the (type-unaware) C parser splits a declaration such as
    /// `std::ifstream file(path);` into an object read (`std` `.` `ifstream`)
    /// followed by a constructor-style call named after the *variable*
    /// (`file(path)`). Covers:
    ///  1. File-stream opens with a tainted path (fstream path traversal),
    ///  2. `std::filesystem::exists(x)` then a stream-open of x (TOCTOU),
    ///  3. A `find("..")`-only guard feeding a tainted path return (encoded
    ///     path traversal / CWE-22 bypass) that never decodes or rejects
    ///     slashes/backslashes.
    func checkCxxPatterns(fn: CFunctionDef, function: String, tainted: Set<String>, crossTainted: Set<String>, guarded: Set<String>, findings: inout [AstFinding], reachable: Bool) {
        let streamTypes: Set<String> = ["ifstream", "ofstream", "fstream"]
        let streamRule = AstSinkRule(category: "Path Traversal", severity: .medium, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false)

        func isStreamTypeRead(_ e: CExpr) -> Bool {
            switch e {
            case .member(_, let m, _, _): return streamTypes.contains(m)
            case .identifier(let n, _): return streamTypes.contains(n)
            default: return false
            }
        }

        func idents(_ e: CExpr, into out: inout Set<String>) {
            switch e {
            case .identifier(let n, _): out.insert(n)
            case .unary(_, let x, _), .cast(let x, _), .paren(let x, _):
                idents(x, into: &out)
            case .binary(_, let l, let r, _), .comma(let l, let r, _):
                idents(l, into: &out); idents(r, into: &out)
            case .ternary(let c, let t, let f, _):
                idents(c, into: &out); idents(t, into: &out); idents(f, into: &out)
            case .assign(_, let l, let r, _):
                idents(l, into: &out); idents(r, into: &out)
            case .call(_, let args, _):
                for a in args { idents(a, into: &out) }
            case .member(let b, _, _, _):
                idents(b, into: &out)
            case .index(let b, let idx, _):
                idents(b, into: &out); idents(idx, into: &out)
            case .arrayInit(let els, _):
                for el in els { idents(el, into: &out) }
            case .newExpr(_, let args, _):
                for a in args { idents(a, into: &out) }
            case .sizeOf, .lambda, .integerLiteral, .floatLiteral, .stringLiteral, .charLiteral, .booleanLiteral:
                break
            }
        }

        // Identifier set of a stream-constructor call's first (path) argument.
        var streamOpenIdents: Set<String> = []
        var streamOpenTainted: String? = nil
        // Locals that receive a value inside this function (`path =
        // "./allowed/" + requested`). A stream open fed straight from its own
        // parameter (`void w(const std::string& path) { ofstream o(path); }`)
        // is a helper whose caller owns the path decision — not a traversal on
        // its own — mirroring the corpus's "safe pair" boundary for that shape.
        func declName(_ e: CExpr) -> String? {
            switch e {
            case .identifier(let n, _): return n
            case .cast(let x, _), .paren(let x, _): return declName(x)
            case .binary(let op, let l, let r, _) where op == "*" || op == "&":
                return declName(r) ?? declName(l)
            default: return nil
            }
        }
        func rootIdent(_ e: CExpr) -> String? {
            switch e {
            case .identifier(let n, _): return n
            case .unary(_, let x, _), .cast(let x, _), .paren(let x, _): return rootIdent(x)
            case .binary(_, let l, let r, _), .comma(let l, let r, _):
                return rootIdent(l) ?? rootIdent(r)
            case .member(let b, _, _, _): return rootIdent(b)
            case .index(let b, _, _): return rootIdent(b)
            default: return nil
            }
        }
        var assignedLocals: Set<String> = []
        func collectAssignedLocals(_ stmt: CStmt) {
            switch stmt {
            case .block(let arr):
                for s in arr { collectAssignedLocals(s) }
            case .expr(let e):
                if case .assign(_, let lhs, _, _) = e, let n = declName(lhs) { assignedLocals.insert(n) }
            case .declaration(let d):
                if case .variable(_, let name, _) = d.kind { assignedLocals.insert(name) }
            case .ifStmt(_, let t, let eb, _):
                collectAssignedLocals(t); if let eb = eb { collectAssignedLocals(eb) }
            case .whileStmt(_, let b, _):
                collectAssignedLocals(b)
            case .doWhileStmt(let b, _, _):
                collectAssignedLocals(b)
            case .forStmt(let initS, _, _, let b, _):
                if let initS = initS { collectAssignedLocals(initS) }
                collectAssignedLocals(b)
            case .switchStmt(_, let cases, _):
                for c in cases { for s in c.body { collectAssignedLocals(s) } }
            case .returnStmt, .labeledStmt, .breakStmt, .continueStmt, .gotoStmt, .empty:
                break
            }
        }
        collectAssignedLocals(fn.body)

        // Walk a statement sequence looking for the stream-type-read +
        // constructor-call adjacency produced by `std::ifstream file(path);`.
        func scanAdjacency(_ stmts: [CStmt]) {
            var pendingStream = false
            for s in stmts {
                guard case .expr(let e) = s else { pendingStream = false; continue }
                if isStreamTypeRead(e) { pendingStream = true; continue }
                if case .call(_, let args, let off) = e {
                    if pendingStream, let first = args.first {
                        var ids: Set<String> = []
                        idents(first, into: &ids)
                        streamOpenIdents.formUnion(ids)
                        if exprTainted(first, tainted: tainted) != nil { streamOpenTainted = exprTainted(first, tainted: tainted) }
                        if !ids.isEmpty {
                            // The path was constructed inside this function (its
                            // root local was reassigned/declared here) or is a
                            // compound expression — a bare parameter handed to a
                            // helper is the caller's decision, not a finding.
                            let rootBuilt = rootIdent(first).map { assignedLocals.contains($0) } ?? true
                            if rootBuilt, let taint = exprTainted(first, tainted: tainted),
                               !isGuarded(first, guarded: guarded, category: "Path Traversal") {
                                emit(&findings, function, off, streamRule,
                                     message: "File stream is opened with a path that can be controlled by the caller.",
                                     taint: taint, reachable: reachable, crossFile: exprCrossFile(first, crossTainted: crossTainted))
                            }
                        }
                    }
                    pendingStream = false
                } else {
                    pendingStream = false
                }
            }
        }

        var existsOffsets: [Int] = []
        var checkedPathIdents: Set<String> = []

        func scanExprCalls(_ e: CExpr) {
            switch e {
            case .call(let callee, let args, let off):
                let n = callName(callee) ?? ""
                let q = callQualifiedName(callee) ?? n
                if n == "exists" || q.hasSuffix(".exists") || q == "std.filesystem.exists" {
                    var ids: Set<String> = []
                    for a in args { idents(a, into: &ids) }
                    if args.contains(where: { exprTainted($0, tainted: tainted) != nil }) {
                        existsOffsets.append(off)
                        checkedPathIdents.formUnion(ids)
                    }
                }
                scanExprCalls(callee)
                for a in args { scanExprCalls(a) }
            case .unary(_, let x, _), .cast(let x, _), .paren(let x, _):
                scanExprCalls(x)
            case .binary(_, let l, let r, _), .comma(let l, let r, _):
                scanExprCalls(l); scanExprCalls(r)
            case .ternary(let c, let t, let f, _):
                scanExprCalls(c); scanExprCalls(t); scanExprCalls(f)
            case .assign(_, let l, let r, _):
                scanExprCalls(l); scanExprCalls(r)
            case .member(let b, _, _, _):
                scanExprCalls(b)
            case .index(let b, let idx, _):
                scanExprCalls(b); scanExprCalls(idx)
            case .arrayInit(let els, _):
                for el in els { scanExprCalls(el) }
            case .newExpr(_, let args, _):
                for a in args { scanExprCalls(a) }
            case .identifier, .sizeOf, .lambda, .integerLiteral, .floatLiteral, .stringLiteral, .charLiteral, .booleanLiteral:
                break
            }
        }

        func scanNode(_ stmt: CStmt) {
            switch stmt {
            case .block(let arr):
                scanAdjacency(arr)
                for s in arr { scanNode(s) }
            case .expr(let e):
                scanExprCalls(e)
            case .declaration(let d):
                if case .variable(_, _, let ie?) = d.kind { scanExprCalls(ie) }
            case .ifStmt(let cond, let t, let eb, _):
                scanExprCalls(cond)
                scanNode(t)
                if let eb = eb { scanNode(eb) }
            case .whileStmt(let cond, let b, _):
                scanExprCalls(cond); scanNode(b)
            case .doWhileStmt(let b, let cond, _):
                scanNode(b); scanExprCalls(cond)
            case .forStmt(let initS, let cond, let inc, let b, _):
                if let initS = initS { scanNode(initS) }
                if let cond = cond { scanExprCalls(cond) }
                if let inc = inc { scanExprCalls(inc) }
                scanNode(b)
            case .switchStmt(let e, let cases, _):
                scanExprCalls(e)
                for c in cases { for s in c.body { scanNode(s) } }
            case .returnStmt, .labeledStmt, .breakStmt, .continueStmt, .gotoStmt, .empty:
                break
            }
        }

        scanNode(fn.body)

        // TOCTOU: a reachable `exists(p)`/`status(p)` check immediately followed
        // (on another line) by opening the same path with a file stream. The
        // safe/refactored pattern opens the stream directly with a non-truncating
        // mode and never consults the filesystem first.
        if let firstCheck = existsOffsets.first, !checkedPathIdents.isEmpty {
            // Require the checked path to be the same one later stream-opened.
            if !checkedPathIdents.isDisjoint(with: streamOpenIdents) {
                emit(&findings, function, firstCheck,
                     AstSinkRule(category: "TOCTOU / Race Condition", severity: .medium, vulnArgIndex: 0, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
                     message: "Filesystem state is checked with exists()/status() before opening the same path with a file stream; the file may be replaced between the check and the use.",
                     taint: streamOpenTainted, reachable: reachable, crossFile: false)
            }
        }

        // Encoded path traversal: a tainted value flows through a path built for
        // return while the only traversal guard is a literal `find("..")` check
        // that never rejects `/`, `\`, or encoded forms, and no decode or
        // canonicalization is applied before the concatenation.
        let ns = source as NSString
        let bodyStart = min(max(0, fn.bodyOffset), ns.length)
        let bodyLen = max(0, min(fn.endOffset, ns.length) - bodyStart)
        let bodySlice = ns.substring(with: NSRange(location: bodyStart, length: bodyLen))
        let weakGuard = (bodySlice.range(of: "find(\"..") != nil)
        if weakGuard {
            var guardVars = Set<String>()
            // Scan backwards from each `.find(".."` to the identifier it is
            // invoked on (the guarded path variable): `requested.find(".."`.
            var idx = bodySlice.startIndex
            let ms = "find(\".."
            while let r = bodySlice.range(of: ms, range: idx..<bodySlice.endIndex) {
                idx = r.upperBound
                var j = r.lowerBound
                while j > bodySlice.startIndex {
                    let prev = bodySlice.index(before: j)
                    let ch = bodySlice[prev]
                    if ch == "." || ch == ">" || ch == ":" || ch == "-" {
                        j = prev
                    } else {
                        break
                    }
                }
                var k = j
                while k > bodySlice.startIndex {
                    let prev = bodySlice.index(before: k)
                    let ch = bodySlice[prev]
                    if ch.isLetter || ch == "_" {
                        k = prev
                    } else {
                        break
                    }
                }
                if k < j { guardVars.insert(String(bodySlice[k..<j])) }
            }
            weakGuardPathReturn(in: fn.body, guardVars: guardVars, bodySlice: bodySlice, tainted: tainted, function: function, findings: &findings, reachable: reachable)
        }
    }


    /// Emits encoded-path-traversal findings when a tainted value reaches a
    /// `return` as part of a path concatenation and that same value passed only
    /// an incomplete (`find("..")`-only) traversal guard.
    private func weakGuardPathReturn(in body: CStmt, guardVars: Set<String>, bodySlice: String, tainted: Set<String>, function: String, findings: inout [AstFinding], reachable: Bool) {
        guard !guardVars.isEmpty else { return }
        // A decode/canonicalization step before the guard, or an additional
        // slash/backslash rejection, outlaws the naive bypass and is handled
        // correctly -> do not flag.
        let lowered = bodySlice.lowercased()
        if lowered.contains("decode") || lowered.contains("canonical") || lowered.contains("realpath")
            || lowered.contains("normalize") || bodySlice.contains("find('/") {
            return
        }
        func walk(_ stmt: CStmt) {
            switch stmt {
            case .block(let arr):
                for s in arr { walk(s) }
            case .expr, .declaration:
                break
            case .ifStmt(_, let t, let eb, _):
                walk(t); if let eb = eb { walk(eb) }
            case .whileStmt(_, let b, _):
                walk(b)
            case .doWhileStmt(let b, _, _):
                walk(b)
            case .forStmt(_, _, _, let b, _):
                walk(b)
            case .switchStmt(_, let cases, _):
                for c in cases { for s in c.body { walk(s) } }
            case .labeledStmt(_, let s, _):
                walk(s)
            case .returnStmt(let e, let off):
                guard let e = e else { return }
                guard case .binary = e else { return }
                guard let t = exprTainted(e, tainted: tainted), guardVars.contains(t) else { return }
                emit(&findings, function, off,
                     AstSinkRule(category: "Path Traversal", severity: .medium, vulnArgIndex: nil, alwaysVulnerable: false, formatArgIndex: nil, bufferOverflowOnFormat: false),
                     message: "Path is built from a caller-controlled value behind only a literal `..` guard; URL-encoded or slash/backslash forms bypass it.",
                     taint: t, reachable: reachable, crossFile: false)
            case .breakStmt, .continueStmt, .gotoStmt, .empty:
                break
            }
        }
        walk(body)
    }


    // MARK: - C-family integer arithmetic findings

    /// Integer overflow / division-by-zero checks shared by binary `*`, `/`,
    /// `%` expressions and the compound form `x *= n` (assigns reuse the
    /// multiplication logic with the assignment target as the left operand).

    func checkCOverflowBinary(op: String, l: CExpr, r: CExpr, offset: Int, function: String, tainted: Set<String>, guarded: Set<String>, sizeBounded: Set<String>, findings: inout [AstFinding], reachable: Bool) {
        guard isCArithmeticTarget else { return }

        if op == "*" {
            let lTainted = exprTainted(l, tainted: tainted) != nil
            let rTainted = exprTainted(r, tainted: tainted) != nil
            guard lTainted || rTainted else { return }
            // A small-constant multiplier (`x * 2`) is the mundane idiom; only
            // fire when both operands are tainted or the untainted operand can
            // itself be large (a `count * sizeof(T)` allocation-size scaling).
            let fires: Bool
            if lTainted && rTainted { fires = true }
            else if lTainted { fires = isLargeFactor(r) }
            else { fires = isLargeFactor(l) }
            guard fires else { return }
            // Suppress when every tainted identifier involved is already proven
            // small by a size/whitelist guard (`if (n <= MAX) { n * 4 }`) or by
            // a loop-variable constant header (`for (i = 0; i < 8; i++) { i * 4 }`).
            var taintedIds: [String] = []
            if lTainted, let tn = taintedIdentifier(l, tainted: tainted) { taintedIds.append(tn) }
            if rTainted, let tn = taintedIdentifier(r, tainted: tainted) { taintedIds.append(tn) }
            if !taintedIds.isEmpty,
               taintedIds.allSatisfy({ guarded.contains($0) || sizeBounded.contains($0)
                                       || overflowConstBoundedRef.vars.contains($0) }) { return }
            let taint = exprTainted(l, tainted: tainted) ?? exprTainted(r, tainted: tainted)
            findings.append(AstFinding(function: function, offset: offset,
                                       category: "Integer Overflow",
                                       severity: .medium,
                                       message: "Multiplication of tainted values can wrap past the integer width, defeating size and bounds checks.",
                                       taintPath: taint, reachable: reachable, crossFile: false))
        } else if op == "/" || op == "%" {
            guard isZeroRiskyDivisor(r, tainted: tainted) else { return }
            let taint = exprTainted(r, tainted: tainted)
            findings.append(AstFinding(function: function, offset: offset,
                                       category: "Possible Division by Zero",
                                       severity: .medium,
                                       message: "Division by an unchecked expression crashes when the divisor is zero.",
                                       taintPath: taint, reachable: reachable, crossFile: false))
        }
    }

    /// Compound-assign overflow (`x *= n`); mirrors the binary `*` rule.
    func checkCOverflowAssign(op: String, lhs: CExpr, rhs: CExpr, offset: Int, function: String, tainted: Set<String>, guarded: Set<String>, sizeBounded: Set<String>, findings: inout [AstFinding], reachable: Bool) {
        guard op == "*=" else { return }
        checkCOverflowBinary(op: "*", l: lhs, r: rhs, offset: offset, function: function,
                             tainted: tainted, guarded: guarded, sizeBounded: sizeBounded,
                             findings: &findings, reachable: reachable)
    }


    /// The bare identifier backing a tainted expression, if any.
    private func taintedIdentifier(_ e: CExpr, tainted: Set<String>) -> String? {
        guard exprTainted(e, tainted: tainted) != nil else { return nil }
        return simpleIdentifier(e)
    }

    /// True when an expression can evaluate to a large value: any identifier,
    /// member, index, `sizeof`, call, or arithmetic result. Small integer
    /// literals and chars are not (a literal multiplier is a constant).
    private func isLargeFactor(_ e: CExpr) -> Bool {
        switch e {
        case .integerLiteral(let s, _):
            return abs(intLiteralValue(s) ?? 0) > 1024
        case .charLiteral:
            return false
        case .floatLiteral:
            return true
        case .identifier, .member, .index, .sizeOf, .call, .binary, .ternary, .assign, .arrayInit, .newExpr:
            return true
        case .paren(let x, _), .cast(let x, _):
            return isLargeFactor(x)
        default:
            return false
        }
    }

    /// True when a divisor expression can be zero at runtime (mirrors the JS
    /// and Swift zero-risk models): a literal `0`, a tainted identifier not
    /// proven non-zero, or a tainted member/index access.
    private func isZeroRiskyDivisor(_ e: CExpr, tainted: Set<String>) -> Bool {
        switch e {
        case .integerLiteral(let s, _):
            return intLiteralValue(s) == 0
        case .identifier(let n, _):
            if zeroCheckedRef.vars.contains(n) { return false }
            return tainted.contains(n)
        case .member, .index:
            return exprTainted(e, tainted: tainted) != nil
        case .paren(let x, _), .cast(let x, _):
            return isZeroRiskyDivisor(x, tainted: tainted)
        default:
            return false
        }
    }

    /// Parses a C integer literal text (dec/hex/bin/octal, with `u`/`l`
    /// suffixes) into its numeric value, or nil when not parseable.
    private func intLiteralValue(_ s: String) -> Int64? {
        var v = s.lowercased()
        while let last = v.last, last == "u" || last == "l" { v.removeLast() }
        if v.isEmpty { return nil }
        let radix: Int
        if v.hasPrefix("0x") { radix = 16; v = String(v.dropFirst(2)) }
        else if v.hasPrefix("0b") { radix = 2; v = String(v.dropFirst(2)) }
        else if v.hasPrefix("0o") { radix = 8; v = String(v.dropFirst(2)) }
        else if v.count > 1 && v.hasPrefix("0") { radix = 8; v = String(v.dropFirst(1)) }
        else { radix = 10 }
        return Int64(v, radix: radix)
    }


} // end extension AstSecurityDetector

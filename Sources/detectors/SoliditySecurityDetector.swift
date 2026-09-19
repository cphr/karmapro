// by cipher.org.uk
// MARK: - Solidity-specific AST + heuristic security checks
// Extracted from AstSecurityDetector.swift + VulnerabilityScanner.swift
// to keep per-language vulnerability detection modular.

import Foundation

extension AstSecurityDetector {

    // MARK: - Solidity sink checks

    /// Per-call taint sinks that carry attacker-controlled data in Solidity.
    /// The dangerous calls are (a) low-level/external calls whose arguments
    /// embed untrusted data (a reentrancy/forge path), (b) the classic
    /// `abi.encodePacked`-into-hash random oracle, (c) delegatecall to an
    /// attacker-controlled target, and (d) selfdestruct to an arbitrary address.
    func checkSoliditySinks(name: String, qualified: String, callee: CExpr, args: [CExpr], offset: Int, function: String, tainted: Set<String>, crossTainted: Set<String>, guarded: Set<String>, sizeBounded: Set<String>, findings: inout [AstFinding], reachable: Bool) -> Bool {
        // Weak/predictable randomness: `keccak256(abi.encodePacked(...))` (and
        // `sha256`/`sha3`) whose packed payload references a block/blockhash
        // timestamp or a caller-chosen nonce — an on-chain attacker can predict
        // or influence every term.
        if name == "keccak256" || name == "sha256" || name == "sha3" {
            if containsPredictableEntropy(args) {
                let cross = args.contains(where: { exprCrossFile($0, crossTainted: crossTainted) || crossFileSourceCall($0) != nil })
                emit(&findings, function, offset,
                     rule("Predictable Randomness", .high, always: true),
                     message: "\(name) mixes predictable on-chain entropy (block.* / now); an attacker can reproduce the outcome.",
                     taint: nil, reachable: reachable, crossFile: cross)
                return true
            }
            return true
        }
        // Delegatecall to an untrusted address: `addr.delegatecall(...)` where
        // the receiver `addr` is tainted — the target contract's code runs in
        // our storage context, allowing the attacker to overwrite any slot.
        // A receiver backed by a MUTABLE state variable (a library pointer
        // anyone can reassign, e.g. `fibonacciLibrary.delegatecall(...)`) is
        // equally untrusted; `immutable`/`constant` targets stay trusted.
        if name == "delegatecall", let recv = memberBase(callee),
           exprTainted(recv, tainted: tainted) != nil || isMutableStateReceiver(recv) {
            emit(&findings, function, offset,
                 rule("Delegatecall to Untrusted Address", .critical, always: false),
                 message: "delegatecall target is attacker-controlled; the called contract can overwrite any storage slot.",
                 taint: taintLabel(recv, tainted: tainted), reachable: reachable,
                 crossFile: exprCrossFile(recv, crossTainted: crossTainted))
            return true
        }
        // Selfdestruct to an arbitrary address: `selfdestruct(addr)` where
        // `addr` is tainted — the attacker drains all remaining Ether and
        // permanently destroys the contract.
        if (name == "selfdestruct" || name == "suicide"), let addr = args.first, exprTainted(addr, tainted: tainted) != nil {
            emit(&findings, function, offset,
                 rule("Selfdestruct to Arbitrary Address", .critical, always: false),
                 message: "selfdestruct target is attacker-controlled; the attacker drains all remaining Ether.",
                 taint: taintLabel(addr, tainted: tainted), reachable: reachable,
                 crossFile: exprCrossFile(addr, crossTainted: crossTainted))
            return true
        }
        // Ether sent to an arbitrary recipient: `addr.transfer(value)` /
        // `addr.send(value)` where the receiver comes from caller input — the
        // attacker redirects the payout to any address they choose. Only the
        // single-argument form is a native Ether transfer; `token.transfer(to,
        // amount)` is an ERC-20 token move and belongs to the ERC-20 checks.
        if (name == "transfer" || name == "send"), args.count == 1,
           let recv = memberBase(callee), exprTainted(recv, tainted: tainted) != nil {
            emit(&findings, function, offset,
                 rule("Ether Sent to Arbitrary Recipient", .high, always: false),
                 message: "\(name)() sends Ether to an attacker-controlled address; funds can be drained to any recipient.",
                 taint: taintLabel(recv, tainted: tainted), reachable: reachable,
                 crossFile: exprCrossFile(recv, crossTainted: crossTainted))
            return true
        }
        // ERC20-style transfer to the zero address: `token.transfer(address(0), x)`
        // silently burns tokens or breaks bookkeeping when the zero address is not
        // rejected.
        if (name == "transfer" || name == "transferFrom"), args.contains(where: { isAddressZeroExpr($0) }) {
            emit(&findings, function, offset,
                 rule("Transfer to Zero Address", .medium, always: true),
                 message: "\(name)() sends tokens to address(0); the zero address should be rejected to avoid burned or stuck funds.",
                 taint: nil, reachable: reachable, crossFile: false)
            return true
        }
        // Unsafe `send`: forwards only the 2300 gas stipend and returns `false`
        // on failure instead of reverting — silently lost funds.
        if name == "send" {
            emit(&findings, function, offset,
                 rule("Unsafe send", .medium, always: true),
                 message: "send() forwards only 2300 gas and silently returns false on failure; prefer transfer/revert or a checked call.",
                 taint: nil, reachable: reachable, crossFile: false)
            return true
        }
        // `blockhash(block.number)` always returns 0 (the hash is only known
        // after the block is mined) — a silent logic bug.
        if name == "blockhash", let a = args.first, isBlockNumberExpr(a) {
            emit(&findings, function, offset,
                 rule("Blockhash of Current Block", .medium, always: true),
                 message: "blockhash(block.number) always returns 0; the current block's hash is not known yet.",
                 taint: nil, reachable: reachable, crossFile: false)
            return true
        }
        return false
    }

    /// Extracts the receiver (base) of a member call expression, if any.
    private func memberBase(_ e: CExpr) -> CExpr? {
        if case .member(let base, _, _, _) = e { return base }
        if case .index(let base, _, _) = e { return memberBase(base) }
        return nil
    }

    /// True if any argument (recursively) references a predictable-on-chain value:
    /// block.timestamp / block.number / blockhash / block.difficulty / now, or a
    /// caller-chosen argument.
    private func containsPredictableEntropy(_ args: [CExpr]) -> Bool {
        for a in args {
            if exprReferencesPredictable(a) { return true }
        }
        return false
    }

    private func exprReferencesPredictable(_ e: CExpr) -> Bool {
        switch e {
        case .identifier(let n, _):
            return n == "now" || n == "timestamp" || n == "nonce"
        case .member(let b, let m, _, _):
            if m == "timestamp" || m == "blockhash" || m == "number" || m == "difficulty" || m == "prevrandao" || m == "gaslimit" || m == "coinbase" {
                return true
            }
            return exprReferencesPredictable(b)
        case .call(let c, let args, _):
            if exprReferencesPredictable(c) { return true }
            return args.contains { exprReferencesPredictable($0) }
        case .binary(_, let l, let r, _), .comma(let l, let r, _):
            return exprReferencesPredictable(l) || exprReferencesPredictable(r)
        case .unary(_, let o, _):
            return exprReferencesPredictable(o)
        case .ternary(let c, let t, let f, _):
            return exprReferencesPredictable(c) || exprReferencesPredictable(t) || exprReferencesPredictable(f)
        case .cast(let x, _), .paren(let x, _):
            return exprReferencesPredictable(x)
        case .index(let b, let i, _):
            return exprReferencesPredictable(b) || exprReferencesPredictable(i)
        case .assign(_, let l, let r, _):
            return exprReferencesPredictable(l) || exprReferencesPredictable(r)
        default:
            return false
        }
    }

    // MARK: - Solidity structural (3-walk) checks

    /// Runs the whole-function Solidity checks that depend on statement/offset
    /// ordering and guard presence, over three conceptual walks:
    ///  - Walk 1 (guard walk): does `nonReentrant`/an explicit guard car size the
    ///    function against reentrancy?
    ///  - Walk 2 (external-call + state-write ordering): is there an external
    ///    call followed by a storage write (classic reentrancy)?
    ///  - Walk 3 (expression walk): tx.origin authorization and unchecked-call
    ///    detection (is the external call's return/condition guarded?).
    func checkSolidityStructural(function: String, fn: CFunctionDef, params: Set<String>, tainted: Set<String>, crossTainted: Set<String>, findings: inout [AstFinding], reachable: Bool) {
        // Guard: reentrancy-protected if a `nonReentrant`-style modifier is
        // applied or `msg.sender = ...`/a lock boolean is set before any call.
        let modifiers = fn.qualifiers
        let hasNonReentrantModifier = modifiers.contains("nonReentrant")
            || modifiers.contains { $0.lowercased().contains("nonreentrant") }
            || modifiers.contains("nonReentrant_guard")
            || modifiers.contains { $0.lowercased().hasPrefix("nonreentrant") || $0.lowercased().hasPrefix("reentrancy") }

        // Collect ordered events: external calls (offset, name) and storage
        // writes, plus tx.origin uses and explicit guard-set statements.
        var externalCalls: [(offset: Int, name: String)] = []
        var stateWrites: [Int] = []
        var txOriginUses: [Int] = []
        var sawGuardSet = false
        collectSolidityEvents(fn.body, params: params, externalCalls: &externalCalls, stateWrites: &stateWrites, txOriginUses: &txOriginUses, sawGuardSet: &sawGuardSet)
        // --- Reentrancy: an external call occurs before a storage write and the
        // function is not guarded.
        if !hasNonReentrantModifier && !sawGuardSet {
            // Violation = an external call that has ANY storage write after it
            // (checks-effects-interactions broken). A write merely *before* the
            // call does not excuse a later write, so compare the earliest call
            // against the LAST write. `send()` forwards only the 2300 gas
            // stipend, which cannot re-enter, so it is excluded.
            if let firstCall = externalCalls.first(where: { $0.name != "send" }),
               let lastWrite = stateWrites.last, firstCall.offset < lastWrite {
                emit(&findings, function, firstCall.offset,
                     rule("Reentrancy", .high, always: true),
                     message: "External call before state update with no reentrancy guard; re-entrant callers can corrupt storage.",
                     taint: nil, reachable: reachable, crossFile: false)
            }
        }

        // --- tx.origin authorization: using tx.origin in a security boundary.
        for offset in txOriginUses {
            emit(&findings, function, offset,
                 rule("tx.origin Authorization", .high, always: true),
                 message: "tx.origin used for authorization; a malicious intermediate contract can impersonate the sender.",
                 taint: nil, reachable: reachable, crossFile: false)
        }

        // --- Unchecked external call return value: `call()` / `send()` /
        // `staticcall()` / `delegatecall()` whose boolean success flag is never
        // consumed in an `if`, `require`, or `assert` — a silent failure can
        // lead to lost funds or logic errors.
        var consumedOffsets = Set<Int>()
        var callSourceVar: [String: Int] = [:]
        collectConsumedExternalCalls(fn.body, offsets: &consumedOffsets, callSourceVar: &callSourceVar)
        for ec in externalCalls where !consumedOffsets.contains(ec.offset) && uncheckedReturnCall(ec.name) {
            emit(&findings, function, ec.offset,
                 rule("Unchecked External Call Return", .high, always: true),
                 message: "\(ec.name)() return value is not checked; a silent failure can lead to lost funds or logic errors.",
                 taint: nil, reachable: reachable, crossFile: false)
        }

        // --- Extended walk: time/balance dependence, loops, authorization,
        // ERC20 correctness and pre-0.8 arithmetic (Walk 4).
        var ev = SolidityExtEvents()
        collectSolidityExtendedEvents(fn.body, params: params, tainted: tainted, inLoop: false, ev: &ev)

        for offset in ev.timestampLogicUses {
            emit(&findings, function, offset,
                 rule("Block Timestamp Dependence", .medium, always: true),
                 message: "block.timestamp decides control flow; a miner can skew it by a few seconds, so time-sensitive logic is manipulable.",
                 taint: nil, reachable: reachable, crossFile: false)
        }
        for offset in ev.nowUses {
            emit(&findings, function, offset,
                 rule("Deprecated now Global", .low, always: true),
                 message: "`now` is deprecated (removed in Solidity 0.8); use block.timestamp explicitly.",
                 taint: nil, reachable: reachable, crossFile: false)
        }
        // A balance-dependent invariant is only a finding when the function does not
        // authorize the caller first: an owner/admin-gated sweep that drains or
        // rebalances the contract's balance is the intended use of that balance,
        // not a logic flaw a force-send could break. Functions with an auth
        // check (require/if on msg.sender/tx.origin) are excluded; open public
        // view functions that read `address(this).balance` remain flagged.
        if !ev.hasAuthCheck {
            for offset in ev.balanceUses {
                emit(&findings, function, offset,
                     rule("Balance Dependence", .medium, always: true),
                     message: "logic depends on a contract's Ether balance; anyone can force-send Ether (selfdestruct) and break the invariant.",
                     taint: nil, reachable: reachable, crossFile: false)
            }
        }
        for offset in ev.loopCallOffsets {
            emit(&findings, function, offset,
                 rule("External Call in Loop", .high, always: true),
                 message: "external call inside a loop: one reverting/failing iteration can block the whole batch or invite reentrancy per iteration.",
                 taint: nil, reachable: reachable, crossFile: false)
        }
        for offset in ev.unboundedLoopOffsets {
            emit(&findings, function, offset,
                 rule("Unbounded Loop Gas DoS", .medium, always: true),
                 message: "loop iterates over a dynamically-sized array; growth beyond the block gas limit makes the function revert permanently.",
                 taint: nil, reachable: reachable, crossFile: false)
        }
        for offset in ev.assertInputOffsets {
            emit(&findings, function, offset,
                 rule("Assert for Input Validation", .medium, always: false),
                 message: "assert() on caller-controlled input burns all gas on failure; use require() for input validation.",
                 taint: nil, reachable: reachable, crossFile: false)
        }
        if !ev.ecrecoverOffsets.isEmpty && !ev.ecrecoverGuarded {
            emit(&findings, function, ev.ecrecoverOffsets[0],
                 rule("Unchecked ecrecover Return", .medium, always: true),
                 message: "ecrecover returns address(0) for invalid signatures; the result must be checked against address(0) before authorization.",
                 taint: nil, reachable: reachable, crossFile: false)
        }
        let hasAuthModifier = fn.qualifiers.contains { q in
            let l = q.lowercased()
            return l.contains("only") || l.contains("auth") || l == "admin" || l.contains("restricted") || l.contains("governance")
        }
        for w in ev.privilegedWrites where !hasAuthModifier && !ev.hasAuthCheck {
            emit(&findings, function, w.offset,
                 rule("Missing Access Control", .high, always: true),
                 message: "'\(w.target)' is updated with no owner/admin check or only* modifier; anyone can change this security-relevant state.",
                 taint: nil, reachable: reachable, crossFile: false)
        }
        if function.lowercased().contains("approve") {
            // A contract that also exposes increaseAllowance/decreaseAllowance has
            // the standard race-free alternative; the bare approve() is a
            // compatibility shim, not the double-spend vector.
            let hasAllowanceMitigation = self.astFns.keys.contains { n in
                let l = n.lowercased()
                return l.contains("increaseallowance") || l.contains("decreaseallowance")
            }
            if !hasAllowanceMitigation {
                for offset in ev.approvalWriteOffsets {
                    emit(&findings, function, offset,
                         rule("ERC20 Approval Race", .medium, always: true),
                         message: "approve() overwrites the allowance with `=`; a pending transaction lets the spender double-spend. Use increaseAllowance/decreaseAllowance.",
                         taint: nil, reachable: reachable, crossFile: false)
                }
            }
        }
        for t in ev.erc20TransferCalls where !consumedOffsets.contains(t.offset) {
            emit(&findings, function, t.offset,
                 rule("Unchecked ERC20 Transfer Return", .medium, always: true),
                 message: "\(t.name)() returns a success flag that is not checked; non-reverting tokens silently fail and bookkeeping diverges.",
                 taint: nil, reachable: reachable, crossFile: false)
        }
        for w in ev.privilegedWrites {
            if let src = w.source, !ev.zeroCheckedParams.contains(src), isAddressLikeStateName(w.target) {
                emit(&findings, function, w.offset,
                     rule("Missing Zero-Address Check", .medium, always: true),
                     message: "'\(w.target)' is set from '\(src)' without rejecting address(0); funds/authority can be irreversibly locked.",
                     taint: nil, reachable: reachable, crossFile: false)
            }
        }
        if solidityPre08 && function != "constructor" {
            let hasVisibility = fn.qualifiers.contains("public") || fn.qualifiers.contains("private")
                || fn.qualifiers.contains("internal") || fn.qualifiers.contains("external")
            if !hasVisibility {
                emit(&findings, function, fn.startOffset,
                     rule("Function Default Visibility", .medium, always: true),
                     message: "function visibility is implicit (public before Solidity 0.5); state it explicitly.",
                     taint: nil, reachable: reachable, crossFile: false)
            }
        }
        if solidityPre08 {
            for offset in ev.overflowOffsets {
                emit(&findings, function, offset,
                     rule("Unchecked Arithmetic Overflow", .high, always: true),
                     message: "arithmetic on caller-controlled values before Solidity 0.8 silently wraps on overflow/underflow; use SafeMath or checked math.",
                     taint: nil, reachable: reachable, crossFile: false)
            }
        }
        // Solidity `unchecked { ... }` blocks re-enable pre-0.8 wrap-around
        // semantics in 0.8.x sources; compound assignment or increment inside
        // such a block can silently overflow/underflow.
        if isSolidity {
            checkUncheckedArithmeticBlocks(fn: fn, findings: &findings, reachable: reachable)
        }
    }

    /// Flags arithmetic inside `unchecked { ... }` blocks. The C body parser
    /// cannot represent `unchecked` (it is not a C statement), so this walks
    /// the function source: locate each `unchecked {` with comments masked out,
    /// find its matching closing brace, and report if the block contains
    /// arithmetic operations.
    private func checkUncheckedArithmeticBlocks(fn: CFunctionDef, findings: inout [AstFinding], reachable: Bool) {
        guard fn.startOffset >= 0, fn.endOffset > fn.startOffset,
              fn.endOffset <= source.utf16.count else { return }
        let ns = source as NSString
        let fnLen = fn.endOffset - fn.startOffset
        let masked = commentMasked(ns.substring(with: NSRange(location: fn.startOffset, length: fnLen)))
        let fnNS = masked as NSString
        let options: NSRegularExpression.Options = []
        guard let kw = try? NSRegularExpression(pattern: "\\bunchecked\\s*\\{", options: options),
              let ops = try? NSRegularExpression(pattern: "(?:\\+\\=|\\-\\=|\\*=|\\+|\\+|\\-\\-)", options: options) else { return }
        for m in kw.matches(in: masked, options: [], range: NSRange(location: 0, length: fnNS.length)) {
            let open = m.range.location + m.range.length - 1
            guard open >= 0, open < fnNS.length else { continue }
            var depth = 0
            var close = -1
            var i = open
            while i < fnNS.length {
                let ch = fnNS.character(at: i)
                if ch == 0x7B { depth += 1 }          // '{'
                else if ch == 0x7D {                  // '}'
                    depth -= 1
                    if depth == 0 { close = i; break }
                }
                i += 1
            }
            guard close > open else { continue }
            let bodyRange = NSRange(location: open, length: close - open + 1)
            let body = fnNS.substring(with: bodyRange) as NSString
            if !ops.matches(in: body as String, options: [], range: NSRange(location: 0, length: body.length)).isEmpty {
                emit(&findings, fn.name, fn.startOffset + open,
                     rule("Unchecked Arithmetic Overflow", .high, always: true),
                     message: "unchecked block restores pre-0.8 wrap-around arithmetic; overflow/underflow is silently possible.",
                     taint: nil, reachable: reachable, crossFile: false)
            }
        }
    }

    /// Returns a copy of `src` with `//` line comments and `/* ... */` block
    /// comments blanked (same length, offset-preserving); string literals are
    /// left intact so `"//"` inside them is not mistaken for a comment.
    private func commentMasked(_ src: String) -> String {
        var chars = Array(src)
        var i = 0
        var stringCh: Character?
        var blockComment = false
        let n = chars.count
        while i < n {
            let c = chars[i]
            if let q = stringCh {
                if c == q && (i == 0 || chars[i - 1] != "\\") { stringCh = nil }
                i += 1
                continue
            }
            if blockComment {
                if c == "*" && i + 1 < n && chars[i + 1] == "/" {
                    blockComment = false
                    chars[i] = " "; chars[i + 1] = " "
                    i += 2
                } else {
                    if c != "\n" { chars[i] = " " }
                    i += 1
                }
                continue
            }
            if c == "\"" || c == "'" {
                stringCh = c
                i += 1
                continue
            }
            if c == "/" && i + 1 < n && chars[i + 1] == "/" {
                while i < n && chars[i] != "\n" { chars[i] = " "; i += 1 }
                continue
            }
            if c == "/" && i + 1 < n && chars[i + 1] == "*" {
                blockComment = true
                chars[i] = " "; chars[i + 1] = " "
                i += 2
                continue
            }
            i += 1
        }
        return String(chars)
    }

    /// Calls whose failure silently returns `false` and thus MUST be checked.
    /// `transfer` is excluded because it reverts the whole transaction on failure.
    private func uncheckedReturnCall(_ name: String) -> Bool {
        name == "call" || name == "delegatecall" || name == "staticcall"
            || name == "callcode" || name == "send"
    }

    // MARK: - Solidity extended (Walk 4) events

    /// Collections for the extended Solidity walk: time/balance dependence,
    /// loop hazards, authorization, ERC20 correctness, ecrecover handling and
    /// pre-0.8 arithmetic.
    private struct SolidityExtEvents {
        // True while collecting a `require(...)` call's arguments. A monotonic
        // `>=`/`<=` timestamp comparison inside a require is a deadline or
        // timelock validation (the safe pattern), not time-gated control flow.
        var inRequireContext = false
        var timestampLogicUses: [Int] = []
        var nowUses: [Int] = []
        var balanceUses: [Int] = []
        var loopCallOffsets: [Int] = []
        var unboundedLoopOffsets: [Int] = []
        var assertInputOffsets: [Int] = []
        var ecrecoverOffsets: [Int] = []
        var ecrecoverResultVars: Set<String> = []
        var ecrecoverGuarded = false
        var privilegedWrites: [(offset: Int, target: String, source: String?)] = []
        var hasAuthCheck = false
        var zeroCheckedParams: Set<String> = []
        var approvalWriteOffsets: [Int] = []
        var erc20TransferCalls: [(offset: Int, name: String)] = []
        var overflowOffsets: [Int] = []
    }

    private func collectSolidityExtendedEvents(_ stmt: CStmt, params: Set<String>, tainted: Set<String>, inLoop: Bool, ev: inout SolidityExtEvents) {
        switch stmt {
        case .block(let arr):
            for s in arr { collectSolidityExtendedEvents(s, params: params, tainted: tainted, inLoop: inLoop, ev: &ev) }
        case .declaration(let d):
            if case .variable(_, let name, let ie?) = d.kind {
                collectSolidityExtendedExpr(ie, params: params, tainted: tainted, inLoop: inLoop, ev: &ev)
                if case .call(let callee, _, _) = ie, callName(callee) == "ecrecover" {
                    ev.ecrecoverResultVars.insert(name)
                }
            }
        case .expr(let e):
            collectSolidityExtendedExpr(e, params: params, tainted: tainted, inLoop: inLoop, ev: &ev)
        case .ifStmt(let cond, let then, let elseStmt, _):
            collectSolidityExtendedExpr(cond, params: params, tainted: tainted, inLoop: inLoop, ev: &ev)
            collectSolidityExtendedEvents(then, params: params, tainted: tainted, inLoop: inLoop, ev: &ev)
            if let et = elseStmt {
                collectSolidityExtendedEvents(et, params: params, tainted: tainted, inLoop: inLoop, ev: &ev)
            }
        case .whileStmt(let cond, let body, let offset):
            collectSolidityExtendedExpr(cond, params: params, tainted: tainted, inLoop: inLoop, ev: &ev)
            if isUnboundedLengthCond(cond, params: params) { ev.unboundedLoopOffsets.append(offset) }
            collectSolidityExtendedEvents(body, params: params, tainted: tainted, inLoop: true, ev: &ev)
        case .doWhileStmt(let body, let cond, _):
            collectSolidityExtendedEvents(body, params: params, tainted: tainted, inLoop: true, ev: &ev)
            collectSolidityExtendedExpr(cond, params: params, tainted: tainted, inLoop: inLoop, ev: &ev)
        case .forStmt(let ini, let cond, let incr, let body, let offset):
            if let i = ini { collectSolidityExtendedEvents(i, params: params, tainted: tainted, inLoop: false, ev: &ev) }
            if let c = cond {
                collectSolidityExtendedExpr(c, params: params, tainted: tainted, inLoop: inLoop, ev: &ev)
                if isUnboundedLengthCond(c, params: params) { ev.unboundedLoopOffsets.append(offset) }
            }
            if let ic = incr { collectSolidityExtendedExpr(ic, params: params, tainted: tainted, inLoop: inLoop, ev: &ev) }
            collectSolidityExtendedEvents(body, params: params, tainted: tainted, inLoop: true, ev: &ev)
        case .switchStmt(_, let cases, _):
            for c in cases {
                for s in c.body {
                    collectSolidityExtendedEvents(s, params: params, tainted: tainted, inLoop: inLoop, ev: &ev)
                }
            }
        case .returnStmt(let e, _):
            if let e = e { collectSolidityExtendedExpr(e, params: params, tainted: tainted, inLoop: inLoop, ev: &ev) }
        case .labeledStmt(_, let s, _):
            collectSolidityExtendedEvents(s, params: params, tainted: tainted, inLoop: inLoop, ev: &ev)
        default:
            break
        }
    }

    private func collectSolidityExtendedExpr(_ e: CExpr, params: Set<String>, tainted: Set<String>, inLoop: Bool, ev: inout SolidityExtEvents) {
        switch e {
        case .call(let callee, let args, let offset):
            let cn = callName(callee)
            if cn == "ecrecover" {
                ev.ecrecoverOffsets.append(offset)
            }
            if let cn = cn, isSolidityExternalCall(cn) {
                if inLoop { ev.loopCallOffsets.append(offset) }
                if (cn == "transfer" && args.count == 2) || (cn == "transferFrom" && args.count == 3) {
                    ev.erc20TransferCalls.append((offset: offset, name: cn))
                }
            }
            if cn == "assert", let first = args.first, case .binary(let op, let l, let r, _) = first,
               op == "==" || op == "!=" || op == ">" || op == ">=" || op == "<" || op == "<=" {
                // Input-validation shape: a caller-controlled value compared
                // against a constant. (Taint flows into accumulators, so an
                // assert between two state variables is an invariant, not a
                // validation.)
                let lLit = isLiteralExpr(l), rLit = isLiteralExpr(r)
                if (!lLit && rLit && exprTainted(l, tainted: tainted) != nil)
                    || (!rLit && lLit && exprTainted(r, tainted: tainted) != nil) {
                    ev.assertInputOffsets.append(offset)
                }
            }
            collectSolidityExtendedExpr(callee, params: params, tainted: tainted, inLoop: inLoop, ev: &ev)
            let prevRequireContext = ev.inRequireContext
            if cn == "require" { ev.inRequireContext = true }
            for a in args {
                collectSolidityExtendedExpr(a, params: params, tainted: tainted, inLoop: inLoop, ev: &ev)
            }
            ev.inRequireContext = prevRequireContext
        case .assign(let op, let lhs, let rhs, let offset):
            if solidityIsStateWrite(lhs, params: params) {
                if case .identifier(let target, _) = lhs, isPrivilegedStateName(target),
                   let src = simpleIdentifier(rhs), params.contains(src) {
                    // Only caller-settable writes (from a function parameter) are
                    // security-relevant; `owner = msg.sender` in a constructor is
                    // the canonical safe pattern.
                    ev.privilegedWrites.append((offset: offset, target: target, source: src))
                }
                if op == "=", case .index(let ib, _, _) = lhs, let base = solidityIndexChainBase(ib), base.lowercased().contains("allow") {
                    ev.approvalWriteOffsets.append(offset)
                }
                if solidityPre08, (op == "+=" || op == "-=" || op == "*=") {
                    ev.overflowOffsets.append(offset)
                }
            }
            if op == "=", let dst = simpleIdentifier(lhs), case .call(let callee, _, _) = rhs, callName(callee) == "ecrecover" {
                ev.ecrecoverResultVars.insert(dst)
            }
            collectSolidityExtendedExpr(lhs, params: params, tainted: tainted, inLoop: inLoop, ev: &ev)
            collectSolidityExtendedExpr(rhs, params: params, tainted: tainted, inLoop: inLoop, ev: &ev)
        case .member(let base, let m, _, let offset):
            if m == "balance", solidityBaseIsSelfAddress(base) {
                ev.balanceUses.append(offset)
            }
            collectSolidityExtendedExpr(base, params: params, tainted: tainted, inLoop: inLoop, ev: &ev)
        case .index(let b, let i, _):
            collectSolidityExtendedExpr(b, params: params, tainted: tainted, inLoop: inLoop, ev: &ev)
            collectSolidityExtendedExpr(i, params: params, tainted: tainted, inLoop: inLoop, ev: &ev)
        case .binary(let op, let l, let r, _):
            if op == "+" || op == "-" || op == "*" {
                if exprTainted(l, tainted: tainted) != nil, exprTainted(r, tainted: tainted) != nil, solidityPre08 {
                    ev.overflowOffsets.append(e.offset)
                }
            }
            if op == "==" || op == "!=" || op == ">" || op == ">=" || op == "<" || op == "<=" {
                // A `>=`/`<=` deadline or timelock comparison inside a require is
                // the canonical safe pattern (EIP-2612 expiry, timelock gates);
                // strict equality and non-monotonic comparisons still record.
                let monotonicInRequire = ev.inRequireContext && (op == ">=" || op == "<=")
                if !monotonicInRequire {
                    collectBlockTimestampUses(l, ev: &ev)
                    collectBlockTimestampUses(r, ev: &ev)
                }
                let lZero = isAddressZeroExpr(l), rZero = isAddressZeroExpr(r)
                if lZero || rZero {
                    if let idName = simpleIdentifier(lZero ? r : l) {
                        ev.zeroCheckedParams.insert(idName)
                        if ev.ecrecoverResultVars.contains(idName) { ev.ecrecoverGuarded = true }
                    }
                    if let cn = callName(lZero ? r : l), cn == "ecrecover" { ev.ecrecoverGuarded = true }
                }
                if ev.hasAuthCheck == false, exprContainsMsgSenderOrTxOrigin(l) || exprContainsMsgSenderOrTxOrigin(r) {
                    ev.hasAuthCheck = true
                }
            }
            collectSolidityExtendedExpr(l, params: params, tainted: tainted, inLoop: inLoop, ev: &ev)
            collectSolidityExtendedExpr(r, params: params, tainted: tainted, inLoop: inLoop, ev: &ev)
        case .unary(_, let o, _):
            collectSolidityExtendedExpr(o, params: params, tainted: tainted, inLoop: inLoop, ev: &ev)
        case .ternary(let c, let t, let f, _):
            collectSolidityExtendedExpr(c, params: params, tainted: tainted, inLoop: inLoop, ev: &ev)
            collectSolidityExtendedExpr(t, params: params, tainted: tainted, inLoop: inLoop, ev: &ev)
            collectSolidityExtendedExpr(f, params: params, tainted: tainted, inLoop: inLoop, ev: &ev)
        case .cast(let x, _), .paren(let x, _):
            collectSolidityExtendedExpr(x, params: params, tainted: tainted, inLoop: inLoop, ev: &ev)
        case .identifier(let n, let offset):
            if n == "now" { ev.nowUses.append(offset) }
        case .comma(let l, let r, _):
            collectSolidityExtendedExpr(l, params: params, tainted: tainted, inLoop: inLoop, ev: &ev)
            collectSolidityExtendedExpr(r, params: params, tainted: tainted, inLoop: inLoop, ev: &ev)
        case .arrayInit(let arr, _):
            for a in arr { collectSolidityExtendedExpr(a, params: params, tainted: tainted, inLoop: inLoop, ev: &ev) }
        case .newExpr(_, let args, _):
            for a in args { collectSolidityExtendedExpr(a, params: params, tainted: tainted, inLoop: inLoop, ev: &ev) }
        default:
            break
        }
    }

    /// Records `block.timestamp` member uses that appear inside a comparison
    /// (control-flow/logic decision), not inside e.g. hashing arguments.
    private func collectBlockTimestampUses(_ e: CExpr, ev: inout SolidityExtEvents) {
        switch e {
        case .member(let base, let m, _, let offset):
            if m == "timestamp", baseIsBlockGlobal(base) { ev.timestampLogicUses.append(offset) }
            collectBlockTimestampUses(base, ev: &ev)
        case .call(let c, let args, _):
            collectBlockTimestampUses(c, ev: &ev)
            for a in args { collectBlockTimestampUses(a, ev: &ev) }
        case .binary(_, let l, let r, _), .comma(let l, let r, _):
            collectBlockTimestampUses(l, ev: &ev)
            collectBlockTimestampUses(r, ev: &ev)
        case .unary(_, let o, _):
            collectBlockTimestampUses(o, ev: &ev)
        case .ternary(let c, let t, let f, _):
            collectBlockTimestampUses(c, ev: &ev)
            collectBlockTimestampUses(t, ev: &ev)
            collectBlockTimestampUses(f, ev: &ev)
        case .cast(let x, _), .paren(let x, _):
            collectBlockTimestampUses(x, ev: &ev)
        case .index(let b, let i, _):
            collectBlockTimestampUses(b, ev: &ev)
            collectBlockTimestampUses(i, ev: &ev)
        default:
            break
        }
    }

    // MARK: - Solidity extended-walk helpers

    private func isUnboundedLengthCond(_ cond: CExpr, params: Set<String>) -> Bool {
        if case .binary(_, let l, let r, _) = cond {
            return unboundedLengthIn(l, params: params) || unboundedLengthIn(r, params: params)
        }
        return false
    }

    /// True when `e` references a `.length` whose base is state (Storage) rather
    /// than a caller-supplied array parameter. Storage arrays grow across
    /// transactions and can exceed the block gas limit; a function parameter's
    /// size is fixed at call time, so the loop is bounded.
    private func unboundedLengthIn(_ e: CExpr, params: Set<String>) -> Bool {
        switch e {
        case .member(let base, let m, _, _):
            if m == "length" {
                if let id = simpleIdentifier(base) {
                    return !params.contains(id)
                }
                return true
            }
            return unboundedLengthIn(base, params: params)
        case .call(let c, let args, _):
            if unboundedLengthIn(c, params: params) { return true }
            return args.contains { unboundedLengthIn($0, params: params) }
        case .binary(_, let l, let r, _), .comma(let l, let r, _):
            return unboundedLengthIn(l, params: params) || unboundedLengthIn(r, params: params)
        case .unary(_, let o, _):
            return unboundedLengthIn(o, params: params)
        case .ternary(let c, let t, let f, _):
            return unboundedLengthIn(c, params: params) || unboundedLengthIn(t, params: params) || unboundedLengthIn(f, params: params)
        case .cast(let x, _), .paren(let x, _):
            return unboundedLengthIn(x, params: params)
        case .index(let b, let i, _):
            return unboundedLengthIn(b, params: params) || unboundedLengthIn(i, params: params)
        default:
            return false
        }
    }

    /// `address(this)` or bare `this` — the base of a `.balance` read.
    private func solidityBaseIsSelfAddress(_ e: CExpr) -> Bool {
        if case .identifier(let n, _) = e { return n == "this" }
        if case .call(let callee, _, _) = e { return callName(callee) == "address" }
        if case .paren(let x, _) = e { return solidityBaseIsSelfAddress(x) }
        return false
    }

    private func baseIsBlockGlobal(_ e: CExpr) -> Bool {
        if case .identifier(let n, _) = e { return n == "block" }
        return false
    }

    private func isPrivilegedStateName(_ n: String) -> Bool {
        let low = n.lowercased()
        let names = ["owner", "admin", "fee", "price", "rate", "paused", "limit", "threshold", "treasury", "vault", "wallet", "beneficiary", "gatekeeper", "whitelist", "blacklist"]
        return names.contains { low == $0 || low.hasPrefix($0) }
    }

    /// State names that semantically hold an address, where a zero-address
    /// validation is meaningful.
    private func isAddressLikeStateName(_ n: String) -> Bool {
        let low = n.lowercased()
        let names = ["owner", "admin", "beneficiary", "treasury", "wallet", "gatekeeper", "controller", "authority"]
        return names.contains { low == $0 || low.hasPrefix($0) }
    }

    private func solidityIndexChainBase(_ e: CExpr) -> String? {
        switch e {
        case .index(let b, _, _): return solidityIndexChainBase(b)
        case .identifier(let n, _): return n
        default: return nil
        }
    }

    private func exprContainsMsgSenderOrTxOrigin(_ e: CExpr) -> Bool {
        switch e {
        case .member(let b, let m, _, _):
            if m == "sender" || m == "origin" { return true }
            return exprContainsMsgSenderOrTxOrigin(b)
        case .call(let c, let args, _):
            if exprContainsMsgSenderOrTxOrigin(c) { return true }
            return args.contains { exprContainsMsgSenderOrTxOrigin($0) }
        case .binary(_, let l, let r, _), .comma(let l, let r, _):
            return exprContainsMsgSenderOrTxOrigin(l) || exprContainsMsgSenderOrTxOrigin(r)
        case .unary(_, let o, _):
            return exprContainsMsgSenderOrTxOrigin(o)
        case .ternary(let c, let t, let f, _):
            return exprContainsMsgSenderOrTxOrigin(c) || exprContainsMsgSenderOrTxOrigin(t) || exprContainsMsgSenderOrTxOrigin(f)
        case .cast(let x, _), .paren(let x, _):
            return exprContainsMsgSenderOrTxOrigin(x)
        case .index(let b, let i, _):
            return exprContainsMsgSenderOrTxOrigin(b) || exprContainsMsgSenderOrTxOrigin(i)
        case .assign(_, let l, let r, _):
            return exprContainsMsgSenderOrTxOrigin(l) || exprContainsMsgSenderOrTxOrigin(r)
        default:
            return false
        }
    }

    /// True when the expression is `address(0)` (possibly wrapped in a cast/paren).
    private func isAddressZeroExpr(_ e: CExpr) -> Bool {
        if case .paren(let x, _) = e { return isAddressZeroExpr(x) }
        if case .cast(let x, _) = e { return isAddressZeroExpr(x) }
        if case .call(let callee, let args, _) = e, callName(callee) == "address", args.count == 1, isZeroLiteral(args[0]) {
            return true
        }
        return false
    }

    private func isZeroLiteral(_ e: CExpr) -> Bool {
        if case .paren(let x, _) = e { return isZeroLiteral(x) }
        if case .integerLiteral(let v, _) = e {
            return v == "0" || v.hasSuffix("x0") || v.hasSuffix("X0")
        }
        return false
    }

    private func isLiteralExpr(_ e: CExpr) -> Bool {
        switch e {
        case .integerLiteral, .floatLiteral, .stringLiteral, .charLiteral, .booleanLiteral:
            return true
        case .paren(let x, _):
            return isLiteralExpr(x)
        default:
            return false
        }
    }

    /// True when the expression is exactly `block.number` (possibly wrapped in a
    /// cast/paren) — not an arithmetic variant like `block.number - 1`.
    private func isBlockNumberExpr(_ e: CExpr) -> Bool {
        if case .paren(let x, _) = e { return isBlockNumberExpr(x) }
        if case .cast(let x, _) = e { return isBlockNumberExpr(x) }
        if case .member(let base, let m, _, _) = e, m == "number", baseIsBlockGlobal(base) {
            return true
        }
        return false
    }

    /// Walks the statement tree collecting external calls, storage writes and
    /// tx.origin uses, and whether a reentrancy guard is set at the top.
    private func collectSolidityEvents(_ stmt: CStmt, params: Set<String>, externalCalls: inout [(offset: Int, name: String)], stateWrites: inout [Int], txOriginUses: inout [Int], sawGuardSet: inout Bool) {
        switch stmt {
        case .block(let arr):
            for s in arr {
                collectSolidityEvents(s, params: params, externalCalls: &externalCalls, stateWrites: &stateWrites, txOriginUses: &txOriginUses, sawGuardSet: &sawGuardSet)
            }
        case .declaration(let d):
            if case .variable(_, _, let ie?) = d.kind {
                collectSolidityExpr(ie, params: params, externalCalls: &externalCalls, stateWrites: &stateWrites, txOriginUses: &txOriginUses, sawGuardSet: &sawGuardSet)
            }
        case .expr(let e):
            collectSolidityExpr(e, params: params, externalCalls: &externalCalls, stateWrites: &stateWrites, txOriginUses: &txOriginUses, sawGuardSet: &sawGuardSet)
        case .ifStmt(let cond, let then, let elseStmt, _):
            collectSolidityExpr(cond, params: params, externalCalls: &externalCalls, stateWrites: &stateWrites, txOriginUses: &txOriginUses, sawGuardSet: &sawGuardSet)
            collectSolidityEvents(then, params: params, externalCalls: &externalCalls, stateWrites: &stateWrites, txOriginUses: &txOriginUses, sawGuardSet: &sawGuardSet)
            if let et = elseStmt {
                collectSolidityEvents(et, params: params, externalCalls: &externalCalls, stateWrites: &stateWrites, txOriginUses: &txOriginUses, sawGuardSet: &sawGuardSet)
            }
        case .whileStmt(let cond, let body, _):
            collectSolidityExpr(cond, params: params, externalCalls: &externalCalls, stateWrites: &stateWrites, txOriginUses: &txOriginUses, sawGuardSet: &sawGuardSet)
            collectSolidityEvents(body, params: params, externalCalls: &externalCalls, stateWrites: &stateWrites, txOriginUses: &txOriginUses, sawGuardSet: &sawGuardSet)
        case .doWhileStmt(let body, let cond, _):
            collectSolidityEvents(body, params: params, externalCalls: &externalCalls, stateWrites: &stateWrites, txOriginUses: &txOriginUses, sawGuardSet: &sawGuardSet)
            collectSolidityExpr(cond, params: params, externalCalls: &externalCalls, stateWrites: &stateWrites, txOriginUses: &txOriginUses, sawGuardSet: &sawGuardSet)
        case .forStmt(let ini, let cond, let incr, let body, _):
            if let i = ini { collectSolidityEvents(i, params: params, externalCalls: &externalCalls, stateWrites: &stateWrites, txOriginUses: &txOriginUses, sawGuardSet: &sawGuardSet) }
            if let c = cond { collectSolidityExpr(c, params: params, externalCalls: &externalCalls, stateWrites: &stateWrites, txOriginUses: &txOriginUses, sawGuardSet: &sawGuardSet) }
            if let ic = incr { collectSolidityExpr(ic, params: params, externalCalls: &externalCalls, stateWrites: &stateWrites, txOriginUses: &txOriginUses, sawGuardSet: &sawGuardSet) }
            collectSolidityEvents(body, params: params, externalCalls: &externalCalls, stateWrites: &stateWrites, txOriginUses: &txOriginUses, sawGuardSet: &sawGuardSet)
        case .switchStmt(_, let cases, _):
            for c in cases {
                for s in c.body {
                    collectSolidityEvents(s, params: params, externalCalls: &externalCalls, stateWrites: &stateWrites, txOriginUses: &txOriginUses, sawGuardSet: &sawGuardSet)
                }
            }
        case .returnStmt(let e, _):
            if let e = e { collectSolidityExpr(e, params: params, externalCalls: &externalCalls, stateWrites: &stateWrites, txOriginUses: &txOriginUses, sawGuardSet: &sawGuardSet) }
        case .labeledStmt(_, let s, _):
            collectSolidityEvents(s, params: params, externalCalls: &externalCalls, stateWrites: &stateWrites, txOriginUses: &txOriginUses, sawGuardSet: &sawGuardSet)
        default:
            break
        }
    }

    private func collectSolidityExpr(_ e: CExpr, params: Set<String>, externalCalls: inout [(offset: Int, name: String)], stateWrites: inout [Int], txOriginUses: inout [Int], sawGuardSet: inout Bool) {
        switch e {
        case .call(let callee, let args, let offset):
            if isSolidityArrayMutationCall(callee, params: params) {
                stateWrites.append(offset)
            }
            let extName = callName(callee).flatMap { isSolidityExternalCall($0) ? $0 : nil }
                ?? solidityChainedExternalCall(callee)
            if let cn = extName {
                externalCalls.append((offset: offset, name: cn))
            }
            collectSolidityExpr(callee, params: params, externalCalls: &externalCalls, stateWrites: &stateWrites, txOriginUses: &txOriginUses, sawGuardSet: &sawGuardSet)
            for a in args {
                collectSolidityExpr(a, params: params, externalCalls: &externalCalls, stateWrites: &stateWrites, txOriginUses: &txOriginUses, sawGuardSet: &sawGuardSet)
            }
        case .assign(_, let lhs, let rhs, let offset2):
            if solidityIsStateWrite(lhs, params: params) {
                stateWrites.append(offset2)
                if isGuardVar(lhs), isTruthyGuardValue(rhs) { sawGuardSet = true }
            }
            collectSolidityExpr(lhs, params: params, externalCalls: &externalCalls, stateWrites: &stateWrites, txOriginUses: &txOriginUses, sawGuardSet: &sawGuardSet)
            collectSolidityExpr(rhs, params: params, externalCalls: &externalCalls, stateWrites: &stateWrites, txOriginUses: &txOriginUses, sawGuardSet: &sawGuardSet)
        case .member(let base, let m, _, let offset3):
            if baseRefsTxOrigin(base), m == "origin" {
                txOriginUses.append(offset3)
            }
            collectSolidityExpr(base, params: params, externalCalls: &externalCalls, stateWrites: &stateWrites, txOriginUses: &txOriginUses, sawGuardSet: &sawGuardSet)
        case .index(let b, let i, _):
            collectSolidityExpr(b, params: params, externalCalls: &externalCalls, stateWrites: &stateWrites, txOriginUses: &txOriginUses, sawGuardSet: &sawGuardSet)
            collectSolidityExpr(i, params: params, externalCalls: &externalCalls, stateWrites: &stateWrites, txOriginUses: &txOriginUses, sawGuardSet: &sawGuardSet)
        case .binary(_, let l, let r, _), .comma(let l, let r, _):
            collectSolidityExpr(l, params: params, externalCalls: &externalCalls, stateWrites: &stateWrites, txOriginUses: &txOriginUses, sawGuardSet: &sawGuardSet)
            collectSolidityExpr(r, params: params, externalCalls: &externalCalls, stateWrites: &stateWrites, txOriginUses: &txOriginUses, sawGuardSet: &sawGuardSet)
        case .unary(_, let o, _):
            collectSolidityExpr(o, params: params, externalCalls: &externalCalls, stateWrites: &stateWrites, txOriginUses: &txOriginUses, sawGuardSet: &sawGuardSet)
        case .ternary(let c, let t, let f, _):
            collectSolidityExpr(c, params: params, externalCalls: &externalCalls, stateWrites: &stateWrites, txOriginUses: &txOriginUses, sawGuardSet: &sawGuardSet)
            collectSolidityExpr(t, params: params, externalCalls: &externalCalls, stateWrites: &stateWrites, txOriginUses: &txOriginUses, sawGuardSet: &sawGuardSet)
            collectSolidityExpr(f, params: params, externalCalls: &externalCalls, stateWrites: &stateWrites, txOriginUses: &txOriginUses, sawGuardSet: &sawGuardSet)
        case .cast(let x, _), .paren(let x, _):
            collectSolidityExpr(x, params: params, externalCalls: &externalCalls, stateWrites: &stateWrites, txOriginUses: &txOriginUses, sawGuardSet: &sawGuardSet)
        case .arrayInit(let arr, _):
            for a in arr { collectSolidityExpr(a, params: params, externalCalls: &externalCalls, stateWrites: &stateWrites, txOriginUses: &txOriginUses, sawGuardSet: &sawGuardSet) }
        case .newExpr(_, let args, _):
            for a in args { collectSolidityExpr(a, params: params, externalCalls: &externalCalls, stateWrites: &stateWrites, txOriginUses: &txOriginUses, sawGuardSet: &sawGuardSet) }
        default:
            break
        }
    }

    /// Collects the offsets of external calls whose return value IS consumed —
    /// i.e. used directly in an `if` condition or as an argument to `require` /
    /// `assert`. It also tracks `varName = call()` bindings so a later
    /// `if (varName)` / `require(varName)` marks the original call consumed.
    /// External calls NOT in the consumed set are "unchecked".
    private func collectConsumedExternalCalls(_ stmt: CStmt, offsets: inout Set<Int>, callSourceVar: inout [String: Int]) {
        switch stmt {
        case .block(let arr):
            for s in arr { collectConsumedExternalCalls(s, offsets: &offsets, callSourceVar: &callSourceVar) }
        case .ifStmt(let cond, let then, let elseStmt, _):
            collectConsumedCondition(cond, offsets: &offsets, callSourceVar: &callSourceVar)
            collectConsumedExternalCalls(then, offsets: &offsets, callSourceVar: &callSourceVar)
            if let e = elseStmt { collectConsumedExternalCalls(e, offsets: &offsets, callSourceVar: &callSourceVar) }
        case .whileStmt(let cond, let body, _):
            collectConsumedCondition(cond, offsets: &offsets, callSourceVar: &callSourceVar)
            collectConsumedExternalCalls(body, offsets: &offsets, callSourceVar: &callSourceVar)
        case .doWhileStmt(let body, let cond, _):
            collectConsumedExternalCalls(body, offsets: &offsets, callSourceVar: &callSourceVar)
            collectConsumedCondition(cond, offsets: &offsets, callSourceVar: &callSourceVar)
        case .forStmt(let ini, let cond, let incr, let body, _):
            if let i = ini { collectConsumedExternalCalls(i, offsets: &offsets, callSourceVar: &callSourceVar) }
            if let c = cond { collectConsumedCondition(c, offsets: &offsets, callSourceVar: &callSourceVar) }
            if let ic = incr { collectConsumedCondition(ic, offsets: &offsets, callSourceVar: &callSourceVar) }
            collectConsumedExternalCalls(body, offsets: &offsets, callSourceVar: &callSourceVar)
        case .declaration(let d):
            if case .variable(_, let name, let ie?) = d.kind {
                bindExternalCallResult(ie, to: name, callSourceVar: &callSourceVar, offsets: &offsets)
            }
        case .expr(let e):
            // A top-level `require(...)` / `assert(...)` guards the following
            // code; any external call inside its arguments is consumed.
            if case .call(let callee, let args, _) = e, let cn = callName(callee),
               cn == "require" || cn == "assert" {
                for a in args {
                    collectConsumedExternalCallExpr(a, offsets: &offsets, callSourceVar: &callSourceVar)
                }
            } else if case .assign(_, let lhs, let rhs, _) = e {
                if let v = simpleIdentifier(lhs) {
                    bindExternalCallResult(rhs, to: v, callSourceVar: &callSourceVar, offsets: &offsets)
                }
            }
        case .returnStmt(let e, _):
            if let e = e { collectConsumedExternalCallExpr(e, offsets: &offsets, callSourceVar: &callSourceVar) }
        case .switchStmt(_, let cases, _):
            for c in cases { for s in c.body { collectConsumedExternalCalls(s, offsets: &offsets, callSourceVar: &callSourceVar) } }
        case .labeledStmt(_, let s, _):
            collectConsumedExternalCalls(s, offsets: &offsets, callSourceVar: &callSourceVar)
        default:
            break
        }
    }

    /// An `if`/`while` condition or a `require`/`assert` argument marks the
    /// external calls it contains (directly, or via a bound result variable) as
    /// consumed.
    private func collectConsumedCondition(_ e: CExpr, offsets: inout Set<Int>, callSourceVar: inout [String: Int]) {
        switch e {
        case .call(let callee, let args, let offset):
            if let cn = callName(callee), (cn == "require" || cn == "assert") {
                for a in args { collectConsumedExternalCallExpr(a, offsets: &offsets, callSourceVar: &callSourceVar) }
                return
            }
            if let cn = callName(callee), isSolidityExternalCall(cn) {
                offsets.insert(offset)
                return
            }
            // Non-external call in a condition (e.g. `if (pendingTransfers(...))`):
            // a bare external call nested in its args is still used as a check.
            collectConsumedExternalCallExpr(callee, offsets: &offsets, callSourceVar: &callSourceVar)
            for a in args { collectConsumedExternalCallExpr(a, offsets: &offsets, callSourceVar: &callSourceVar) }
        case .identifier(let n, _):
            if let off = callSourceVar[n] { offsets.insert(off) }
        case .member(let b, _, _, _):
            collectConsumedCondition(b, offsets: &offsets, callSourceVar: &callSourceVar)
        case .index(let b, let i, _):
            collectConsumedCondition(b, offsets: &offsets, callSourceVar: &callSourceVar)
            collectConsumedCondition(i, offsets: &offsets, callSourceVar: &callSourceVar)
        case .unary(_, let o, _):
            collectConsumedCondition(o, offsets: &offsets, callSourceVar: &callSourceVar)
        case .binary(_, let l, let r, _), .comma(let l, let r, _):
            collectConsumedCondition(l, offsets: &offsets, callSourceVar: &callSourceVar)
            collectConsumedCondition(r, offsets: &offsets, callSourceVar: &callSourceVar)
        case .ternary(let c, let t, let f, _):
            collectConsumedCondition(c, offsets: &offsets, callSourceVar: &callSourceVar)
            collectConsumedCondition(t, offsets: &offsets, callSourceVar: &callSourceVar)
            collectConsumedCondition(f, offsets: &offsets, callSourceVar: &callSourceVar)
        case .cast(let x, _), .paren(let x, _):
            collectConsumedCondition(x, offsets: &offsets, callSourceVar: &callSourceVar)
        case .arrayInit(let arr, _):
            for a in arr { collectConsumedCondition(a, offsets: &offsets, callSourceVar: &callSourceVar) }
        default:
            break
        }
    }

    /// If `e` is (or yields) an external call assigned to `name`, remember the
    /// call offset under that variable so `if (name)` / `require(name)` later
    /// marks it consumed. If `e` is a bare external call directly assigned (no
    /// name usage), it stays unchecked.
    private func bindExternalCallResult(_ e: CExpr, to name: String, callSourceVar: inout [String: Int], offsets: inout Set<Int>) {
        switch e {
        case .call(let callee, _, let offset):
            if let cn = callName(callee), isSolidityExternalCall(cn) {
                callSourceVar[name] = offset
            }
        case .binary(_, let l, let r, _), .comma(let l, let r, _):
            bindExternalCallResult(l, to: name, callSourceVar: &callSourceVar, offsets: &offsets)
            bindExternalCallResult(r, to: name, callSourceVar: &callSourceVar, offsets: &offsets)
        case .unary(_, let o, _):
            bindExternalCallResult(o, to: name, callSourceVar: &callSourceVar, offsets: &offsets)
        case .cast(let x, _), .paren(let x, _):
            bindExternalCallResult(x, to: name, callSourceVar: &callSourceVar, offsets: &offsets)
        default:
            break
        }
    }

    /// Walks a general expression marking any external calls it directly contains
    /// as consumed (used for `require`/`assert` arguments and if-conditions).
    private func collectConsumedExternalCallExpr(_ e: CExpr, offsets: inout Set<Int>, callSourceVar: inout [String: Int]) {
        switch e {
        case .call(let callee, let args, let offset):
            let extName = callName(callee).flatMap { isSolidityExternalCall($0) ? $0 : nil }
                ?? solidityChainedExternalCall(callee)
            if extName != nil {
                offsets.insert(offset)
            }
            collectConsumedExternalCallExpr(callee, offsets: &offsets, callSourceVar: &callSourceVar)
            for a in args { collectConsumedExternalCallExpr(a, offsets: &offsets, callSourceVar: &callSourceVar) }
        case .assign(_, _, let rhs, _):
            collectConsumedExternalCallExpr(rhs, offsets: &offsets, callSourceVar: &callSourceVar)
        case .binary(_, let l, let r, _), .comma(let l, let r, _):
            collectConsumedExternalCallExpr(l, offsets: &offsets, callSourceVar: &callSourceVar)
            collectConsumedExternalCallExpr(r, offsets: &offsets, callSourceVar: &callSourceVar)
        case .unary(_, let o, _):
            collectConsumedExternalCallExpr(o, offsets: &offsets, callSourceVar: &callSourceVar)
        case .ternary(let c, let t, let f, _):
            collectConsumedExternalCallExpr(c, offsets: &offsets, callSourceVar: &callSourceVar)
            collectConsumedExternalCallExpr(t, offsets: &offsets, callSourceVar: &callSourceVar)
            collectConsumedExternalCallExpr(f, offsets: &offsets, callSourceVar: &callSourceVar)
        case .cast(let x, _), .paren(let x, _):
            collectConsumedExternalCallExpr(x, offsets: &offsets, callSourceVar: &callSourceVar)
        case .member(let b, _, _, _):
            collectConsumedExternalCallExpr(b, offsets: &offsets, callSourceVar: &callSourceVar)
        case .index(let b, let i, _):
            collectConsumedExternalCallExpr(b, offsets: &offsets, callSourceVar: &callSourceVar)
            collectConsumedExternalCallExpr(i, offsets: &offsets, callSourceVar: &callSourceVar)
        case .arrayInit(let arr, _):
            for a in arr { collectConsumedExternalCallExpr(a, offsets: &offsets, callSourceVar: &callSourceVar) }
        case .newExpr(_, let args, _):
            for a in args { collectConsumedExternalCallExpr(a, offsets: &offsets, callSourceVar: &callSourceVar) }
        case .identifier(let n, _):
            if let off = callSourceVar[n] { offsets.insert(off) }
        default:
            break
        }
    }

    private func isSolidityExternalCall(_ name: String) -> Bool {
        name == "call" || name == "delegatecall" || name == "staticcall"
            || name == "callcode" || name == "transfer" || name == "send"
    }

    /// Solidity 0.4.x chained external calls — `<addr>.call.value(v)(...)` /
    /// `<addr>.call.gas(g)(...)` — bury the actual external-call name in the
    /// member chain (the trailing names are `value`/`gas`). Walk the whole
    /// member chain and return the external-call member name if present.
    /// True when the delegatecall receiver is a plain identifier not declared
    /// `immutable`/`constant` in the source — i.e. a mutable state variable
    /// (library pointer) the contract or anyone can repoint.
    private func isMutableStateReceiver(_ recv: CExpr) -> Bool {
        guard case .identifier(let n, _) = recv else { return false }
        // A receiver that is a storage variable declared `constant`/`immutable`
        // is fixed once and can never be re-pointed by an attacker, so a
        // delegatecall/transfer to it is not an untrusted target. The modifier
        // may sit anywhere in the declaration line, e.g.
        // `address private constant LIB = …;`, `uint256 public immutable OWNER;`,
        // `address private immutable impl;`. Find the line where the variable
        // first appears (its declaration) and look for the modifier there.
        let namePattern = "\\b" + NSRegularExpression.escapedPattern(for: n) + "\\b"
        for line in source.split(separator: "\n") {
            if line.range(of: namePattern, options: .regularExpression) != nil {
                let decl = String(line)
                let modifierPattern = "(?i)\\b(?:constant|immutable)\\b"
                let isFixed = (try? NSRegularExpression(pattern: modifierPattern))?
                    .firstMatch(in: decl, range: NSRange(location: 0, length: (decl as NSString).length)) != nil
                return !isFixed
            }
        }
        return true
    }

    private func solidityChainedExternalCall(_ callee: CExpr) -> String? {
        switch callee {
        case .member(let base, let m, _, _):
            if isSolidityExternalCall(m) { return m }
            return solidityChainedExternalCall(base)
        case .call(let inner, _, _):
            return solidityChainedExternalCall(inner)
        default:
            return nil
        }
    }

    private func solidityIsStateWrite(_ lhs: CExpr, params: Set<String>) -> Bool {
        switch lhs {
        case .member, .index:
            return true
        case .identifier(let n, _):
            return !params.contains(n)
        default:
            return false
        }
    }

    /// `arr.push(...)` / `arr.pop()` on a storage array mutates contract state;
    /// counts as a state write for checks-effects-interactions analysis.
    private func isSolidityArrayMutationCall(_ callee: CExpr, params: Set<String>) -> Bool {
        guard case .member(let base, let m, _, _) = callee, m == "push" || m == "pop" else { return false }
        guard let root = expressionRootName(base) else { return false }
        return !params.contains(root)
    }

    private func expressionRootName(_ e: CExpr) -> String? {
        switch e {
        case .identifier(let n, _):
            return n
        case .member(let b, _, _, _), .index(let b, _, _):
            return expressionRootName(b)
        default:
            return nil
        }
    }

    private func isGuardVar(_ lhs: CExpr) -> Bool {
        switch lhs {
        case .member(let b, let m, _, _):
            return isGuardName(m) || isGuardVar(b)
        case .identifier(let n, _):
            return isGuardName(n)
        default:
            return false
        }
    }

    private func isGuardName(_ n: String) -> Bool {
        let low = n.lowercased()
        return low.hasPrefix("lock") || low.hasPrefix("_lock") || low.hasPrefix("_entered")
            || low.hasPrefix("_guard") || low.hasPrefix("guard") || low.hasPrefix("_reent")
            || low.hasPrefix("reentrancy")
    }

    /// A "guard" assignment only actually guards when it is set to a truthy
    /// value. `lock = false` / `locked = 0` disarm the guard, so they must not
    /// suppress reentrancy detection.
    private func isTruthyGuardValue(_ rhs: CExpr) -> Bool {
        switch rhs {
        case .booleanLiteral(false, _):
            return false
        case .integerLiteral(let v, _):
            return v != "0"
        case .stringLiteral(let s, _):
            return !s.isEmpty && s != "false"
        case .unary(let op, _, _):
            return op != "!"
        case .paren(let x, _):
            return isTruthyGuardValue(x)
        default:
            return true
        }
    }

    private func baseRefsTxOrigin(_ base: CExpr) -> Bool {
        if case .identifier(let n, _) = base { return n == "tx" }
        return false
    }

} // end extension AstSecurityDetector

extension VulnerabilityScanner {

    private static let solidityHygieneCategories: Set<String> = [
        "Floating Pragma", "Missing Version Pragma", "Outdated Solidity Compiler",
        "Function Default Visibility", "Deprecated now Global",
        "Balance Dependence", "Unchecked Arithmetic Overflow",
    ]

    /// Drops hygiene-tier findings for `.sol` files that already carry at
    /// least one defect-tier finding, so the labeled defect dominates the
    /// report instead of era-normal lint noise.
    static func applySolidityHygieneTier(_ all: [ScanFinding]) -> [ScanFinding] {
        var byFile: [URL: Bool] = [:]
        for f in all where f.fileURL.pathExtension.lowercased() == "sol" {
            if !solidityHygieneCategories.contains(f.category) {
                byFile[f.fileURL] = true
            }
        }
        guard !byFile.isEmpty else { return all }
        return all.filter { f in
            guard f.fileURL.pathExtension.lowercased() == "sol",
                  solidityHygieneCategories.contains(f.category),
                  byFile[f.fileURL] == true else { return true }
            return false
        }
    }

    // MARK: - Solidity file-level checks (pragma hygiene)

    /// File-level Solidity findings that don't live in a function body:
    /// floating / outdated / missing compiler version pragmas.
    static func scanSolidityFileLevel(url: URL, source: String, scanningSource: String) -> [ScanFinding] {
        var findings: [ScanFinding] = []
        let ns = source as NSString
        let re = try! NSRegularExpression(pattern: "(?m)^\\s*pragma\\s+solidity\\s+([^;\\n]+);")
        let whole = NSRange(location: 0, length: ns.length)

        func appendFinding(_ line: Int, _ category: String, _ severity: ScanFinding.Severity, _ message: String) {
            findings.append(ScanFinding(
                fileURL: url,
                line: line,
                function: "",
                category: category,
                message: message,
                taint: nil,
                severity: severity,
                exploitability: severity,
                reachable: true,
                taintPath: nil,
                ignored: false,
                scanningSource: scanningSource
            ))
        }

        if let m = re.firstMatch(in: source, options: [], range: whole), m.range(at: 1).location != NSNotFound {
            let line = lineNumber(in: ns, location: m.range.location)
            let version = ns.substring(with: m.range(at: 1)).trimmingCharacters(in: .whitespaces)
            // A caret or range constraint pins nothing: the code can be compiled
            // with any (future) compiler in the range.
            if version.contains("^") || version.contains("<") || version.contains(">") {
                appendFinding(line, "Floating Pragma", .medium,
                              "pragma uses a floating version range ('\(version)'); pin an exact compiler version to avoid deploying untested code.")
            } else if let minor = solidityMinorVersion(version), minor < 8 {
                appendFinding(line, "Outdated Solidity Compiler", .medium,
                              "pragma targets Solidity 0.\(minor); versions before 0.8 lack checked arithmetic (silent over/underflows). Use 0.8.x.")
            }
        } else {
            appendFinding(1, "Missing Version Pragma", .medium,
                          "no `pragma solidity` directive; the file can be compiled by any compiler version, changing semantics silently.")
        }
        return findings
    }

    /// True when the file's `pragma solidity` pins/requests a compiler older
    /// than 0.8 (unchecked arithmetic semantics).
    static func solidityPragmaPre08(_ source: String) -> Bool {
        let ns = source as NSString
        let re = try! NSRegularExpression(pattern: "(?m)^\\s*pragma\\s+solidity\\s+([^;\\n]+);")
        guard let m = re.firstMatch(in: source, options: [], range: NSRange(location: 0, length: ns.length)),
              m.range(at: 1).location != NSNotFound else { return false }
        let version = ns.substring(with: m.range(at: 1)).trimmingCharacters(in: .whitespaces)
        guard let minor = solidityMinorVersion(version) else { return false }
        return minor < 8
    }

    /// Extracts the minor version digit from a Solidity version string such as
    /// `0.8.19`, `^0.7.6` or `>=0.6.0 <0.8.0` (returns the first match).
    private static func solidityMinorVersion(_ version: String) -> Int? {
        let re = try! NSRegularExpression(pattern: "\\b0\\.(\\d+)")
        let vns = version as NSString
        guard let m = re.firstMatch(in: version, options: [], range: NSRange(location: 0, length: vns.length)),
              m.range(at: 1).location != NSNotFound else { return nil }
        return Int(vns.substring(with: m.range(at: 1)))
    }

} // end extension VulnerabilityScanner

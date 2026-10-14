// by cipher.org.uk
// MARK: - Solidity-specific AST + heuristic security checks
// Extracted from AstSecurityDetector.swift + VulnerabilityScanner.swift
// to keep per-language vulnerability detection modular.

import Foundation

extension AstSecurityDetector {

    // MARK: - Solidity sink checks

    /// Per-call taint sinks that carry attacker-controlled data in Solidity.
    /// The dangerous calls are (a) low-level/external calls whose arguments
    /// embed untrusted data (a reentrancy/forge path), (b) delegatecall to an
    /// attacker-controlled target, and (c) selfdestruct to an arbitrary address.
    func checkSoliditySinks(name: String, qualified: String, callee: CExpr, args: [CExpr], offset: Int, function: String, tainted: Set<String>, crossTainted: Set<String>, guarded: Set<String>, sizeBounded: Set<String>, findings: inout [AstFinding], reachable: Bool) -> Bool {
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
        // ERC20-style transfer to the zero address: `token.transfer(address(0), x)`
        // silently burns tokens or breaks bookkeeping when the zero address is not
        // rejected.
        if (name == "transfer" || name == "transferFrom"), hasMemberReceiver(callee),
           args.contains(where: { isAddressZeroExpr($0) }) {
            emit(&findings, function, offset,
                 rule("Transfer to Zero Address", .medium, always: true),
                 message: "\(name)() sends tokens to address(0); the zero address should be rejected to avoid burned or stuck funds.",
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

    // MARK: - Solidity structural (3-walk) checks

    /// An external call observed in a function: its offset, name, and whether it
    /// is a native single-argument `transfer` (2300-gas stipend, cannot re-enter).
    private typealias SolExternalCall = (offset: Int, name: String, nativeTransfer: Bool)

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
        // An owner/admin-gated function is only callable by a trusted party, so an
        // external call before a write there is not an attacker-reachable
        // reentrancy or an unprotected privileged write.
        let hasAuthModifier = modifiers.contains { q in
            let l = q.lowercased()
            return l.contains("only") || l.contains("auth") || l == "admin" || l.contains("restricted") || l.contains("governance")
        }

        // Collect ordered events: external calls (offset, name) and storage
        // writes, plus tx.origin uses and explicit guard-set statements.
        var externalCalls: [SolExternalCall] = []
        var stateWrites: [Int] = []
        var txOriginUses: [Int] = []
        var sawGuardSet = false
        collectSolidityEvents(fn.body, params: params, externalCalls: &externalCalls, stateWrites: &stateWrites, txOriginUses: &txOriginUses, sawGuardSet: &sawGuardSet)
        // --- Extended walk: time/balance dependence, loops, authorization,
        // ERC20 correctness and pre-0.8 arithmetic (Walk 4). Collected here so
        // the tx.origin check below can require a comparison context.
        var ev = SolidityExtEvents()
        collectSolidityExtendedEvents(fn.body, params: params, tainted: tainted, inLoop: false, ev: &ev)
        // --- Reentrancy: an external call occurs before a storage write and the
        // function is not guarded.
        if !hasNonReentrantModifier && !sawGuardSet && !hasAuthModifier {
            // Violation = an external call that has ANY storage write after it
            // (checks-effects-interactions broken). A write merely *before* the
            // call does not excuse a later write, so compare the earliest call
            // against the LAST write. `send()` and native `transfer()` forward
            // only the 2300 gas stipend, which cannot re-enter, so both are
            // excluded. External calls hidden behind local helpers are inlined
            // so a call-before-write split across functions is still caught.
            let calls = (externalCalls + inlinedHelperExternalCalls(fn.body)).filter { $0.name != "send" && !$0.nativeTransfer }
            if let firstCall = calls.min(by: { $0.offset < $1.offset }),
               let lastWrite = stateWrites.max(), firstCall.offset < lastWrite {
                emit(&findings, function, firstCall.offset,
                     rule("Reentrancy", .high, always: true),
                     message: "External call before state update with no reentrancy guard; re-entrant callers can corrupt storage.",
                     taint: nil, reachable: reachable, crossFile: false)
            }
        }

        // --- tx.origin authorization: using tx.origin in a security boundary.
        // Only a *comparison* (e.g. `require(tx.origin == owner)`) is an
        // authorization decision; using `tx.origin` as a mapping key or value
        // (`balances[tx.origin]`) is not an access-control flaw.
        if ev.txOriginCompared {
            for offset in txOriginUses {
                emit(&findings, function, offset,
                     rule("tx.origin Authorization", .high, always: true),
                     message: "tx.origin used for authorization; a malicious intermediate contract can impersonate the sender.",
                     taint: nil, reachable: reachable, crossFile: false)
            }
        }

        // --- Extended walk: time/balance dependence and pre-0.8 arithmetic
        // (Walk 4).
        for offset in ev.randomnessUses {
            emit(&findings, function, offset,
                 rule("Predictable Randomness", .high, always: true),
                 message: "outcome is derived from block-hash/number/difficulty or coinbase, values a miner controls and others can predict.",
                 taint: nil, reachable: reachable, crossFile: false)
        }
        for offset in ev.timestampLogicUses {
            emit(&findings, function, offset,
                 rule("Block Timestamp Dependence", .medium, always: true),
                 message: "block.timestamp decides control flow; a miner can skew it by a few seconds, so time-sensitive logic is manipulable.",
                 taint: nil, reachable: reachable, crossFile: false)
        }
        for offset in ev.arrayClearOffsets {
            emit(&findings, function, offset,
                 rule("Denial of Service", .medium, always: true),
                 message: "clearing an unbounded storage array costs gas proportional to its length and can exceed the block gas limit, permanently blocking callers.",
                 taint: nil, reachable: reachable, crossFile: false)
        }
        for offset in ev.checkedSendOffsets {
            emit(&findings, function, offset,
                 rule("Denial of Service", .medium, always: true),
                 message: "a low-level send's success is required; a recipient that rejects Ether reverts every call and can block the contract.",
                 taint: nil, reachable: reachable, crossFile: false)
        }
        for offset in ev.lengthGuardOffsets {
            emit(&findings, function, offset,
                 rule("Array Length Underflow", .high, always: true),
                 message: "an unsigned array length is compared against zero — a bound that always holds, leaving a length decrement free to underflow and rewrite storage.",
                 taint: nil, reachable: reachable, crossFile: false)
        }
        for offset in ev.hashCommitOffsets {
            emit(&findings, function, offset,
                 rule("Transaction Order Dependence", .medium, always: true),
                 message: "a caller-supplied value is accepted when its hash matches a stored value; the winning solution is visible in the mempool and can be front-run.",
                 taint: nil, reachable: reachable, crossFile: false)
        }
        // Rewriting a storage array length from a caller-controlled value with no
        // owner/admin guard lets any caller resize the array arbitrarily.
        if !hasAuthModifier && !ev.hasAuthCheck {
            for offset in ev.lengthWriteOffsets {
                emit(&findings, function, offset,
                     rule("Missing Access Control", .high, always: true),
                     message: "a storage array length is set from a caller-controlled value with no authorization; an attacker can resize storage arbitrarily.",
                     taint: nil, reachable: reachable, crossFile: false)
            }
        }
        // A selfdestruct that no owner/admin check guards is callable by anyone,
        // who can then permanently destroy the contract.
        if !hasAuthModifier && !ev.hasAuthCheck {
            for offset in ev.selfdestructOffsets {
                emit(&findings, function, offset,
                     rule("Unprotected Selfdestruct", .critical, always: true),
                     message: "selfdestruct is reachable by anyone; any caller can permanently destroy the contract and drain its Ether.",
                     taint: nil, reachable: reachable, crossFile: false)
            }
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
        for w in ev.privilegedWrites where !hasAuthModifier && !ev.hasAuthCheck {
            emit(&findings, function, w.offset,
                 rule("Missing Access Control", .high, always: true),
                 message: "'\(w.target)' is updated with no owner/admin check or only* modifier; anyone can change this security-relevant state.",
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
        // A low-level `send`/`call` written as a bare statement discards its
        // success flag, so a rejected send or a reverting callee passes
        // silently and the caller cannot detect the failure.
        if isSolidity {
            var discarded: [Int] = []
            collectDiscardedLowLevelCalls(fn.body, into: &discarded)
            for offset in discarded {
                emit(&findings, function, offset,
                     rule("Unchecked Low-Level Call", .medium, always: true),
                     message: "low-level call's success flag is discarded; a failed send or a reverting callee is silently ignored.",
                     taint: nil, reachable: reachable, crossFile: false)
            }
        }
        // Before 0.5 a constructor is a function named after its contract, so a
        // different function that stamps ownership from the caller is an
        // initializer anyone can invoke to seize the contract.
        if solidityPre05, !hasAuthModifier, !ev.hasAuthCheck,
           function != "constructor", !solidityContainerNames.contains(function) {
            for w in ev.ownershipFromCaller {
                emit(&findings, function, w.offset,
                     rule("Unprotected Ownership Initialization", .high, always: true),
                     message: "'\(w.target)' is set from msg.sender outside the constructor; anyone can seize ownership.",
                     taint: nil, reachable: reachable, crossFile: false)
            }
        }
    }

    /// Collects offsets of low-level `send`/`call` calls written as a bare
    /// statement — the boolean result is discarded so a failure is invisible.
    private func collectDiscardedLowLevelCalls(_ stmt: CStmt, into offsets: inout [Int]) {
        switch stmt {
        case .block(let arr):
            for s in arr { collectDiscardedLowLevelCalls(s, into: &offsets) }
        case .expr(let e):
            if let off = discardedLowLevelCallOffset(e) { offsets.append(off) }
        case .ifStmt(_, let then, let elseStmt, _):
            collectDiscardedLowLevelCalls(then, into: &offsets)
            if let es = elseStmt { collectDiscardedLowLevelCalls(es, into: &offsets) }
        case .whileStmt(_, let body, _):
            collectDiscardedLowLevelCalls(body, into: &offsets)
        case .doWhileStmt(let body, _, _):
            collectDiscardedLowLevelCalls(body, into: &offsets)
        case .forStmt(_, _, _, let body, _):
            collectDiscardedLowLevelCalls(body, into: &offsets)
        case .switchStmt(_, let cases, _):
            for c in cases { for s in c.body { collectDiscardedLowLevelCalls(s, into: &offsets) } }
        case .labeledStmt(_, let s, _):
            collectDiscardedLowLevelCalls(s, into: &offsets)
        default:
            break
        }
    }

    private func discardedLowLevelCallOffset(_ e: CExpr) -> Int? {
        switch e {
        case .call(let callee, _, let offset):
            guard let n = solidityExternalCallName(callee), n == "send" || n == "call" else { return nil }
            return offset
        case .paren(let x, _), .cast(let x, _):
            return discardedLowLevelCallOffset(x)
        default:
            return nil
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
              let compoundOps = try? NSRegularExpression(pattern: "(?:\\+\\=|\\-\\=|\\*=|/=|%=|\\+\\+|\\-\\-)", options: options),
              let bareOps = try? NSRegularExpression(pattern: "(?:\\*|/|%|<<|>>|\\+|-|&|\\||\\^)", options: options) else { return }
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
            let bodyLen = NSRange(location: 0, length: body.length)
            // A compound assignment / increment is reported at the block header
            // (its exact operand may be a continuation line); a bare operator is
            // reported at its own position.
            if !compoundOps.matches(in: body as String, options: [], range: bodyLen).isEmpty {
                emit(&findings, fn.name, fn.startOffset + open,
                     rule("Unchecked Arithmetic Overflow", .high, always: true),
                     message: "unchecked block restores pre-0.8 wrap-around arithmetic; overflow/underflow is silently possible.",
                     taint: nil, reachable: reachable, crossFile: false)
            } else if let op = bareOps.firstMatch(in: body as String, options: [], range: bodyLen) {
                emit(&findings, fn.name, fn.startOffset + open + op.range.location,
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

    // MARK: - Solidity extended (Walk 4) events

    /// Collections for the extended Solidity walk: time/balance dependence,
    /// authorization and pre-0.8 arithmetic.
    private struct SolidityExtEvents {
        // True while collecting a `require(...)` call's arguments. A monotonic
        // `>=`/`<=` timestamp comparison inside a require is a deadline or
        // timelock validation (the safe pattern), not time-gated control flow.
        var inRequireContext = false
        var timestampLogicUses: [Int] = []
        var balanceUses: [Int] = []
        var privilegedWrites: [(offset: Int, target: String, source: String?)] = []
        var ownershipFromCaller: [(offset: Int, target: String)] = []
        var randomnessUses: [Int] = []
        var hasAuthCheck = false
        var txOriginCompared = false
        var zeroCheckedParams: Set<String> = []
        var overflowOffsets: [Int] = []
        var arrayClearOffsets: [Int] = []
        var selfdestructOffsets: [Int] = []
        var hashCommitOffsets: [Int] = []
        var checkedSendOffsets: [Int] = []
        var lengthGuardOffsets: [Int] = []
        var lengthWriteOffsets: [Int] = []
    }

    private func collectSolidityExtendedEvents(_ stmt: CStmt, params: Set<String>, tainted: Set<String>, inLoop: Bool, ev: inout SolidityExtEvents) {
        switch stmt {
        case .block(let arr):
            for s in arr { collectSolidityExtendedEvents(s, params: params, tainted: tainted, inLoop: inLoop, ev: &ev) }
        case .declaration(let d):
            if case .variable(_, _, let ie?) = d.kind {
                collectSolidityExtendedExpr(ie, params: params, tainted: tainted, inLoop: inLoop, ev: &ev)
            }
        case .expr(let e):
            collectSolidityExtendedExpr(e, params: params, tainted: tainted, inLoop: inLoop, ev: &ev)
        case .ifStmt(let cond, let then, let elseStmt, _):
            collectSolidityExtendedExpr(cond, params: params, tainted: tainted, inLoop: inLoop, ev: &ev)
            collectSolidityExtendedEvents(then, params: params, tainted: tainted, inLoop: inLoop, ev: &ev)
            if let et = elseStmt {
                collectSolidityExtendedEvents(et, params: params, tainted: tainted, inLoop: inLoop, ev: &ev)
            }
        case .whileStmt(let cond, let body, _):
            collectSolidityExtendedExpr(cond, params: params, tainted: tainted, inLoop: inLoop, ev: &ev)
            collectSolidityExtendedEvents(body, params: params, tainted: tainted, inLoop: true, ev: &ev)
        case .doWhileStmt(let body, let cond, _):
            collectSolidityExtendedEvents(body, params: params, tainted: tainted, inLoop: true, ev: &ev)
            collectSolidityExtendedExpr(cond, params: params, tainted: tainted, inLoop: inLoop, ev: &ev)
        case .forStmt(let ini, let cond, let incr, let body, _):
            if let i = ini { collectSolidityExtendedEvents(i, params: params, tainted: tainted, inLoop: false, ev: &ev) }
            if let c = cond {
                collectSolidityExtendedExpr(c, params: params, tainted: tainted, inLoop: inLoop, ev: &ev)
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
        case .call(let callee, let args, let callOffset):
            let cn = callName(callee)
            collectSolidityExtendedExpr(callee, params: params, tainted: tainted, inLoop: inLoop, ev: &ev)
            // A low-level `send` whose success is required (`require(addr.send(v))`)
            // turns a rejected recipient into a reverting transaction, so one
            // payee that refuses Ether blocks every caller — a denial of service.
            if cn == "send", ev.inRequireContext {
                ev.checkedSendOffsets.append(callOffset)
            }
            // A block-hash lookup is a public, miner-influenced value, so it is
            // not an unpredictable entropy source. `blockhash(block.number)` is
            // the separate always-zero case and is reported elsewhere.
            if cn == "blockhash", let a = args.first, !isBlockNumberExpr(a) {
                ev.randomnessUses.append(callOffset)
            }
            if cn == "selfdestruct" || cn == "suicide" {
                ev.selfdestructOffsets.append(callOffset)
            }
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
                // A non-constructor function that stamps ownership from the
                // caller can be invoked by anyone to seize the contract.
                if case .identifier(let target, _) = lhs, isOwnershipStateName(target), isCallerAddressExpr(rhs) {
                    ev.ownershipFromCaller.append((offset: offset, target: target))
                }
                // `owners[account] = msg.sender` grants the same ownership via a
                // mapping element, so the container write is equally unprotected.
                if case .index(let base, _, _) = lhs, case .identifier(let target, _) = base,
                   isOwnershipStateName(target), isCallerAddressExpr(rhs) {
                    ev.ownershipFromCaller.append((offset: offset, target: target))
                }
                // Clearing a dynamically-sized storage array (`x = new T[](0)`)
                // costs gas proportional to its length; once the array grows
                // without a bound the clear can exceed the block gas limit and
                // wedge every caller that depends on it.
                if case .newExpr(let tn, _, _) = rhs, tn.hasSuffix("[]") {
                    ev.arrayClearOffsets.append(offset)
                }
                // `arr.length = <caller-controlled>` resizes a storage array to
                // any size; with no authorization the caller can rewrite storage
                // past the array's logical bounds.
                if op == "=", case .member(let base, let m, _, _) = lhs, m == "length",
                   let root = expressionRootName(base), !params.contains(root),
                   exprTainted(rhs, tainted: tainted) != nil {
                    ev.lengthWriteOffsets.append(offset)
                }
                // A compound assignment of a constant (`count += 1`) cannot
                // reach overflow in practice and is developer-controlled, not a
                // caller-driven wrap; only a non-literal right-hand side is the
                // pre-0.8 overflow pattern.
                if solidityPre08, (op == "+=" || op == "-=" || op == "*="), !isLiteralExpr(rhs) {
                    ev.overflowOffsets.append(offset)
                }
            }
            collectSolidityExtendedExpr(lhs, params: params, tainted: tainted, inLoop: inLoop, ev: &ev)
            collectSolidityExtendedExpr(rhs, params: params, tainted: tainted, inLoop: inLoop, ev: &ev)
        case .member(let base, let m, _, let offset):
            if m == "balance", solidityBaseIsSelfAddress(base) {
                ev.balanceUses.append(offset)
            }
            // block.coinbase / block.difficulty are miner-controlled and known
            // before the block is mined, so any "random" value derived from them
            // is predictable.
            if baseIsBlockGlobal(base), m == "difficulty" || m == "coinbase" {
                ev.randomnessUses.append(offset)
            }
            collectSolidityExtendedExpr(base, params: params, tainted: tainted, inLoop: inLoop, ev: &ev)
        case .index(let b, let i, _):
            collectSolidityExtendedExpr(b, params: params, tainted: tainted, inLoop: inLoop, ev: &ev)
            collectSolidityExtendedExpr(i, params: params, tainted: tainted, inLoop: inLoop, ev: &ev)
        case .binary(let op, let l, let r, let binOffset):
            if op == "+" || op == "-" || op == "*" {
                if exprTainted(l, tainted: tainted) != nil, exprTainted(r, tainted: tainted) != nil, solidityPre08 {
                    ev.overflowOffsets.append(e.offset)
                }
            }
            // `block.number % 2` / a remainder of the block number or time is a
            // classic weak "coin flip" — miners choose the block that decides it.
            if op == "%", isBlockNumberMember(l) || isBlockNumberMember(r) || isBlockTimestampMember(l) || isBlockTimestampMember(r) {
                ev.randomnessUses.append(binOffset)
            }
            // A remainder taken from a hash of the block time (e.g.
            // `sha3(block.timestamp) % 2`) is still time-gated logic: the miner
            // selects the timestamp the outcome depends on.
            if op == "%" {
                collectBlockTimestampUses(l, ev: &ev)
                collectBlockTimestampUses(r, ev: &ev)
            }
            if op == "==" || op == "!=" || op == ">" || op == ">=" || op == "<" || op == "<=" {
                // A caller-supplied value accepted when its hash equals a stored
                // value is a public pre-image puzzle: the winning solution is
                // visible in the mempool and can be copied before the original
                // transaction confirms (transaction-order dependence).
                if op == "==", isHashCallWithTaintedArg(l, tainted: tainted) || isHashCallWithTaintedArg(r, tainted: tainted) {
                    ev.hashCommitOffsets.append(binOffset)
                }
                // A `>=`/`<=` deadline or timelock comparison inside a require is
                // the canonical safe pattern (EIP-2612 expiry, timelock gates);
                // strict equality and non-monotonic comparisons still record.
                let monotonicInRequire = ev.inRequireContext && (op == ">=" || op == "<=")
                if !monotonicInRequire {
                    collectBlockTimestampUses(l, ev: &ev)
                    collectBlockTimestampUses(r, ev: &ev)
                }
                // `0 <= x.length` / `x.length >= 0` is always true for an
                // unsigned length — a bound check that never fires, letting a
                // subsequent `x.length--` underflow and rewrite adjacent storage.
                if op == "<=" || op == ">=",
                   (isZeroLiteral(l) && isArrayLengthMember(r)) || (isZeroLiteral(r) && isArrayLengthMember(l)) {
                    ev.lengthGuardOffsets.append(binOffset)
                }
                let lZero = isAddressZeroExpr(l), rZero = isAddressZeroExpr(r)
                if lZero || rZero {
                    if let idName = simpleIdentifier(lZero ? r : l) {
                        ev.zeroCheckedParams.insert(idName)
                    }
                }
                if ev.hasAuthCheck == false, exprContainsMsgSenderOrTxOrigin(l) || exprContainsMsgSenderOrTxOrigin(r) {
                    ev.hasAuthCheck = true
                }
                if exprContainsTxOrigin(l) || exprContainsTxOrigin(r) {
                    ev.txOriginCompared = true
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

    /// State names that grant control of the contract — setting one from the
    /// caller is an ownership assignment.
    private func isOwnershipStateName(_ n: String) -> Bool {
        let low = n.lowercased()
        let names = ["owner", "creator", "admin", "authority", "controller", "governor"]
        return names.contains { low == $0 || low.hasPrefix($0) }
    }

    /// `msg.sender` / `tx.origin`, possibly wrapped in a cast or parentheses.
    private func isCallerAddressExpr(_ e: CExpr) -> Bool {
        switch e {
        case .member(let b, let m, _, _):
            if case .identifier(let n, _) = b {
                if m == "sender" { return n == "msg" }
                if m == "origin" { return n == "tx" }
            }
            return false
        case .paren(let x, _), .cast(let x, _):
            return isCallerAddressExpr(x)
        default:
            return false
        }
    }

    /// State names that semantically hold an address, where a zero-address
    /// validation is meaningful.
    private func isAddressLikeStateName(_ n: String) -> Bool {
        let low = n.lowercased()
        let names = ["owner", "admin", "beneficiary", "treasury", "wallet", "gatekeeper", "controller", "authority"]
        return names.contains { low == $0 || low.hasPrefix($0) }
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

    /// True when the expression references `tx.origin` (a member access with
    /// base `tx` and field `origin`).
    private func exprContainsTxOrigin(_ e: CExpr) -> Bool {
        if case .member(let b, let m, _, _) = e, m == "origin", baseRefsTxOrigin(b) { return true }
        switch e {
        case .member(let b, _, _, _): return exprContainsTxOrigin(b)
        case .call(let c, let args, _):
            if exprContainsTxOrigin(c) { return true }
            return args.contains { exprContainsTxOrigin($0) }
        case .binary(_, let l, let r, _), .comma(let l, let r, _):
            return exprContainsTxOrigin(l) || exprContainsTxOrigin(r)
        case .unary(_, let o, _): return exprContainsTxOrigin(o)
        case .ternary(let c, let t, let f, _):
            return exprContainsTxOrigin(c) || exprContainsTxOrigin(t) || exprContainsTxOrigin(f)
        case .cast(let x, _), .paren(let x, _): return exprContainsTxOrigin(x)
        case .index(let b, let i, _): return exprContainsTxOrigin(b) || exprContainsTxOrigin(i)
        case .assign(_, let l, let r, _): return exprContainsTxOrigin(l) || exprContainsTxOrigin(r)
        default: return false
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

    /// True when the expression is a `.length` member access (array/bytes/string
    /// length), which is unsigned and can never be negative.
    private func isArrayLengthMember(_ e: CExpr) -> Bool {
        if case .paren(let x, _) = e { return isArrayLengthMember(x) }
        if case .member(_, let m, _, _) = e { return m == "length" }
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

    /// `block.number` / `block.timestamp` member reads (possibly wrapped).
    private func isBlockNumberMember(_ e: CExpr) -> Bool {
        if case .paren(let x, _) = e { return isBlockNumberMember(x) }
        if case .cast(let x, _) = e { return isBlockNumberMember(x) }
        if case .member(let base, let m, _, _) = e, m == "number", baseIsBlockGlobal(base) { return true }
        return false
    }

    private func isBlockTimestampMember(_ e: CExpr) -> Bool {
        if case .paren(let x, _) = e { return isBlockTimestampMember(x) }
        if case .cast(let x, _) = e { return isBlockTimestampMember(x) }
        if case .member(let base, let m, _, _) = e, m == "timestamp", baseIsBlockGlobal(base) { return true }
        return false
    }

    /// `sha3`/`keccak256` applied to a caller-supplied (tainted) value.
    private func isHashCallWithTaintedArg(_ e: CExpr, tainted: Set<String>) -> Bool {
        if case .paren(let x, _) = e { return isHashCallWithTaintedArg(x, tainted: tainted) }
        if case .cast(let x, _) = e { return isHashCallWithTaintedArg(x, tainted: tainted) }
        if case .call(let callee, let args, _) = e, let n = callName(callee),
           n == "sha3" || n == "keccak" || n == "keccak256" {
            // Only a direct caller-supplied value counts: `sha3(abi.encodePacked
            // (constant))` is a fixed hash, not a public pre-image puzzle.
            return args.contains { a in
                guard let id = simpleIdentifier(a) else { return false }
                return tainted.contains(id)
            }
        }
        return false
    }

    /// Walks the statement tree collecting external calls, storage writes and
    /// tx.origin uses, and whether a reentrancy guard is set at the top.
    private func collectSolidityEvents(_ stmt: CStmt, params: Set<String>, externalCalls: inout [SolExternalCall], stateWrites: inout [Int], txOriginUses: inout [Int], sawGuardSet: inout Bool) {
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

    private func collectSolidityExpr(_ e: CExpr, params: Set<String>, externalCalls: inout [SolExternalCall], stateWrites: inout [Int], txOriginUses: inout [Int], sawGuardSet: inout Bool) {
        switch e {
        case .call(let callee, let args, let offset):
            if isSolidityArrayMutationCall(callee, params: params) {
                stateWrites.append(offset)
            }
            let extName = solidityExternalCallName(callee)
            if let cn = extName {
                externalCalls.append((offset: offset, name: cn, nativeTransfer: cn == "transfer" && args.count == 1))
            }
            collectSolidityExpr(callee, params: params, externalCalls: &externalCalls, stateWrites: &stateWrites, txOriginUses: &txOriginUses, sawGuardSet: &sawGuardSet)
            for a in args {
                collectSolidityExpr(a, params: params, externalCalls: &externalCalls, stateWrites: &stateWrites, txOriginUses: &txOriginUses, sawGuardSet: &sawGuardSet)
            }
        case .assign(_, let lhs, let rhs, let offset2):
            if solidityIsStateWrite(lhs, params: params) {
                if isGuardVar(lhs), isTruthyGuardValue(rhs) { sawGuardSet = true }
                if isReentrancyEffectWrite(lhs, rhs: rhs) { stateWrites.append(offset2) }
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

    private func isSolidityExternalCall(_ name: String) -> Bool {
        name == "call" || name == "delegatecall" || name == "staticcall"
            || name == "callcode" || name == "transfer" || name == "transferFrom"
            || name == "send"
    }

    /// True when the callee is reached through a member access, i.e. the call
    /// has an explicit receiver (`token.transfer(...)`, `addr.call{...}()`) and
    /// is therefore an external call. A bare identifier call (`transfer(...)`)
    /// is a local/self function and never external.
    private func hasMemberReceiver(_ callee: CExpr) -> Bool {
        switch callee {
        case .member: return true
        case .call(let inner, _, _): return hasMemberReceiver(inner)
        default: return false
        }
    }

    /// The external-call name for a callee, or nil when it is not an external
    /// call. Requires a member receiver so same-named internal functions are
    /// not misclassified, and recognises 0.4.x chained forms.
    private func solidityExternalCallName(_ callee: CExpr) -> String? {
        guard hasMemberReceiver(callee) else { return nil }
        if let n = callName(callee), isSolidityExternalCall(n) { return n }
        return solidityChainedExternalCall(callee)
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

    /// A state write is only a reentrancy hazard when it changes attacker-
    /// observable storage: a container element/field, or a variable assigned a
    /// non-literal value. Resetting a scalar to a constant (`stored = 1`) is a
    /// benign effect and must not, on its own, complete a reentrancy pattern.
    private func isReentrancyEffectWrite(_ lhs: CExpr, rhs: CExpr) -> Bool {
        switch lhs {
        case .member, .index: return true
        case .identifier: return !isLiteralExpr(rhs)
        default: return false
        }
    }

    /// External calls performed by local helper functions reachable from `body`
    /// (breadth-first, depth-capped). Lets the reentrancy walk see a call that
    /// lives in a helper but is ordered before a write in the caller.
    private func inlinedHelperExternalCalls(_ body: CStmt) -> [SolExternalCall] {
        var helpers = Set<String>()
        collectInternalHelperNames(body, into: &helpers)
        guard !helpers.isEmpty else { return [] }
        var out: [SolExternalCall] = []
        var seen = helpers
        var queue = Array(helpers)
        var steps = 0
        while let h = queue.first, steps < 32 {
            queue.removeFirst()
            steps += 1
            guard let hf = astFns[h] else { continue }
            var calls: [SolExternalCall] = []
            var writes: [Int] = []
            var txo: [Int] = []
            var g = false
            collectSolidityEvents(hf.body, params: Set(hf.params.compactMap { $0.name }), externalCalls: &calls, stateWrites: &writes, txOriginUses: &txo, sawGuardSet: &g)
            out.append(contentsOf: calls)
            var nested = Set<String>()
            collectInternalHelperNames(hf.body, into: &nested)
            for n in nested where !seen.contains(n) { seen.insert(n); queue.append(n) }
        }
        return out
    }

    private func collectInternalHelperNames(_ stmt: CStmt, into names: inout Set<String>) {
        switch stmt {
        case .block(let arr): for s in arr { collectInternalHelperNames(s, into: &names) }
        case .declaration(let d):
            if case .variable(_, _, let ie?) = d.kind { collectInternalHelperNames(ie, into: &names) }
        case .expr(let e): collectInternalHelperNames(e, into: &names)
        case .ifStmt(let c, let t, let e2, _):
            collectInternalHelperNames(c, into: &names)
            collectInternalHelperNames(t, into: &names)
            if let e2 = e2 { collectInternalHelperNames(e2, into: &names) }
        case .whileStmt(let c, let b, _):
            collectInternalHelperNames(c, into: &names)
            collectInternalHelperNames(b, into: &names)
        case .doWhileStmt(let b, let c, _):
            collectInternalHelperNames(b, into: &names)
            collectInternalHelperNames(c, into: &names)
        case .forStmt(let i, let c, let inc, let b, _):
            if let i = i { collectInternalHelperNames(i, into: &names) }
            if let c = c { collectInternalHelperNames(c, into: &names) }
            if let inc = inc { collectInternalHelperNames(inc, into: &names) }
            collectInternalHelperNames(b, into: &names)
        case .switchStmt(_, let cases, _):
            for cc in cases { for s in cc.body { collectInternalHelperNames(s, into: &names) } }
        case .returnStmt(let e, _):
            if let e = e { collectInternalHelperNames(e, into: &names) }
        case .labeledStmt(_, let s, _): collectInternalHelperNames(s, into: &names)
        default: break
        }
    }

    private func collectInternalHelperNames(_ e: CExpr, into names: inout Set<String>) {
        switch e {
        case .call(let callee, let args, _):
            if case .identifier(let n, _) = callee, astFns[n] != nil { names.insert(n) }
            collectInternalHelperNames(callee, into: &names)
            for a in args { collectInternalHelperNames(a, into: &names) }
        case .assign(_, let l, let r, _):
            collectInternalHelperNames(l, into: &names)
            collectInternalHelperNames(r, into: &names)
        case .member(let b, _, _, _): collectInternalHelperNames(b, into: &names)
        case .index(let b, let i, _):
            collectInternalHelperNames(b, into: &names)
            collectInternalHelperNames(i, into: &names)
        case .binary(_, let l, let r, _), .comma(let l, let r, _):
            collectInternalHelperNames(l, into: &names)
            collectInternalHelperNames(r, into: &names)
        case .unary(_, let o, _): collectInternalHelperNames(o, into: &names)
        case .ternary(let c, let t, let f, _):
            collectInternalHelperNames(c, into: &names)
            collectInternalHelperNames(t, into: &names)
            collectInternalHelperNames(f, into: &names)
        case .cast(let x, _), .paren(let x, _): collectInternalHelperNames(x, into: &names)
        case .arrayInit(let arr, _): for a in arr { collectInternalHelperNames(a, into: &names) }
        case .newExpr(_, let args, _): for a in args { collectInternalHelperNames(a, into: &names) }
        default: break
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
        guard let minor = solidityPragmaMinor(source) else { return false }
        return minor < 8
    }

    /// True when the file's `pragma solidity` pins/requests a compiler older
    /// than 0.5 (constructor named after the contract; no explicit visibility).
    static func solidityPragmaPre05(_ source: String) -> Bool {
        guard let minor = solidityPragmaMinor(source) else { return false }
        return minor < 5
    }

    /// Minor component of the `pragma solidity` version, e.g. `0.4.24` → 4.
    private static func solidityPragmaMinor(_ source: String) -> Int? {
        let ns = source as NSString
        let re = try! NSRegularExpression(pattern: "(?m)^\\s*pragma\\s+solidity\\s+([^;\\n]+);")
        guard let m = re.firstMatch(in: source, options: [], range: NSRange(location: 0, length: ns.length)),
              m.range(at: 1).location != NSNotFound else { return nil }
        let version = ns.substring(with: m.range(at: 1)).trimmingCharacters(in: .whitespaces)
        return solidityMinorVersion(version)
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

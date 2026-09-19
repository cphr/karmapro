// by cipher.org.uk
import Foundation

/// A finding produced by the dedicated kernel detector. Reports a kernel-specific
/// vulnerability category (see `KernelAstDetector`) at the exact AST offset.
struct KernelAstFinding {
    let function: String
    let offset: Int
    let category: String
    let severity: ScanFinding.Severity
    let message: String
    let taintPath: String?
    let reachable: Bool
}

/// Structural kernel-security detector for C/C++ files that appear to be Linux
/// kernel code (functions using `__user` pointers, `linux/uaccess.h`, the
/// `copy_*_user`/`kmalloc` families, ...).
///
/// Unlike the generic `AstSecurityDetector` (which approximates every kernel
/// API as a plain sink on a single walk), this detector performs **three
/// independent AST walks** for much higher precision:
///
///  - **Walk 1 (Taint walk)** threads two taint flavours through every function
///    body in order: `.data` (the value holds attacker-influenced data) and
///    `.userPtr` (the value is a pointer into userspace). All `__user` pointers
///    are tracked, and every user-space copy (`copy_from_user`, `get_user`,
///    `memdup_user`, ...) becomes a first-class data source instead of a sink.
///  - **Walk 2 (Bounds walk)** collects which variables are provably size-bounded
///    at each statement either by an enclosing `if (count < cap)` guard or by a
///    `if (count > cap) return;` / `if (count <= cap) { } else return;` rejection
///    guard. Provably fixed sizes (`sizeof(...)`, `ARRAY_SIZE`, integer literals)
///    and clamping wrappers (`min`, `min_t`, `clamp`, `struct_size`, ...) are
///    recognized so safe kernel patterns are not reported.
///  - **Walk 3 (Boundary walk)** computes, to a fixpoint over the AST call graph,
///    which functions return tainted data and which parameters receive tainted
///    arguments. Entry points are the conventional socket/ioctl handlers and any
///    function taking a `__user` pointer; their parameters seed the taint walk.
///
/// The taint/bounds information is then combined at every sink call to decide
/// exactly which precise kernel category applies:
///
///  - `copy_from_user`/`copyin` with an unvalidated size -> Kernel Memory Corruption
///  - `copy_to_user`/`copyout` with an unvalidated size   -> Kernel Memory Disclosure
///  - `strncpy_from_user`/`strcpy`/`sprintf` with tainted, unbounded data
///                                                         -> Kernel Buffer Overflow
///  - `kmalloc`/`kzalloc`/... with a tainted, unbounded size -> Kernel Heap Overflow
///  - a kernel memory function given a raw `__user` pointer -> Kernel User Pointer Dereference
///  - a user copy whose return value is silently discarded   -> Kernel Unchecked User Copy
fileprivate let kernelDetectorCategories: Set<String> = [
    "Kernel Memory Corruption",
    "Kernel Memory Disclosure",
    "Kernel Buffer Overflow",
    "Kernel Heap Overflow",
    "Kernel User Pointer Dereference",
    "Kernel Unchecked User Copy",
    "Kernel Null Dereference",
    "Kernel Use-After-Free",
    "Kernel Out-of-Bounds Access",
    "Kernel Unbounded Memory Copy",
]

struct KernelAstDetector {

    /// Taint flavours: attacker-controlled *data* flowing through a variable,
    /// versus a variable holding an actual *pointer into userspace*.
    private enum Flavor: Hashable {
        case data, userPtr
    }
    private typealias FlavorSet = Set<Flavor>

    /// Whether `source` looks like a Linux-kernel source file. Cheap and safe:
    /// the detector only ever runs when this returns true, so unrelated corpus
    /// files keep their previous behaviour.
    static func isKernelShaped(_ source: String) -> Bool {
        if source.contains("__user") { return true }
        if source.contains("<linux/uaccess.h>") || source.contains("<linux/uaccess.h> //") { return true }
        if source.contains("<linux/module.h>"),
           (source.contains("copy_from_user") || source.contains("copy_to_user")) {
            return true
        }
        return false
    }

    /// True for files that manage sk_buff packet buffers (`skb_push`/`skb_reserve`
    /// and friends) but do not otherwise look kernel-shaped. Such files run the
    /// skb headroom provenance walk only — the full kernel walks require the
    /// kernel-shape signal to stay precise.
    static func isSkbShaped(_ source: String) -> Bool {
        if source.contains("<linux/skbuff.h>") || source.contains("<net/bluetooth/") { return true }
        if source.contains("skb_push(") || source.contains("skb_reserve(") { return true }
        return false
    }

    // ---------------------------------------------------------------------
    // Kernel API tables
    // ---------------------------------------------------------------------

    /// User-space -> kernel copies: they WRITE tainted data into arg 0 and are
    /// the primary kernel data sources. `strncpy_from_user` is covered by its own
    /// rule, and `get_user` writes through its first (target) argument.
    private static let userSourceReadFns: Set<String> = [
        "copy_from_user", "_copy_from_user", "__copy_from_user", "raw_copy_from_user",
        "copy_struct_from_user", "unsafe_copy_from_user", "simple_copy_from_user",
        "copyin", "copyin_user", "strncpy_from_user", "get_user",
    ]

    /// Kernel -> user-space copies: with an unvalidated size they disclose kernel
    /// memory (Kernel Memory Disclosure).
    private static let userSinkWriteFns: Set<String> = [
        "copy_to_user", "_copy_to_user", "__copy_to_user", "raw_copy_to_user",
        "copyout", "copyout_user", "put_user",
    ]

    /// Functions that return a fresh heap copy of userspace data; calling them in
    /// an initializer/assignment taints the target variable.
    private static let userDataReturningFns: Set<String> = [
        "memdup_user", "memdup_user_nul", "vmemdup_user", "memdup_user_misc",
    ]

    /// Functions whose caller MUST check the return value; a bare expression
    /// statement silently dropping the error is the "unchecked user copy" defect.
    /// Deliberately excludes the `unsafe_*` / `raw_*` / `simple_*` internals that
    /// assume a preceding `access_ok`, and `strnlen_user`.
    private static let uncheckedUserCopyFns: Set<String> = [
        "copy_from_user", "_copy_from_user", "__copy_from_user",
        "copy_struct_from_user", "strncpy_from_user", "get_user", "put_user",
        "copyin", "copyin_user", "copy_to_user", "_copy_to_user", "__copy_to_user",
        "copyout", "copyout_user",
    ]

    /// Kernel heap allocations whose size argument (index 0, or `n` for the
    /// `*_array` variants) must not be attacker-controlled.
    private static let heapAllocFns: Set<String> = [
        "kmalloc", "kzalloc", "kcalloc", "kvzalloc", "kvmalloc", "vmalloc", "vzalloc",
        "devm_kzalloc", "devm_kmalloc", "kvcalloc", "devm_kcalloc",
        "kmalloc_array", "kzalloc_array", "kvmalloc_array", "kmalloc_node", "kzalloc_node",
    ]

    /// Functions that dereference memory through a pointer. Passing them a raw
    /// `__user` pointer dereferences userspace memory directly. The user-space
    /// transfer helpers are excluded by design: they know how to touch
    /// `__user` memory.
    private static let kernelMemPtrPos: [String: [Int]] = [
        "memcpy": [0, 1], "memmove": [0, 1], "memset": [0], "memcmp": [0, 1],
        "strcpy": [0, 1], "strcat": [1], "sprintf": [1], "vsprintf": [1],
        "snprintf": [1], "vsnprintf": [1], "strlen": [0],
        "strcmp": [0, 1], "strncmp": [0, 1], "strcasecmp": [0, 1], "strncasecmp": [0, 1],
        "kfree": [0], "vfree": [0],
    ]

    /// String sink calls into fixed kernel buffers. A tainted, unbounded source
    /// is a Kernel Buffer Overflow.
    private static let kernelStringSinks: Set<String> = [
        "strcpy", "strcat", "sprintf", "snprintf", "vsnprintf",
    ]

    /// Functions that WRITE through their first (destination) argument. Passing an
    /// allocation-returned pointer as the destination without a NULL check dereferences
    /// a possibly-NULL pointer (Kernel Null Dereference).
    private static let kernelWriteDstFns: Set<String> = [
        "memset", "memcpy", "memmove", "strcpy", "strncpy", "strcat", "strncat",
        "sprintf", "snprintf", "vsprintf", "vsnprintf",
    ]

    /// Conventional kernel entry-point handler names whose parameters are all
    /// influenced by userspace.
    private static let kernelEntryNames: Set<String> = [
        "ioctl", "unlocked_ioctl", "compat_ioctl", "read", "write", "read_iter",
        "write_iter", "readv", "writev", "mmap", "poll", "sendfile", "copy_file_range",
        "request_handler",
    ]

    /// Parameter names conventionally carrying a userspace pointer / value in an
    /// ioctl-style handler (`unsigned long arg`).
    private static let kernelArgParamNames: Set<String> = ["arg", "argp", "_arg"]

    /// `sizeof`-like / clamping helpers that make a size expression provably safe.
    private static let fixedSizeCallNames: Set<String> = [
        "sizeof", "ARRAY_SIZE", "array_size", "min", "min_t", "min3", "min_not_zero",
        "min_t", "clamp", "clamp_val", "clamp_t", "struct_size", "size_mul", "size_add",
        "size_max", "size_min", "check_mul_overflow",
    ]

    private let source: String
    private let tu: CTranslationUnit
    private let astFns: [String: CFunctionDef]

    /// Kernel API names that this translation unit *defines* locally (with a
    /// body). A redefined API shadows the real kernel symbol, so calls to it are
    /// treated as ordinary functions, never as kernel sources/sinks.
    private let defined: Set<String>

    /// When true, only the sk_buff headroom provenance walk runs (for files
    /// that manage skbs without otherwise being kernel-shaped).
    private let skbOnly: Bool

    init(source: String, astFns: [String: CFunctionDef], skbOnly: Bool = false) {
        self.source = source
        self.tu = CParser(tokens: CTokenizer(source: source).tokenize()).parseTranslationUnit()
        self.astFns = astFns
        self.defined = Set(astFns.keys)
        self.skbOnly = skbOnly
    }

    // MARK: - Detect (three-walk driver)

    func detect() -> [KernelAstFinding] {
        guard !astFns.isEmpty else { return [] }

        // skbOnly mode: run the sk_buff provenance walk alone (used for files
        // that manage skbs without otherwise being kernel-shaped).
        if skbOnly {
            var skbFindings: [KernelAstFinding] = []
            for fn in astFns.values {
                var skbState: [String: Int] = [:]
                skbWalkStmt(fn.body, state: &skbState, fnName: fn.name,
                            reachable: true, findings: &skbFindings)
            }
            return skbFindings
        }

        // Walk 2 (bounds) — computed once per function, independent of data flow.
        var boundedByFn: [String: (Set<String>, Bool)] = [:]
        for fn in astFns.values {
            boundedByFn[fn.name] = boundedAndAccessOk(in: fn.body)
        }

        // Structural facts computed per function, independent of data flow:
        //   * allocation-derived pointer names (from kmalloc/kzalloc/memdup_user/...)
        //   * pointer names that are provably null-checked somewhere in the body
        //   * fixed-size local array names declared in the body
        //   * the set of pointers passed to kfree/vfree by name (for reachability)
        var allocPtrsByFn: [String: Set<String>] = [:]
        var nullCheckedByFn: [String: Set<String>] = [:]
        var fixedArraysByFn: [String: Set<String>] = [:]
        for fn in astFns.values {
            allocPtrsByFn[fn.name] = allocationPointers(in: fn.body)
            nullCheckedByFn[fn.name] = nullCheckedNames(in: fn.body)
            fixedArraysByFn[fn.name] = fixedArrays(in: fn.body)
        }

        // Walk 3 (boundary) — taint-returning functions and tainted parameters,
        // fixed point over the AST call graph.
        var ctx = KernelContext()
        var callGraph: [String: Set<String>] = [:]
        for fn in astFns.values {
            callGraph[fn.name] = callees(in: fn.body)
        }
        for _ in 0..<8 {
            var changed = false
            for fn in astFns.values {
                let input = flowInput(for: fn, ctx: ctx)
                var result = KernelFlowResult()
                var data = input.dataSeeds
                var userPtr = input.userPtrSeeds
                var freed: Set<String> = []
                flow(fn.body, fn: fn, input: input, ctx: ctx,
                     bounded: boundedByFn[fn.name]?.0 ?? [], accessOk: boundedByFn[fn.name]?.1 ?? false,
                     allocPtrs: [], nullChecked: [], fixedArrays: [],
                     emit: false, reachable: false, data: &data, userPtr: &userPtr,
                     freed: &freed, result: &result)
                if result.returnsData, !ctx.dataReturning.contains(fn.name) {
                    ctx.dataReturning.insert(fn.name); changed = true
                }
                if result.returnsUserPtr, !ctx.userPtrReturning.contains(fn.name) {
                    ctx.userPtrReturning.insert(fn.name); changed = true
                }
                for (callee, perArg) in result.calls {
                    guard let calleeFn = astFns[callee] else { continue }
                    for (k, flavors) in perArg.enumerated() where k < calleeFn.params.count {
                        if flavors.contains(.data), !(ctx.dataParam[callee] ?? []).contains(k) {
                            ctx.dataParam[callee, default: []].insert(k); changed = true
                        }
                        if flavors.contains(.userPtr), !(ctx.userPtrParam[callee] ?? []).contains(k) {
                            ctx.userPtrParam[callee, default: []].insert(k); changed = true
                        }
                    }
                }
            }
            if !changed { break }
        }

        // Functions reachable from the kernel entry points (transitively), plus
        // the functions that receive tainted arguments on those paths.
        var reached = Set<String>()
        for fn in astFns.values where isEntry(fn) { reached.insert(fn.name) }
        var queue = reached.sorted()
        while !queue.isEmpty {
            let cur = queue.removeFirst()
            for next in (callGraph[cur] ?? []) where !reached.contains(next) {
                reached.insert(next)
                queue.append(next)
            }
        }
        for name in astFns.keys {
            if !(ctx.dataParam[name] ?? []).isEmpty || !(ctx.userPtrParam[name] ?? []).isEmpty {
                reached.insert(name)
            }
        }

        // Walk 1 (taint) with emission on, using the fixed-point context.
        var findings: [KernelAstFinding] = []
        for fn in astFns.values {
            let input = flowInput(for: fn, ctx: ctx)
            var result = KernelFlowResult()
            var data = input.dataSeeds
            var userPtr = input.userPtrSeeds
            var freed: Set<String> = []
            flow(fn.body, fn: fn, input: input, ctx: ctx,
                 bounded: boundedByFn[fn.name]?.0 ?? [], accessOk: boundedByFn[fn.name]?.1 ?? false,
                 allocPtrs: allocPtrsByFn[fn.name] ?? [], nullChecked: nullCheckedByFn[fn.name] ?? [],
                 fixedArrays: fixedArraysByFn[fn.name] ?? [],
                 emit: true, reachable: reached.contains(fn.name),
                 data: &data, userPtr: &userPtr, freed: &freed, result: &result)
            findings.append(contentsOf: result.candidates)
        }

        // Walk 4 (sk_buff provenance): `skb_push(skb, N)` writes N bytes
        // *before* skb->data, so it is only in-bounds when the skb provably
        // carries at least N bytes of headroom. Track the per-skb headroom
        // established by the allocating/reserving calls and flag pushes that
        // provably exceed it.
        for fn in astFns.values {
            var skbState: [String: Int] = [:]
            var skbFindings: [KernelAstFinding] = []
            skbWalkStmt(fn.body, state: &skbState, fnName: fn.name,
                        reachable: reached.contains(fn.name), findings: &skbFindings)
            findings.append(contentsOf: skbFindings)
        }
        return findings
    }

    // MARK: - Context / inputs

    private struct KernelContext {
        var dataReturning = Set<String>()
        var userPtrReturning = Set<String>()
        var dataParam: [String: Set<Int>] = [:]
        var userPtrParam: [String: Set<Int>] = [:]
    }

    private struct FlowInput {
        let dataSeeds: Set<String>
        let userPtrSeeds: Set<String>
    }

    private func isEntry(_ fn: CFunctionDef) -> Bool {
        if Self.kernelEntryNames.contains(fn.name) { return true }
        for p in fn.params {
            if (p.type ?? "").contains("__user") { return true }
            if let n = p.name, Self.kernelArgParamNames.contains(n) { return true }
        }
        return false
    }

    private func flowInput(for fn: CFunctionDef, ctx: KernelContext) -> FlowInput {
        let entry = isEntry(fn)
        var data = Set<String>()
        var userPtr = Set<String>()
        for (i, p) in fn.params.enumerated() {
            guard let n = p.name else { continue }
            let isUserPtrType = (p.type ?? "").contains("__user")
            if entry || isUserPtrType { data.insert(n) }
            if isUserPtrType { userPtr.insert(n) }
            if (ctx.dataParam[fn.name] ?? []).contains(i) { data.insert(n) }
            if (ctx.userPtrParam[fn.name] ?? []).contains(i) { userPtr.insert(n) }
        }
        return FlowInput(dataSeeds: data, userPtrSeeds: userPtr)
    }

    private struct KernelFlowResult {
        var candidates: [KernelAstFinding] = []
        var calls: [(callee: String, perArg: [FlavorSet])] = []
        var returnsData = false
        var returnsUserPtr = false
    }

    // MARK: - Walk 1: taint flow

    private func flow(_ stmt: CStmt, fn: CFunctionDef, input: FlowInput, ctx: KernelContext,
                      bounded: Set<String>, accessOk: Bool,
                      allocPtrs: Set<String>, nullChecked: Set<String>, fixedArrays: Set<String>,
                      emit: Bool, reachable: Bool,
                      data: inout Set<String>, userPtr: inout Set<String>, freed: inout Set<String>,
                      result: inout KernelFlowResult) {
        switch stmt {
        case .block(let arr):
            var accBounded = bounded
            for s in arr {
                // A top-level `if (x > K) return;` guard bounds `x` on the
                // fallthrough path (subsequent statements in this block).
                accBounded.formUnion(earlyExitBounds(in: s))
                flow(s, fn: fn, input: input, ctx: ctx, bounded: accBounded, accessOk: accessOk,
                     allocPtrs: allocPtrs, nullChecked: nullChecked, fixedArrays: fixedArrays,
                     emit: emit, reachable: reachable, data: &data, userPtr: &userPtr,
                     freed: &freed, result: &result)
            }
        case .expr(let e):
            flowExpr(e, fn: fn, ctx: ctx, bounded: bounded, accessOk: accessOk,
                     allocPtrs: allocPtrs, nullChecked: nullChecked, fixedArrays: fixedArrays,
                     emit: emit, reachable: reachable, bareStatement: true,
                     data: &data, userPtr: &userPtr, freed: &freed, result: &result)
        case .declaration(let d):
            if case .variable(let typeName, let name, let initExpr?) = d.kind {
                if (typeName ?? "").contains("__user") { userPtr.insert(name) }
                let flavors = flavorRefs(initExpr, data: data, userPtr: userPtr, ctx: ctx)
                if flavors.contains(.data) { data.insert(name) }
                if flavors.contains(.userPtr) { userPtr.insert(name) }
                flowExpr(initExpr, fn: fn, ctx: ctx, bounded: bounded, accessOk: accessOk,
                         allocPtrs: allocPtrs, nullChecked: nullChecked, fixedArrays: fixedArrays,
                         emit: emit, reachable: reachable, bareStatement: false,
                         data: &data, userPtr: &userPtr, freed: &freed, result: &result)
            }
        case .ifStmt(let cond, let thenBranch, let elseBranch, _):
            // Path-sensitive bounds: inside the then-branch, a `var < K` condition
            // guarantees `var` is bounded.
            var thenBounded = bounded
            for (varName, effOp) in comparisons(in: cond) where effOp == "<" {
                thenBounded.insert(varName)
            }
            // Save freed state: if the then-branch definitely returns
            // (e.g. `if (err) { kfree(ptr); return; }`), the `kfree` in
            // the error branch must not pollute the fallthrough path.
            let freedBeforeThen = freed
            flow(thenBranch, fn: fn, input: input, ctx: ctx, bounded: thenBounded, accessOk: accessOk,
                 allocPtrs: allocPtrs, nullChecked: nullChecked, fixedArrays: fixedArrays,
                 emit: emit, reachable: reachable, data: &data, userPtr: &userPtr,
                 freed: &freed, result: &result)
            if definitelyReturns(thenBranch) {
                freed = freedBeforeThen
            }
            if let elseBranch = elseBranch {
                flow(elseBranch, fn: fn, input: input, ctx: ctx, bounded: thenBounded, accessOk: accessOk,
                     allocPtrs: allocPtrs, nullChecked: nullChecked, fixedArrays: fixedArrays,
                     emit: emit, reachable: reachable, data: &data, userPtr: &userPtr,
                     freed: &freed, result: &result)
            }
            flowExpr(cond, fn: fn, ctx: ctx, bounded: bounded, accessOk: accessOk,
                     allocPtrs: allocPtrs, nullChecked: nullChecked, fixedArrays: fixedArrays,
                     emit: emit, reachable: reachable, bareStatement: false,
                     data: &data, userPtr: &userPtr, freed: &freed, result: &result)
        case .whileStmt(let cond, let body, _):
            flow(body, fn: fn, input: input, ctx: ctx, bounded: bounded, accessOk: accessOk,
                 allocPtrs: allocPtrs, nullChecked: nullChecked, fixedArrays: fixedArrays,
                 emit: emit, reachable: reachable, data: &data, userPtr: &userPtr,
                 freed: &freed, result: &result)
            flowExpr(cond, fn: fn, ctx: ctx, bounded: bounded, accessOk: accessOk,
                     allocPtrs: allocPtrs, nullChecked: nullChecked, fixedArrays: fixedArrays,
                     emit: emit, reachable: reachable, bareStatement: false,
                     data: &data, userPtr: &userPtr, freed: &freed, result: &result)
        case .forStmt(let initS, let cond, let incr, let body, _):
            if let initS = initS {
                flow(initS, fn: fn, input: input, ctx: ctx, bounded: bounded, accessOk: accessOk,
                     allocPtrs: allocPtrs, nullChecked: nullChecked, fixedArrays: fixedArrays,
                     emit: emit, reachable: reachable, data: &data, userPtr: &userPtr,
                     freed: &freed, result: &result)
            }
            flow(body, fn: fn, input: input, ctx: ctx, bounded: bounded, accessOk: accessOk,
                 allocPtrs: allocPtrs, nullChecked: nullChecked, fixedArrays: fixedArrays,
                 emit: emit, reachable: reachable, data: &data, userPtr: &userPtr,
                 freed: &freed, result: &result)
            if let cond = cond {
                flowExpr(cond, fn: fn, ctx: ctx, bounded: bounded, accessOk: accessOk,
                         allocPtrs: allocPtrs, nullChecked: nullChecked, fixedArrays: fixedArrays,
                         emit: emit, reachable: reachable, bareStatement: false,
                         data: &data, userPtr: &userPtr, freed: &freed, result: &result)
            }
            if let incr = incr {
                flowExpr(incr, fn: fn, ctx: ctx, bounded: bounded, accessOk: accessOk,
                         allocPtrs: allocPtrs, nullChecked: nullChecked, fixedArrays: fixedArrays,
                         emit: emit, reachable: reachable, bareStatement: false,
                         data: &data, userPtr: &userPtr, freed: &freed, result: &result)
            }
        case .switchStmt(_, let cases, _):
            for c in cases {
                for s in c.body {
                    flow(s, fn: fn, input: input, ctx: ctx, bounded: bounded, accessOk: accessOk,
                         allocPtrs: allocPtrs, nullChecked: nullChecked, fixedArrays: fixedArrays,
                         emit: emit, reachable: reachable, data: &data, userPtr: &userPtr,
                         freed: &freed, result: &result)
                }
            }
        case .returnStmt(let e, _):
            if let e = e {
                if flavorRefs(e, data: data, userPtr: userPtr, ctx: ctx).contains(.data) { result.returnsData = true }
                if flavorRefs(e, data: data, userPtr: userPtr, ctx: ctx).contains(.userPtr) { result.returnsUserPtr = true }
                flowExpr(e, fn: fn, ctx: ctx, bounded: bounded, accessOk: accessOk,
                         allocPtrs: allocPtrs, nullChecked: nullChecked, fixedArrays: fixedArrays,
                         emit: emit, reachable: reachable, bareStatement: false,
                         data: &data, userPtr: &userPtr, freed: &freed, result: &result)
            }
        case .labeledStmt(_, let s, _):
            flow(s, fn: fn, input: input, ctx: ctx, bounded: bounded, accessOk: accessOk,
                 allocPtrs: allocPtrs, nullChecked: nullChecked, fixedArrays: fixedArrays,
                 emit: emit, reachable: reachable, data: &data, userPtr: &userPtr,
                 freed: &freed, result: &result)
        default:
            break
        }
    }

    private func flowExpr(_ e: CExpr, fn: CFunctionDef, ctx: KernelContext,
                          bounded: Set<String>, accessOk: Bool,
                          allocPtrs: Set<String>, nullChecked: Set<String>, fixedArrays: Set<String>,
                          emit: Bool, reachable: Bool, bareStatement: Bool,
                          data: inout Set<String>, userPtr: inout Set<String>, freed: inout Set<String>,
                          result: inout KernelFlowResult) {
        switch e {
        case .call(let callee, let args, let offset):
            handleKernelCall(callee: callee, args: args, offset: offset, fn: fn, ctx: ctx,
                             bounded: bounded, accessOk: accessOk,
                             allocPtrs: allocPtrs, nullChecked: nullChecked, fixedArrays: fixedArrays,
                             emit: emit, reachable: reachable, bareStatement: bareStatement,
                             data: &data, userPtr: &userPtr, freed: &freed, result: &result)
            // The call's arguments are walked too (they may contain their own
            // sources/sinks), but the callee side is not.
            for a in args {
                flowExpr(a, fn: fn, ctx: ctx, bounded: bounded, accessOk: accessOk,
                         allocPtrs: allocPtrs, nullChecked: nullChecked, fixedArrays: fixedArrays,
                         emit: emit, reachable: reachable, bareStatement: false,
                         data: &data, userPtr: &userPtr, freed: &freed, result: &result)
            }
        case .assign(_, let lhs, let rhs, _):
            if let name = simpleIdentifier(lhs) {
                let flavors = flavorRefs(rhs, data: data, userPtr: userPtr, ctx: ctx)
                if flavors.contains(.data) { data.insert(name) }
                if flavors.contains(.userPtr) { userPtr.insert(name) }
            }
            flowExpr(lhs, fn: fn, ctx: ctx, bounded: bounded, accessOk: accessOk,
                     allocPtrs: allocPtrs, nullChecked: nullChecked, fixedArrays: fixedArrays,
                     emit: emit, reachable: reachable, bareStatement: false,
                     data: &data, userPtr: &userPtr, freed: &freed, result: &result)
            flowExpr(rhs, fn: fn, ctx: ctx, bounded: bounded, accessOk: accessOk,
                     allocPtrs: allocPtrs, nullChecked: nullChecked, fixedArrays: fixedArrays,
                     emit: emit, reachable: reachable, bareStatement: false,
                     data: &data, userPtr: &userPtr, freed: &freed, result: &result)
        case .unary(_, let operand, _), .cast(let operand, _), .paren(let operand, _):
            flowExpr(operand, fn: fn, ctx: ctx, bounded: bounded, accessOk: accessOk,
                     allocPtrs: allocPtrs, nullChecked: nullChecked, fixedArrays: fixedArrays,
                     emit: emit, reachable: reachable, bareStatement: false,
                     data: &data, userPtr: &userPtr, freed: &freed, result: &result)
        case .binary(_, let l, let r, _), .comma(let l, let r, _):
            flowExpr(l, fn: fn, ctx: ctx, bounded: bounded, accessOk: accessOk,
                     allocPtrs: allocPtrs, nullChecked: nullChecked, fixedArrays: fixedArrays,
                     emit: emit, reachable: reachable, bareStatement: false,
                     data: &data, userPtr: &userPtr, freed: &freed, result: &result)
            flowExpr(r, fn: fn, ctx: ctx, bounded: bounded, accessOk: accessOk,
                     allocPtrs: allocPtrs, nullChecked: nullChecked, fixedArrays: fixedArrays,
                     emit: emit, reachable: reachable, bareStatement: false,
                     data: &data, userPtr: &userPtr, freed: &freed, result: &result)
        case .ternary(let c, let t, let f, _):
            flowExpr(c, fn: fn, ctx: ctx, bounded: bounded, accessOk: accessOk,
                     allocPtrs: allocPtrs, nullChecked: nullChecked, fixedArrays: fixedArrays,
                     emit: emit, reachable: reachable, bareStatement: false,
                     data: &data, userPtr: &userPtr, freed: &freed, result: &result)
            flowExpr(t, fn: fn, ctx: ctx, bounded: bounded, accessOk: accessOk,
                     allocPtrs: allocPtrs, nullChecked: nullChecked, fixedArrays: fixedArrays,
                     emit: emit, reachable: reachable, bareStatement: false,
                     data: &data, userPtr: &userPtr, freed: &freed, result: &result)
            flowExpr(f, fn: fn, ctx: ctx, bounded: bounded, accessOk: accessOk,
                     allocPtrs: allocPtrs, nullChecked: nullChecked, fixedArrays: fixedArrays,
                     emit: emit, reachable: reachable, bareStatement: false,
                     data: &data, userPtr: &userPtr, freed: &freed, result: &result)
        case .member(let base, _, _, _):
            checkNullDerefAndUAF(base, fn: fn, allocPtrs: allocPtrs, nullChecked: nullChecked,
                                 emit: emit, reachable: reachable, offset: e.offset,
                                 freed: &freed, result: &result)
            flowExpr(base, fn: fn, ctx: ctx, bounded: bounded, accessOk: accessOk,
                     allocPtrs: allocPtrs, nullChecked: nullChecked, fixedArrays: fixedArrays,
                     emit: emit, reachable: reachable, bareStatement: false,
                     data: &data, userPtr: &userPtr, freed: &freed, result: &result)
        case .index(let base, let idx, _):
            checkNullDerefAndUAF(base, fn: fn, allocPtrs: allocPtrs, nullChecked: nullChecked,
                                 emit: emit, reachable: reachable, offset: e.offset,
                                 freed: &freed, result: &result)
            checkKernelOOBIndex(base: base, idx: idx, fixedArrays: fixedArrays, bounded: bounded,
                                ctx: ctx, fn: fn, emit: emit, reachable: reachable, offset: e.offset,
                                data: data, userPtr: userPtr, result: &result)
            flowExpr(base, fn: fn, ctx: ctx, bounded: bounded, accessOk: accessOk,
                     allocPtrs: allocPtrs, nullChecked: nullChecked, fixedArrays: fixedArrays,
                     emit: emit, reachable: reachable, bareStatement: false,
                     data: &data, userPtr: &userPtr, freed: &freed, result: &result)
            flowExpr(idx, fn: fn, ctx: ctx, bounded: bounded, accessOk: accessOk,
                     allocPtrs: allocPtrs, nullChecked: nullChecked, fixedArrays: fixedArrays,
                     emit: emit, reachable: reachable, bareStatement: false,
                     data: &data, userPtr: &userPtr, freed: &freed, result: &result)
        case .arrayInit(let elements, _):
            for el in elements {
                flowExpr(el, fn: fn, ctx: ctx, bounded: bounded, accessOk: accessOk,
                         allocPtrs: allocPtrs, nullChecked: nullChecked, fixedArrays: fixedArrays,
                         emit: emit, reachable: reachable, bareStatement: false,
                         data: &data, userPtr: &userPtr, freed: &freed, result: &result)
            }
        case .newExpr(_, let args, _):
            for a in args {
                flowExpr(a, fn: fn, ctx: ctx, bounded: bounded, accessOk: accessOk,
                         allocPtrs: allocPtrs, nullChecked: nullChecked, fixedArrays: fixedArrays,
                         emit: emit, reachable: reachable, bareStatement: false,
                         data: &data, userPtr: &userPtr, freed: &freed, result: &result)
            }
        default:
            break
        }
    }

    // MARK: - Kernel call handling

    private func handleKernelCall(callee: CExpr, args: [CExpr], offset: Int, fn: CFunctionDef,
                                  ctx: KernelContext, bounded: Set<String>, accessOk: Bool,
                                  allocPtrs: Set<String>, nullChecked: Set<String>, fixedArrays: Set<String>,
                                  emit: Bool, reachable: Bool, bareStatement: Bool,
                                  data: inout Set<String>, userPtr: inout Set<String>, freed: inout Set<String>,
                                  result: inout KernelFlowResult) {
        guard let name = calleeName(callee) else { return }
        let isLocal = defined.contains(name)

        // A user-defined function: record how this caller taints its parameters
        // so the boundary walk can propagate (never treated as a kernel symbol).
        if isLocal, let calleeFn = astFns[name] {
            var perArg: [FlavorSet] = []
            for (k, a) in args.enumerated() where k < calleeFn.params.count {
                perArg.append(flavorRefs(a, data: data, userPtr: userPtr, ctx: ctx))
            }
            result.calls.append((name, perArg))
            return
        }

        // --- Data sources (side effects that persist in this function) ---
        // `copy_from_user`/`get_user`/... write attacker data into their first
        // (destination) argument; that variable is tainted for the rest of the walk.
        if Self.userSourceReadFns.contains(name), let target = args.first.flatMap(simpleIdentifier) {
            data.insert(target)
        }

        // --- Allocation / free bookkeeping for null-deref and use-after-free ---
        if let target = args.first.flatMap(simpleIdentifier) {
            if type(of: self).heapAllocFns.contains(name) || type(of: self).userDataReturningFns.contains(name) {
                freed.remove(target)  // allocation resets any prior free state
            } else if name == "kfree" || name == "vfree" {
                freed.insert(target)
            }
        }

        // --- Sink checks (only when emitting) ---
        if emit, !isLocal {
            // 1) Kernel user-pointer dereference.
            if let positions = type(of: self).kernelMemPtrPos[name] {
                for p in positions where p < args.count {
                    if flavorRefs(args[p], data: data, userPtr: userPtr, ctx: ctx).contains(.userPtr) {
                        emitFinding(&result, function: fn.name, offset: offset,
                                    category: "Kernel User Pointer Dereference",
                                    severity: .critical,
                                    message: "\(name) dereferences a raw __user pointer (userspace memory) as kernel memory.",
                                    taint: "kernel-address → __user pointer", reachable: reachable)
                    }
                }
            }

            // 2) Copy size overflows (Kernel Memory Corruption / Disclosure).
            if Self.userSourceReadFns.contains(name) || Self.userSinkWriteFns.contains(name) {
                if name != "get_user", name != "put_user", !name.hasPrefix("unsafe_") {
                    let sizeIdx = name == "copy_struct_from_user" ? 3 : 2
                    if sizeIdx < args.count, flavorRefs(args[sizeIdx], data: data, userPtr: userPtr, ctx: ctx).contains(.data),
                       !sizeIsSafe(args[sizeIdx], bounded: bounded) {
                        let isRead = Self.userSourceReadFns.contains(name)
                        emitFinding(&result, function: fn.name, offset: offset,
                                    category: isRead ? "Kernel Memory Corruption" : "Kernel Memory Disclosure",
                                    severity: isRead ? .critical : .high,
                                    message: "\(name) copies an attacker-controlled size into kernel memory without a bounds check\(isRead ? "." : ", disclosing kernel memory.")",
                                    taint: "user input → size", reachable: reachable)
                    }
                }
            }

            // 3) strncpy_from_user with an unbounded count.
            if name == "strncpy_from_user", args.count > 2,
               flavorRefs(args[2], data: data, userPtr: userPtr, ctx: ctx).contains(.data),
               !sizeIsSafe(args[2], bounded: bounded) {
                emitFinding(&result, function: fn.name, offset: offset,
                            category: "Kernel Buffer Overflow", severity: .high,
                            message: "strncpy_from_user copies an attacker-controlled number of bytes into a kernel buffer.",
                            taint: "user input → count", reachable: reachable)
            }

            // 4) String copies with tainted, unbounded sources.
            if Self.kernelStringSinks.contains(name), args.count > 1,
               flavorRefs(args[1], data: data, userPtr: userPtr, ctx: ctx).contains(.data) {
                emitFinding(&result, function: fn.name, offset: offset,
                            category: "Kernel Buffer Overflow", severity: .high,
                            message: "\(name) writes untrusted data into a fixed kernel buffer without a bound.",
                            taint: "user input → source", reachable: reachable)
            }

            // 5) Heap allocations with tainted, unbounded sizes.
            if (type(of: self).heapAllocFns).contains(name) {
                // devm_* allocators take the struct device as arg 0; their size is arg 1.
                let sizeIdx = (name == "devm_kzalloc" || name == "devm_kmalloc" || name == "devm_kcalloc") ? 1 : 0
                if sizeIdx < args.count,
                   flavorRefs(args[sizeIdx], data: data, userPtr: userPtr, ctx: ctx).contains(.data),
                   !sizeIsSafe(args[sizeIdx], bounded: bounded) {
                    emitFinding(&result, function: fn.name, offset: offset,
                                category: "Kernel Heap Overflow", severity: .high,
                                message: "\(name) allocates a size derived from untrusted data without validation (possible integer overflow / undersized allocation).",
                                taint: "user input → size", reachable: reachable)
                }
            }

            // 5b) Unbounded kernel-to-kernel memory copy: memcpy/memmove with an
            // attacker-controlled, unvalidated count into/out of a kernel buffer.
            if name == "memcpy" || name == "memmove" {
                let countIdx = 2
                if countIdx < args.count,
                   flavorRefs(args[countIdx], data: data, userPtr: userPtr, ctx: ctx).contains(.data),
                   !sizeIsSafe(args[countIdx], bounded: bounded) {
                    emitFinding(&result, function: fn.name, offset: offset,
                                category: "Kernel Unbounded Memory Copy", severity: .high,
                                message: "\(name) copies an attacker-controlled number of bytes between kernel buffers without a bound.",
                                taint: "user input → count", reachable: reachable)
                }
            }

            // 6) User copy whose return value is silently discarded.
            if bareStatement, type(of: self).uncheckedUserCopyFns.contains(name), !accessOk {
                emitFinding(&result, function: fn.name, offset: offset,
                            category: "Kernel Unchecked User Copy", severity: .medium,
                            message: "\(name) return value is ignored; the transfer may fail silently leaving the destination uninitialized.",
                            taint: "unchecked user copy", reachable: reachable)
            }

            // 7) Null dereference: an allocation-returning API's result is directly
            // dereferenced through the same call expression without a NULL check on
            // the returned pointer (e.g. `kmalloc(...)->field` or `memset(kmalloc(...),...)`).
            if (type(of: self).heapAllocFns.contains(name) || type(of: self).userDataReturningFns.contains(name)) {
                if let base = args.first, baseIsDereference(base) {
                    emitFinding(&result, function: fn.name, offset: offset,
                                category: "Kernel Null Dereference", severity: .high,
                                message: "\(name) result is dereferenced without checking for NULL; allocation failure causes a null-pointer dereference.",
                                taint: "unchecked allocation", reachable: reachable)
                }
            }
            // 7b) Null dereference through a write destination: a kernel allocation
            // whose result is never checked is used as the destination of a
            // memory-write call (memset/memcpy/strcpy/...) — writes through NULL on
            // allocation failure.
            if type(of: self).kernelWriteDstFns.contains(name),
               !args.isEmpty, let dst = simpleIdentifier(args[0]),
               allocPtrs.contains(dst), !nullChecked.contains(dst) {
                emitFinding(&result, function: fn.name, offset: offset,
                            category: "Kernel Null Dereference", severity: .high,
                            message: "\(name) writes through \(dst), a kernel allocation that is never NULL-checked.",
                            taint: "unchecked allocation → write", reachable: reachable)
            }
            // 7c) Use-after-free through a memory-access argument: a kfree'd pointer
            // is later passed to a kernel memory function (memcpy/memmove/strcpy/...),
            // reading/writing freed memory.
            if !(name == "kfree" || name == "vfree"), !(name == "kzfree"),
               !(type(of: self).heapAllocFns.contains(name)),
               !freed.isEmpty {
                for arg in args {
                    if let an = simpleIdentifier(arg), freed.contains(an) {
                        emitFinding(&result, function: fn.name, offset: offset,
                                    category: "Kernel Use-After-Free", severity: .critical,
                                    message: "\(an) is used after being kfree'd (use-after-free).",
                                    taint: "kfree → reuse", reachable: reachable)
                        break
                    }
                }
            }
        }
    }

    /// Whether an allocation-return expression is consumed as a dereference right
    /// away (member access via `->`, array subscript, or `memset`/`memcpy` destination).
    private func baseIsDereference(_ e: CExpr) -> Bool {
        switch e {
        case .member(_, _, let isPtr, _): return isPtr
        case .index(_, _, _): return true
        case .unary(let op, _, _): return op == "*" || op == "->"
        case .paren(let x, _), .cast(let x, _): return baseIsDereference(x)
        default: return false
        }
    }

    private func emitFinding(_ result: inout KernelFlowResult, function: String, offset: Int,
                             category: String, severity: ScanFinding.Severity, message: String,
                             taint: String?, reachable: Bool) {
        result.candidates.append(KernelAstFinding(function: function, offset: offset,
                                                   category: category, severity: severity,
                                                   message: message, taintPath: taint,
                                                   reachable: reachable))
    }

    // MARK: - Null-deref / use-after-free / OOB helpers

    /// Called when an expression dereferences `base` (as `base->field` or `base[i]`).
    /// Emits a use-after-free if the base pointer was `kfree`d earlier in the walk,
    /// or a null-dereference if the base is a kernel allocation whose result is never
    /// null-checked anywhere in the function.
    private func checkNullDerefAndUAF(_ base: CExpr, fn: CFunctionDef,
                                      allocPtrs: Set<String>, nullChecked: Set<String>,
                                      emit: Bool, reachable: Bool, offset: Int,
                                      freed: inout Set<String>, result: inout KernelFlowResult) {
        guard emit, let name = simpleIdentifier(base) else { return }
        if freed.contains(name) {
            emitFinding(&result, function: fn.name, offset: offset,
                        category: "Kernel Use-After-Free", severity: .critical,
                        message: "\(name) is dereferenced after being kfree'd (use-after-free).",
                        taint: "kfree → dereference", reachable: reachable)
        } else if allocPtrs.contains(name), !nullChecked.contains(name) {
            emitFinding(&result, function: fn.name, offset: offset,
                        category: "Kernel Null Dereference", severity: .high,
                        message: "\(name) is a kernel allocation that is dereferenced without any NULL check.",
                        taint: "unchecked allocation → dereference", reachable: reachable)
        }
    }

    /// Emits a Kernel Out-of-Bounds Access when a fixed-size local array is indexed
    /// by an attacker-controlled index that is not provably bounded.
    private func checkKernelOOBIndex(base: CExpr, idx: CExpr, fixedArrays: Set<String>,
                                     bounded: Set<String>,
                                     ctx: KernelContext,
                                     fn: CFunctionDef, emit: Bool, reachable: Bool, offset: Int,
                                     data: Set<String>, userPtr: Set<String>,
                                     result: inout KernelFlowResult) {
        guard emit, let name = simpleIdentifier(base), fixedArrays.contains(name) else { return }
        guard flavorRefs(idx, data: data, userPtr: userPtr, ctx: ctx).contains(.data) else { return }
        guard !sizeIsSafe(idx, bounded: bounded) else { return }
        emitFinding(&result, function: fn.name, offset: offset,
                    category: "Kernel Out-of-Bounds Access", severity: .high,
                    message: "\(name) is a fixed-size array indexed by an attacker-controlled value without a bounds check.",
                    taint: "user input → index", reachable: reachable)
    }

    // MARK: - Structural facts (Walk 2b)

    /// Pointer variables whose value is produced by a kernel allocation
    /// (kmalloc/kzalloc/... or memdup_user/...) — candidates for missing NULL checks.
    private func allocationPointers(in body: CStmt) -> Set<String> {
        var names = Set<String>()
        walkStructurally(body) { stmt in
            if case .declaration(let d) = stmt, case .variable(_, let name, let initExpr?) = d.kind {
                if isAllocationReturn(initExpr) { names.insert(name) }
            }
        }
        return names
    }

    /// Pointer names that appear in a `if (!p) ... return;` / `if (p == NULL) ...`
    /// null-rejection guard anywhere in the body. Function-wide so a single guard
    /// protects every later dereference.
    private func nullCheckedNames(in body: CStmt) -> Set<String> {
        var names = Set<String>()
        walkStructurally(body) { stmt in
            guard case .ifStmt(let cond, let thenBranch, _, _) = stmt else { return }
            if definitelyReturns(thenBranch), let n = nullGuardIdentifier(cond) {
                names.insert(n)
            }
        }
        return names
    }

    /// Fixed-size local array names declared in the body, e.g. `char buf[64];`.
    private func fixedArrays(in body: CStmt) -> Set<String> {
        var names = Set<String>()
        walkStructurally(body) { stmt in
            guard case .declaration(let d) = stmt, case .variable(let typeName, let name, _) = d.kind else { return }
            if (typeName ?? "").contains("[") { names.insert(name) }
        }
        return names
    }

    private func isAllocationReturn(_ e: CExpr) -> Bool {
        switch e {
        case .call(let callee, _, _):
            guard let name = calleeName(callee) else { return false }
            return type(of: self).heapAllocFns.contains(name) || type(of: self).userDataReturningFns.contains(name)
        case .paren(let x, _), .cast(let x, _):
            return isAllocationReturn(x)
        default:
            return false
        }
    }

    /// Extracts a pointer name from a null-rejection condition: `!p`, `p == NULL`,
    /// `NULL == p`, `!p != 0`/`p != NULL`. Only the simple/inequality forms.
    private func nullGuardIdentifier(_ cond: CExpr) -> String? {
        switch cond {
        case .unary("!", let op, _):
            return simpleIdentifier(op)
        case .binary(let op, let l, let r, _):
            if op == "==" || op == "!=" {
                let pair = (simpleIdentifier(l), simpleIdentifier(r))
                switch pair {
                case (let a?, _) where isNullLiteral(r): return a
                case (_, let b?) where isNullLiteral(l): return b
                default: return nil
                }
            }
            return nil
        case .paren(let x, _), .cast(let x, _):
            return nullGuardIdentifier(x)
        default:
            return nil
        }
    }

    private func isNullLiteral(_ e: CExpr) -> Bool {
        switch e {
        case .integerLiteral(let v, _): return v == "0"
        case .identifier(let n, _): return n == "NULL"
        case .paren(let x, _), .cast(let x, _): return isNullLiteral(x)
        default: return false
        }
    }

    /// Generic structural walker over statements, for computing the 2b facts.
    private func walkStructurally(_ stmt: CStmt, _ visit: (CStmt) -> Void) {
        visit(stmt)
        switch stmt {
        case .block(let arr):
            for s in arr { walkStructurally(s, visit) }
        case .ifStmt(_, let t, let e, _):
            walkStructurally(t, visit)
            if let e = e { walkStructurally(e, visit) }
        case .whileStmt(_, let b, _), .doWhileStmt(let b, _, _):
            walkStructurally(b, visit)
        case .forStmt(let i, _, _, let b, _):
            if let i = i { walkStructurally(i, visit) }
            walkStructurally(b, visit)
        case .switchStmt(_, let cases, _):
            for c in cases { for s in c.body { walkStructurally(s, visit) } }
        case .labeledStmt(_, let s, _):
            walkStructurally(s, visit)
        default:
            break
        }
    }

    // MARK: - Flavor reflection

    private func flavorRefs(_ e: CExpr, data: Set<String>, userPtr: Set<String>, ctx: KernelContext) -> FlavorSet {
        switch e {
        case .identifier(let n, _):
            var f = FlavorSet()
            if data.contains(n) { f.insert(.data) }
            if userPtr.contains(n) { f.insert(.userPtr) }
            return f
        case .call(let callee, _, _):
            guard let name = calleeName(callee) else { return [] }
            if type(of: self).userDataReturningFns.contains(name) {
                return [.data]
            }
            if ctx.dataReturning.contains(name) { return [.data] }
            if ctx.userPtrReturning.contains(name) { return [.userPtr] }
            return []
        case .assign(_, _, let rhs, _):
            return flavorRefs(rhs, data: data, userPtr: userPtr, ctx: ctx)
        case .binary(_, let l, let r, _), .comma(let l, let r, _):
            return flavorRefs(l, data: data, userPtr: userPtr, ctx: ctx)
                .union(flavorRefs(r, data: data, userPtr: userPtr, ctx: ctx))
        case .ternary(let c, let t, let f, _):
            return flavorRefs(c, data: data, userPtr: userPtr, ctx: ctx)
                .union(flavorRefs(t, data: data, userPtr: userPtr, ctx: ctx))
                .union(flavorRefs(f, data: data, userPtr: userPtr, ctx: ctx))
        case .member(let base, _, _, _):
            return flavorRefs(base, data: data, userPtr: userPtr, ctx: ctx)
        case .index(let base, let idx, _):
            return flavorRefs(base, data: data, userPtr: userPtr, ctx: ctx)
                .union(flavorRefs(idx, data: data, userPtr: userPtr, ctx: ctx))
        case .unary(_, let operand, _), .cast(let operand, _), .paren(let operand, _):
            return flavorRefs(operand, data: data, userPtr: userPtr, ctx: ctx)
        case .arrayInit(let elements, _):
            var f = FlavorSet()
            for el in elements {
                f.formUnion(flavorRefs(el, data: data, userPtr: userPtr, ctx: ctx))
            }
            return f
        case .newExpr(_, let args, _):
            var f = FlavorSet()
            for a in args {
                f.formUnion(flavorRefs(a, data: data, userPtr: userPtr, ctx: ctx))
            }
            return f
        default:
            return []
        }
    }

    // MARK: - Bounds (Walk 2)

    /// Computes (a) the set of function-wide bounded variables and (b) whether the
    /// function guards its user copies with `access_ok(...)`.
    private func boundedAndAccessOk(in body: CStmt) -> (Set<String>, Bool) {
        var bounded = Set<String>()
        var accessOk = false
        boundsWalk(body, into: &bounded, accessOk: &accessOk)
        return (bounded, accessOk)
    }

    private func boundsWalk(_ stmt: CStmt, into bounded: inout Set<String>, accessOk: inout Bool) {
        switch stmt {
        case .block(let arr):
            for s in arr { boundsWalk(s, into: &bounded, accessOk: &accessOk) }
        case .ifStmt(let cond, let thenBranch, let elseBranch, _):
            let thenReturns = definitelyReturns(thenBranch)
            let elseReturns = elseBranch.map(definitelyReturns) ?? false
            for (varName, effOp) in comparisons(in: cond) {
                if effOp == ">", thenReturns { bounded.insert(varName) }
                else if effOp == "<", elseReturns { bounded.insert(varName) }
            }
            if thenReturns, containsAccessOk(cond) { accessOk = true }
            boundsWalk(thenBranch, into: &bounded, accessOk: &accessOk)
            if let elseBranch = elseBranch {
                boundsWalk(elseBranch, into: &bounded, accessOk: &accessOk)
            }
        case .whileStmt(_, let b, _), .doWhileStmt(let b, _, _):
            boundsWalk(b, into: &bounded, accessOk: &accessOk)
        case .forStmt(_, _, _, let b, _):
            boundsWalk(b, into: &bounded, accessOk: &accessOk)
        case .switchStmt(_, let cases, _):
            for c in cases {
                for s in c.body { boundsWalk(s, into: &bounded, accessOk: &accessOk) }
            }
        case .labeledStmt(_, let s, _):
            boundsWalk(s, into: &bounded, accessOk: &accessOk)
        default:
            break
        }
    }

    /// Extracts `(variable, effectiveOp)` pairs from a condition, e.g.
    /// `count > sizeof(buf)` -> ("count", ">"); `sizeof(buf) < count` ->
    /// ("count", ">"). Only handles plain comparisons and `||` chains;
    /// `&&` chains are ignored (a var is only provably bounded when *any* too-big
    /// check rejects), which keeps suppression conservative.
    private func comparisons(in cond: CExpr) -> [(String, String)] {
        var out: [(String, String)] = []
        switch cond {
        case .binary(let op, let l, let r, _):
            if op == "||" {
                out.append(contentsOf: comparisons(in: l))
                out.append(contentsOf: comparisons(in: r))
                return out
            }
            let gtOps: Set<String> = [">", ">="]
            let ltOps: Set<String> = ["<", "<="]
            switch (l, r) {
            case (.identifier(let vn, _), _):
                // `var` on the left. The right side may itself be a capacity
                // parameter (e.g. `if (len > dst_cap) return;`), so no
                // constant requirement is imposed — a rejection guard bounds
                // `var` from above regardless of what the cap is.
                if gtOps.contains(op) { out.append((vn, ">")) }
                else if ltOps.contains(op) { out.append((vn, "<")) }
            case (_, .identifier(let vn, _)):
                if gtOps.contains(op) { out.append((vn, "<" )) }  // `K > var` ~ var < K
                else if ltOps.contains(op) { out.append((vn, ">" )) }  // `K < var` ~ var > K
            default:
                break
            }
        case .paren(let x, _), .cast(let x, _):
            return comparisons(in: x)
        default:
            break
        }
        return out
    }

    private func containsAccessOk(_ e: CExpr) -> Bool {
        switch e {
        case .call(let callee, _, _):
            return calleeName(callee) == "access_ok"
        case .unary(_, let operand, _), .cast(let operand, _), .paren(let operand, _):
            return containsAccessOk(operand)
        case .binary(_, let l, let r, _):
            return containsAccessOk(l) || containsAccessOk(r)
        case .ternary(let c, let t, let f, _):
            return containsAccessOk(c) || containsAccessOk(t) || containsAccessOk(f)
        default:
            return false
        }
    }

    /// Bounds established by an `if (... ) return;`-style early-exit guard.
    /// When the guard exits on `VAR > K` (or `K < VAR`), the fallthrough path
    /// has `VAR <= K`, i.e. it is bounded above — exactly the condition size
    /// checks (`copy_from_user(dst, src, count)`) need to be safe.
    private func earlyExitBounds(in stmt: CStmt) -> Set<String> {
        guard case .ifStmt(let cond, let thenBranch, let elseB, _) = stmt else { return [] }
        guard definitelyReturns(thenBranch), elseB == nil else { return [] }
        var out = Set<String>()
        for (vn, effOp) in comparisons(in: cond) where effOp == ">" {
            out.insert(vn)
        }
        return out
    }

    /// True when the statement cannot fall through (a `return`, or a block ending
    /// in one). Used to recognize `if (... ) return; ...` guard patterns.
    private func definitelyReturns(_ stmt: CStmt) -> Bool {
        switch stmt {
        case .returnStmt:
            return true
        case .block(let arr):
            return arr.last.map(definitelyReturns) ?? false
        case .ifStmt(_, let t, let e, _):
            return definitelyReturns(t) && e.map(definitelyReturns) ?? false
        case .labeledStmt(_, let s, _):
            return definitelyReturns(s)
        case .switchStmt(_, let cases, _):
            return !cases.isEmpty && cases.allSatisfy { $0.body.last.map(definitelyReturns) ?? false }
        default:
            return false
        }
    }

    /// Whether a size expression is provably bounded: fixed (`sizeof`, literals),
    /// clamped (`min`, `clamp`, `struct_size`, ...), or a variable proven bounded
    /// by an earlier guard.
    private func sizeIsSafe(_ e: CExpr, bounded: Set<String>) -> Bool {
        switch e {
        case .integerLiteral, .sizeOf:
            return true
        case .paren(let x, _), .cast(let x, _):
            return sizeIsSafe(x, bounded: bounded)
        case .identifier(let n, _):
            return bounded.contains(n)
        case .call(let callee, _, _):
            guard let name = calleeName(callee) else { return false }
            return type(of: self).fixedSizeCallNames.contains(name)
        case .binary(let op, let l, let r, _):
            if op == "+" { return sizeIsSafe(l, bounded: bounded) && sizeIsSafe(r, bounded: bounded) }
            if op == "-" { return sizeIsSafe(l, bounded: bounded) && isPlainLiteral(r) }
            return false
        default:
            return false
        }
    }

    private func isPlainLiteral(_ e: CExpr) -> Bool {
        switch e {
        case .integerLiteral, .floatLiteral, .charLiteral: return true
        case .paren(let x, _), .cast(let x, _): return isPlainLiteral(x)
        default: return false
        }
    }

    // MARK: - sk_buff headroom provenance

    /// sk_buff allocators and the headroom (bytes) they guarantee. The raw
    /// `alloc_skb` family reserves nothing; the Bluetooth core helpers reserve
    /// `BT_SKB_RESERVE` (8). Netdev allocators (`dev_alloc_skb`, ...) reserve
    /// `NET_SKB_PAD`, which varies per kernel config (>= 32), so their result
    /// is deliberately *not* modeled as a known value (avoids false positives).
    private static let skbAllocReserve: [String: Int] = [
        "alloc_skb": 0, "alloc_skb_fclone": 0, "__alloc_skb": 0,
        "bt_skb_alloc": 8, "bt_skb_send_alloc": 8,
    ]

    /// skb helpers whose result inherits the headroom of their skb argument
    /// (clone/copy share or reproduce the same linear buffer layout).
    private static let skbInheritFns: Set<String> = [
        "skb_clone", "skb_copy", "__skb_copy", "pskb_copy", "skb_share_check",
        "skb_unshare", "skb_copy_expand",
    ]

    private static let skbPushFns: Set<String> = ["skb_push", "__skb_push"]
    private static let skbPullFns: Set<String> = ["skb_pull", "__skb_pull", "skb_pull_inline"]

    /// Walks a function body in source order, maintaining the guaranteed
    /// headroom (`[skbName: Int]`; absent = unknown provenance) and flagging
    /// `skb_push(skb, N)` calls where N provably exceeds the headroom.
    private func skbWalkStmt(_ stmt: CStmt, state: inout [String: Int], fnName: String,
                             reachable: Bool, findings: inout [KernelAstFinding]) {
        switch stmt {
        case .block(let arr):
            for s in arr {
                skbWalkStmt(s, state: &state, fnName: fnName, reachable: reachable, findings: &findings)
            }
        case .declaration(let d):
            if case .variable(_, let name, let initExpr?) = d.kind {
                skbScanExpr(initExpr, state: &state, fnName: fnName, reachable: reachable, findings: &findings)
                skbUpdateVar(name, rhs: initExpr, state: &state)
            }
        case .expr(let e):
            skbScanExpr(e, state: &state, fnName: fnName, reachable: reachable, findings: &findings)
            skbApplyExprState(e, state: &state)
        case .ifStmt(let cond, let thenB, let elseB, _):
            skbScanExpr(cond, state: &state, fnName: fnName, reachable: reachable, findings: &findings)
            var thenState = state
            skbWalkStmt(thenB, state: &thenState, fnName: fnName, reachable: reachable, findings: &findings)
            if let elseB = elseB {
                var elseState = state
                skbWalkStmt(elseB, state: &elseState, fnName: fnName, reachable: reachable, findings: &findings)
                state = skbMergeStates(thenState, elseState)
            } else {
                // The implicit else path continues with the pre-if state.
                state = skbMergeStates(thenState, state)
            }
        case .whileStmt(let cond, let body, _):
            skbScanExpr(cond, state: &state, fnName: fnName, reachable: reachable, findings: &findings)
            var bodyState = state
            skbWalkStmt(body, state: &bodyState, fnName: fnName, reachable: reachable, findings: &findings)
            state = skbMergeStates(state, bodyState)
        case .doWhileStmt(let body, let cond, _):
            var bodyState = state
            skbWalkStmt(body, state: &bodyState, fnName: fnName, reachable: reachable, findings: &findings)
            skbScanExpr(cond, state: &state, fnName: fnName, reachable: reachable, findings: &findings)
            state = skbMergeStates(state, bodyState)
        case .forStmt(let initS, let cond, let inc, let body, _):
            if let initS = initS {
                skbWalkStmt(initS, state: &state, fnName: fnName, reachable: reachable, findings: &findings)
            }
            if let cond = cond {
                skbScanExpr(cond, state: &state, fnName: fnName, reachable: reachable, findings: &findings)
            }
            var bodyState = state
            skbWalkStmt(body, state: &bodyState, fnName: fnName, reachable: reachable, findings: &findings)
            if let inc = inc {
                skbScanExpr(inc, state: &bodyState, fnName: fnName, reachable: reachable, findings: &findings)
            }
            state = skbMergeStates(state, bodyState)
        case .switchStmt(let expr, let cases, _):
            skbScanExpr(expr, state: &state, fnName: fnName, reachable: reachable, findings: &findings)
            var merged: [String: Int]? = nil
            for c in cases {
                var caseState = state
                for s in c.body {
                    skbWalkStmt(s, state: &caseState, fnName: fnName, reachable: reachable, findings: &findings)
                }
                merged = merged.map { skbMergeStates($0, caseState) } ?? caseState
            }
            if let m = merged {
                // The switch may also be skipped entirely.
                state = skbMergeStates(state, m)
            }
        case .labeledStmt(_, let s, _):
            skbWalkStmt(s, state: &state, fnName: fnName, reachable: reachable, findings: &findings)
        case .returnStmt(let e, _):
            if let e = e {
                skbScanExpr(e, state: &state, fnName: fnName, reachable: reachable, findings: &findings)
            }
        default:
            break
        }
    }

    /// A guarantee only holds after a branch if it holds on *every* path, so a
    /// variable's provable headroom merges by taking the minimum; unknown on
    /// either side destroys the guarantee.
    private func skbMergeStates(_ a: [String: Int], _ b: [String: Int]) -> [String: Int] {
        var out: [String: Int] = [:]
        for (k, v) in a where b[k] != nil {
            out[k] = min(v, b[k]!)
        }
        return out
    }

    /// Recursively scans an expression for `skb_push` calls, checking each
    /// against the skb's provable headroom and consuming the pushed bytes.
    private func skbScanExpr(_ e: CExpr, state: inout [String: Int], fnName: String,
                             reachable: Bool, findings: inout [KernelAstFinding]) {
        switch e {
        case .call(let callee, let args, let offset):
            if let name = calleeName(callee) {
                if Self.skbPushFns.contains(name), args.count >= 2,
                   let key = skbKey(args[0]), let n = skbIntLiteral(args[1]) {
                    skbCheckPush(key: key, pushed: n, offset: offset, fnName: fnName,
                                 reachable: reachable, state: &state, findings: &findings)
                } else if name == "skb_reserve", args.count >= 2,
                          let key = skbKey(args[0]), let n = skbIntLiteral(args[1]) {
                    // headroom_after = headroom_before + n (n bytes pulled in
                    // from the head); unknown provenance still guarantees >= n.
                    state[key] = (state[key] ?? 0) + n
                } else if Self.skbPullFns.contains(name), args.count >= 2,
                          let key = skbKey(args[0]), let n = skbIntLiteral(args[1]),
                          let cur = state[key] {
                    // Pulling data forward grows the headroom by n.
                    state[key] = cur + n
                }
            }
            for a in args {
                skbScanExpr(a, state: &state, fnName: fnName, reachable: reachable, findings: &findings)
            }
        case .assign(_, let l, let r, _):
            skbScanExpr(l, state: &state, fnName: fnName, reachable: reachable, findings: &findings)
            skbScanExpr(r, state: &state, fnName: fnName, reachable: reachable, findings: &findings)
        case .binary(_, let l, let r, _), .comma(let l, let r, _):
            skbScanExpr(l, state: &state, fnName: fnName, reachable: reachable, findings: &findings)
            skbScanExpr(r, state: &state, fnName: fnName, reachable: reachable, findings: &findings)
        case .unary(_, let o, _), .cast(let o, _), .paren(let o, _):
            skbScanExpr(o, state: &state, fnName: fnName, reachable: reachable, findings: &findings)
        case .ternary(let c, let t, let f, _):
            skbScanExpr(c, state: &state, fnName: fnName, reachable: reachable, findings: &findings)
            skbScanExpr(t, state: &state, fnName: fnName, reachable: reachable, findings: &findings)
            skbScanExpr(f, state: &state, fnName: fnName, reachable: reachable, findings: &findings)
        case .member(let b, _, _, _):
            skbScanExpr(b, state: &state, fnName: fnName, reachable: reachable, findings: &findings)
        case .index(let b, let i, _):
            skbScanExpr(b, state: &state, fnName: fnName, reachable: reachable, findings: &findings)
            skbScanExpr(i, state: &state, fnName: fnName, reachable: reachable, findings: &findings)
        case .arrayInit(let els, _):
            for el in els {
                skbScanExpr(el, state: &state, fnName: fnName, reachable: reachable, findings: &findings)
            }
        case .newExpr(_, let args, _):
            for a in args {
                skbScanExpr(a, state: &state, fnName: fnName, reachable: reachable, findings: &findings)
            }
        case .sizeOf, .lambda, .integerLiteral, .floatLiteral, .stringLiteral, .charLiteral, .booleanLiteral, .identifier:
            break
        }
    }

    /// Checks one `skb_push(key, n)` against the provable headroom and records
    /// the headroom it consumes.
    private func skbCheckPush(key: String, pushed: Int, offset: Int, fnName: String,
                              reachable: Bool, state: inout [String: Int],
                              findings: inout [KernelAstFinding]) {
        if let reserved = state[key] {
            state[key] = max(0, reserved - pushed)
            guard pushed > reserved else { return }
            findings.append(KernelAstFinding(
                function: fnName, offset: offset,
                category: "Kernel OOB Write",
                severity: .high,
                message: "skb_push writes \(pushed) byte\(pushed == 1 ? "" : "s") before skb->data but only \(reserved) byte\(reserved == 1 ? "" : "s") of headroom are provably reserved here (allocation/reserve history) — the data pointer moves out of bounds before the buffer.",
                taintPath: nil, reachable: reachable))
        } else {
            // Provenance outside this function (a parameter, a queue dequeue,
            // an opaque call). The Bluetooth core guarantees BT_SKB_RESERVE
            // (8) bytes for frames it hands to transports; a push larger than
            // that cannot be justified by the core invariant alone.
            guard pushed > 8 else { return }
            findings.append(KernelAstFinding(
                function: fnName, offset: offset,
                category: "Kernel OOB Write Risk",
                severity: .low,
                message: "skb_push consumes \(pushed) bytes of headroom on an skb whose provenance is outside this function; the Bluetooth core only reserves BT_SKB_RESERVE (8) bytes for transport frames — verify the producer reserves at least \(pushed) bytes.",
                taintPath: nil, reachable: reachable))
        }
    }

    /// Applies the headroom effects of a top-level assignment statement.
    private func skbApplyExprState(_ e: CExpr, state: inout [String: Int]) {
        if case .assign(let op, let lhs, let rhs, _) = e, op == "=",
           let name = simpleIdentifier(lhs) {
            skbUpdateVar(name, rhs: rhs, state: &state)
        }
    }

    /// Sets a variable's provenance from its initializer/RHS.
    private func skbUpdateVar(_ name: String, rhs: CExpr, state: inout [String: Int]) {
        switch rhs {
        case .call(let callee, let args, _):
            guard let name0 = calleeName(callee) else { state.removeValue(forKey: name); return }
            if let reserve = Self.skbAllocReserve[name0] {
                state[name] = reserve
            } else if name0 == "skb_realloc_headroom", args.count >= 2,
                      let base = skbKey(args[0]), let grown = skbIntLiteral(args[1]) {
                state[name] = max(state[base] ?? 0, grown)
            } else if Self.skbInheritFns.contains(name0), args.count >= 1,
                      let base = skbKey(args[0]) {
                if name0 == "skb_copy_expand" {
                    // Guarantees exactly the requested new headroom.
                    if args.count >= 2, let headroom = skbIntLiteral(args[1]) {
                        state[name] = headroom
                    } else {
                        state.removeValue(forKey: name)
                    }
                } else if let v = state[base] {
                    state[name] = v
                } else {
                    state.removeValue(forKey: name)
                }
            } else if Self.skbPushFns.contains(name0), args.count >= 2,
                      let base = skbKey(args[0]) {
                // `skb2 = skb_push(skb1, n)` aliases skb1's buffer *after* the
                // push consumed headroom (already applied by the scan).
                if let left = state[base] { state[name] = left }
                else { state.removeValue(forKey: name) }
            } else {
                state.removeValue(forKey: name)
            }
        case .identifier(let other, _):
            if let v = state[other] { state[name] = v }
            else { state.removeValue(forKey: name) }
        case .paren(let x, _), .cast(let x, _):
            skbUpdateVar(name, rhs: x, state: &state)
        default:
            state.removeValue(forKey: name)
        }
    }

    /// Resolves the tracked skb identity of an expression (plain variable or
    /// a member path such as `dev->skb`).
    private func skbKey(_ e: CExpr) -> String? {
        switch e {
        case .identifier(let n, _):
            return n
        case .paren(let x, _), .cast(let x, _):
            return skbKey(x)
        case .member(let base, let m, _, _):
            return skbKey(base).map { $0 + "->" + m }
        default:
            return nil
        }
    }

    /// Literal integer value of a size expression (decimal/hex literals with
    /// optional u/l suffixes, parentheses, and literal sums).
    private func skbIntLiteral(_ e: CExpr) -> Int? {
        switch e {
        case .integerLiteral(let text, _):
            var t = text.lowercased()
            while t.last == "u" || t.last == "l" { t.removeLast() }
            if t.hasPrefix("0x"), let v = Int(t.dropFirst(2), radix: 16) { return v }
            return Int(t)
        case .paren(let x, _):
            return skbIntLiteral(x)
        case .binary(let op, let l, let r, _) where op == "+":
            if let a = skbIntLiteral(l), let b = skbIntLiteral(r) { return a + b }
            return nil
        default:
            return nil
        }
    }

    // MARK: - Call graph / expression helpers

    private func calleeName(_ callee: CExpr) -> String? {
        switch callee {
        case .identifier(let n, _): return n
        case .member(_, let m, _, _): return m
        case .call(let inner, _, _): return calleeName(inner)
        default: return nil
        }
    }

    /// The variable written by `&var`, `(&var)` or `(char *)&var` style arguments.
    private func simpleIdentifier(_ e: CExpr) -> String? {
        switch e {
        case .identifier(let n, _): return n
        case .paren(let x, _), .cast(let x, _): return simpleIdentifier(x)
        case .unary(let op, let x, _): return op == "&" ? simpleIdentifier(x) : nil
        default: return nil
        }
    }

    private func callees(in body: CStmt) -> Set<String> {
        var set = Set<String>()
        collectCallees(body, into: &set)
        return set
    }

    private func collectCallees(_ stmt: CStmt, into set: inout Set<String>) {
        switch stmt {
        case .block(let arr):
            for s in arr { collectCallees(s, into: &set) }
        case .expr(let e):
            collectExprCallees(e, into: &set)
        case .declaration(let d):
            if case .variable(_, _, let initExpr?) = d.kind {
                collectExprCallees(initExpr, into: &set)
            }
        case .ifStmt(_, let t, let e, _):
            collectCallees(t, into: &set)
            if let e = e { collectCallees(e, into: &set) }
        case .whileStmt(_, let b, _), .doWhileStmt(let b, _, _):
            collectCallees(b, into: &set)
        case .forStmt(_, _, _, let b, _):
            collectCallees(b, into: &set)
        case .switchStmt(_, let cases, _):
            for c in cases {
                for s in c.body { collectCallees(s, into: &set) }
            }
        case .labeledStmt(_, let s, _):
            collectCallees(s, into: &set)
        default:
            break
        }
    }

    private func collectExprCallees(_ e: CExpr, into set: inout Set<String>) {
        switch e {
        case .call(let callee, let args, _):
            if let name = calleeName(callee), defined.contains(name) { set.insert(name) }
            for a in args { collectExprCallees(a, into: &set) }
        case .assign(_, _, let rhs, _):
            collectExprCallees(rhs, into: &set)
        case .unary(_, let o, _), .cast(let o, _), .paren(let o, _):
            collectExprCallees(o, into: &set)
        case .binary(_, let l, let r, _), .comma(let l, let r, _):
            collectExprCallees(l, into: &set)
            collectExprCallees(r, into: &set)
        case .ternary(let c, let t, let f, _):
            collectExprCallees(c, into: &set)
            collectExprCallees(t, into: &set)
            collectExprCallees(f, into: &set)
        case .member(let b, _, _, _):
            collectExprCallees(b, into: &set)
        case .index(let b, let i, _):
            collectExprCallees(b, into: &set)
            collectExprCallees(i, into: &set)
        case .arrayInit(let arr, _):
            for a in arr { collectExprCallees(a, into: &set) }
        case .newExpr(_, let args, _):
            for a in args { collectExprCallees(a, into: &set) }
        default:
            break
        }
    }
}
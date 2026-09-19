// by cipher.org.uk
import Foundation

/// Per-file analysis result from the pre-scan phase.
struct FileAnalysis {
    let url: URL
    let taintReturning: Set<String>
    let writeThroughParam: [String: Set<Int>]
    let astFns: [String: CFunctionDef]
    let callees: [String: [String]]
    let phpSanitizers: Set<String>
    /// Per-file parameter-taint seeds: which parameters of each function are
    /// tainted at some call site in this file (cross-file parameter provenance).
    let paramTaintSeeds: [String: Set<Int>]
}

/// Project-wide cross-file analysis index. Built by scanning all source files
/// in the project and computing a transitive taint-returning fixpoint across
/// file boundaries. This lets the per-file scanner detect taint flows that
/// cross import/require/include boundaries.
struct ProjectIndex {
    let fileAnalyses: [URL: FileAnalysis]
    let globalTaintReturning: Set<String>
    let globalWriteThroughParam: [String: Set<Int>]
    let globalAstFns: [String: CFunctionDef]
    let globalPHPSanitizers: Set<String>
    /// Python functions that return an SSRF-safe URL after enforcing a scheme
    /// and host allowlist.  These are computed project-wide so a request handler
    /// can safely consume a validator defined in another module.
    let globalPythonSSRFValidators: Set<String>
    /// Project-wide object-like string macros (`#define LOG_FMT "%s: id=%u"`),
    /// resolved from every C-family file so a format argument that names a
    /// macro constant is treated as the literal format string it expands to.
    let globalStringMacros: [String: String]
    /// Cross-file *rejecting* functions, classified by the shape of their body:
    /// `"id"`  = character-whitelist validator returning a constant nonzero only
    ///           for accepted input (guards Command/SQL/Path) — e.g. a
    ///           `char* -> int` predicate that `return 0;`s on any non-([A-Za-z0-9_])
    ///           byte and `return 1;` otherwise;
    /// `"path"` = pointer-returning path sanitizer that `return NULL;` on inputs
    ///            containing traversal markers (`..`, `/`, `\`) and otherwise
    ///            builds a path under a fixed base — e.g. a `safe_join`.
    /// Consumers (the heuristic whitelist-guard pass and the AST guarded-var
    /// walk) treat `if (!F(x)) return;` / `if (!p) return;` as sanitization.
    let globalSanitizers: [String: String]
    /// Project-wide *parameter-taint* table: functions whose parameters
    /// are tainted at some call site, keyed by function name with the
    /// set of tainted parameter indices. Populated by per-language
    /// analyzers (JAnalyzer, JSAnalyzer) and merged across files.
    let globalParamTaintSeeds: [String: Set<Int>]
    /// Names of string constants declared at namespace/global scope in any
    /// project file (`inline constexpr const char* K = "..."`,
    /// `const char K[] = "..."`, `const std::string K = "..."`). A format
    /// argument naming one is a compile-time constant format string.
    let globalConstantFormats: Set<String>
    /// The short names (last `::` component) of every user-defined function in
    /// the project. A bare-name C-family sink call (e.g. `open(id)`) whose name
    /// the project itself defines resolves to the user function, not the C
    /// library sink of the same name — unqualified name lookup prefers the
    /// user declaration.
    let globalDefinedFunctions: Set<String>

    /// All source APIs across all languages, used for the cross-file
    /// taint-returning fixpoint.
    private static let allSourceAPIs: Set<String> = AstCSourceAPIs.cSourceAPIs
        .union(javaSourceAPIs)
        .union(csharpSourceAPIs)
        .union(goSourceAPIs)
        .union(kotlinSourceAPIs)
        .union(pythonSourceAPIs)
        .union(rubySourceAPIs)
        .union(rustSourceAPIs)
        .union(phpSourceAPIs)
        .union(soliditySourceAPIs)
        .union(jsSourceAPIs)
        .union(swiftSourceAPIs)

    /// Build the project index by pre-scanning all source files, running
    /// per-language analyzers, and computing a cross-file taint-returning
    /// fixpoint. When a load-time `ProjectSourceIndex` is available it is
    /// reused for the file list and the file reads (no re-walk, no re-read);
    /// the per-language analysis itself still runs here.
    static func build(projectRoot: URL, sourceIndex: ProjectSourceIndex? = nil) -> ProjectIndex {
        let files = enumerateSourceFiles(in: projectRoot)
        let readSource = sourceReader(from: sourceIndex)
        var analyses: [URL: FileAnalysis] = [:]

        for url in files {
            guard let source = readSource(url),
                  source.count <= 1_000_000 else { continue }
            if let fa = analyzeForIndex(url: url, source: source) {
                analyses[url] = fa
            }
        }

        let globalTaint = computeGlobalTaintReturning(analyses: analyses)
        let globalWT = mergeWriteThrough(analyses: analyses)
        let globalAST = mergeASTFunctions(analyses: analyses)
        let globalPHP = Set(analyses.values.flatMap { $0.phpSanitizers })
        let globalPythonSSRFValidators = computePythonSSRFValidators(files: files, readSource: readSource)
        let globalMacros = extractStringMacros(files: files, readSource: readSource)
        let globalSanitizers = classifySanitizers(astFns: globalAST)
        let globalConstantFormats = extractGlobalStringConstants(files: files, readSource: readSource)
        let globalDefinedFunctions = projectFunctionNames(astFns: globalAST, files: files, readSource: readSource)
        let globalParamSeeds = mergeParamTaintSeeds(analyses: analyses)

        return ProjectIndex(fileAnalyses: analyses,
                            globalTaintReturning: globalTaint,
                            globalWriteThroughParam: globalWT,
                            globalAstFns: globalAST,
                            globalPHPSanitizers: globalPHP,
                            globalPythonSSRFValidators: globalPythonSSRFValidators,
                            globalStringMacros: globalMacros,
                            globalSanitizers: globalSanitizers,
                            globalParamTaintSeeds: globalParamSeeds,
                            globalConstantFormats: globalConstantFormats,
                            globalDefinedFunctions: globalDefinedFunctions)
    }

    /// Finds Python URL validators that parse a URL and enforce a fixed host
    /// policy, then closes over simple wrappers around those validators.  This
    /// is intentionally narrow: merely naming a function `validate_url` does
    /// not make its result safe; its body must inspect a parsed host and refer
    /// to an allowlist-style constant.
    private static func computePythonSSRFValidators(files: [URL], readSource: (URL) -> String?) -> Set<String> {
        var bodies: [String: String] = [:]
        for url in files where isPythonFile(url) {
            guard let source = readSource(url),
                  source.count <= 1_000_000 else { continue }
            for method in ScriptMethodParser(language: .python, source: source).parseMethods() {
                let range = method.bodyRange
                guard range.location != NSNotFound,
                      range.location + range.length <= (source as NSString).length else { continue }
                bodies[method.name] = (source as NSString).substring(with: range)
            }
        }

        var validators = Set<String>()
        for (name, body) in bodies {
            let parsesURL = body.contains("urlparse(") || body.contains("urlsplit(")
            let checksHost = body.contains(".hostname") || body.contains(".netloc")
            let hasAllowlist = body.contains("ALLOWED_HOST") || body.contains("TRUSTED_HOST")
            if parsesURL && checksHost && hasAllowlist {
                validators.insert(name)
            }
        }

        // A service-layer wrapper which returns a known validator's result is
        // just as safe as the validator itself.  Iterate to support more than
        // one wrapper hop without treating arbitrary transforms as sanitizers.
        var changed = true
        while changed {
            changed = false
            for (name, body) in bodies where !validators.contains(name) {
                if validators.contains(where: { body.contains("return \($0)(") }) {
                    validators.insert(name)
                    changed = true
                }
            }
        }
        return validators
    }

    /// Resolves object-like `#define NAME "literal"` macro definitions in every
    /// C-family file. These are compile-time string constants shared across
    /// translation units (the preprocessor expands them before the compiler
    /// sees the source), so a format argument naming one is a constant format
    /// string. #define lines are skipped by the C tokenizer, so they are parsed
    /// directly here. Backslash-continued lines are joined into a single body
    /// before matching.
    private static func extractStringMacros(files: [URL], readSource: (URL) -> String?) -> [String: String] {
        var macros: [String: String] = [:]
        let isCFamily: Set<String> = ["c", "h", "cpp", "cc", "cxx", "hpp", "m", "mm"]
        guard let macroRe = try? NSRegularExpression(
            pattern: #"#define\s+([A-Za-z_][A-Za-z0-9_]*)\s*((?:"(?:[^"\\\n]|\\.)*")|'[^'\n]*')"#) else {
            return macros
        }
        for url in files where isCFamily.contains(url.pathExtension.lowercased()) {
            guard let source = readSource(url),
                  source.count <= 1_000_000 else { continue }
            let lines = source.split(separator: "\n", omittingEmptySubsequences: false)
            var i = 0
            while i < lines.count {
                let trimmed = String(lines[i]).trimmingCharacters(in: .whitespaces)
                if trimmed.hasPrefix("#define"), !trimmed.hasPrefix("#define(") {
                    var body = String(lines[i])
                    while body.hasSuffix("\\"), i + 1 < lines.count {
                        i += 1
                        body = String(body.dropLast()) + String(lines[i])
                    }
                    if let m = macroRe.firstMatch(in: body,
                                                  range: NSRange(body.startIndex..., in: body)),
                       m.numberOfRanges >= 3,
                       let nameR = Range(m.range(at: 1), in: body),
                       let valR = Range(m.range(at: 2), in: body) {
                        macros[String(body[nameR])] = String(body[valR])
                    }
                }
                i += 1
            }
        }
        return macros
    }

    // MARK: - Global string constants

    /// Collects namespace/global-scope string constants in every C-family file:
    /// `inline constexpr const char* K = "..."`, `const char K[] = "..."`,
    /// `static constexpr char K[] = "..."`, `const std::string K = "..."`.
    /// A format argument (snprintf/printf/…) that names one is a constant
    /// format string — the value never changes, so it cannot be turned into a
    /// non-constant format. Function-body declarations are excluded (a local
    /// `const char*` pointer may be re-pointed at data later).
    private static func extractGlobalStringConstants(files: [URL], readSource: (URL) -> String?) -> Set<String> {
        var names = Set<String>()
        let isCFamily: Set<String> = ["c", "h", "cpp", "cc", "cxx", "hpp", "m", "mm"]
        let qualifiers: Set<String> = ["const", "constexpr", "static", "inline", "extern", "volatile"]
        let typeWords: Set<String> = ["char", "string", "string_view", "wstring",
                                      "u8string", "u16string", "u32string", "basic_string"]
        for url in files where isCFamily.contains(url.pathExtension.lowercased()) {
            guard let source = readSource(url),
                  source.count <= 1_000_000 else { continue }
            let tokens = CTokenizer(source: source).tokenize()
            let count = tokens.count
            if count == 0 { continue }

            // Function-body open-brace indices: a `{` whose nearest preceding
            // significant token at depth 0 is `)` opens a function definition
            // (namespace/class bodies are preceded by an identifier).
            var fnBodyOpens = Set<Int>()
            var depth = 0
            for (idx, tok) in tokens.enumerated() {
                if tok.text == "{" {
                    if depth == 0 {
                        var j = idx - 1
                        while j >= 0 {
                            let tprev = tokens[j].text
                            if tprev == ")" { fnBodyOpens.insert(idx); break }
                            if tprev == "{" || tprev == "}" || tprev == ";" { break }
                            j -= 1
                        }
                    } else {
                        depth += 1
                    }
                } else if tok.text == "}" {
                    if depth > 0 { depth -= 1 }
                }
            }
            let bodyEnds = bodyEndRanges(in: tokens, opens: fnBodyOpens)

            // Match namespace-scope constant declarations outside fn bodies.
            var i = 0
            while i < count - 1 {
                if let end = bodyEnds[i] { i = end + 1; continue }
                let t = tokens[i]
                // Qualifier words (`inline`, `const`, `static`, …) tokenize as
                // keywords, not identifiers — accept both kinds.
                if (t.kind == CAstToken.Kind.identifier || t.kind == CAstToken.Kind.keyword),
                   qualifiers.contains(t.text) {
                    // Possible constant declaration start. Walk the declaration
                    // tokens until `=`/`;`/`{`; a `(` before the name means this
                    // is a function returning a const type, not a constant.
                    var j = i
                    var sawType = false
                    var name: String? = nil
                    while j < count {
                        let text = tokens[j].text
                        if text == ";" || text == "{" { break }
                        if text == "=" {
                            if let nm = name, sawType {
                                let vKind = tokens[j + 1].kind
                                let vText = tokens[j + 1].text
                                let isLiteral = vKind == CAstToken.Kind.string
                                    || (vKind == CAstToken.Kind.identifier && ["u8", "U", "L", "u"].contains(vText)
                                        && j + 2 < count && tokens[j + 2].kind == CAstToken.Kind.string)
                                if isLiteral { names.insert(nm) }
                            }
                            break
                        }
                        if text == "(" && name == nil { break }
                        if tokens[j].kind == CAstToken.Kind.keyword {
                            if qualifiers.contains(text) { j += 1; continue }
                            if typeWords.contains(text) { sawType = true; j += 1; continue }
                            j += 1
                            continue
                        }
                        if tokens[j].kind == CAstToken.Kind.identifier {
                            if qualifiers.contains(text) { j += 1; continue }
                            if text == "::" { j += 1; continue }
                            if typeWords.contains(text) { sawType = true; j += 1; continue }
                            if name == nil {
                                if j + 1 < count, tokens[j + 1].text == "(" { break }
                                name = text
                            }
                            j += 1
                            continue
                        }
                        j += 1
                    }
                    i = j
                    continue
                }
                i += 1
            }
        }
        return names
    }

    /// Maps each function-body `{` (from `opens`) to the index of its matching
    /// `}`, so namespace-scope scans can skip the whole body.
    private static func bodyEndRanges(in tokens: [CAstToken], opens: Set<Int>) -> [Int: Int] {
        var ends: [Int: Int] = [:]
        var stack: [Int] = []
        for (idx, t) in tokens.enumerated() {
            if t.text == "{" { stack.append(idx) }
            else if t.text == "}" {
                if let po = stack.popLast(), opens.contains(po) { ends[po] = idx }
            }
        }
        return ends
    }

    /// Short, unqualified names of every user-defined function in the project
    /// (last `::` component). Used to resolve bare-name call sites against user
    /// declarations rather than C library sinks of the same name. The AST
    /// frontend can miss bodies whose return type is a template (`std::unique_ptr<
    /// T> open(...)` parses as a member access), so the scanner's own lenient
    /// CFunctionParser is consulted for every C-family file as well.
    private static func projectFunctionNames(astFns: [String: CFunctionDef], files: [URL], readSource: (URL) -> String?) -> Set<String> {
        var names = definedFunctionNames(astFns: astFns)
        let isCFamily: Set<String> = ["c", "h", "cpp", "cc", "cxx", "hpp", "m", "mm"]
        for url in files where isCFamily.contains(url.pathExtension.lowercased()) {
            guard let source = readSource(url),
                  source.count <= 1_000_000 else { continue }
            for def in CCFunctionParser(source: source).parseDefinitions() {
                guard !def.name.isEmpty else { continue }
                let parts = def.name.split(separator: ":").map(String.init)
                if let last = parts.last, !last.isEmpty {
                    names.insert(last)
                    names.insert(def.name)
                } else {
                    names.insert(def.name)
                }
            }
        }
        return names
    }

    /// Short, unqualified names of every user-defined function in the project
    /// (last `::` component). Used to resolve bare-name call sites against user
    /// declarations rather than C library sinks of the same name.
    private static func definedFunctionNames(astFns: [String: CFunctionDef]) -> Set<String> {
        var names = Set<String>()
        for key in astFns.keys {
            let parts = key.split(separator: ":").map(String.init)
            if let last = parts.last, !last.isEmpty { names.insert(last) }
            else if !key.isEmpty { names.insert(key) }
        }
        return names
    }

    // MARK: - Sanitizer classification

    /// Classifies cross-file *rejecting* functions from their parsed bodies.
    /// Only C/C++/ObjC shapes are considered (a `char*` parameter is required),
    /// so Java/C#/script function ASTs can never be mistaken for a validator.
    private static func classifySanitizers(astFns: [String: CFunctionDef]) -> [String: String] {
        var out: [String: String] = [:]
        for (name, fn) in astFns {
            if let kind = classifySanitizer(fn: fn) {
                out[name] = kind
                // Also register the unqualified short name so call sites that
                // reference the validator with or without its namespace prefix
                // both resolve (the C++ parser keys C++ functions either way).
                if let short = name.split(separator: ":").last.map(String.init),
                   !short.isEmpty, short != name {
                    out[short] = kind
                }
            }
        }
        return out
    }

    private static func classifySanitizer(fn: CFunctionDef) -> String? {
        let params = fn.params.compactMap { $0.name }
        let returnType = fn.returnType ?? ""
        // Java shape: String/File/Path return types with String params.
        // These are nullable-return validators: they reject invalid input by
        // returning `null` and accept by returning a non-null value.
        let isJavaStringReturn = returnType.contains("String")
        let isJavaPathReturn = returnType.contains("File") || returnType.contains("Path")
        let hasStringParam = params.contains(where: { p in
            if let pt = fn.params.first(where: { $0.name == p })?.type {
                return pt.contains("String")
            }
            return false
        })

        if isJavaStringReturn || isJavaPathReturn {
            guard hasStringParam else { return nil }
            let parameterNames = Set(params)
            let derived = paramDerivedIdentifiers(fn.body, seeds: parameterNames)

            var inputRejects = 0
            var hasNonNullReturn = false
            var hasContainmentCheck = false

            func walk(_ stmt: CStmt) {
                switch stmt {
                case .block(let arr):
                    for s in arr { walk(s) }
                case .ifStmt(let cond, let thenBranch, let elseBranch, _):
                    if isConstantZeroExit(thenBranch), condReferences(cond, names: derived) {
                        inputRejects += 1
                    }
                    if let eb = elseBranch, isConstantZeroExit(eb), condReferences(cond, names: derived) {
                        inputRejects += 1
                    }
                    if condHasContainmentCheck(cond) { hasContainmentCheck = true }
                    walk(thenBranch)
                    if let eb = elseBranch { walk(eb) }
                case .whileStmt(_, let b, _), .doWhileStmt(let b, _, _):
                    walk(b)
                case .forStmt(_, _, _, let b, _):
                    walk(b)
                case .switchStmt(_, let cases, _):
                    for c in cases { for s in c.body { walk(s) } }
                case .labeledStmt(_, let s, _):
                    walk(s)
                case .returnStmt(let e, _):
                    if let e = e, !isZeroValue(e) {
                        hasNonNullReturn = true
                    }
                default:
                    break
                }
            }
            walk(fn.body)

            if isJavaStringReturn, inputRejects > 0, hasNonNullReturn {
                return "id"
            }
            if isJavaPathReturn, inputRejects > 0, hasContainmentCheck, hasNonNullReturn {
                return "path"
            }
            return nil
        }

        // C/C++ shape only: at least one parameter whose type is a `char*`
        // (C) or a `std::string` / `std::string_view` (C++) reference/value,
        // plus an int/bool (validator) or pointer (path sanitizer) return.
        guard params.contains(where: { p in
            if let pt = fn.params.first(where: { $0.name == p })?.type {
                return pt.contains("char") || pt.contains("string_view")
                    || pt.contains("basic_string") || pt.contains("wstring")
            }
            return false
        }) else { return nil }
        let parameterNames = Set(params)
        let derived = paramDerivedIdentifiers(fn.body, seeds: parameterNames)

        let isPointerReturn = returnType.contains("*")
        let isIntReturn = returnType == "int" || returnType == "bool"
            || returnType == "long" || returnType == "short"
            || returnType == "signed" || returnType == "unsigned"
            || returnType.contains("int") || returnType.contains("bool")

        var inputRejects = 0          // conditional `return 0/NULL` checking the input
        var traversalMarkerRejects = 0 // reject conditions carrying `..` `/` `\`
        var hasLiteralNonzeroReturn = false  // top-level final `return 1;/true`
        var hasPointerReturn = false         // a non-NULL pointer return path exists

        func walk(_ stmt: CStmt) {
            switch stmt {
            case .block(let arr):
                for s in arr { walk(s) }
            case .ifStmt(let cond, let thenBranch, let elseBranch, _):
                if isConstantZeroExit(thenBranch), condReferences(cond, names: derived) {
                    inputRejects += 1
                    if condHasTraversalMarker(cond) { traversalMarkerRejects += 1 }
                }
                if let eb = elseBranch, isConstantZeroExit(eb), condReferences(cond, names: derived) {
                    inputRejects += 1
                    if condHasTraversalMarker(cond) { traversalMarkerRejects += 1 }
                }
                walk(thenBranch)
                if let eb = elseBranch { walk(eb) }
            case .whileStmt(_, let b, _), .doWhileStmt(let b, _, _):
                walk(b)
            case .forStmt(_, _, _, let b, _):
                walk(b)
            case .switchStmt(_, let cases, _):
                for c in cases { for s in c.body { walk(s) } }
            case .labeledStmt(_, let s, _):
                walk(s)
            case .returnStmt(let e, _):
                if let e = e {
                    if isZeroValue(e) {} else if isLiteral(e) {
                        hasLiteralNonzeroReturn = true
                    } else if isPointerReturn {
                        hasPointerReturn = true
                    }
                }
            default:
                break
            }
        }
        walk(fn.body)

        if isIntReturn, inputRejects > 0, hasLiteralNonzeroReturn {
            return "id"
        }
        if isPointerReturn, inputRejects > 0, traversalMarkerRejects > 0, hasPointerReturn {
            return "path"
        }
        return nil
    }

    /// The parameter seeds plus every local assigned/mutated from them
    /// (`c = (unsigned char)*p`, `bl = strlen(base)`) — reject conditions may
    /// inspect the input indirectly through such locals.
    private static func paramDerivedIdentifiers(_ body: CStmt, seeds: Set<String>) -> Set<String> {
        var derived = seeds
        var changed = true
        while changed {
            changed = false
            func walkExpr(_ e: CExpr) {
                switch e {
                case .assign(_, let l, let r, _):
                    if let n = simpleIdentifier(l), !derived.contains(n),
                       references(r, names: derived) {
                        derived.insert(n)
                        changed = true
                    }
                default:
                    break
                }
            }
            func walk(_ stmt: CStmt) {
                switch stmt {
                case .block(let arr):
                    for s in arr { walk(s) }
                case .declaration(let d):
                    if case .variable(_, let name, let initExpr?) = d.kind,
                       !derived.contains(name), references(initExpr, names: derived) {
                        derived.insert(name)
                        changed = true
                    }
                case .expr(let e):
                    walkExpr(e)
                case .ifStmt(_, let t, let eb, _):
                    walk(t)
                    if let e = eb { walk(e) }
                case .whileStmt(_, let b, _), .doWhileStmt(let b, _, _):
                    walk(b)
                case .forStmt(_, _, _, let b, _):
                    walk(b)
                case .switchStmt(_, let cases, _):
                    for c in cases { for s in c.body { walk(s) } }
                case .labeledStmt(_, let s, _):
                    walk(s)
                default:
                    break
                }
            }
            walk(body)
        }
        return derived
    }

    private static func simpleIdentifier(_ e: CExpr) -> String? {
        switch e {
        case .identifier(let n, _): return n
        case .paren(let x, _), .cast(let x, _): return simpleIdentifier(x)
        default: return nil
        }
    }

    private static func references(_ e: CExpr, names: Set<String>) -> Bool {
        var hit = false
        func walk(_ x: CExpr) {
            switch x {
            case .identifier(let n, _):
                if names.contains(n) { hit = true }
            case .binary(_, let l, let r, _), .comma(let l, let r, _):
                walk(l); walk(r)
            case .unary(_, let o, _), .cast(let o, _), .paren(let o, _):
                walk(o)
            case .assign(_, let l, let r, _):
                walk(l); walk(r)
            case .call(let c, let a, _):
                walk(c); for ar in a { walk(ar) }
            case .member(let b, _, _, _):
                walk(b)
            case .index(let b, let i, _):
                walk(b); walk(i)
            case .ternary(let c, let t, let f, _):
                walk(c); walk(t); walk(f)
            case .arrayInit(let arr, _):
                for a in arr { walk(a) }
            case .newExpr(_, let a, _):
                for ar in a { walk(ar) }
            case .sizeOf(let o, _, _):
                if let o = o { walk(o) }
            default:
                break
            }
        }
        walk(e)
        return hit
    }

    private static func condReferences(_ cond: CExpr, names: Set<String>) -> Bool {
        references(cond, names: names)
    }

    /// True when a statement is an unconditional `return` of a falsy constant
    /// (`0`, `false`, `NULL`, `-1`), possibly wrapped in a block.
    private static func isConstantZeroExit(_ stmt: CStmt) -> Bool {
        switch stmt {
        case .block(let arr):
            if let e = arr.last { return isConstantZeroExit(e) }
            return false
        case .returnStmt(let e, _):
            guard let e = e else { return true }
            return isZeroValue(e)
        default:
            return false
        }
    }

    private static func isZeroValue(_ e: CExpr) -> Bool {
        switch e {
        case .integerLiteral(let v, _):
            if let big = Int(v.trimmingCharacters(in: .whitespaces)) { return big == 0 }
            return v.contains("0")
        case .booleanLiteral(let b, _):
            return !b
        case .identifier(let n, _):
            return n == "NULL" || n == "nullptr" || n == "false" || n == "null"
        case .unary(let op, let o, _):
            if op == "-", isZeroValue(o) { return true }
            if op == "(" { return isZeroValue(o) }
            return false
        case .paren(let x, _), .cast(let x, _):
            return isZeroValue(x)
        default:
            return false
        }
    }

    /// A non-zero literal (`1`, `true`, `'x'` constant char) — the validator's
    /// unconditional accept outcome.
    private static func isLiteral(_ e: CExpr) -> Bool {
        switch e {
        case .integerLiteral(let v, _):
            return Int(v.trimmingCharacters(in: .whitespaces)).map { $0 != 0 } ?? false
        case .booleanLiteral(let b, _):
            return b
        case .charLiteral(let v, _):
            return numericValueOfCharLiteral(v) != 0
        case .paren(let x, _), .cast(let x, _):
            return isLiteral(x)
        default:
            return false
        }
    }

    private static func numericValueOfCharLiteral(_ v: String) -> Int {
        // 'A' / '\n' / '\x41' — treat any non-empty literal as nonzero except
        // the explicit NUL byte.
        if v == "'\\0'" || v == "'\\x00'" { return 0 }
        return 1
    }

    /// True when a reject condition references path-traversal markers — the
    /// `strstr(x, "..") != NULL`, `strchr(x, '/')`, `strchr(x, '\\')` idiom.
    private static func condHasTraversalMarker(_ cond: CExpr) -> Bool {
        var hit = false
        func walk(_ e: CExpr) {
            switch e {
            case .stringLiteral(let s, _):
                if s.contains("..") || s.contains("/") || s.contains("\\") { hit = true }
            case .charLiteral(let c, _):
                if c.contains("/") || c.contains("\\") { hit = true }
            case .binary(_, let l, let r, _), .comma(let l, let r, _):
                walk(l); walk(r)
            case .unary(_, let o, _), .cast(let o, _), .paren(let o, _):
                walk(o)
            case .call(let c, let a, _):
                walk(c); for ar in a { walk(ar) }
            case .assign(_, let l, let r, _):
                walk(l); walk(r)
            case .member(let b, _, _, _):
                walk(b)
            case .index(let b, let i, _):
                walk(b); walk(i)
            case .ternary(let c, let t, let f, _):
                walk(c); walk(t); walk(f)
            case .sizeOf(let o, _, _):
                if let o = o { walk(o) }
            default:
                break
            }
        }
        walk(cond)
        return hit
    }

    /// True when a condition performs a canonical-path containment check —
    /// the `startsWith(base + separator)` / `equals(base)` idiom used by
    /// path-sanitizer helpers.
    private static func condHasContainmentCheck(_ cond: CExpr) -> Bool {
        var hit = false
        func calleeName(_ e: CExpr) -> String? {
            switch e {
            case .identifier(let n, _): return n
            case .member(_, let m, _, _): return m
            case .call(let inner, _, _): return calleeName(inner)
            default: return nil
            }
        }
        func walk(_ e: CExpr) {
            switch e {
            case .call(let callee, _, _):
                if let m = calleeName(callee), m == "startsWith" || m == "equals" {
                    hit = true
                }
            case .binary(_, let l, let r, _), .comma(let l, let r, _):
                walk(l); walk(r)
            case .unary(_, let o, _), .cast(let o, _), .paren(let o, _):
                walk(o)
            case .member(let b, _, _, _):
                walk(b)
            case .index(let b, let i, _):
                walk(b); walk(i)
            case .ternary(let c, let t, let f, _):
                walk(c); walk(t); walk(f)
            case .sizeOf(let o, _, _):
                if let o = o { walk(o) }
            default:
                break
            }
        }
        walk(cond)
        return hit
    }

    // MARK: - Per-file pre-scan

    private static func analyzeForIndex(url: URL, source: String) -> FileAnalysis? {
        let isC = isCFile(url)
        let isJava = isJavaFile(url)
        let isCSharp = isCSharpFile(url)
        let isKotlin = isKotlinFile(url)
        let isPython = isPythonFile(url)
        let isRuby = isRubyFile(url)
        let isGo = isGoFile(url)
        let isRust = isRustFile(url)
        let isPHP = isPHPFile(url)
        let isSolidity = isSolidityFile(url)
        let isJS = isJSFile(url)
        let isObjC = ["m", "mm", "objc"].contains(url.pathExtension.lowercased())
        let isSwift = url.pathExtension.lowercased() == "swift"

        if isC {
            let cAnalyzer = CAnalyzer(source: source)
            let cAnalysis = cAnalyzer.analyze()
            let symtab = CSymbolTable()
            let tokens = CTokenizer(source: source).tokenize()
            let tu = CParser(tokens: tokens).parseTranslationUnit()
            var calleesMap: [String: [String]] = [:]
            for fn in tu.functions {
                let sum = symtab.analyze(fn)
                calleesMap[fn.name] = sum.flowFacts.compactMap { fact in
                    if case .call(let c, _, _) = fact { return c }
                    return nil
                }
            }
            var taintRet = cAnalysis.taintReturning
            var wt = cAnalysis.writeThroughParam
            var ast = cAnalyzer.astFunctions
            if isObjC {
                let objcAnalyzer = ObjCAnalyzer(source: source)
                let objcAnalysis = objcAnalyzer.analyze()
                taintRet.formUnion(objcAnalysis.taintReturning)
                for (k, v) in objcAnalysis.writeThroughParam { wt[k] = v }
                ast.merge(objcAnalyzer.astFunctions) { $1 }
                for def in objcAnalyzer.methodDefinitions {
                    let lo = def.signatureRange.location
                    let hi = def.bodyRange.location + def.bodyRange.length
                    let bodyTokens = Self.bodyTokens(lo, hi, tokens: tokens)
                    var calls = Set<String>()
                    for (idx, t) in bodyTokens.enumerated() where t.kind == .identifier {
                        guard idx + 1 < bodyTokens.count,
                              bodyTokens[idx + 1].kind == .punct, bodyTokens[idx + 1].text == "(" else { continue }
                        if idx > 0, bodyTokens[idx - 1].kind == .operator, bodyTokens[idx - 1].text == "." { continue }
                        calls.insert(t.text)
                    }
                    calleesMap[def.name, default: []].append(contentsOf: Array(calls))
                }
            }
            return FileAnalysis(url: url, taintReturning: taintRet,
                                writeThroughParam: wt, astFns: ast, callees: calleesMap,
                                phpSanitizers: [],
                                paramTaintSeeds: [:])
        }

        if isJava {
            let methods = JParser(source: source).parseMethods()
            let jAnalyzer = JAnalyzer(source: source, methods: methods)
            let jAnalysis = jAnalyzer.analyze()
            let tokens = CTokenizer(source: source).tokenize()
            let definedNames = Set(methods.map { $0.name })
            var calleesMap: [String: [String]] = [:]
            for m in methods {
                let lo = m.bodyOffset
                let hi = m.bodyRange.location + m.bodyRange.length
                let bodyTokens = Self.bodyTokens(lo, hi, tokens: tokens)
                var calling = Set<String>()
                for (idx, t) in bodyTokens.enumerated() where t.kind == .identifier {
                    guard idx + 1 < bodyTokens.count,
                          bodyTokens[idx + 1].kind == .punct, bodyTokens[idx + 1].text == "(" else { continue }
                    if idx > 0, bodyTokens[idx - 1].kind == .operator, bodyTokens[idx - 1].text == "." { continue }
                    if definedNames.contains(t.text) && t.text != m.name { calling.insert(t.text) }
                }
                calleesMap[m.name] = Array(calling)
            }
            return FileAnalysis(url: url, taintReturning: jAnalysis.taintReturning,
                                     writeThroughParam: jAnalysis.writeThroughParam,
                                     astFns: jAnalyzer.astFunctions, callees: calleesMap,
                                      phpSanitizers: [],
                                      paramTaintSeeds: jAnalysis.paramTaintSeeds)
        }

        if isCSharp {
            let methods = CSharpParser(source: source).parseMethods()
            let csAnalyzer = CSharpAnalyzer(source: source, methods: methods)
            let csAnalysis = csAnalyzer.analyze()
            let tokens = CTokenizer(source: source).tokenize()
            let definedNames = Set(methods.map { $0.name })
            var calleesMap: [String: [String]] = [:]
            for m in methods {
                let lo = m.bodyOffset
                let hi = m.bodyRange.location + m.bodyRange.length
                let bodyTokens = Self.bodyTokens(lo, hi, tokens: tokens)
                var calling = Set<String>()
                for (idx, t) in bodyTokens.enumerated() where t.kind == .identifier {
                    guard idx + 1 < bodyTokens.count,
                          bodyTokens[idx + 1].kind == .punct, bodyTokens[idx + 1].text == "(" else { continue }
                    if idx > 0, bodyTokens[idx - 1].kind == .operator, bodyTokens[idx - 1].text == "." { continue }
                    if definedNames.contains(t.text) && t.text != m.name { calling.insert(t.text) }
                }
                calleesMap[m.name] = Array(calling)
            }
            return FileAnalysis(url: url, taintReturning: csAnalysis.taintReturning,
                                 writeThroughParam: csAnalysis.writeThroughParam,
                                 astFns: csAnalyzer.astFunctions, callees: calleesMap,
                                  phpSanitizers: [],
                                  paramTaintSeeds: csAnalysis.paramTaintSeeds)
        }

        if isKotlin {
            let kMethods = ScriptMethodParser(language: .kotlin, source: source).parseMethods()
            let kAnalyzer = ScriptAnalyzer(source: source, methods: kMethods,
                                           sourceAPIs: kotlinSourceAPIs,
                                           writeThroughSinks: kotlinWriteThroughSinks)
            let kAnalysis = kAnalyzer.analyze()
            let calleesMap = extractScriptCallees(source: source, methods: kMethods)
            return FileAnalysis(url: url, taintReturning: kAnalysis.taintReturning,
                                 writeThroughParam: kAnalysis.writeThroughParam,
                                 astFns: kAnalyzer.astFunctions, callees: calleesMap,
                                  phpSanitizers: [],
                                  paramTaintSeeds: kAnalysis.paramTaintSeeds)
        }

        if isPython {
            let pyMethods = ScriptMethodParser(language: .python, source: source).parseMethods()
            let pyAnalyzer = ScriptAnalyzer(source: source, methods: pyMethods,
                                            sourceAPIs: pythonSourceAPIs,
                                            writeThroughSinks: pythonWriteThroughSinks)
            let pyAnalysis = pyAnalyzer.analyze()
            let calleesMap = extractScriptCallees(source: source, methods: pyMethods)
            return FileAnalysis(url: url, taintReturning: pyAnalysis.taintReturning,
                                 writeThroughParam: pyAnalysis.writeThroughParam,
                                 astFns: pyAnalyzer.astFunctions, callees: calleesMap,
                                  phpSanitizers: [],
                                  paramTaintSeeds: pyAnalysis.paramTaintSeeds)
        }

        if isRuby {
            let rubyMethods = ScriptMethodParser(language: .ruby, source: source).parseMethods()
            let rubyAnalyzer = ScriptAnalyzer(source: source, methods: rubyMethods,
                                              sourceAPIs: rubySourceAPIs,
                                              writeThroughSinks: rubyWriteThroughSinks)
            let rubyAnalysis = rubyAnalyzer.analyze()
            let calleesMap = extractScriptCallees(source: source, methods: rubyMethods)
            return FileAnalysis(url: url, taintReturning: rubyAnalysis.taintReturning,
                                 writeThroughParam: rubyAnalysis.writeThroughParam,
                                 astFns: rubyAnalyzer.astFunctions, callees: calleesMap,
                                  phpSanitizers: [],
                                  paramTaintSeeds: rubyAnalysis.paramTaintSeeds)
        }

        if isGo {
            let goMethods = ScriptMethodParser(language: .go, source: source).parseMethods()
            let goAnalyzer = ScriptAnalyzer(source: source, methods: goMethods,
                                            sourceAPIs: goSourceAPIs,
                                            writeThroughSinks: goWriteThroughSinks)
            let goAnalysis = goAnalyzer.analyze()
            let calleesMap = extractScriptCallees(source: source, methods: goMethods)
            return FileAnalysis(url: url, taintReturning: goAnalysis.taintReturning,
                                 writeThroughParam: goAnalysis.writeThroughParam,
                                 astFns: goAnalyzer.astFunctions, callees: calleesMap,
                                  phpSanitizers: [],
                                  paramTaintSeeds: goAnalysis.paramTaintSeeds)
        }

        if isRust {
            let rustMethods = ScriptMethodParser(language: .rust, source: source).parseMethods()
            let rustAnalyzer = ScriptAnalyzer(source: source, methods: rustMethods,
                                              sourceAPIs: rustSourceAPIs,
                                              writeThroughSinks: rustWriteThroughSinks)
            let rustAnalysis = rustAnalyzer.analyze()
            let calleesMap = extractScriptCallees(source: source, methods: rustMethods)
            return FileAnalysis(url: url, taintReturning: rustAnalysis.taintReturning,
                                 writeThroughParam: rustAnalysis.writeThroughParam,
                                 astFns: rustAnalyzer.astFunctions, callees: calleesMap,
                                  phpSanitizers: [],
                                  paramTaintSeeds: rustAnalysis.paramTaintSeeds)
        }

        if isPHP {
            let phpMethods = ScriptMethodParser(language: .php, source: source).parseMethods()
            let phpAnalyzer = ScriptAnalyzer(source: source, methods: phpMethods,
                                             sourceAPIs: phpSourceAPIs,
                                             writeThroughSinks: phpWriteThroughSinks)
            let phpAnalysis = phpAnalyzer.analyze()
            let calleesMap = extractScriptCallees(source: source, methods: phpMethods)
            let phpSanitizers = computePHPSanitizers(source: source)
            return FileAnalysis(url: url, taintReturning: phpAnalysis.taintReturning,
                                 writeThroughParam: phpAnalysis.writeThroughParam,
                                 astFns: phpAnalyzer.astFunctions, callees: calleesMap,
                                 phpSanitizers: phpSanitizers,
                                 paramTaintSeeds: phpAnalysis.paramTaintSeeds)
        }

        if isSolidity {
            let solMethods = SolidityParser(source: source).parseMethods()
            let solAnalyzer = SolidityAnalyzer(source: source, methods: solMethods)
            let solAnalysis = solAnalyzer.analyze()
            let calleesMap = extractSolidityCallees(source: source, methods: solMethods)
            return FileAnalysis(url: url, taintReturning: solAnalysis.taintReturning,
                                 writeThroughParam: solAnalysis.writeThroughParam,
                                 astFns: solAnalyzer.astFunctions, callees: calleesMap,
                                  phpSanitizers: [],
                                  paramTaintSeeds: solAnalysis.paramTaintSeeds)
        }

        if isJS {
            let jsTokens = JSTokenizer(source: source).tokenize()
            let jsDefs = JSParser(source: source, tokens: jsTokens).parseDefinitions()
            let jsAnalyzer = JSAnalyzer(source: source, defs: jsDefs, tokens: jsTokens,
                                        sourceAPIs: jsSourceAPIs,
                                        writeThroughSinks: jsWriteThroughSinks)
            let jsAnalysis = jsAnalyzer.analyze()
            // Intra-file call edges for the cross-file taint fixpoint: an
            // identifier followed by `(` inside a body that names another
            // defined function in this file.
            let definedNames = Set(jsDefs.map { $0.name })
            var calleesMap: [String: [String]] = [:]
            for d in jsDefs {
                let lo = d.bodyRange.location
                let hi = lo + d.bodyRange.length
                let bodyTokens = jsTokens.filter { $0.offset >= lo && $0.offset < hi && $0.kind != .eof }
                var calls = Set<String>()
                var i = 1
                while i < bodyTokens.count {
                    if bodyTokens[i].text == "(" {
                        let prev = bodyTokens[i - 1]
                        if (prev.kind == .identifier || prev.kind == .keyword),
                           definedNames.contains(prev.text), prev.text != d.name {
                            calls.insert(prev.text)
                        }
                    }
                    i += 1
                }
                calleesMap[d.name] = Array(calls)
            }
            return FileAnalysis(url: url, taintReturning: jsAnalysis.taintReturning,
                                 writeThroughParam: jsAnalysis.writeThroughParam,
                                 astFns: jsAnalyzer.astFunctions, callees: calleesMap,
                                  phpSanitizers: [],
                                  paramTaintSeeds: jsAnalysis.paramTaintSeeds)
        }

        if isSwift {
            let swiftTokens = CTokenizer(source: source).tokenize()
            let swiftDefs = SwiftParser(source: source).parseDefinitions()
            let swiftAnalyzer = SwiftAnalyzer(source: source, defs: swiftDefs, tokens: swiftTokens,
                                              sourceAPIs: swiftSourceAPIs,
                                              writeThroughSinks: swiftWriteThroughSinks)
            let swiftAnalysis = swiftAnalyzer.analyze()
            // Intra-file call edges for the cross-file taint fixpoint: an
            // identifier followed by `(` inside a body that names another
            // defined function in this file.
            let definedNames = Set(swiftDefs.map { $0.name })
            var calleesMap: [String: [String]] = [:]
            for d in swiftDefs {
                let lo = d.bodyRange.location
                let hi = lo + d.bodyRange.length
                let bodyTokens = swiftTokens.filter { $0.offset >= lo && $0.offset < hi && $0.kind != .eof }
                var calls = Set<String>()
                var i = 1
                while i < bodyTokens.count {
                    if bodyTokens[i].text == "(" {
                        let prev = bodyTokens[i - 1]
                        if (prev.kind == .identifier || prev.kind == .keyword),
                           definedNames.contains(prev.text), prev.text != d.name {
                            calls.insert(prev.text)
                        }
                    }
                    i += 1
                }
                calleesMap[d.name] = Array(calls)
            }
return FileAnalysis(url: url, taintReturning: swiftAnalysis.taintReturning,
                                  writeThroughParam: swiftAnalysis.writeThroughParam,
                                  astFns: swiftAnalyzer.astFunctions, callees: calleesMap,
                                  phpSanitizers: [],
                                  paramTaintSeeds: swiftAnalysis.paramTaintSeeds)
        }

        return nil
    }

    // MARK: - Cross-file taint-returning fixpoint

    /// Computes the project-wide transitive taint-returning set using a
    /// fixpoint iteration across all files.
    private static func computeGlobalTaintReturning(analyses: [URL: FileAnalysis]) -> Set<String> {
        var globalReturning = Set<String>()
        for fa in analyses.values {
            globalReturning.formUnion(fa.taintReturning)
        }

        for _ in 0..<10 {
            var changed = false
            for fa in analyses.values {
                for (fnName, fnCallees) in fa.callees {
                    guard !globalReturning.contains(fnName) else { continue }
                    for callee in fnCallees {
                        if globalReturning.contains(callee) || allSourceAPIs.contains(callee) {
                            globalReturning.insert(fnName)
                            changed = true
                            break
                        }
                    }
                }
            }
            if !changed { break }
        }
        return globalReturning
    }

    private static func mergeWriteThrough(analyses: [URL: FileAnalysis]) -> [String: Set<Int>] {
        var merged: [String: Set<Int>] = [:]
        for fa in analyses.values {
            for (fn, idxs) in fa.writeThroughParam {
                merged[fn, default: Set<Int>()].formUnion(idxs)
            }
        }
        return merged
    }

    private static func mergeASTFunctions(analyses: [URL: FileAnalysis]) -> [String: CFunctionDef] {
        var merged: [String: CFunctionDef] = [:]
        for fa in analyses.values {
            merged.merge(fa.astFns) { $1 }
        }
        return merged
    }

    private static func mergeParamTaintSeeds(analyses: [URL: FileAnalysis]) -> [String: Set<Int>] {
        var merged: [String: Set<Int>] = [:]
        for fa in analyses.values {
            for (fn, idxs) in fa.paramTaintSeeds {
                merged[fn, default: Set<Int>()].formUnion(idxs)
            }
        }
        return merged
    }

    // MARK: - Helpers

    private static func enumerateSourceFiles(in root: URL) -> [URL] {
        SourceTree.enumerate(extensions: ProjectSourceIndex.scanExtensions, in: root)
    }

    /// Reuses a load-time `ProjectSourceIndex` for both the file list and the
    /// file reads whenever one is available, so the security pre-scan never
    /// walks the tree or reads a file the shared index already cached. Files
    /// the scanner's extension set covers but the shared index skipped (or
    /// huge files it dropped) fall back to disk.
    static func sourceReader(from index: ProjectSourceIndex?) -> (URL) -> String? {
        guard let index = index else {
            return { url in try? String(contentsOf: url, encoding: .utf8) }
        }
        let entries = index.entries
        return { url in
            if let entry = entries[url.standardizedFileURL] { return entry.source }
            return try? String(contentsOf: url, encoding: .utf8)
        }
    }

    private static func isCFile(_ url: URL) -> Bool {
        let cExts: Set<String> = ["c", "h", "cpp", "cc", "cxx", "hpp", "hxx", "hh", "c++", "h++", "m", "mm", "objc"]
        return cExts.contains(url.pathExtension.lowercased())
    }

    /// Tokens whose offset lies in [lo, hi). The tokenizer emits tokens in
    /// ascending offset order, so the slice is located with two binary
    /// searches — filtering the whole token array once per method was
    /// O(methods × tokens) per file and dominated index builds on large
    /// projects (e.g. the Ruby source tree).
    private static func bodyTokens(_ lo: Int, _ hi: Int, tokens: [CAstToken]) -> [CAstToken] {
        let start = lowerBound(of: lo, in: tokens)
        let end = lowerBound(of: hi, in: tokens)
        guard start < end else { return [] }
        return Array(tokens[start..<end])
    }

    private static func lowerBound(of offset: Int, in tokens: [CAstToken]) -> Int {
        var lo = 0
        var hi = tokens.count
        while lo < hi {
            let mid = (lo + hi) / 2
            if tokens[mid].offset < offset { lo = mid + 1 } else { hi = mid }
        }
        return lo
    }

    private static func extractScriptCallees(source: String, methods: [ScriptMethodDef]) -> [String: [String]] {
        let tokens = CTokenizer(source: source).tokenize()
        let definedNames = Set(methods.map { $0.name })
        var callees: [String: [String]] = [:]
        for m in methods {
            let lo = m.bodyOffset
            let hi = m.bodyRange.location + m.bodyRange.length
            let bodyTokens = Self.bodyTokens(lo, hi, tokens: tokens)
            var calling = Set<String>()
            for (idx, t) in bodyTokens.enumerated() where t.kind == .identifier {
                guard idx + 1 < bodyTokens.count,
                      bodyTokens[idx + 1].kind == .punct, bodyTokens[idx + 1].text == "(" else { continue }
                if idx > 0, bodyTokens[idx - 1].kind == .operator, bodyTokens[idx - 1].text == "." { continue }
                let callee = t.text
                if definedNames.contains(callee), callee != m.name {
                    calling.insert(callee)
                }
            }
            callees[m.name] = Array(calling)
        }
        return callees
    }

    private static func extractSolidityCallees(source: String, methods: [SolidityMethodDef]) -> [String: [String]] {
        let tokens = CTokenizer(source: source).tokenize()
        let definedNames = Set(methods.map { $0.name })
        var callees: [String: [String]] = [:]
        for m in methods {
            let lo = m.bodyOffset
            let hi = m.bodyRange.location + m.bodyRange.length
            let bodyTokens = Self.bodyTokens(lo, hi, tokens: tokens)
            var calling = Set<String>()
            for (idx, t) in bodyTokens.enumerated() where t.kind == .identifier {
                guard idx + 1 < bodyTokens.count,
                      bodyTokens[idx + 1].kind == .punct, bodyTokens[idx + 1].text == "(" else { continue }
                if idx > 0, bodyTokens[idx - 1].kind == .operator, bodyTokens[idx - 1].text == "." { continue }
                let callee = t.text
                if definedNames.contains(callee), callee != m.name {
                    calling.insert(callee)
                }
            }
            callees[m.name] = Array(calling)
        }
        return callees
    }

    /// Detect PHP functions whose bodies only reference sanitizer helpers
    /// (preg_replace, htmlspecialchars, …) and their own parameters.
    /// Calls to these functions produce clean values.
    private static func computePHPSanitizers(source: String) -> Set<String> {
        let phpMethods = ScriptMethodParser(language: .php, source: source).parseMethods()
        guard !phpMethods.isEmpty else { return [] }
let allTokens = CTokenizer(source: source).tokenize()
        let phpSuperglobals: Set<String> = ["_GET","_POST","_REQUEST","_FILES","_COOKIE","_SERVER","_ENV"]
        let phpTaintReturn: Set<String> = phpSourceAPIs
        let phpSanitizerSet: Set<String> = ["htmlspecialchars", "htmlentities", "preg_replace",
                                             "preg_quote", "escapeshellarg", "urlencode", "rawurlencode",
                                             "strip_tags", "addcslashes", "bin2hex", "clean",
                                             "strlen", "substr", "trim", "ltrim", "rtrim",
                                             "strtolower", "strtoupper", "str_replace", "str_ireplace",
                                             "preg_match", "preg_match_all", "preg_split", "preg_filter",
                                             "implode", "explode", "join", "sprintf", "number_format",
                                             "round", "abs", "intval", "floatval", "boolval",
                                             "bindec", "hexdec", "octdec", "decbin", "dechex", "decoct",
                                             "wordwrap", "strrev", "strtr", "chunk_split", "str_pad",
                                             "str_repeat", "strcmp", "strcasecmp", "str_contains",
                                             "str_starts_with", "str_ends_with",
                                             "array_filter", "array_map", "array_values", "array_keys",
                                             "sort", "rsort", "ksort", "asort", "array_unique",
                                             "array_merge", "array_slice", "array_splice",
                                             "array_change_key_case", "array_chunk", "array_column",
                                             "array_combine", "array_count_values", "array_diff",
                                             "array_fill", "array_fill_keys", "array_flip", "array_intersect",
                                             "array_key_exists", "array_key_first", "array_key_last",
                                             "array_merge_recursive", "array_pad", "array_pop", "array_product",
                                             "array_push", "array_rand", "array_replace", "array_replace_recursive",
                                             "array_reverse", "array_search", "array_shift", "array_sum",
                                             "array_udiff", "array_unshift", "array_values", "array_walk",
                                             "arsort", "asort", "krsort", "ksort", "natcasesort", "natsort",
                                             "range", "uasort", "uksort", "usort", "sort", "rsort"]
        var phpDefParams: [String: Set<String>] = [:]
        for def in phpMethods {
            let params = def.params.compactMap { $0.name }
            phpDefParams[def.name] = Set(params)
        }
        // Compute taint-returning functions first (source-reading functions).
        var sourceReading: Set<String> = []
        var changed = true
        while changed {
            changed = false
            for def in phpMethods where !sourceReading.contains(def.name) {
                let r = def.bodyRange
                let body = Self.bodyTokens(r.location, r.location + r.length, tokens: allTokens)
                for tk in body where tk.kind == .identifier {
                    if phpSuperglobals.contains(tk.text) || phpTaintReturn.contains(tk.text) || sourceReading.contains(tk.text) {
                        sourceReading.insert(def.name)
                        changed = true
                        break
                    }
                }
            }
        }
        var sanitizerFns = Set<String>()
        changed = true
        while changed {
            changed = false
            for def in phpMethods where !sanitizerFns.contains(def.name) && !sourceReading.contains(def.name) {
                let defParams = phpDefParams[def.name] ?? []
                let r = def.bodyRange
                let body = Self.bodyTokens(r.location, r.location + r.length, tokens: allTokens)
                var onlySanitizers = true
                var i = 0
                while i < body.count {
                    let tk = body[i]
                    if tk.kind == .identifier, i + 1 < body.count, body[i + 1].text == "(" {
                        let name = tk.text
                        if name == def.name || ["foreach", "if", "return", "function", "while", "for", "switch", "case", "else", "elseif"].contains(name) {
                            i += 2
                            continue
                        }
                        if defParams.contains(name) || phpSanitizerSet.contains(name) || sanitizerFns.contains(name) {
                            i += 2
                            continue
                        }
                        onlySanitizers = false
                        break
                    }
                    i += 1
                }
                if onlySanitizers {
                    sanitizerFns.insert(def.name)
                    changed = true
                }
            }
        }
        return sanitizerFns
    }
}

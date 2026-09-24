// by cipher.org.uk
import Foundation

/// A single receive-API call/property site in a source file.
struct EntrySite {
    let fileURL: URL
    let line: Int
    let column: Int
    /// UTF-16 offset of the matched leaf token, used to locate the enclosing
    /// function when tracing the flow of `entryVariable`.
    let charIndex: Int
    /// Matched leaf name (e.g. `getParameter`, `sender`).
    let apiName: String
    /// Receiver path struck against, normalized with dots (`msg`, `request`,
    /// `System`, `ProcessInfo.processInfo`, ...) or the bare leaf.
    let apiPath: String
    let category: String
    let origin: EntryOrigin
    let confidence: EntryConfidence
    /// Variable the receive call/property is assigned to, if determinable from
    /// the surrounding statement. `nil` sites are still recorded as entries but
    /// have no variable to trace.
    let entryVariable: String?
    /// The trimmed source line for display.
    let snippet: String
    /// How this site was recognised as an entry point, shown on the results row
    /// ("API call", "HTTP handler", "input binding (@RequestBody)", ...).
    let sourceKind: String
}

/// One results-list group: a receive category with its sites.
struct EntryGroup {
    let category: String
    let origin: EntryOrigin
    let confidence: EntryConfidence
    var sites: [EntrySite] = []

    static func orderIndex(_ confidence: EntryConfidence, _ origin: EntryOrigin) -> Int {
        switch (confidence, origin) {
        case (.primary, .internet): return 0
        case (.primary, .local): return 1
        case (.indirect, _): return 2
        }
    }
}

/// Walks a project's token streams and matches the receive-API catalog to find
/// user-controlled entry points. Each file is matched independently against the
/// language's entries (C-family files reuse the C table; ObjC gets both).
enum EntryPointCollector {

    /// Hard cap on the number of entry point sites collected in one pass.
    static let siteCap = 500

    /// Collect all entry-point sites across the indexed project.
    /// - Parameters:
    ///   - includeIndirect: when true, indirect tiers (file reads, persisted
    ///     data, deserialization) are scanned too. Primary tiers are always
    ///     scanned. Callers satisfy `includeIndirect` lazily via this param.
    ///   - progress: (processedFiles, totalFiles) — called frequently.
    static func collect(sourceIndex: ProjectSourceIndex,
                        includeIndirect: Bool,
                        progress: ((Int, Int) -> Void)? = nil) -> [EntryGroup] {
        let files = Array(sourceIndex.entries.values).sorted { $0.url.path < $1.url.path }
        var groups: [String: EntryGroup] = [:]
        var seen: Set<String> = []
        var total = 0
        var truncated = false
        let totalCount = files.count
        var done = 0
        let flushEvery = max(1, totalCount / 200)

        progress?(0, totalCount)

        outer: for entry in files {
            let c1 = Self.matchedSites(source: entry.source,
                                       tokens: entry.tokens,
                                       url: entry.url,
                                       includeIndirect: includeIndirect)
            // Structural checks (C2–C6). A handler/route/binding site is
            // suppressed when its function body already contains a catalog
            // (C1) receive site — the concrete call is the more specific check.
            let structural = Self.structuralSites(source: entry.source,
                                                  tokens: entry.tokens,
                                                  url: entry.url,
                                                  funcs: entry.funcs,
                                                  c1Offsets: Set(c1.map { $0.charIndex }))
            for site in c1 + structural {
                let key = "\(site.fileURL.path)#\(site.charIndex)#\(site.apiName)#\(site.sourceKind)"
                guard seen.insert(key).inserted else { continue }
                if total >= Self.siteCap {
                    truncated = true
                    break outer
                }
                total += 1
                var group = groups[site.category] ?? EntryGroup(category: site.category,
                                                                origin: site.origin,
                                                                confidence: site.confidence)
                group.sites.append(site)
                groups[site.category] = group
            }
            done += 1
            if done % flushEvery == 0 { progress?(done, totalCount) }
        }
        progress?(totalCount, totalCount)

        let result = groups
            .values
            .sorted { lhs, rhs in
                let li = EntryGroup.orderIndex(lhs.confidence, lhs.origin)
                let ri = EntryGroup.orderIndex(rhs.confidence, rhs.origin)
                if li != ri { return li < ri }
                return lhs.category < rhs.category
            }

        Self.truncationWarning = truncated
        return result
    }

    /// Set by `collect` when the site cap was hit.
    private(set) static var truncationWarning = false

    // MARK: - Per-file matching

    /// Catalog indexed by leaf name so token scanning is O(tokens), not
    /// O(tokens × catalog).
    static let entriesByLeaf: [String: [EPEntry]] = {
        var map: [String: [EPEntry]] = [:]
        for entry in EntryPointCatalog.entries {
            map[entry.leaf, default: []].append(entry)
        }
        return map
    }()

    static func matchedSites(source: String, tokens: [CAstToken], url: URL,
                             includeIndirect: Bool) -> [EntrySite] {
        guard let lang = EPLanguage.from(ext: url.pathExtension) else { return [] }
        let lines = source.components(separatedBy: "\n")
        var sites: [EntrySite] = []

        for (i, token) in tokens.enumerated() {
            guard token.kind == .identifier else { continue }
            guard let candidates = entriesByLeaf[token.text] else { continue }
            for entry in candidates {
                guard entry.applies(to: lang) else { continue }
                guard entry.confidence == .primary || includeIndirect else { continue }
                guard let site = Self.match(entry: entry, tokens: tokens, index: i,
                                            lines: lines, url: url) else { continue }
                sites.append(site)
                break
            }
        }
        return sites
    }

    /// Matches `entry` against the token at `i`. Returns a site on success.
    static func match(entry: EPEntry, tokens: [CAstToken], index i: Int,
                      lines: [String], url: URL) -> EntrySite? {
        let leaf = tokens[i]
        guard leaf.text == entry.leaf else { return nil }
        let chain = receiverPath(tokens, i)
        let prefix = entry.prefix
        let prefixOK = prefix == nil || chain == prefix || chain.hasSuffix("." + prefix!)

        let isCall = i + 1 < tokens.count && tokens[i + 1].text == "("
        // `func foo(`, `public String foo(` etc. are declarations, not calls.
        // CTokenizer.classify knows C/Java keywords only, so Swift's `func` and
        // Python's `def` arrive as identifiers — accept either kind. Also bail
        // on a leading type + visibility/modifier (`public String getParameter`),
        // which is a method signature, not a receive site.
        var precededByDeclarationKeyword = false
        if i > 0 {
            var k = 1
            while k <= 3, i - k >= 0 {
                let t = tokens[i - k]
                let direct = ["func", "function", "def", "sub", "fn", "method",
                              "proc", "fun", "class", "interface", "struct", "enum"]
                let modifier = ["public", "private", "protected", "internal", "static",
                                "final", "abstract", "override", "virtual", "sync",
                                "async", "export", "def", "func", "function", "sub",
                                "fn", "fun"]
                if direct.contains(t.text) || modifier.contains(t.text) {
                    precededByDeclarationKeyword = true
                    break
                }
                k += 1
            }
        }

        var matchedLeaf: String? = nil
        if entry.match != .property, isCall, !precededByDeclarationKeyword, prefixOK {
            matchedLeaf = leaf.text
        } else if entry.match != .call, prefix != nil, prefixOK {
            matchedLeaf = leaf.text
        } else if entry.match != .call, prefix == nil, entry.allowBareProperty,
                  i == 0 || (tokens[i - 1].text != "." && tokens[i - 1].text != "::"),
                  !(i + 1 < tokens.count && [")", ",", ";", "="].contains(tokens[i + 1].text)) {
            // Bare property read (argv, environ, $_GET, …). The next-token check
            // skips parameter lists and declarations (`char **argv)`), which are
            // not receive sites — only later uses of the identifier are.
            matchedLeaf = leaf.text
        }

        guard let apiName = matchedLeaf else { return nil }

        let variable = Self.receiverVariable(entry: entry, tokens: tokens, index: i)
        let line = max(1, leaf.line)
        let snippet = line <= lines.count
            ? lines[line - 1].trimmingCharacters(in: .whitespacesAndNewlines)
            : ""
        let displayPath: String
        if let p = prefix {
            displayPath = p
        } else if !chain.isEmpty {
            displayPath = chain
        } else {
            displayPath = leaf.text
        }
        return EntrySite(fileURL: url,
                         line: line,
                         column: leaf.column,
                         charIndex: leaf.offset,
                         apiName: apiName,
                         apiPath: displayPath,
                         category: entry.category,
                         origin: entry.origin,
                         confidence: entry.confidence,
                         entryVariable: variable,
                         snippet: snippet,
                         sourceKind: Self.sourceKindLabel(for: entry))
    }

    /// Human label for how a catalog (C1) site was recognised.
    static func sourceKindLabel(for entry: EPEntry) -> String {
        if entry.receiverArg != nil { return "buffer-arg receive" }
        switch entry.match {
        case .call:
            return entry.allowBareProperty ? "bare read" : "API call"
        case .property: return "property read"
        case .both: return entry.allowBareProperty ? "bare read" : "API call"
        }
    }

    // MARK: - Structural entry-point checks (C2–C6)

    /// Non-catalog checks that still recognise a site as an entry point:
    ///    C2  HTTP handler signature      (func params carried into a request)
    ///    C3  routing/decorator           (@RequestMapping, @app.get, [HttpPost])
    ///    C4  event / delegate surface    (onMessageReceived, URLSession data, …)
    ///    C5  — flow continuation only; never promoted to a source itself.
    ///    C6  known-standard trust markers(@TrustBoundary, @UserInput, …)
    ///
    /// A structural site for a function is suppressed when the function body
    /// already holds a C1 catalog receive site — the concrete call is the more
    /// specific check and wins to avoid double-flagging a handler.
    static func structuralSites(source: String,
                                tokens: [CAstToken],
                                url: URL,
                                funcs: [CCFunctionParser.FunctionDef],
                                c1Offsets: Set<Int>) -> [EntrySite] {
        guard let lang = EPLanguage.from(ext: url.pathExtension) else { return [] }
        let lines = source.components(separatedBy: "\n")
        var out: [EntrySite] = []
        for def in funcs {
            out.append(contentsOf: structuralSites(for: def,
                                                   tokens: tokens,
                                                   lines: lines,
                                                   url: url,
                                                   lang: lang,
                                                   c1Offsets: c1Offsets))
        }
        return out
    }

    private static func structuralSites(for def: CCFunctionParser.FunctionDef,
                                        tokens: [CAstToken],
                                        lines: [String],
                                        url: URL,
                                        lang: EPLanguage,
                                        c1Offsets: Set<Int>) -> [EntrySite] {
        let nameOffset = def.nameRange.location
        guard nameOffset != NSNotFound,
              let nameTok = token(at: nameOffset, tokens: tokens) else { return [] }
        var bodyHasC1 = false
        if def.bodyRange.location != NSNotFound {
            bodyHasC1 = c1Offsets.contains { NSLocationInRange($0, def.bodyRange) }
        }
        let sigSlices = sigParams(nameOffset: nameOffset, tokens: tokens) ?? []
        let sigs = params(sigSlices: sigSlices, lang: lang)
        let decs = decorations(before: nameOffset, tokens: tokens)
        let name = nameTok.text
        let nameLineText = lineText(lines: lines, line: nameTok.line)

        var sites: [EntrySite] = []
        let http = EntryPointCatalog.httpRequest
        switch lang {
        case .java, .kotlin:
            let bindings = ["RequestParam", "PathVariable", "RequestBody", "RequestHeader",
                            "CookieValue", "ModelAttribute", "PathParam", "QueryParam",
                            "FormParam", "HeaderParam", "Body", "BodyParam"]
            for p in sigs {
                let anns = annotations(in: p.tokens)
                if let hit = anns.first(where: { bindings.contains($0) }) {
                    sites.append(makeSite(fileURL: url, apiName: hit, apiPath: "@\(hit)",
                                          category: http, origin: .internet, confidence: .primary,
                                          variable: p.name, offset: p.nameOffset, tokenLine: p.nameLine,
                                          snippet: lineText(lines: lines, line: p.nameLine),
                                          kind: "input binding (@\(hit))"))
                }
            }
            let mapped = decs.contains { ["RequestMapping", "GetMapping", "PostMapping",
                                          "PutMapping", "DeleteMapping", "PatchMapping"].contains($0) }
            let hadBinding = sites.contains { $0.category == http }
            if mapped, !hadBinding, !bodyHasC1 {
                sites.append(makeSite(fileURL: url, apiName: name, apiPath: "mapped handler",
                                      category: http, origin: .internet, confidence: .primary,
                                      variable: nil, offset: nameOffset, tokenLine: nameTok.line,
                                      snippet: nameLineText, kind: "routed endpoint"))
            }
            if ["doGet", "doPost", "doPut", "doDelete", "doHead", "doOptions", "doTrace"]
                .contains(name), !bodyHasC1 {
                if let req = lookupParam(sigs, containedIDs: ["HttpServletRequest"]) {
                    sites.append(makeSite(fileURL: url, apiName: name, apiPath: "HttpServletRequest",
                                          category: http, origin: .internet, confidence: .primary,
                                          variable: req.name, offset: req.nameOffset, tokenLine: req.nameLine,
                                          snippet: lineText(lines: lines, line: req.nameLine),
                                          kind: "HTTP handler"))
                }
            }
            if name == "onMessageReceived", !bodyHasC1,
               let msg = lookupParam(sigs, containedIDs: ["RemoteMessage"]) {
                sites.append(makeSite(fileURL: url, apiName: "onMessageReceived",
                                      apiPath: "RemoteMessage", category: EntryPointCatalog.deepLinks,
                                      origin: .internet, confidence: .primary,
                                      variable: msg.name, offset: msg.nameOffset, tokenLine: msg.nameLine,
                                      snippet: lineText(lines: lines, line: msg.nameLine),
                                      kind: "push payload delegate"))
            }
            if name == "onNewIntent", !bodyHasC1,
               let it = lookupParam(sigs, containedIDs: ["Intent"]) {
                sites.append(makeSite(fileURL: url, apiName: "onNewIntent",
                                      apiPath: "Intent", category: EntryPointCatalog.deepLinks,
                                      origin: .internet, confidence: .primary,
                                      variable: it.name, offset: it.nameOffset, tokenLine: it.nameLine,
                                      snippet: lineText(lines: lines, line: it.nameLine),
                                      kind: "deep-link intent"))
            }

        case .csharp:
            let bindings = ["FromBody", "FromQuery", "FromRoute", "FromForm"]
            var bindingSeen = false
            for p in sigs {
                let anns = annotations(in: p.tokens)
                if let hit = anns.first(where: { bindings.contains($0) }) {
                    bindingSeen = true
                    sites.append(makeSite(fileURL: url, apiName: hit, apiPath: "[\(hit)]",
                                          category: http, origin: .internet, confidence: .primary,
                                          variable: p.name, offset: p.nameOffset, tokenLine: p.nameLine,
                                          snippet: lineText(lines: lines, line: p.nameLine),
                                          kind: "input binding ([\(hit)])"))
                }
            }
            let action = decs.contains { ["HttpPost", "HttpPut", "HttpPatch"].contains($0) }
            if action, !bindingSeen, !bodyHasC1 {
                if let p = sigs.first {
                    sites.append(makeSite(fileURL: url, apiName: name, apiPath: "action",
                                          category: http, origin: .internet, confidence: .primary,
                                          variable: p.name, offset: p.nameOffset, tokenLine: p.nameLine,
                                          snippet: lineText(lines: lines, line: p.nameLine),
                                          kind: "HTTP action binding"))
                }
            }

        case .go:
            if !bodyHasC1,
               let req = lookupParam(sigs, containedIDs: ["Request"]) ?? lookupParam(sigs, containedIDs: ["gin", "Context"]) ?? lookupParam(sigs, containedIDs: ["echo", "Context"]) ?? lookupParam(sigs, containedIDs: ["fasthttp", "RequestCtx"]) {
                sites.append(makeSite(fileURL: url, apiName: name, apiPath: "handler",
                                      category: http, origin: .internet, confidence: .primary,
                                      variable: req.name, offset: req.nameOffset, tokenLine: req.nameLine,
                                      snippet: lineText(lines: lines, line: req.nameLine),
                                      kind: "HTTP handler"))
            }

        case .python:
            let fastDecorators = ["get", "post", "put", "delete", "patch", "head", "options"]
            let routeDecorated = decs.contains { $0 == "route" }
            let fastAPIMapped = decs.contains { fastDecorators.contains($0) }
            let djangoMapped = decs.contains { ["api_view", "require_http_methods",
                                                "require_POST", "require_GET",
                                                "login_required", "csrf_exempt"].contains($0) }
            if fastAPIMapped {
                for p in sigs {
                    let markerIDs = ids(in: p.tokens).filter { ["Query", "Body", "Path", "Header",
                                                                "Cookie", "Form", "File"].contains($0) }
                    if !markerIDs.isEmpty {
                        sites.append(makeSite(fileURL: url, apiName: markerIDs.first ?? "Param",
                                              apiPath: "FastAPI", category: http, origin: .internet,
                                              confidence: .primary,
                                              variable: p.name, offset: p.nameOffset, tokenLine: p.nameLine,
                                              snippet: lineText(lines: lines, line: p.nameLine),
                                              kind: "route param binding"))
                    }
                }
            } else if (routeDecorated || djangoMapped), !bodyHasC1 {
                if djangoMapped, let p = sigs.first, p.name == "request" {
                    sites.append(makeSite(fileURL: url, apiName: "request", apiPath: "view",
                                          category: http, origin: .internet, confidence: .primary,
                                          variable: p.name, offset: p.nameOffset, tokenLine: p.nameLine,
                                          snippet: lineText(lines: lines, line: p.nameLine),
                                          kind: "routed endpoint"))
                } else if routeDecorated {
                    sites.append(makeSite(fileURL: url, apiName: name, apiPath: "endpoint",
                                          category: http, origin: .internet, confidence: .primary,
                                          variable: nil, offset: nameOffset, tokenLine: nameTok.line,
                                          snippet: nameLineText, kind: "routed endpoint"))
                }
            }
            if name == "application", !bodyHasC1,
               let p = sigs.first, p.name == "environ" {
                sites.append(makeSite(fileURL: url, apiName: "application", apiPath: "WSGI",
                                      category: http, origin: .internet, confidence: .primary,
                                      variable: p.name, offset: p.nameOffset, tokenLine: p.nameLine,
                                      snippet: lineText(lines: lines, line: p.nameLine),
                                      kind: "WSGI gateway"))
            }

        case .php:
            if !bodyHasC1,
               let p = lookupParam(sigs, containedIDs: ["Request", "RequestInterface", "ServerRequestInterface"]) {
                sites.append(makeSite(fileURL: url, apiName: name, apiPath: "Request",
                                      category: http, origin: .internet, confidence: .primary,
                                      variable: p.name, offset: p.nameOffset, tokenLine: p.nameLine,
                                      snippet: lineText(lines: lines, line: p.nameLine),
                                      kind: "framework request param"))
            }

        case .rust:
            if !bodyHasC1,
               let p = lookupParam(sigs, containedIDs: ["Json"]) ?? lookupParam(sigs, containedIDs: ["Query"])
                ?? lookupParam(sigs, containedIDs: ["HttpRequest"]) ?? lookupParam(sigs, containedIDs: ["Path"]) {
                sites.append(makeSite(fileURL: url, apiName: name, apiPath: "axum/actix",
                                      category: http, origin: .internet, confidence: .primary,
                                      variable: p.name, offset: p.nameOffset, tokenLine: p.nameLine,
                                      snippet: lineText(lines: lines, line: p.nameLine),
                                      kind: "route param binding"))
            }

        case .swift:
            if name == "urlSession", !bodyHasC1,
               let p = lookupParam(sigs, containedIDs: ["Data"]) {
                sites.append(makeSite(fileURL: url, apiName: "urlSession", apiPath: "URLSession",
                                      category: EntryPointCatalog.webClient, origin: .internet,
                                      confidence: .primary,
                                      variable: p.name, offset: p.nameOffset, tokenLine: p.nameLine,
                                      snippet: lineText(lines: lines, line: p.nameLine),
                                      kind: "URLSession delegate"))
            }
            if name == "userNotificationCenter", !bodyHasC1,
               let p = lookupParam(sigs, containedIDs: ["UNNotificationResponse"]) {
                sites.append(makeSite(fileURL: url, apiName: "userNotificationCenter",
                                      apiPath: "UNNotificationResponse", category: EntryPointCatalog.deepLinks,
                                      origin: .internet, confidence: .primary,
                                      variable: p.name, offset: p.nameOffset, tokenLine: p.nameLine,
                                      snippet: lineText(lines: lines, line: p.nameLine),
                                      kind: "push payload delegate"))
            }

        case .objc:
            if name.contains("didReceiveData"), !bodyHasC1,
               let p = lookupParam(sigs, containedIDs: ["NSData"]) ?? sigs.first {
                sites.append(makeSite(fileURL: url, apiName: name, apiPath: "didReceiveData",
                                      category: EntryPointCatalog.webClient, origin: .internet,
                                      confidence: .primary,
                                      variable: p.name, offset: p.nameOffset, tokenLine: p.nameLine,
                                      snippet: lineText(lines: lines, line: p.nameLine),
                                      kind: "URL delegate"))
            }

        case .solidity:
            let visibility = solidityVisibility(before: def.bodyRange.location, from: nameOffset, tokens: tokens)
            if visibility.contains("external") || visibility.contains("public"), !bodyHasC1 {
                let first = sigs.first
                sites.append(makeSite(fileURL: url, apiName: name, apiPath: visibility.joined(separator: "+"),
                                      category: EntryPointCatalog.blockchain, origin: .internet,
                                      confidence: .primary,
                                      variable: first?.name, offset: first?.nameOffset ?? nameOffset,
                                      tokenLine: first?.nameLine ?? nameTok.line,
                                      snippet: nameLineText,
                                      kind: "external/httpd callable"))
            }

        case .javascript:
            if !bodyHasC1,
               let req = lookupParam(sigs, containedIDs: ["NextApiRequest"])
                ?? lookupParam(sigs, containedIDs: ["NextRequest"])
                ?? lookupParam(sigs, containedIDs: ["IncomingMessage"]) {
                sites.append(makeSite(fileURL: url, apiName: name, apiPath: "handler",
                                      category: http, origin: .internet, confidence: .primary,
                                      variable: req.name, offset: req.nameOffset, tokenLine: req.nameLine,
                                      snippet: lineText(lines: lines, line: req.nameLine),
                                      kind: "HTTP handler"))
            }

        case .c, .ruby:
            break   // C is already catalog-rich; Ruby routes via blocks and request APIs.
        }

        // C6: known-standard trust-boundary markers.
        let markers = ["TrustBoundary", "UntrustedInput", "UserInput", "RawInput",
                       "ReceiveInput", "InputSource", "TrustedBoundary"]
        if !bodyHasC1 {
            let decIDs = decs.filter { markers.contains($0) }
            let paramMarkers = sigs.flatMap { p -> [(SigParam, String)] in
                annotations(in: p.tokens).compactMap { a in markers.contains(a) ? (p, a) : nil }
            }
            if let (p, ann) = paramMarkers.first {
                sites.append(makeSite(fileURL: url, apiName: ann, apiPath: "@\(ann)",
                                      category: "Trust-boundary markers", origin: .internet,
                                      confidence: .primary,
                                      variable: p.name, offset: p.nameOffset, tokenLine: p.nameLine,
                                      snippet: lineText(lines: lines, line: p.nameLine),
                                      kind: "trust-boundary marker"))
            } else if let ann = decIDs.first, let p = sigs.first {
                sites.append(makeSite(fileURL: url, apiName: ann, apiPath: "@\(ann)",
                                      category: "Trust-boundary markers", origin: .local,
                                      confidence: .primary,
                                      variable: p.name, offset: p.nameOffset, tokenLine: p.nameLine,
                                      snippet: nameLineText, kind: "trust-boundary marker"))
            }
        }

        return sites
    }

    // MARK: - Structural helpers

    private struct SigParam {
        let tokens: [CAstToken]
        let name: String
        let nameOffset: Int
        let nameLine: Int
    }

    /// Splits the parameter list of the function whose name is at `nameOffset`
    /// into syntactic slices (top-level `,`-separated).
    private static func sigParams(nameOffset: Int, tokens: [CAstToken]) -> [[CAstToken]]? {
        var open = nameOffset
        while open < tokens.count, tokens[open].text != "(" { open += 1 }
        guard open < tokens.count else { return nil }
        var i = open + 1
        var depth = 0
        var current: [CAstToken] = []
        var params: [[CAstToken]] = []
        while i < tokens.count {
            let t = tokens[i]
            switch t.text {
            case "(": depth += 1; current.append(t)
            case ")":
                if depth == 0 {
                    if !current.filter({ $0.kind == .identifier }).isEmpty { params.append(current) }
                    return params
                }
                depth -= 1; current.append(t)
            case ",":
                if depth == 0 { params.append(current); current = [] }
                else { current.append(t) }
            default: current.append(t)
            }
            i += 1
        }
        return nil
    }

    private static func paramName(_ toks: [CAstToken], lang: EPLanguage) -> (name: String, offset: Int, line: Int)? {
        var slice = toks
        if slice.first?.text == "_" { slice.removeFirst() }
        // `name: Type` signatures (Swift, Rust, Kotlin) — the identifier before
        // the first `:` is the parameter name.
        if lang == .swift || lang == .rust || lang == .kotlin || lang == .javascript {
            if let ci = slice.firstIndex(where: { $0.text == ":" }) {
                let ids = slice[..<ci].filter { $0.kind == .identifier }
                if let last = ids.last, last.text != "_" { return (last.text, last.offset, last.line) }
            }
        }
        // Go and Python declare parameters as `name type` / `name: type` where
        // the name leads (`w http.ResponseWriter`, `x: int = Query(...)`).
        // Go declares parameters as `name type` — the name is the first
        // identifier; the type follows (`w http.ResponseWriter`, `r *http.Request`).
        // Python/JavaScript are conventionally `name = default` / `name: Type[, = …]`
        // parameter lists, where the name leads (`def f(x: int = Query(…))`,
        // `handler(req: NextApiRequest)`, `handler(req, res)`).
        if lang == .go || lang == .python || lang == .javascript,
           let nm = slice.first(where: { $0.kind == .identifier }) {
            return (nm.text, nm.offset, nm.line)
        }
        // ObjC selector params: `external:(Type)internalName`.
        if lang == .objc, let colon = slice.lastIndex(where: { $0.text == ":" }),
           let close = slice[..<colon].lastIndex(where: { $0.text == ")" }),
           close + 1 < colon {
            let nm = slice[close + 1]
            if nm.kind == .identifier { return (nm.text, nm.offset, nm.line) }
        }
        if let nm = slice.last(where: { $0.kind == .identifier }) {
            return (nm.text, nm.offset, nm.line)
        }
        return nil
    }

    private static func params(sigSlices: [[CAstToken]], lang: EPLanguage) -> [SigParam] {
        sigSlices.compactMap { slice in
            guard let (n, off, line) = paramName(slice, lang: lang) else { return nil }
            return SigParam(tokens: slice, name: n, nameOffset: off, nameLine: line)
        }
    }

    /// Identifiers in a token slice that are not the parameter's own name.
    private static func ids(in toks: [CAstToken]) -> [String] {
        toks.filter { $0.kind == .identifier }.map { $0.text }
    }

    private static func lookupParam(_ params: [SigParam], containedIDs wanted: [String]) -> SigParam? {
        for p in params {
            let idSet = Set(ids(in: p.tokens)).subtracting([p.name])
            if wanted.allSatisfy(idSet.contains) { return p }
        }
        return nil
    }

    /// Annotation/attribute names attached to a parameter slice: identifiers
    /// preceded by `@` (Java/Spring, FastAPI) or inside `[ ... ]` (C#).
    private static func annotations(in toks: [CAstToken]) -> [String] {
        var out: [String] = []
        for i in 0..<toks.count {
            if toks[i].text == "@", i + 1 < toks.count, toks[i + 1].kind == .identifier {
                out.append(toks[i + 1].text)
            }
            if toks[i].text == "[", i + 1 < toks.count, toks[i + 1].kind == .identifier {
                out.append(toks[i + 1].text)
            }
        }
        return out
    }

    /// `@Name`/`[Name]` markers on the lines immediately preceding a definition.
    /// `@app.get`/`@router.route` decorators yield both the base and the method
    /// (`["app", "get"]`) so FastAPI/Flask attach points are recognised.
    private static func decorations(before nameOffset: Int, tokens: [CAstToken]) -> [String] {
        guard let nm = token(at: nameOffset, tokens: tokens) else { return [] }
        var out: [String] = []
        for (i, t) in tokens.enumerated() {
            guard t.offset < nameOffset, t.line >= nm.line - 4 else { continue }
            guard (t.text == "@" || t.text == "[") && i + 1 < tokens.count,
                  tokens[i + 1].kind == .identifier else { continue }
            var j = i + 1
            out.append(tokens[j].text)
            while j + 2 < tokens.count, tokens[j + 1].text == ".",
                  tokens[j + 2].kind == .identifier {
                j += 2
                if !out.contains(tokens[j].text) { out.append(tokens[j].text) }
            }
        }
        return out
    }

    /// `public` / `external` visibility modifiers placed after a Solidity
    /// function's parameter list (before its body `{`).
    private static func solidityVisibility(before bodyOpen: Int, from nameOffset: Int, tokens: [CAstToken]) -> [String] {
        guard bodyOpen != NSNotFound else { return [] }
        var out: [String] = []
        for t in tokens {
            guard t.offset > nameOffset, t.offset < bodyOpen else { continue }
            if t.kind == .identifier, t.text == "public" || t.text == "external" {
                out.append(t.text)
            }
        }
        return out
    }

    private static func makeSite(fileURL: URL, apiName: String, apiPath: String,
                                 category: String, origin: EntryOrigin, confidence: EntryConfidence,
                                 variable: String?, offset: Int, tokenLine: Int,
                                 snippet: String, kind: String) -> EntrySite {
        EntrySite(fileURL: fileURL,
                  line: max(1, tokenLine),
                  column: 0,
                  charIndex: offset,
                  apiName: apiName,
                  apiPath: apiPath,
                  category: category,
                  origin: origin,
                  confidence: confidence,
                  entryVariable: variable,
                  snippet: snippet,
                  sourceKind: kind)
    }

    /// The 1-based source line `line` trimmed, or "" when out of range.
    static func lineText(lines: [String], line: Int) -> String {
        guard line >= 1, line <= lines.count else { return "" }
        return lines[line - 1].trimmingCharacters(in: .whitespacesAndNewlines)
    }

    /// Finds the token whose `.offset` equals `offset` via binary search.
    static func token(at offset: Int, tokens: [CAstToken]) -> CAstToken? {
        var lo = 0
        var hi = tokens.count - 1
        while lo <= hi {
            let mid = (lo + hi) / 2
            let t = tokens[mid]
            if t.offset < offset { lo = mid + 1 }
            else if t.offset > offset { hi = mid - 1 }
            else { return t }
        }
        return nil
    }

    /// Normalized receiver path before `tokens[i]`, e.g.
    /// `os.Getenv` → `os`, `ProcessInfo.processInfo.environment` →
    /// `ProcessInfo.processInfo`, `std::env::var` → `std.env`.
    /// `->` (PHP/Kotlin/Scala object calls) is treated like `.` so
    /// `$request->input` yields `request`.
    static func receiverPath(_ tokens: [CAstToken], _ i: Int) -> String {
        var parts: [String] = []
        var j = i - 1
        var expectingSeparator = true
        while j >= 0 {
            let t = tokens[j]
            if expectingSeparator {
                if t.text == "." || t.text == "::" { expectingSeparator = false }
                else if t.text == ">" && j - 1 >= 0, tokens[j - 1].text == "-" {
                    expectingSeparator = false
                    j -= 1            // consume the `-` of `->`
                } else { break }
            } else {
                if t.kind == .identifier {
                    parts.append(t.text)
                    expectingSeparator = true
                } else if t.text == ">" && j - 1 >= 0, tokens[j - 1].text == "-" {
                    j -= 1            // `->` separates the same way as `.`
                } else { break }
            }
            j -= 1
        }
        return parts.reversed().joined(separator: ".")
    }

    /// Resolves the variable whose data-flow receives the entry's value, in
    /// order of precision:
    /// 1. write-style receive calls: the buffer/out argument they fill
    ///    (fgets/scanf/read/recv/copy_from_user/get_user/...);
    /// 2. the assignment target (`x = getenv("…")` → `x`);
    /// 3. property/bare sites read off an object that is itself the entry value
    ///    (`msg.sender` → `msg`, `userActivity.webpageURL` → `userActivity`,
    ///    bare `argv`/`environ` → the identifier itself).
    /// Returns nil only when the value is genuinely consumed inline with no
    /// stored receiver the tracer could follow.
    static func receiverVariable(entry: EPEntry, tokens: [CAstToken], index i: Int) -> String? {
        if let arg = entry.receiverArg,
           let v = argumentVariable(tokens: tokens, callIndex: i, argIndex: arg) {
            return v
        }
        if let v = entry.entryVariable(tokens: tokens, callIndex: i) { return v }
        if entry.match == .call { return nil }
        return selfReceiver(entry: entry, tokens: tokens, index: i)
    }

    /// The variable data lands in at `argIndex` of the write-style receive call
    /// at `callIndex`, skimming `&x` / `*p` prefixes and string-literal format
    /// arguments.
    static func argumentVariable(tokens: [CAstToken], callIndex: Int, argIndex: Int) -> String? {
        var j = callIndex + 2
        var depth = 0
        var arg = 0
        var found: String?
        while j < tokens.count {
            let t = tokens[j]
            switch t.text {
            case "(":
                depth += 1
            case ")":
                if depth == 0 { return found }
                depth -= 1
            case ",":
                if depth == 0 {
                    if arg >= argIndex { return found }
                    arg += 1
                    found = nil
                }
            default:
                if depth == 0, arg == argIndex, found == nil, t.kind == .identifier {
                    found = t.text
                }
            }
            j += 1
        }
        return found
    }

    /// For property/bare entries, the receiver object itself carries the
    /// external data and can be traced (`msg.sender` → `msg`, bare `argv`).
    static func selfReceiver(entry: EPEntry, tokens: [CAstToken], index i: Int) -> String? {
        if entry.allowBareProperty {
            guard ["argv", "environ", "ARGV", "ENV", "_ENV",
                    "_GET", "_POST", "_REQUEST", "_COOKIE", "_FILES", "_SERVER"].contains(entry.leaf),
                  looksLikeIdentifier(entry.leaf) else { return nil }
            return entry.leaf
        }
        let chain = receiverPath(tokens, i)
        let comps = chain.split(separator: ".").map(String.init)
            .filter { $0 != "self" && $0 != "this" }
        guard let n = comps.last, looksLikeIdentifier(n), n != entry.leaf else { return nil }
        return n
    }

    private static func looksLikeIdentifier(_ s: String) -> Bool {
        guard let first = s.first else { return false }
        guard first == "_" || first.isLetter || first == "$" else { return false }
        return s.allSatisfy { $0 == "_" || $0.isLetter || $0.isNumber || $0 == "$" }
    }
}

extension EPEntry {

    /// Best-effort name of the variable this receive call is assigned to, by
    /// scanning the statement backwards from the call for an assignment.
    ///
    /// Switches on token *text* (not `kind`): the C tokenizer classifies only
    /// `()[]{};,.?:#` as `.punct`, so `=`, `<`, `>`, `!` etc. arrive as
    /// `.operator` — gating on `.punct` would silently skip the `=`.
    func entryVariable(tokens: [CAstToken], callIndex: Int) -> String? {
        var j = callIndex - 1
        if j >= 0, tokens[j].text == "(" { j -= 1 }
        var depth = 0
        while j >= 0 {
            let t = tokens[j]
            switch t.text {
            case ")":
                depth += 1
            case "(":
                if depth == 0 { return nil }
                depth -= 1
            case "=":
                if depth == 0 { return assignmentTarget(tokens: tokens, eq: j) }
            case ";", "{", "}", ":":
                if depth == 0 { return nil }
            default:
                if t.kind == .keyword, depth == 0,
                   ["if", "while", "for", "return", "switch", "case", "catch",
                    "else", "do", "until", "begin", "when", "unless"].contains(t.text) {
                    return nil
                }
            }
            j -= 1
        }
        return nil
    }

    /// The identifier being assigned, if the `=` at `eq` is a plain assignment
    /// (not `==`, `<=`, `!=`, `+=`, ...) to a plain variable (not a property
    /// like `foo.bar =` or `arr[i] =`).
    private func assignmentTarget(tokens: [CAstToken], eq: Int) -> String? {
        guard eq > 0 else { return nil }
        let prev = tokens[eq - 1]
        if prev.kind == .punct,
           ["=", "<", ">", "!", "+", "-", "*", "/", "%", "&", "|", "^", "~"].contains(prev.text) {
            return nil
        }
        guard prev.kind == .identifier else { return nil }
        if eq >= 2 {
            let q = tokens[eq - 2]
            if q.text == "." || q.text == "::" { return nil }
        }
        return prev.text
    }
}
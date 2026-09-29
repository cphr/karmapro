// by cipher.org.uk
import Foundation
import CryptoKit

/// AI-powered vulnerability discovery scanner.
///
/// Looks at the same source files the heuristic scanner examines, but asks the
/// configured AI model — OpenRouter cloud or a local Ollama server, whichever
/// the user selected in the AI Assistant window — to find vulnerabilities
/// independently ("discovery" mode, no seeding from the heuristic results).
/// Findings come back in the same `ScanFinding` shape as the regular scanner,
/// tagged `scanningSource = "AI"`, so they render in the identical result
/// columns (Exploitability / Severity / Category / Function / File / Line /
/// Engine / Cross-file / Finding).
///
/// The engine is fully language-agnostic: every source file is split into
/// "code cards" whose lines carry absolute line numbers, the model anchors
/// each finding to a real line, and we validate the line against the actual
/// file before accepting it. A finding that duplicates an issue the built-in
/// scanner already found is dropped.
final class AISecurityScanner {
    private init() {}

    /// Outcome of one AI pass. Partial results are returned even when some
    /// requests failed, so the UI can show what the model did manage to review.
    struct AIRunResult {
        let findings: [ScanFinding]
        let cardsProcessed: Int
        let cardsTotal: Int
        let errors: [String]
        let cancelled: Bool
    }

    /// What the model is doing right now, surfaced from the stream deltas so
    /// the UI can show a "thinking" indicator while reasoning and hide it once
    /// actual answers start streaming back.
    enum AIReviewPhase {
        case thinking
        case answering
    }

    /// A raw finding as the model returns it (keys are kept optional so a
    /// malformed record is skipped rather than failing the whole batch).
    private struct ParsedFinding: Codable {
        var line: Int?
        var category: String?
        var severity: String?
        var exploitability: String?
        var cross_file: Bool?
        var function: String?
        var summary: String?
        var file: String?
    }

    /// One numbered slice of a source file.
    private struct Card {
        let fileURL: URL
        let relativePath: String
        let startLine: Int
        /// Lines formatted as `NNNN| original text`, so the model reports the
        /// absolute line number of the file directly.
        let numberedText: String
        let digest: String
    }

    private struct CardRange {
        let card: Card
        let endLine: Int
    }

    /// Reference-type box for mutable state so it can be captured by the
    /// escaping per-batch completion closures.
    private final class BatchState {
        var findings: [ScanFinding] = []
        var errors: [String] = []
        var processedCards = 0
    }

    /// Accumulates a single batch's findings across continuation requests.
    private final class BatchCollector {
        var valid: [ValidatedFinding] = []
    }

    /// When a model stops mid-answer we push a "continue" prompt (keeping the
    /// conversation history) up to this many times before giving up on a batch.
    private static let maxContinuations = 2

    /// Categories the model may choose from. Mirrors the labels the built-in
    /// scanner produces so the Category column stays consistent; anything else
    /// maps to "Other".
    private static let knownCategories: [String] = [
        "SQL Injection", "Command Injection", "XSS (HTML Injection)", "Reflected XSS",
        "Stored XSS", "Insecure Deserialization", "ReDoS", "SSRF", "Path Traversal",
        "Path Traversal (File Inclusion)", "Local File Inclusion", "LDAP Injection",
        "Header Injection", "XPath Injection", "Template Injection", "XML External Entity (XXE)",
        "Hardcoded Secret", "Hardcoded Connection String (with password)", "Weak Cryptography (MD5 / SHA-1 / DES / RC4)",
        "Insecure Random Number Generation", "Insecure Transport", "Insecure Cookie",
        "Unsafe Reflection", "Arbitrary Code Loading", "Integer Overflow", "Buffer Overflow",
        "Stack Buffer Overflow", "Heap Buffer Overflow", "Use After Free", "Double Free",
        "Memory Leak", "Race Condition", "Null Pointer Dereference", "Uninitialized Memory",
        "Return of Local Variable Address", "Out-of-bounds Read", "Out-of-bounds Write",
        "JWT Weakness", "CORS Misconfiguration", "Unsafe File Upload", "Authentication Bypass",
        "Authorization Bypass", "Improper Access Control", "Sensitive Data Exposure",
        "Log Injection", "Format String", "Cryptographic Failure", "Password in URL",
        "Remote Code Execution", "Denial of Service", "CSRF", "Prototype Pollution", "Other"
    ]

    private static let cardCharBudget = 6_000
    private static let batchCharBudget = 11_000
    private static let maxFileChars = 1_000_000   // mirrors VulnerabilityScanner's guard

    // MARK: - Public entry point

    /// Runs the AI discovery pass over `projectRoot` using the model currently
    /// selected in the AI Assistant window. Findings already produced by the
    /// built-in scanner (`existingFindings`) are used to suppress duplicates.
    /// Completion fires on a background queue.
    static func runAI(projectRoot: URL,
                      existingFindings: [ScanFinding],
                      progress: @escaping (Double) -> Void,
                      isCancelled: @escaping () -> Bool,
                      completion: @escaping (AIRunResult) -> Void,
                      onPhase: @escaping (AIReviewPhase) -> Void = { _ in }) {
        let client = OpenRouterClient.shared
        let model = client.selectedModel
        let provider = client.provider.rawValue

        let files = enumerateSourceFiles(in: projectRoot)
        var cards: [Card] = []
        var cardRanges: [CardRange] = []
        var skippedFiles = 0

        for url in files {
            guard let source = try? String(contentsOf: url, encoding: .utf8), !source.isEmpty else { continue }
            if source.count > maxFileChars { skippedFiles += 1; continue }
            let rel = relativePath(of: url, under: projectRoot)
            let lines = source.components(separatedBy: "\n")
            var line = 1
            for chunk in sliceChunks(of: lines, budget: cardCharBudget) {
                let numbered = chunk.enumerated().map { idx, text in
                    "\(line + idx)|\(text)"
                }.joined(separator: "\n")
                let digest = sha256("\(provider)|\(model)|\(rel)\n\(numbered)")
                let card = Card(fileURL: url,
                                relativePath: rel,
                                startLine: line,
                                numberedText: numbered,
                                digest: digest)
                cards.append(card)
                cardRanges.append(CardRange(card: card, endLine: line + chunk.count - 1))
                line += chunk.count
            }
        }

        let totalCards = cards.count
        guard totalCards > 0 else {
            completion(AIRunResult(findings: [], cardsProcessed: 0, cardsTotal: 0,
                                   errors: ["No source files found to review."], cancelled: false))
            return
        }
        guard !client.requiresAPIKey
            || !client.apiKey.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
            completion(AIRunResult(findings: [], cardsProcessed: 0, cardsTotal: totalCards,
                                   errors: ["No OpenRouter API key is configured — open the AI Assistant, add your key, and connect."],
                                   cancelled: false))
            return
        }

        // Group cards into batches so each request carries several cards.
        var batches: [[Card]] = []
        var pending: [Card] = []
        var pendingChars = 0
        for card in cards {
            if !pending.isEmpty && pendingChars + card.numberedText.count > batchCharBudget {
                batches.append(pending)
                pending = []
                pendingChars = 0
            }
            pending.append(card)
            pendingChars += card.numberedText.count + card.relativePath.count
        }
        if !pending.isEmpty { batches.append(pending) }

        let state = BatchState()

        let finish = { (cancelled: Bool) in
            let deduped = dedupe(state.findings, against: existingFindings)
            completion(AIRunResult(findings: deduped,
                                   cardsProcessed: state.processedCards,
                                   cardsTotal: totalCards,
                                   errors: state.errors,
                                   cancelled: cancelled))
        }

        processBatches(index: 0,
                       batches: batches,
                       cardRanges: cardRanges,
                       model: model,
                       provider: provider,
                       state: state,
                       progress: progress,
                       isCancelled: isCancelled,
                       onPhase: onPhase,
                       finish: finish)
    }

    // MARK: - Sequential batch runner

    private static func processBatches(index: Int,
                                       batches: [[Card]],
                                       cardRanges: [CardRange],
                                       model: String,
                                       provider: String,
                                       state: BatchState,
                                       progress: @escaping (Double) -> Void,
                                       isCancelled: @escaping () -> Bool,
                                       onPhase: @escaping (AIReviewPhase) -> Void,
                                       finish: @escaping (Bool) -> Void) {
        if isCancelled() {
            OpenRouterClient.shared.cancelActiveStream()
            finish(true)
            return
        }
        guard index < batches.count else {
            finish(false)
            return
        }
        let batch = batches[index]
        let totalCards = batches.reduce(0) { $0 + $1.count }

        // Honour the on-disk cache first so unchanged code is not billed twice.
        if let cached = loadCachedFindings(for: batch, provider: provider, model: model) {
            appendValidated(findings: &state.findings, from: cached, batch: batch, cardRanges: cardRanges)
            state.processedCards += batch.count
            progress(Double(state.processedCards) / Double(totalCards))
            processBatches(index: index + 1, batches: batches, cardRanges: cardRanges,
                           model: model, provider: provider, state: state,
                           progress: progress, isCancelled: isCancelled, onPhase: onPhase, finish: finish)
            return
        }

        let batchText = batch.map { card in
            let end = card.startLine + cardLineCount(card) - 1
            return "### FILE: \(card.relativePath) (absolute lines \(card.startLine)-\(end))\n\(card.numberedText)"
        }.joined(separator: "\n\n")

        // Rough token estimate for the reply, used to map streamed character
        // deltas onto intra-batch progress so the bar moves as the model types.
        let expectedOutputChars = max(600, batchText.count / 3)
        let collector = BatchCollector()
        let batchLabel = "Batch \(index + 1)/\(batches.count)"

        requestBatch(messages: [["role": "system", "content": Self.systemPrompt],
                                ["role": "user", "content": batchText]],
                     batch: batch,
                     cardRanges: cardRanges,
                     model: model,
                     provider: provider,
                     state: state,
                     totalCards: totalCards,
                     expectedOutputChars: expectedOutputChars,
                     collector: collector,
                     progress: progress,
                     isCancelled: isCancelled,
                     onPhase: onPhase,
                     continuation: 0,
                     batchLabel: batchLabel,
                     onDone: {
            if !collector.valid.isEmpty {
                storeCachedFindings(collector.valid, for: batch, provider: provider, model: model)
                appendValidated(findings: &state.findings, from: collector.valid,
                                batch: batch, cardRanges: cardRanges)
            }
            state.processedCards += batch.count
            progress(Double(state.processedCards) / Double(totalCards))
            processBatches(index: index + 1, batches: batches, cardRanges: cardRanges,
                           model: model, provider: provider, state: state,
                           progress: progress, isCancelled: isCancelled, onPhase: onPhase, finish: finish)
        }, onCancel: {
            finish(true)
        })
    }

    /// Sends one batch via the streaming endpoint. `onPart` maps each content
    /// delta onto the progress bar; if the answer arrives truncated we append
    /// a "continue" user message and re-request (same conversation) until the
    /// JSON array is complete or `maxContinuations` is exhausted.
    private static func requestBatch(messages: [[String: Any]],
                                     batch: [Card],
                                     cardRanges: [CardRange],
                                     model: String,
                                     provider: String,
                                     state: BatchState,
                                     totalCards: Int,
                                     expectedOutputChars: Int,
                                     collector: BatchCollector,
                                     progress: @escaping (Double) -> Void,
                                     isCancelled: @escaping () -> Bool,
                                     onPhase: @escaping (AIReviewPhase) -> Void,
                                     continuation: Int,
                                     batchLabel: String,
                                     onDone: @escaping () -> Void,
                                     onCancel: @escaping () -> Void) {
        if isCancelled() {
            OpenRouterClient.shared.cancelActiveStream()
            onCancel()
            return
        }

        let baseFraction = Double(state.processedCards) / Double(totalCards)
        let intraRange = min(1.0, 1.0 / Double(totalCards))
        var charsThisRequest = 0
        var lastReported = -1.0

        OpenRouterClient.shared.sendStreamingMessages(
            messages: messages,
            tools: nil,
            model: model,
            onPart: { part in
                switch part {
                case .reasoning:
                    // Reasoning models spend time emitting "thinking" deltas
                    // before any content; surface that to the UI.
                    onPhase(.thinking)
                case .content(let text):
                    if !text.isEmpty {
                        onPhase(.answering)
                        charsThisRequest += text.count
                        let intra = min(1.0, Double(charsThisRequest) / Double(expectedOutputChars))
                        let fraction = baseFraction + intraRange * intra
                        if fraction != lastReported {
                            lastReported = fraction
                            progress(fraction)
                        }
                    }
                }
            },
            completion: { result in
                switch result {
                case .failure(let error):
                    state.errors.append(Self.classifyFailure(error, batchLabel: batchLabel))
                    onDone()
                case .success(let stream):
                    let content = stream.content
                    let parsed = parse(content)
                    collector.valid.append(contentsOf: parsed.valid)
                    if !parsed.invalid.isEmpty {
                        let dropped = parsed.invalid.map { "\($0.file): \($0.error)" }
                        state.errors.append("\(batchLabel): dropped \(dropped.count) invalid AI finding(s): \(dropped.prefix(3).joined(separator: ", "))")
                    }
                    if quickLooksComplete(content) {
                        onDone()
                    } else if continuation < Self.maxContinuations {
                        var next = messages
                        next.append(["role": "assistant", "content": content])
                        next.append(["role": "user", "content": "Your previous answer was cut off and is incomplete. Continue from exactly where you stopped and return only the REMAINING findings as a JSON array (or [] if there are none). Do not repeat findings you already returned. Respond with JSON only."])
                        requestBatch(messages: next,
                                     batch: batch,
                                     cardRanges: cardRanges,
                                     model: model,
                                     provider: provider,
                                     state: state,
                                     totalCards: totalCards,
                                     expectedOutputChars: max(expectedOutputChars / 2, 600),
                                     collector: collector,
                                     progress: progress,
                                     isCancelled: isCancelled,
                                     onPhase: onPhase,
                                     continuation: continuation + 1,
                                     batchLabel: batchLabel,
                                     onDone: onDone,
                                     onCancel: onCancel)
                    } else {
                        state.errors.append("\(batchLabel) stayed incomplete after \(Self.maxContinuations) continuation(s); keeping the partial results.")
                        onDone()
                    }
                }
            })
    }

    /// Whether an answer looks like a finished JSON array (trailing "]"), so a
    /// mid-stream stop of reasoning models is not mistaken for completion.
    private static func quickLooksComplete(_ content: String) -> Bool {
        var cleaned = content.trimmingCharacters(in: .whitespacesAndNewlines)
        if cleaned.hasSuffix("```") {
            cleaned = String(cleaned.dropLast(3)).trimmingCharacters(in: .whitespacesAndNewlines)
        }
        return cleaned.hasSuffix("]")
    }

    /// Translates transport/model failures into user-friendly messages, calling
    /// out the common "ran out of credits" case so the user knows to top up.
    private static func classifyFailure(_ error: Error, batchLabel: String) -> String {
        let message = error.localizedDescription
        let lower = message.lowercased()
        if lower.contains("credit") || lower.contains("insufficient") || lower.contains("balance")
            || lower.contains("402") || lower.contains("429") || lower.contains("quota") {
            return "\(batchLabel): it looks like you are out of AI credits/quota — the provider refused the request (\(message)). Top up your account or switch model/provider in the AI Assistant window and run the scan again."
        }
        return "\(batchLabel) failed: \(message)"
    }

    private static func cardLineCount(_ card: Card) -> Int {
        var count = 1
        for ch in card.numberedText where ch == "\n" { count += 1 }
        return count
    }

    // MARK: - Prompt

    private static var systemPrompt: String {
        let ontology = knownCategories.joined(separator: ", ")
        return """
        You are an expert application-security researcher reviewing source code for an IDE security scanner.
        I will give you source code snippets. Every line is prefixed with its absolute line number: `NNNN| original text`.
        Identify genuine, exploitable security vulnerabilities ONLY — injection, cross-site scripting, insecure deserialization, hardcoded secrets, weak cryptography, SSRF, path traversal, command execution, unsafe reflection, authentication/authorization bypass, and similar.
        Ignore style, performance, naming, refactoring, and generic best-practice suggestions.
        Respond with ONLY a JSON array of findings. No commentary, no prose, no markdown fences. If there are no vulnerabilities in the snippets, respond with [].
        Each finding is a JSON object with EXACTLY these keys:
        {"line": int, "file": string, "category": string, "severity": "Critical"|"High"|"Medium"|"Low", "exploitability": "Critical"|"High"|"Medium"|"Low", "cross_file": bool, "function": string, "summary": string}
        Rules:
        - "line" must be the EXACT absolute line number of the vulnerable statement/expression, present verbatim in the snippets. Different vulnerabilities in different statements MUST use their own line numbers — never report several distinct issues against the same line unless they are genuinely the very same statement.
        - "file" must be the relative path or file name of the snippet that line belongs to (exactly one of the "### FILE:" headers).
        - "category" is a short, descriptive title naming the vulnerability (e.g. "SQL Injection", "Hardcoded Secret", "Command Injection"). Prefer one of these canonical names when it fits: \(ontology). If none fits, invent a concise, specific title that names the problem — never use "Other".
        - "function" is the enclosing function/method/class name, or an empty string if unknown.
        - "summary" is one concrete sentence, specific to this code.
        - "cross_file" is true only when the dangerous input clearly originates from a symbol declared in a different file than the snippet.
        - Report each distinct vulnerability exactly once — never duplicate.
        - If you are not confident a vulnerability is real, omit it.
        """
    }

    // MARK: - File enumeration & card building

    private static func enumerateSourceFiles(in root: URL) -> [URL] {
        SourceTree.enumerate(extensions: ProjectSourceIndex.scanExtensions, in: root)
    }

    private static func relativePath(of url: URL, under root: URL) -> String {
        let rootPath = root.standardizedFileURL.path
        let path = url.standardizedFileURL.path
        if path.hasPrefix(rootPath) {
            return String(path.dropFirst(rootPath.count).trimmingCharacters(in: CharacterSet(charactersIn: "/")))
        }
        return url.lastPathComponent
    }

    /// Cuts an array of source lines into contiguous chunks, each at most
    /// `budget` characters, trying to break at brace boundaries.
    private static func sliceChunks(of lines: [String], budget: Int) -> [[String]] {
        var chunks: [[String]] = []
        var current: [String] = []
        var chars = 0
        for line in lines {
            if !current.isEmpty && chars + line.count + 1 > budget {
                chunks.append(current)
                current = []
                chars = 0
            }
            current.append(line)
            chars += line.count + 1
        }
        if !current.isEmpty { chunks.append(current) }
        return chunks
    }

    // MARK: - Parsing & validation

    private struct ValidatedFinding {
        let card: Card
        let line: Int
        let category: String
        let severity: ScanFinding.Severity
        let exploitability: ScanFinding.Severity
        let crossFile: Bool
        let function: String
        let summary: String
    }

    private struct ParseOutcome {
        let valid: [ValidatedFinding]
        let invalid: [(file: String, error: String)]
    }

    /// Extracts the JSON array from a model answer (tolerating markdown
    /// fences), decodes it, and validates every record against the file it
    /// points at.
    private static func parse(_ content: String) -> ParseOutcome {
        var valid: [ValidatedFinding] = []
        var invalid: [(String, String)] = []
        guard let array = extractJSONArray(from: content),
              let findings = try? JSONDecoder().decode([ParsedFinding].self, from: array) else {
            invalid.append(("batch", "response was not a JSON array: \(String(content.prefix(120)))"))
            return ParseOutcome(valid: [], invalid: invalid)
        }
        for f in findings {
            guard let line = f.line, line > 0 else {
                invalid.append((f.file ?? "?", "missing or invalid line"))
                continue
            }
            let category = normalizedCategory(f.category ?? "")
            let severity = parseSeverity(f.severity) ?? .high
            let exploitability = parseSeverity(f.exploitability) ?? severity
            let function = (f.function ?? "").trimmingCharacters(in: .whitespacesAndNewlines)
            let summary = (f.summary ?? "").trimmingCharacters(in: .whitespacesAndNewlines)
            guard !summary.isEmpty else {
                invalid.append((f.file ?? "?", "line \(line) had no summary"))
                continue
            }
            valid.append(ValidatedFinding(card: Card(fileURL: URL(fileURLWithPath: f.file ?? ""),
                                                     relativePath: f.file ?? "",
                                                     startLine: line,
                                                     numberedText: "",
                                                     digest: ""),
                                          line: line,
                                          category: category,
                                          severity: severity,
                                          exploitability: exploitability,
                                          crossFile: f.cross_file ?? false,
                                          function: function,
                                          summary: summary))
        }
        return ParseOutcome(valid: valid, invalid: invalid)
    }

    private static func extractJSONArray(from content: String) -> Data? {
        let trimmed = content.trimmingCharacters(in: .whitespacesAndNewlines)
        if let start = trimmed.firstIndex(of: "["), let end = trimmed.lastIndex(of: "]"), start < end {
            // Prefer the outer-most bracket region (handles code-fence noise).
            let slice = trimmed[start...end]
            return Data(slice.utf8)
        }
        // Fenced form fallback: ```json … ``` or ``` … ```.
        let lines = content.components(separatedBy: "\n")
        var jsonLines: [String] = []
        var inFence = false
        for line in lines {
            let stripped = line.trimmingCharacters(in: .whitespaces)
            if stripped.hasPrefix("```") {
                if inFence { break }
                inFence = true
                continue
            }
            if inFence { jsonLines.append(line) }
        }
        if inFence && !jsonLines.isEmpty {
            return Data(jsonLines.joined(separator: "\n").utf8)
        }
        return nil
    }

    /// Maps a model-supplied category on to the canonical ontology label when it
    /// clearly matches one; otherwise keeps the model's own title (capped) so
    /// the user sees a meaningful description instead of a generic "Other".
    private static func normalizedCategory(_ raw: String) -> String {
        let candidate = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !candidate.isEmpty else { return "Other" }
        let lowered = candidate.lowercased()
        for known in knownCategories where known.lowercased() == lowered { return known }
        for known in knownCategories {
            let k = known.lowercased()
            if lowered.contains(k) || k.contains(lowered) { return known }
        }
        return String(candidate.prefix(60))
    }

    private static func parseSeverity(_ raw: String?) -> ScanFinding.Severity? {
        switch (raw ?? "").lowercased() {
        case "critical", "3", "c": return .critical
        case "high", "2", "h": return .high
        case "medium", "1", "m": return .medium
        case "low", "0", "l": return .low
        default: return nil
        }
    }

    /// Accepts only findings whose reported line is inside a card we actually
    /// sent in THIS batch, rewriting them into `ScanFinding`s rooted at the
    /// real file URL. Line spans alone are ambiguous (every file starts at
    /// line 1), so the reported file name disambiguates which card the model
    /// meant.
    private static func appendValidated(findings: inout [ScanFinding],
                                        from parsed: [ValidatedFinding],
                                        batch: [Card],
                                        cardRanges: [CardRange]) {
        for v in parsed {
            guard let range = resolveRange(for: v, batch: batch, cardRanges: cardRanges) else { continue }
            let card = range.card
            let function = v.function.isEmpty ? card.fileURL.lastPathComponent : v.function
            findings.append(ScanFinding(
                fileURL: card.fileURL,
                line: v.line,
                function: function,
                category: v.category,
                message: v.summary,
                taint: nil,
                severity: v.severity,
                exploitability: v.exploitability,
                reachable: true,
                taintPath: nil,
                ignored: false,
                scanningSource: "AI",
                crossFile: v.crossFile
            ))
        }
    }

    /// Finds the card a validated finding refers to: constrained to cards of
    /// the current batch whose line span covers the reported line, preferring
    /// whichever also matches the file name the model supplied.
    private static func resolveRange(for v: ValidatedFinding,
                                     batch: [Card],
                                     cardRanges: [CardRange]) -> CardRange? {
        let batchRanges = cardRanges.filter { range in
            batch.contains(where: { card in
                card.fileURL == range.card.fileURL
                    && card.startLine == range.card.startLine
                    && card.relativePath == range.card.relativePath
            })
        }
        let lineMatches = batchRanges.filter { v.line >= $0.card.startLine && v.line <= $0.endLine }
        let hint = v.card.relativePath.trimmingCharacters(in: .whitespacesAndNewlines)
        if !hint.isEmpty {
            let hintBase = URL(fileURLWithPath: hint).lastPathComponent
            if let direct = lineMatches.first(where: {
                $0.card.relativePath == hint
                    || $0.card.fileURL.lastPathComponent == hintBase
                    || $0.card.relativePath.contains(hintBase)
            }) {
                return direct
            }
        }
        return lineMatches.first
    }

    // MARK: - De-duplication

    /// Drops AI findings that target a line the built-in scanner already reported
    /// (same file AND same line — regardless of category, so nothing is shown
    /// twice), then removes AI-vs-AI duplicates keeping the first occurrence.
    /// Paths are canonicalised (symlinks + standardisation) so a subtle path
    /// representation difference between the scanner and the AI runner can
    /// never defeat the de-duplication.
    static func dedupe(_ ai: [ScanFinding], against existing: [ScanFinding]) -> [ScanFinding] {
        let occupiedLines = Set(existing.map { locationKey($0) })
        var seen = Set<String>()
        var result: [ScanFinding] = []
        for f in ai {
            let location = locationKey(f)
            if occupiedLines.contains(location) { continue }
            let key = findingKey(f)
            guard !seen.contains(key) else { continue }
            seen.insert(key)
            result.append(f)
        }
        return result
    }

    /// Canonical key for "this line in this file": identical for both scanner
    /// engines so cross-engine de-duplication is reliable.
    static func locationKey(_ f: ScanFinding) -> String {
        "\(canonicalPath(f.fileURL))|\(f.line)"
    }

    private static func findingKey(_ f: ScanFinding) -> String {
        "\(canonicalPath(f.fileURL))|\(f.line)|\(f.category.lowercased())|\(f.function)"
    }

    private static func canonicalPath(_ url: URL) -> String {
        url.standardizedFileURL.resolvingSymlinksInPath().path
    }

    // MARK: - On-disk cache

    private static func cacheDirectory() -> URL? {
        let fm = FileManager.default
        guard let base = try? fm.url(for: .applicationSupportDirectory, in: .userDomainMask,
                                     appropriateFor: nil, create: true) else { return nil }
        let dir = base.appendingPathComponent("Karma Pro/AI Findings Cache", isDirectory: true)
        try? fm.createDirectory(at: dir, withIntermediateDirectories: true)
        return dir
    }

    private static func sha256(_ text: String) -> String {
        SHA256.hash(data: Data(text.utf8)).map { String(format: "%02x", $0) }.joined()
    }

    private static func modelSlug(_ model: String) -> String {
        let allowed = model.map { $0.isLetter || $0.isNumber ? $0 : "_" }
        return String(allowed).prefix(64).description
    }

    private static func cacheFileURL(batch: [Card], provider: String, model: String) -> URL? {
        guard let dir = cacheDirectory() else { return nil }
        let modelDir = dir.appendingPathComponent(modelSlug(model), isDirectory: true)
        try? FileManager.default.createDirectory(at: modelDir, withIntermediateDirectories: true)
        let digests = batch.map { $0.digest }.joined(separator: "-")
        return modelDir.appendingPathComponent("\(provider)-\(sha256(digests)).json")
    }

    private static func storeCachedFindings(_ valid: [ValidatedFinding], for batch: [Card], provider: String, model: String) {
        guard let url = cacheFileURL(batch: batch, provider: provider, model: model) else { return }
        let entries = valid.map { ["line": $0.line, "category": $0.category, "severity": $0.severity.rawValue,
                                   "exploitability": $0.exploitability.rawValue, "cross_file": $0.crossFile,
                                   "function": $0.function, "summary": $0.summary] as [String: Any] }
        let payload = ["cards": batch.map(\.digest), "findings": entries] as [String: Any]
        guard let data = try? JSONSerialization.data(withJSONObject: payload) else { return }
        try? data.write(to: url, options: .atomic)
    }

    /// Returns the cached, validated findings for a batch, or nil when there is
    /// no usable cache (so the batch must be sent to the model again).
    private static func loadCachedFindings(for batch: [Card], provider: String, model: String)
        -> [ValidatedFinding]? {
        guard let url = cacheFileURL(batch: batch, provider: provider, model: model),
              let data = try? Data(contentsOf: url),
              let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let cards = obj["cards"] as? [String] else { return nil }
        guard cards == batch.map(\.digest),
              let entries = obj["findings"] as? [[String: Any]] else { return nil }
        let valid = entries.compactMap { entry -> ValidatedFinding? in
            guard let line = entry["line"] as? Int,
                  let category = entry["category"] as? String,
                  let sevRaw = entry["severity"] as? Int,
                  let severity = ScanFinding.Severity(rawValue: sevRaw),
                  let summary = entry["summary"] as? String else { return nil }
            let expRaw = entry["exploitability"] as? Int
            return ValidatedFinding(card: Card(fileURL: URL(fileURLWithPath: ""), relativePath: "",
                                               startLine: line, numberedText: "", digest: ""),
                                    line: line, category: category, severity: severity,
                                    exploitability: expRaw.flatMap(ScanFinding.Severity.init) ?? severity,
                                    crossFile: entry["cross_file"] as? Bool ?? false,
                                    function: entry["function"] as? String ?? "",
                                    summary: summary)
        }
        return valid
    }
}
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
    /// escaping per-batch completion closures. Batches run concurrently, so
    /// every access is guarded by a lock.
    private final class BatchState {
        private let lock = NSLock()
        private var storedFindings: [ScanFinding] = []
        private var storedErrors: [String] = []
        private var storedProcessedCards = 0

        var findings: [ScanFinding] {
            lock.lock(); defer { lock.unlock() }
            return storedFindings
        }

        var errors: [String] {
            lock.lock(); defer { lock.unlock() }
            return storedErrors
        }

        var processedCards: Int {
            lock.lock(); defer { lock.unlock() }
            return storedProcessedCards
        }

        func addFindings(_ items: [ScanFinding]) {
            guard !items.isEmpty else { return }
            lock.lock(); storedFindings.append(contentsOf: items); lock.unlock()
        }

        func addError(_ message: String) {
            lock.lock(); storedErrors.append(message); lock.unlock()
        }

        func completedBatch(_ count: Int) {
            lock.lock(); storedProcessedCards += count; lock.unlock()
        }
    }

    /// Accumulates a single batch's findings across continuation requests.
    private final class BatchCollector {
        var valid: [ValidatedFinding] = []
    }

    /// When a model stops mid-answer we push a "continue" prompt (keeping the
    /// conversation history) up to this many times before giving up on a batch.
    private static let maxContinuations = 2

    /// Bumped whenever the way a finding is attached to a file changes, so
    /// cache entries written by an older build are not reused: they may name
    /// the wrong file.
    private static let cacheVersion = 2

    /// Extra attempts for a batch whose request failed with a transient
    /// transport/provider error. The batch is otherwise dropped for the run.
    private static let maxTransportRetries = 2

    /// Delay before each transport retry (index = retry number - 1).
    private static let transportRetryDelays: [Double] = [2, 8]

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

    /// One card is one contiguous slice of one file, handed to the model as
    /// its own unit of code. 24k characters usually hold a whole function, so
    /// a vulnerability whose source and sink sit in it usually arrives in one
    /// piece.
    private static let cardCharBudget = 24_000
    /// How much code one request may carry: two full cards.
    private static let batchCharBudget = 48_000
    /// How many files one request may carry. A project routinely holds many
    /// files of the same name, and the model mixes them up when it sees many
    /// at once, so a request stays small even when the files are.
    private static let maxCardsPerBatch = 4
    private static let maxFileChars = 1_000_000   // mirrors VulnerabilityScanner's guard

    /// Per-request budget for one batch. A local model may need minutes to
    /// produce its first token and minutes more to finish a long answer.
    private static let firstByteTimeout: Double = 120
    private static let totalTimeout: Double = 600

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
        let provider = client.provider.name

        let files = enumerateSourceFiles(in: projectRoot)
        var cards: [Card] = []
        var cardRanges: [CardRange] = []
        var skippedFiles = 0

        // Binds cached results to the tree they were scanned from: two checkouts
        // sharing a relative path and identical text are still different code,
        // and the model names files loosely enough that a shared cache entry
        // could be re-resolved onto the other checkout's copy.
        let rootKey = sha256(canonicalRootKey(projectRoot))

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
                let digest = sha256("\(provider)|\(model)|\(rootKey)|\(rel)\n\(numbered)")
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
            if !pending.isEmpty && (pending.count >= maxCardsPerBatch
                                    || pendingChars + card.numberedText.count > batchCharBudget) {
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
            // The built-in scanner's rows and the AI's rows are merged, so a
            // vulnerability both engines found is one row naming both.
            let merged = mergeEngines(dedupe(state.findings), into: existingFindings)
            completion(AIRunResult(findings: merged,
                                   cardsProcessed: state.processedCards,
                                   cardsTotal: totalCards,
                                   errors: state.errors,
                                   cancelled: cancelled))
        }

        let scheduler = BatchScheduler(batches: batches,
                                       cardRanges: cardRanges,
                                       model: model,
                                       provider: provider,
                                       state: state,
                                       totalCards: totalCards,
                                       progress: progress,
                                       isCancelled: isCancelled,
                                       onPhase: onPhase,
                                       finish: finish,
                                       maxConcurrent: client.provider.maxConcurrentRequests)
        scheduler.start()
    }

    // MARK: - Concurrent batch runner

    /// Runs the independent batch requests with a bounded number of concurrent
    /// in-flight calls, dispatching the next batch as soon as one finishes. All
    /// coordination happens on a private serial queue, so the shared
    /// `BatchState` and the launch cursor need no additional locking.
    private final class BatchScheduler {
        private let batches: [[Card]]
        private let cardRanges: [CardRange]
        private let model: String
        private let provider: String
        private let state: BatchState
        private let totalCards: Int
        private let progress: (Double) -> Void
        private let isCancelled: () -> Bool
        private let onPhase: (AIReviewPhase) -> Void
        private let finish: (Bool) -> Void
        private let maxConcurrent: Int

        private let queue = DispatchQueue(label: "app.karmapro.ai.security-scan")
        private var nextIndex = 0
        private var inFlight = 0
        private var finished = false
        private var sawCancellation = false
        private var requestedCancellation = false

        init(batches: [[Card]], cardRanges: [CardRange], model: String, provider: String,
             state: BatchState, totalCards: Int, progress: @escaping (Double) -> Void,
             isCancelled: @escaping () -> Bool, onPhase: @escaping (AIReviewPhase) -> Void,
             finish: @escaping (Bool) -> Void, maxConcurrent: Int) {
            self.batches = batches
            self.cardRanges = cardRanges
            self.model = model
            self.provider = provider
            self.state = state
            self.totalCards = totalCards
            self.progress = progress
            self.isCancelled = isCancelled
            self.onPhase = onPhase
            self.finish = finish
            self.maxConcurrent = max(1, min(maxConcurrent, max(batches.count, 1)))
        }

        func start() {
            queue.async { self.pump() }
        }

        /// Fills free slots with new batches and finalises once every batch has
        /// completed. Runs only on `queue`.
        private func pump() {
            guard !finished else { return }
            if isCancelled() { sawCancellation = true }
            if sawCancellation {
                abortIfNeeded()
                // Stop launching and finish once the running requests drain.
                guard inFlight == 0 else { return }
                finished = true
                finish(true)
                return
            }
            while inFlight < maxConcurrent && nextIndex < batches.count {
                let index = nextIndex
                nextIndex += 1
                inFlight += 1
                runBatch(index)
            }
            guard inFlight == 0, nextIndex >= batches.count else { return }
            finished = true
            finish(false)
        }

        /// Cancels the requests still running once, so a Stop aborts them
        /// immediately instead of waiting for them to finish.
        private func abortIfNeeded() {
            guard !requestedCancellation else { return }
            requestedCancellation = true
            OpenRouterClient.shared.cancelActiveStream(scope: .scanner)
        }

        /// Called once a batch — including any continuation requests — has fully
        /// completed. The accounting is done inline, but the next pump is hopped
        /// onto `queue` so a cache-hit batch (which completes synchronously
        /// inside the launch loop) can never re-enter `pump`.
        private func batchFinished() {
            inFlight -= 1
            if isCancelled() { sawCancellation = true }
            queue.async { self.pump() }
        }

        /// Queues an error message from a background callback so it is recorded
        /// on `queue`, in order, before the run finalises.
        private func recordError(_ message: String) {
            queue.async { self.state.addError(message) }
        }

        private func runBatch(_ index: Int) {
            let batch = batches[index]

            // Honour the on-disk cache first so unchanged code is not billed twice.
            if let cached = AISecurityScanner.loadCachedFindings(for: batch, provider: provider, model: model) {
                var collected: [ScanFinding] = []
                AISecurityScanner.appendValidated(findings: &collected, from: cached,
                                                  batch: batch, cardRanges: cardRanges)
                state.addFindings(collected)
                state.completedBatch(batch.count)
                progress(Double(state.processedCards) / Double(totalCards))
                batchFinished()
                return
            }

            let batchText = batch.map { card in
                let end = card.startLine + AISecurityScanner.cardLineCount(card) - 1
                return "### FILE: \(card.relativePath) (absolute lines \(card.startLine)-\(end))\n\(card.numberedText)"
            }.joined(separator: "\n\n")

            // Rough token estimate for the reply, used to map streamed character
            // deltas onto intra-batch progress so the bar moves as the model types.
            let expectedOutputChars = max(600, batchText.count / 3)
            let collector = BatchCollector()
            let batchLabel = "Batch \(index + 1)/\(batches.count)"

            AISecurityScanner.requestBatch(
                messages: [["role": "system", "content": AISecurityScanner.systemPrompt],
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
                recordError: { message in self.recordError(message) },
                continuation: 0,
                attempt: 0,
                batchLabel: batchLabel,
                onDone: {
                    self.queue.async {
                        // Resolve every finding to its real card BEFORE caching:
                        // absolute line numbers alone match every file's first
                        // chunk, so the resolved path is what keeps cached
                        // findings attributed to the right file next time.
                        var ambiguousCount = 0
                        let resolved = collector.valid.compactMap { v -> ValidatedFinding? in
                            guard let r = AISecurityScanner.resolveValidated(v, batch: batch,
                                                                           cardRanges: self.cardRanges) else { return nil }
                            if r.ambiguous { ambiguousCount += 1 }
                            return r.finding
                        }
                        if !resolved.isEmpty {
                            AISecurityScanner.storeCachedFindings(resolved, for: batch,
                                                                  provider: self.provider, model: self.model)
                            var collected: [ScanFinding] = []
                            AISecurityScanner.appendValidated(findings: &collected, from: resolved,
                                                             batch: batch, cardRanges: self.cardRanges)
                            if ambiguousCount > 0 {
                                self.recordError("\(batchLabel): \(ambiguousCount) finding(s) named a file that exists in several directories and could not be told apart - attached to the closest match.")
                            }
                            self.state.addFindings(collected)
                        }
                        self.state.completedBatch(batch.count)
                        self.progress(Double(self.state.processedCards) / Double(self.totalCards))
                        self.batchFinished()
                    }
                },
                onCancel: {
                    self.queue.async { self.batchFinished() }
                })
        }
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
                                     recordError: @escaping (String) -> Void,
                                     continuation: Int,
                                     attempt: Int,
                                     batchLabel: String,
                                     onDone: @escaping () -> Void,
                                     onCancel: @escaping () -> Void) {
        if isCancelled() {
            OpenRouterClient.shared.cancelActiveStream(scope: .scanner)
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
            scope: .scanner,
            firstByteTimeout: Self.firstByteTimeout,
            totalTimeout: Self.totalTimeout,
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
                    // A cancelled request is not an error: the scan was stopped
                    // or a sibling request was aborted.
                    if Self.isCancellation(error) { onCancel(); return }
                    // A transient refusal (rate limit, upstream 5xx, dropped
                    // connection) is retried with backoff rather than dropping
                    // the batch; a permanent error is reported immediately.
                    if Self.isTransientFailure(error), attempt < Self.maxTransportRetries {
                        let delay = Self.transportRetryDelays[min(attempt, Self.transportRetryDelays.count - 1)]
                        DispatchQueue.global().asyncAfter(deadline: .now() + delay) {
                            if isCancelled() { onCancel(); return }
                            requestBatch(messages: messages,
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
                                         recordError: recordError,
                                         continuation: continuation,
                                         attempt: attempt + 1,
                                         batchLabel: batchLabel,
                                         onDone: onDone,
                                         onCancel: onCancel)
                        }
                        return
                    }
                    recordError(Self.classifyFailure(error, batchLabel: batchLabel))
                    onDone()
                case .success(let stream):
                    let content = stream.content
                    let parsed = parse(content)
                    collector.valid.append(contentsOf: parsed.valid)
                    if parsed.salvaged && !stream.interrupted && continuation == 0 && !parsed.valid.isEmpty {
                        recordError("\(batchLabel): the answer was cut off - recovered \(parsed.valid.count) finding(s) from the part that arrived.")
                    }
                    if !parsed.invalid.isEmpty {
                        let dropped = parsed.invalid.map { "\($0.file): \($0.error)" }
                        recordError("\(batchLabel): dropped \(dropped.count) invalid AI finding(s): \(dropped.prefix(3).joined(separator: ", "))")
                    }
                    if quickLooksComplete(content) {
                        onDone()
                    } else if stream.interrupted {
                        // The connection died mid-answer: keep what arrived
                        // rather than paying for another request to continue.
                        recordError("\(batchLabel): the connection dropped mid-answer - kept the \(parsed.valid.count) finding(s) that had arrived.")
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
                                     recordError: recordError,
                                     continuation: continuation + 1,
                                     attempt: attempt,
                                     batchLabel: batchLabel,
                                     onDone: onDone,
                                     onCancel: onCancel)
                    } else {
                        recordError("\(batchLabel) stayed incomplete after \(Self.maxContinuations) continuation(s); keeping the partial results.")
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

    /// True when a failed request may succeed on a retry: rate limiting,
    /// upstream 5xx, a dropped/timed-out connection, or an empty stream.
    /// A missing/unauthorised key, a bad model name or exhausted credits are
    /// permanent and are not retried.
    private static func isTransientFailure(_ error: Error) -> Bool {
        // Transport errors carry the reason in the code, which the message
        // alone does not: "Could not connect to the server." (-1004) and
        // "…hostname could not be found." (-1003) are both worth a retry.
        let ns = error as NSError
        if ns.domain == NSURLErrorDomain {
            switch ns.code {
            case NSURLErrorTimedOut, NSURLErrorCannotConnectToHost, NSURLErrorCannotFindHost,
                 NSURLErrorNetworkConnectionLost, NSURLErrorDNSLookupFailed,
                 NSURLErrorNotConnectedToInternet, NSURLErrorDataNotAllowed,
                 NSURLErrorSecureConnectionFailed:
                return true
            case NSURLErrorCancelled:
                return false
            default:
                break
            }
        }
        let lower = error.localizedDescription.lowercased()
        if lower.contains("credit") || lower.contains("insufficient") || lower.contains("balance")
            || lower.contains("402") || lower.contains("unauthorized") || lower.contains("401")
            || lower.contains("not found") || lower.contains("no api key") {
            return false
        }
        if lower.contains("429") || lower.contains("rate limit") || lower.contains("too many")
            || lower.contains("quota") {
            return true
        }
        if lower.contains("500") || lower.contains("502") || lower.contains("503") || lower.contains("504")
            || lower.contains("timeout") || lower.contains("timed out")
            || lower.contains("connection") || lower.contains("network")
            || lower.contains("empty response") || lower.contains("overloaded")
            || lower.contains("temporarily") || lower.contains("unavailable") {
            return true
        }
        return false
    }

    /// True when the failure is only the request being cancelled (the scan was
    /// stopped, or a sibling request was aborted), not a real error.
    private static func isCancellation(_ error: Error) -> Bool {
        let ns = error as NSError
        return ns.domain == NSURLErrorDomain && ns.code == NSURLErrorCancelled
    }

    /// Turns transport/model failures into user-facing messages. A rate limit
    /// (HTTP 429) is retried before this runs, so what is left here is either a
    /// permanent refusal or a retried-and-still-failing transient error.
    private static func classifyFailure(_ error: Error, batchLabel: String) -> String {
        let message = error.localizedDescription
        let lower = message.lowercased()
        if lower.contains("credit") || lower.contains("insufficient") || lower.contains("balance")
            || lower.contains("402") || lower.contains("quota") {
            return "\(batchLabel): it looks like you are out of AI credits/quota — the provider refused the request (\(message)). Top up your account or switch model/provider in the AI Assistant window and run the scan again."
        }
        if lower.contains("429") || lower.contains("rate limit") || lower.contains("too many") {
            return "\(batchLabel): the provider rate-limited the request (\(message)). The scan will be faster if you retry when the limit resets, or switch provider/model in the AI Assistant window."
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
        - "file" must be COPIED VERBATIM from the "### FILE:" header that the line belongs to, including any directory path exactly as written there. Never shorten it to just the file name. If two snippets share a file name, only the full path distinguishes them.
        - "category" is a short, descriptive title naming the vulnerability (e.g. "SQL Injection", "Hardcoded Secret", "Command Injection"). Prefer one of these canonical names when it fits: \(ontology). If none fits, invent a concise, specific title that names the problem — never use "Other".
        - "function" is the enclosing function/method/class name exactly as it is spelled in the code, or an empty string if unknown.
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

    /// Stable identity for a scanned tree, used to scope cache entries. Symlinks
    /// are resolved so the same directory reached by two paths is one tree.
    private static func canonicalRootKey(_ root: URL) -> String {
        root.standardizedFileURL.resolvingSymlinksInPath().path
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
        /// Relative path of the card this finding was resolved to (nil while
        /// still tied only to the model-reported file name). Persisted with the
        /// cache so a cached finding is never re-attributed to a different file
        /// that merely shares the same line numbers.
        let resolvedPath: String?

        init(card: Card, line: Int, category: String, severity: ScanFinding.Severity,
             exploitability: ScanFinding.Severity, crossFile: Bool, function: String,
             summary: String, resolvedPath: String? = nil) {
            self.card = card
            self.line = line
            self.category = category
            self.severity = severity
            self.exploitability = exploitability
            self.crossFile = crossFile
            self.function = function
            self.summary = summary
            self.resolvedPath = resolvedPath
        }
    }

    private struct ParseOutcome {
        let valid: [ValidatedFinding]
        let invalid: [(file: String, error: String)]
        /// True when the answer was not a JSON array and the records were
        /// salvaged from the complete objects it did contain.
        let salvaged: Bool
    }

    /// Extracts the JSON array from a model answer (tolerating markdown
    /// fences), decodes every record individually, and validates each against
    /// the file it points at — one malformed entry drops only itself.
    private static func parse(_ content: String) -> ParseOutcome {
        var valid: [ValidatedFinding] = []
        var invalid: [(String, String)] = []
        guard let extracted = extractJSONRecords(from: content) else {
            invalid.append(("batch", "response was not a JSON array: \(String(content.prefix(120)))"))
            return ParseOutcome(valid: [], invalid: invalid, salvaged: false)
        }
        for record in extracted.records {
            let file = coerceString(record["file"]) ?? "?"
            guard let line = coerceLine(record["line"]), line > 0 else {
                invalid.append((file, "missing or invalid line"))
                continue
            }
            let category = normalizedCategory(coerceString(record["category"]) ?? "")
            let severity = parseSeverity(coerceString(record["severity"])) ?? .high
            let exploitability = parseSeverity(coerceString(record["exploitability"])) ?? severity
            let function = (coerceString(record["function"]) ?? "").trimmingCharacters(in: .whitespacesAndNewlines)
            let summary = (coerceString(record["summary"]) ?? "").trimmingCharacters(in: .whitespacesAndNewlines)
            guard !summary.isEmpty else {
                invalid.append((file, "line \(line) had no summary"))
                continue
            }
            valid.append(ValidatedFinding(card: Card(fileURL: URL(fileURLWithPath: file),
                                                     relativePath: file,
                                                     startLine: line,
                                                     numberedText: "",
                                                     digest: ""),
                                          line: line,
                                          category: category,
                                          severity: severity,
                                          exploitability: exploitability,
                                          crossFile: coerceBool(record["cross_file"]) ?? false,
                                          function: function,
                                          summary: summary))
        }
        return ParseOutcome(valid: valid, invalid: invalid, salvaged: extracted.salvaged)
    }

    /// Bracket regions to consider, outermost first: each fenced block, then
    /// every balanced `[` … `]` span at progressively deeper starts.
    private static func jsonCandidates(from content: String) -> [Data] {
        var out: [Data] = []
        for block in fencedBlocks(in: content) {
            out.append(Data(block.utf8))
        }
        out.append(contentsOf: balancedArraySlices(in: content))
        return out
    }

    /// The records of a model answer, plus whether they had to be salvaged
    /// from an answer that was not a complete JSON array.
    private struct ExtractedRecords {
        let records: [[String: Any]]
        /// True when the answer was not a JSON array and the records came from
        /// the complete objects it did contain.
        let salvaged: Bool
    }

    /// Lenient extraction: JSONSerialization instead of a strict `Codable`
    /// decode, so a single bad record value (string line number, string
    /// boolean, …) no longer poisons the whole batch. Escalating repairs cover
    /// a trailing comma and single-quoted keys. An answer that is not an array
    /// (a cut-off array, or a continuation returning bare objects) is salvaged
    /// object by object, so the records it did contain are not lost.
    private static func extractJSONRecords(from content: String) -> ExtractedRecords? {
        for candidate in jsonCandidates(from: content) {
            if let records = findingsArray(candidate) {
                return ExtractedRecords(records: records, salvaged: false)
            }
            for repaired in repairPasses(candidate) {
                if let records = findingsArray(repaired) {
                    return ExtractedRecords(records: records, salvaged: false)
                }
            }
        }
        var recovered: [[String: Any]] = []
        for slice in looseObjectSlices(in: content) {
            if let record = (try? JSONSerialization.jsonObject(with: slice)) as? [String: Any] {
                recovered.append(record)
            }
        }
        return recovered.isEmpty ? nil : ExtractedRecords(records: recovered, salvaged: true)
    }

    /// Every balanced top-level `{` … `}` span, so the complete objects of a
    /// cut-off answer can be decoded one by one. Nested objects belong to
    /// their parent and are not returned separately.
    private static func looseObjectSlices(in content: String) -> [Data] {
        let chars = Array(content)
        var slices: [Data] = []
        var start = 0
        while start < chars.count {
            guard chars[start] == "{" else { start += 1; continue }
            var depth = 0
            var inString = false
            var escaped = false
            var end = start
            var closed = false
            while end < chars.count {
                let c = chars[end]
                if inString {
                    if escaped { escaped = false }
                    else if c == "\\" { escaped = true }
                    else if c == "\"" { inString = false }
                } else if c == "\"" {
                    inString = true
                } else if c == "{" {
                    depth += 1
                } else if c == "}" {
                    depth -= 1
                    if depth == 0 {
                        slices.append(Data(String(chars[start...end]).utf8))
                        closed = true
                        break
                    }
                }
                end += 1
            }
            if !closed { break }   // the tail was cut off
            start = end + 1
        }
        return slices
    }

    private static func findingsArray(_ data: Data) -> [[String: Any]]? {
        let obj = (try? JSONSerialization.jsonObject(with: data)) ?? nil
        return obj as? [[String: Any]]
    }

    private static func repairPasses(_ data: Data) -> [Data] {
        let s = String(decoding: data, as: UTF8.self)
        let noCommas = s.replacingOccurrences(of: ",\\s*([\\]}])", with: "$1",
                                             options: .regularExpression)
        var passes = [noCommas]
        if !noCommas.contains("\"") {
            passes.append(noCommas.replacingOccurrences(of: "'", with: "\""))
        }
        return passes.map { Data($0.utf8) }
    }

    private static func coerceString(_ v: Any?) -> String? {
        v as? String
    }

    private static func coerceLine(_ v: Any?) -> Int? {
        if let n = v as? Int { return n }
        if let d = v as? Double, d == d.rounded() { return Int(d) }
        if let s = v as? String { return Int(s.trimmingCharacters(in: .whitespaces)) }
        return nil
    }

    private static func coerceBool(_ v: Any?) -> Bool? {
        if let b = v as? Bool { return b }
        if let s = v as? String {
            switch s.trimmingCharacters(in: .whitespaces).lowercased() {
            case "true", "yes", "1": return true
            case "false", "no", "0": return false
            default: return nil
            }
        }
        return nil
    }

    /// Bodies of ```…``` fenced blocks, in order.
    private static func fencedBlocks(in content: String) -> [String] {
        var blocks: [String] = []
        var current: [String] = []
        var inFence = false
        for line in content.components(separatedBy: "\n") {
            if line.trimmingCharacters(in: .whitespaces).hasPrefix("```") {
                if inFence {
                    blocks.append(current.joined(separator: "\n"))
                    current = []
                }
                inFence.toggle()
                continue
            }
            if inFence { current.append(line) }
        }
        return blocks
    }

    /// Every balanced top-level `[` … `]` span, tried at each `[` so an array
    /// preceded by prose brackets is still found.
    private static func balancedArraySlices(in content: String) -> [Data] {
        let chars = Array(content)
        var slices: [Data] = []
        for start in chars.indices where chars[start] == "[" {
            var depth = 0
            var inString = false
            var escaped = false
            var i = start
            while i < chars.count {
                let c = chars[i]
                if inString {
                    if escaped { escaped = false }
                    else if c == "\\" { escaped = true }
                    else if c == "\"" { inString = false }
                } else if c == "\"" {
                    inString = true
                } else if c == "[" {
                    depth += 1
                } else if c == "]" {
                    depth -= 1
                    if depth == 0 {
                        slices.append(Data(String(chars[start...i]).utf8))
                        break
                    }
                }
                i += 1
            }
        }
        return slices
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
            guard let range = resolveRange(for: v, batch: batch, cardRanges: cardRanges)?.range else { continue }
            let card = range.card
            let function = v.function.isEmpty ? card.fileURL.lastPathComponent : v.function
            findings.append(ScanFinding(
                fileURL: card.fileURL,
                line: clampedLine(v.line, to: range),
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

    /// Marks a validated finding with the relative path of the card it truly
    /// belongs to, so caching can persist a stable file identity. Unresolvable
    /// findings (line outside every sent card) return nil. The second value
    /// says whether the file had to be guessed.
    private static func resolveValidated(_ v: ValidatedFinding,
                                         batch: [Card],
                                         cardRanges: [CardRange]) -> (finding: ValidatedFinding, ambiguous: Bool)? {
        guard let match = resolveRange(for: v, batch: batch, cardRanges: cardRanges) else { return nil }
        let range = match.range
        let finding = ValidatedFinding(card: v.card,
                                       line: clampedLine(v.line, to: range),
                                       category: v.category,
                                       severity: v.severity,
                                       exploitability: v.exploitability,
                                       crossFile: v.crossFile,
                                       function: v.function,
                                       summary: v.summary,
                                       resolvedPath: range.card.relativePath)
        return (finding, match.ambiguous)
    }

    /// A validated finding matched to the card it belongs to.
    private struct RangeMatch {
        let range: CardRange
        /// True when several same-named files matched and neither the line nor
        /// the function name separated them, so one of them was guessed.
        let ambiguous: Bool
    }

    /// Finds the card a validated finding refers to, within the current batch.
    ///
    /// The path the model named decides, and on its own: a finding whose path
    /// IS a card's relative path (or a path ending with it, as an absolute
    /// path does) belongs to that card, never to a same-named file elsewhere.
    /// Projects routinely hold many files of the same name, and the reported
    /// line cannot tell them apart because every file starts at line 1 - so
    /// falling back to the file name alone is what used to pile a whole
    /// batch's findings onto whichever same-named file came first.
    ///
    /// Only a bare file name leaves the choice open, and then the reported
    /// line and the reported function name pick between the files sharing it.
    private static func resolveRange(for v: ValidatedFinding,
                                     batch: [Card],
                                     cardRanges: [CardRange]) -> RangeMatch? {
        let batchRanges = cardRanges.filter { range in
            batch.contains(where: { card in
                card.fileURL == range.card.fileURL
                    && card.startLine == range.card.startLine
                    && card.relativePath == range.card.relativePath
            })
        }
        let hint = normalizedHint(v.resolvedPath ?? v.card.relativePath)
        guard !hint.isEmpty else { return nil }

        // The path the model named, exactly.
        let exact = batchRanges.filter { $0.card.relativePath == hint }
        if !exact.isEmpty { return pick(v, in: exact) }

        // The same path written from a parent directory, or as an absolute one.
        let byPath = batchRanges.filter { namesPath(hint, $0.card.relativePath) }
        if !byPath.isEmpty {
            // The most specific match wins: "src/util.c" over "a/src/util.c".
            let longest = byPath.map { $0.card.relativePath.count }.max() ?? 0
            return pick(v, in: byPath.filter { $0.card.relativePath.count == longest })
        }

        // Only a bare file name was given: the files that share it.
        let base = URL(fileURLWithPath: hint).lastPathComponent
        let named = batchRanges.filter { $0.card.fileURL.lastPathComponent == base }
        guard !named.isEmpty else { return nil }
        return pick(v, in: named)
    }

    /// Picks the card a finding belongs to among candidates that may come from
    /// several files: the reported line picks the file that holds it, the
    /// reported function name the file that declares it. When neither
    /// separates them the closest span wins and the guess is reported.
    private static func pick(_ v: ValidatedFinding, in ranges: [CardRange]) -> RangeMatch {
        let covering = ranges.filter { v.line >= $0.card.startLine && v.line <= $0.endLine }
        let byLine = covering.isEmpty ? ranges : covering
        if namesOneFile(byLine) {
            return RangeMatch(range: closest(to: v.line, in: byLine), ambiguous: false)
        }
        let byFunction = byLine.filter { declares($0.card, function: v.function) }
        if namesOneFile(byFunction) {
            return RangeMatch(range: closest(to: v.line, in: byFunction), ambiguous: false)
        }
        let declaring = ranges.filter { declares($0.card, function: v.function) }
        if namesOneFile(declaring) {
            return RangeMatch(range: closest(to: v.line, in: declaring), ambiguous: false)
        }
        return RangeMatch(range: closest(to: v.line, in: byLine), ambiguous: !namesOneFile(byLine))
    }

    /// True when the card's code declares (or calls) the named function. This
    /// is what tells two same-named files apart when the model gave only the
    /// file name.
    private static func declares(_ card: Card, function: String) -> Bool {
        guard !function.isEmpty else { return false }
        let pattern = "\\b" + NSRegularExpression.escapedPattern(for: function) + "\\s*\\("
        return card.numberedText.range(of: pattern, options: .regularExpression) != nil
    }

    /// The path the model named, cleaned up: quotes and whitespace removed and
    /// a leading "./" dropped, so it compares with a card's relative path.
    private static func normalizedHint(_ raw: String) -> String {
        var hint = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        hint = hint.trimmingCharacters(in: CharacterSet(charactersIn: "\"'`"))
        hint = hint.trimmingCharacters(in: .whitespacesAndNewlines)
        while hint.hasPrefix("./") { hint.removeFirst(2) }
        return hint
    }

    /// True when the path the model named is the card's path, or ends with it
    /// (the model may answer with an absolute path). The comparison ignores
    /// case, as a file system does.
    private static func namesPath(_ hint: String, _ path: String) -> Bool {
        if hint == path { return true }
        guard !path.isEmpty else { return false }
        let h = hint.lowercased()
        let p = path.lowercased()
        return h == p || h.hasSuffix("/" + p)
    }

    /// The candidate whose span is nearest the reported line, the path
    /// breaking ties so the same answer always lands on the same file.
    private static func closest(to line: Int, in ranges: [CardRange]) -> CardRange {
        ranges.sorted { lhs, rhs in
            let dl = distance(from: line, to: lhs)
            let dr = distance(from: line, to: rhs)
            if dl != dr { return dl < dr }
            return lhs.card.relativePath < rhs.card.relativePath
        }[0]
    }

    /// True when every candidate card belongs to the same file, so the name
    /// identified one file even though that file may span several cards.
    private static func namesOneFile(_ ranges: [CardRange]) -> Bool {
        guard let first = ranges.first?.card.relativePath else { return false }
        return ranges.allSatisfy { $0.card.relativePath == first }
    }

    /// How far the reported line sits outside a card's span (0 when inside).
    private static func distance(from line: Int, to range: CardRange) -> Int {
        if line < range.card.startLine { return range.card.startLine - line }
        if line > range.endLine { return line - range.endLine }
        return 0
    }

    /// Pulls the reported line into the resolved card's span, so it never points
    /// outside the file the finding was placed in.
    private static func clampedLine(_ line: Int, to range: CardRange) -> Int {
        min(max(line, range.card.startLine), range.endLine)
    }

    // MARK: - De-duplication & engine merge

    /// Removes AI-vs-AI duplicates (same file, line, category and function),
    /// keeping the first occurrence. Paths are canonicalised (symlinks +
    /// standardisation) so a subtle path representation difference between
    /// two answers cannot defeat the de-duplication.
    static func dedupe(_ ai: [ScanFinding]) -> [ScanFinding] {
        var seen = Set<String>()
        var result: [ScanFinding] = []
        for f in ai {
            let key = findingKey(f)
            guard !seen.contains(key) else { continue }
            seen.insert(key)
            result.append(f)
        }
        return result
    }

    /// Merges the AI's findings into the built-in scanner's rows: a
    /// vulnerability both engines reported (same file, line and category)
    /// becomes a single row whose engine label names both, e.g.
    /// "Heuristic, AI". AI findings the built-in scanner did not report are
    /// kept as rows of their own.
    static func mergeEngines(_ ai: [ScanFinding], into builtIn: [ScanFinding]) -> [ScanFinding] {
        var rows = builtIn
        var indexByLocation: [String: [Int]] = [:]
        for (index, f) in rows.enumerated() where f.scanningSource != "AI" {
            indexByLocation[locationKey(f), default: []].append(index)
        }
        var credited = Set<Int>()
        var aiOnly: [ScanFinding] = []
        for f in ai {
            guard let candidates = indexByLocation[locationKey(f)] else {
                aiOnly.append(f)
                continue
            }
            guard let index = candidates.first(where: { sameIssue(rows[$0].category, f.category) }) else {
                aiOnly.append(f)
                continue
            }
            guard !credited.contains(index) else { continue }   // that row already names the AI
            credited.insert(index)
            rows[index].scanningSource = engineLabel(rows[index].scanningSource, f.scanningSource)
        }
        return rows + aiOnly
    }

    /// True when both labels name the same kind of issue, so the two rows are
    /// one finding reported by two engines.
    private static func sameIssue(_ lhs: String, _ rhs: String) -> Bool {
        let a = lhs.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        let b = rhs.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        if a == b { return true }
        return !a.isEmpty && !b.isEmpty && (a.contains(b) || b.contains(a))
    }

    /// Adds an engine to a row's label, keeping the order the engines were
    /// found in and never naming the same one twice.
    private static func engineLabel(_ existing: String, _ adding: String) -> String {
        let parts = existing.split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }
        if parts.contains(where: { $0.caseInsensitiveCompare(adding) == .orderedSame }) { return existing }
        return existing.isEmpty ? adding : existing + ", " + adding
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
        // The version is part of the name: entries written by an older build may
        // name the wrong file and must not be reused.
        return modelDir.appendingPathComponent("\(provider)-v\(cacheVersion)-\(sha256(digests)).json")
    }

    private static func storeCachedFindings(_ valid: [ValidatedFinding], for batch: [Card], provider: String, model: String) {
        guard let url = cacheFileURL(batch: batch, provider: provider, model: model) else { return }
        let entries = valid.map { ["line": $0.line, "file": $0.resolvedPath ?? $0.card.relativePath,
                                   "category": $0.category, "severity": $0.severity.rawValue,
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
            // The file is the only stable bridge to a real card (line numbers
            // alone match many files). A cache entry without it comes from a
            // pre-fix run and is discarded so the finding is re-requested.
            guard let file = entry["file"] as? String, !file.isEmpty else { return nil }
            guard let line = entry["line"] as? Int,
                  let category = entry["category"] as? String,
                  let sevRaw = entry["severity"] as? Int,
                  let severity = ScanFinding.Severity(rawValue: sevRaw),
                  let summary = entry["summary"] as? String else { return nil }
            let expRaw = entry["exploitability"] as? Int
            return ValidatedFinding(card: Card(fileURL: URL(fileURLWithPath: file),
                                               relativePath: file,
                                               startLine: line, numberedText: "", digest: ""),
                                    line: line, category: category, severity: severity,
                                    exploitability: expRaw.flatMap(ScanFinding.Severity.init) ?? severity,
                                    crossFile: entry["cross_file"] as? Bool ?? false,
                                    function: entry["function"] as? String ?? "",
                                    summary: summary)
        }
        // Any missing file identity means this batch's cache is stale: refuse it.
        guard valid.count == entries.count else { return nil }
        return valid
    }
}
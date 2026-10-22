// by cipher.org.uk
import Foundation

/// A model entry returned by the OpenRouter `/models` endpoint.
struct OpenRouterModel: Codable {
    let id: String
    let name: String?
}

struct OpenRouterModelsResponse: Decodable {
    let data: [OpenRouterModel]
}

/// Response shape of `POST /chat/completions` (OpenAI-compatible) plus the
/// error payload OpenRouter returns for bad keys/models/credits.
struct OpenRouterChatResponse: Decodable {
    struct Choice: Decodable {
        struct Message: Decodable {
            let role: String?
            let content: String?
        }
        let message: Message?
    }
    struct ErrorPayload: Decodable {
        let message: String?
        let code: Int?
    }
    let choices: [Choice]?
    let error: ErrorPayload?
}

/// Fully assembled result of one streaming round: the model's answer text
/// and/or the tool calls it wants executed.
struct OpenRouterStreamResult {
    var reasoning: String = ""
    var content: String = ""
    var toolCalls: [OpenRouterToolCall] = []
    /// True when the stream was cut short (timeout, dropped connection) after
    /// part of the answer had already arrived.
    var interrupted: Bool = false
    var isEmpty: Bool { content.isEmpty && reasoning.isEmpty && toolCalls.isEmpty }
}

/// The kind of delta received from a streaming response. Reasoning models
/// (e.g. qwen3, DeepSeek-R1, Claude with thinking) emit `delta.reasoning`
/// "thinking" chunks first — often hundreds of them with `delta.content` still
/// empty — before the actual answer chunks arrive.
enum OpenRouterStreamPart {
    case content(String)
    case reasoning(String)
}

/// URLSessionDataDelegate that parses OpenRouter's Server-Sent-Events stream
/// and emits every text delta as it arrives, so the UI can render the model's
/// answer in real time instead of waiting for the full response.
///
/// Wire format (verified against live captures):
///   ": OPENROUTER PROCESSING\n\n"                       — keepalive comment
///   "data: {\"choices\":[{\"delta\":{\"content\":\"1\"}}]}\n\n"
///   "data: {\"choices\":[{\"delta\":{\"content\":\"\",\"reasoning\":\"…\"}}]}\n\n"
///   "data: [DONE]\n\n"
final class OpenRouterStreamDelegate: NSObject, URLSessionDataDelegate {
    private var buffer: [UInt8] = []
    private var statusCode = 200
    private var contentAssembled = ""
    private var reasoningAssembled = ""
    private var toolAccums: [Int: (id: String, name: String, args: String)] = [:]
    private var errorMessage: String?
    private var finished = false
    private var gotResponse = false
    private var watchdog: DispatchWorkItem?
    var task: URLSessionDataTask?
    var session: URLSession?
    private let onPart: (OpenRouterStreamPart) -> Void
    private let onFinish: (Result<OpenRouterStreamResult, Error>) -> Void

    init(onPart: @escaping (OpenRouterStreamPart) -> Void,
         onFinish: @escaping (Result<OpenRouterStreamResult, Error>) -> Void) {
        self.onPart = onPart
        self.onFinish = onFinish
    }

    /// Arms a timer that force-fails the request when nothing has arrived
    /// within `seconds` (a firewall dropping the connection, or a local server
    /// still loading its model), so the UI never waits forever. CFNetwork
    /// hands over the response together with the first body byte, so this is
    /// in practice a first-token budget.
    func startWatchdog(seconds: Double = 60) {
        watchdog?.cancel()
        let item = DispatchWorkItem { [weak self] in
            guard let self = self, !self.finished, !self.gotResponse else { return }
            self.finish(.failure(AIError(
                "No response from the AI endpoint within \(Int(seconds))s — connection timed out. " +
                "Check your network and firewall, and if you are using a local server (e.g. Ollama) " +
                "make sure it is running, then try again.")))
            self.task?.cancel()
        }
        watchdog = item
        DispatchQueue.global().asyncAfter(deadline: .now() + seconds, execute: item)
    }

    private func stopWatchdog() {
        watchdog?.cancel()
        watchdog = nil
    }

    /// Cancels the in-flight request. The normal `didCompleteWithError`
    /// callback usually reports the cancellation; a fallback timer plus
    /// session invalidation guarantee the completion fires either way, so the
    /// Stop button always works.
    func cancel() {
        watchdog?.cancel()
        task?.cancel()
        DispatchQueue.global().asyncAfter(deadline: .now() + 1.5) { [weak self] in
            guard let self = self, !self.finished else { return }
            self.session?.invalidateAndCancel()
            // Mirror didCompleteWithError semantics: keep any partial content.
            if !self.contentAssembled.isEmpty || !self.reasoningAssembled.isEmpty || !self.toolAccums.isEmpty {
                self.finish(.success(OpenRouterStreamResult(reasoning: self.reasoningAssembled,
                                                            content: self.contentAssembled,
                                                            toolCalls: self.assembledToolCalls())))
            } else {
                self.finish(.failure(NSError(domain: NSURLErrorDomain,
                                             code: NSURLErrorCancelled,
                                             userInfo: [NSLocalizedDescriptionKey: "Request cancelled."])))
            }
        }
    }

    func urlSession(_ session: URLSession, dataTask: URLSessionDataTask,
                    didReceive response: URLResponse,
                    completionHandler: @escaping (URLSession.ResponseDisposition) -> Void) {
        statusCode = (response as? HTTPURLResponse)?.statusCode ?? 200
        gotResponse = true
        stopWatchdog()
        completionHandler(.allow)
    }

    /// Session invalidation (from `cancel()`'s fallback or session teardown)
    /// still routes through the completion exactly once.
    func urlSession(_ session: URLSession, didBecomeInvalidWithError error: Error?) {
        guard !finished else { return }
        if !contentAssembled.isEmpty || !reasoningAssembled.isEmpty || !toolAccums.isEmpty {
            finish(.success(OpenRouterStreamResult(reasoning: reasoningAssembled,
                                                   content: contentAssembled,
                                                   toolCalls: assembledToolCalls())))
        } else {
            finish(.failure(error ?? AIError("Connection invalidated.")))
        }
    }

    func urlSession(_ session: URLSession, dataTask: URLSessionDataTask, didReceive data: Data) {
        processBytes(data)
    }

    func urlSession(_ session: URLSession, task: URLSessionTask, didCompleteWithError error: Error?) {
        if let error = error {
            // Keep whatever streamed so far: a timed-out or dropped connection
            // still carries the part of the answer that did arrive, which the
            // scanner salvages into findings instead of losing the batch.
            let ns = error as NSError
            let cancelled = ns.domain == NSURLErrorDomain && ns.code == NSURLErrorCancelled
            if !contentAssembled.isEmpty || !reasoningAssembled.isEmpty || !toolAccums.isEmpty {
                finish(.success(OpenRouterStreamResult(reasoning: reasoningAssembled,
                                                       content: contentAssembled,
                                                       toolCalls: assembledToolCalls(),
                                                       interrupted: !cancelled)))
            } else {
                finish(.failure(error))
            }
            return
        }
        complete()
    }

    // MARK: - Parsing (internal so it can be smoke-tested without network)

    /// Buffers incoming bytes and processes every complete line.
    func processBytes(_ data: Data) {
        buffer.append(contentsOf: data)
        while let nl = buffer.firstIndex(of: 0x0A) {
            let lineData = Data(buffer[buffer.startIndex..<nl])
            buffer.removeSubrange(buffer.startIndex...nl)
            if let line = String(data: lineData, encoding: .utf8) {
                handleLine(line)
            }
        }
    }

    /// Called when the stream ends cleanly; processes any leftover buffered
    /// line, then reports the assembled text or an error.
    func complete() {
        if !buffer.isEmpty, let line = String(bytes: buffer, encoding: .utf8) {
            buffer.removeAll()
            handleLine(line)
        }
        if let msg = errorMessage {
            finish(.failure(AIError(msg)))
            return
        }
        if statusCode != 200 {
            if let msg = OpenRouterStreamDelegate.errorMessageBody(Data(buffer)) {
                finish(.failure(AIError(msg)))
            } else {
                finish(.failure(AIError("The AI endpoint returned HTTP \(statusCode).")))
            }
            return
        }
        if contentAssembled.isEmpty && reasoningAssembled.isEmpty && toolAccums.isEmpty {
            finish(.failure(AIError("Empty response from the AI endpoint.")))
            return
        }
        finish(.success(OpenRouterStreamResult(reasoning: reasoningAssembled,
                                               content: contentAssembled,
                                               toolCalls: assembledToolCalls())))
    }

    private func handleLine(_ raw: String) {
        let line = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        if line.isEmpty || line.hasPrefix(":") { return } // blank line / SSE keepalive comment
        guard line.hasPrefix("data:") else { return }
        let payload = line.dropFirst("data:".count).trimmingCharacters(in: .whitespacesAndNewlines)
        if payload == "[DONE]" {
            if let msg = errorMessage {
                finish(.failure(AIError(msg)))
            } else {
                finish(.success(OpenRouterStreamResult(reasoning: reasoningAssembled,
                                                       content: contentAssembled,
                                                       toolCalls: assembledToolCalls())))
            }
            return
        }
        guard let data = payload.data(using: .utf8),
              let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else { return }
        if let err = obj["error"] as? [String: Any],
           let msg = err["message"] as? String {
            errorMessage = msg
            finish(.failure(AIError(msg)))
            return
        }
        if let choices = obj["choices"] as? [[String: Any]],
           let first = choices.first,
           let delta = first["delta"] as? [String: Any] {
            if let content = delta["content"] as? String, !content.isEmpty {
                contentAssembled += content
                onPart(.content(content))
            }
            if let reasoning = delta["reasoning"] as? String, !reasoning.isEmpty {
                reasoningAssembled += reasoning
                onPart(.reasoning(reasoning))
            }
            // Streaming tool calls arrive as fragments keyed by index.
            if let tcs = delta["tool_calls"] as? [[String: Any]] {
                for tc in tcs {
                    let idx = tc["index"] as? Int ?? 0
                    var acc = toolAccums[idx] ?? ("", "", "")
                    if let id = tc["id"] as? String, !id.isEmpty { acc.id = id }
                    if let fn = tc["function"] as? [String: Any] {
                        if let n = fn["name"] as? String { acc.name += n }
                        if let a = fn["arguments"] as? String { acc.args += a }
                    }
                    toolAccums[idx] = acc
                }
            }
        }
    }

    /// Materialises the accumulated tool-call fragments. Some models emit
    /// arguments that are not JSON (e.g. single-quoted dicts); a strict
    /// provider rejects the follow-up round echoing that back, so repair it.
    private func assembledToolCalls() -> [OpenRouterToolCall] {
        toolAccums.sorted { $0.key < $1.key }.map {
            OpenRouterToolCall(id: $0.value.id.isEmpty ? "call_\($0.key)" : $0.value.id,
                               name: $0.value.name,
                               arguments: Self.sanitizeToolArguments($0.value.args))
        }
    }

    /// Returns `raw` when it already parses as a JSON object; otherwise tries
    /// quote repair, then falls back to `{}` so a malformed call degrades to
    /// "no arguments" instead of a 400 from the provider.
    static func sanitizeToolArguments(_ raw: String) -> String {
        let s = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        if isJSONObject(s) { return s }
        // Single-quoted Python-style dict: swap quotes only when no double
        // quote exists, which would make naive swapping ambiguous.
        if !s.contains("\"") {
            let repaired = s.replacingOccurrences(of: "'", with: "\"")
            if isJSONObject(repaired) { return repaired }
        }
        return "{}"
    }

    private static func isJSONObject(_ s: String) -> Bool {
        guard let data = s.data(using: .utf8),
              let obj = try? JSONSerialization.jsonObject(with: data) else { return false }
        return obj is [String: Any]
    }

    private func finish(_ result: Result<OpenRouterStreamResult, Error>) {
        guard !finished else { return }
        finished = true
        stopWatchdog()
        // Invalidate on the main queue (never from inside a delegate callback)
        // to break the session↔delegate retain cycle once the stream is over.
        DispatchQueue.main.async { [weak self] in
            self?.session?.finishTasksAndInvalidate()
        }
        onFinish(result)
    }

    /// Extracts `error.message` from a buffered non-streaming JSON body.
    static func errorMessageBody(_ data: Data) -> String? {
        guard let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let err = obj["error"] as? [String: Any],
              let msg = err["message"] as? String else { return nil }
        return msg
    }
}

/// Minimal OpenAI-compatible API client: chat completions + model listing.
/// The provider list is OpenRouter and Ollama (both shipped, neither editable)
/// plus any endpoints the user adds in the AI window. Each provider keeps its
/// own base URL, API key and selected model, persisted in UserDefaults and
/// keyed by the provider's stable id, so switching providers never loses a key
/// and renaming one never orphans it.
final class OpenRouterClient {
    static let shared = OpenRouterClient()
    /// Endpoint used for the OpenRouter provider.
    static let openRouterBaseURLString = "https://openrouter.ai/api/v1"
    /// Default value of the Ollama server field.
    static let ollamaBaseURLString = "http://localhost:11434/v1"

    /// Used when the OpenRouter model list cannot be fetched (offline / no key
    /// yet). Other providers ship no fallback list.
    static let fallbackModels: [String] = AIProviderConfig.openRouterFallbacks

    private let defaults: UserDefaults

    init(defaults: UserDefaults = .standard) {
        self.defaults = defaults
        Self.migrateLegacyKeysIfNeeded(defaults)
    }

    /// Brings older storage forward. Two shapes existed before the provider
    /// list became user-extensible: a single key/model under a fixed prefix,
    /// and (briefly) key/model stored per provider *name*. Both are moved to
    /// per-provider-id slots, which survive a rename, and the old provider
    /// selector becomes a provider id. Runs once.
    private static func migrateLegacyKeysIfNeeded(_ defaults: UserDefaults) {
        // Resolve which provider the stored values belonged to. The pre-list
        // selector held a name ("OpenRouter" / "Ollama"); anything else is a
        // provider added by a build that has since been replaced, so fall back
        // to OpenRouter rather than lose the key.
        let legacyName = defaults.string(forKey: "AI.provider") ?? ""
        let legacyConfig = AIProviderConfig.builtins.first { $0.name == legacyName } ?? .openRouter

        let migrated = "AI.providerIDMigrationDone"
        if !defaults.bool(forKey: migrated) {
            // Shape 1: "OpenRouter.apiKey" / "OpenRouter.model".
            if let key = defaults.string(forKey: "OpenRouter.apiKey"), !key.isEmpty {
                defaults.set(key, forKey: "AI.\(legacyConfig.id).apiKey")
            }
            if let model = defaults.string(forKey: "OpenRouter.model"), !model.isEmpty {
                defaults.set(model, forKey: "AI.\(legacyConfig.id).model")
            }
            if legacyConfig.isOllama, let url = defaults.string(forKey: "AI.baseURL"), !url.isEmpty {
                defaults.set(url, forKey: "AI.\(legacyConfig.id).baseURL")
            }
            // Shape 2: name-keyed values written by the previous build.
            for provider in AIProviderConfig.builtins {
                let oldKeyPrefix = "AI.\(provider.name)."
                let newKeyPrefix = "AI.\(provider.id)."
                for field in ["apiKey", "model", "baseURL"] {
                    if let value = defaults.string(forKey: oldKeyPrefix + field), !value.isEmpty {
                        // Shape 1 wins if it already wrote this slot.
                        if defaults.string(forKey: newKeyPrefix + field) == nil {
                            defaults.set(value, forKey: newKeyPrefix + field)
                        }
                    }
                    defaults.removeObject(forKey: oldKeyPrefix + field)
                }
            }
            defaults.removeObject(forKey: "OpenRouter.apiKey")
            defaults.removeObject(forKey: "OpenRouter.model")
            defaults.removeObject(forKey: "AI.baseURL")
            defaults.set(true, forKey: migrated)
        }

        // Keep the selected provider pointing at a real entry. Written even
        // when no provider was stored before: a key implies an intent to use
        // OpenRouter, and leaving the id unset would make the first launch's
        // selection implicit rather than recorded.
        let storedID = defaults.string(forKey: "AI.providerID") ?? ""
        if storedID.isEmpty, !legacyName.isEmpty || defaults.string(forKey: "AI.\(legacyConfig.id).apiKey") != nil {
            defaults.set(legacyConfig.id, forKey: "AI.providerID")
        }
    }

    /// The stored key for the current provider, so switching providers keeps
    /// each one's key instead of overwriting a shared slot. Keyed by the
    /// provider's stable id, so renaming it keeps the key.
    var apiKey: String {
        get { defaults.string(forKey: "AI.\(provider.id).apiKey") ?? "" }
        set { defaults.set(newValue, forKey: "AI.\(provider.id).apiKey") }
    }

    var selectedModel: String {
        get {
            let stored = defaults.string(forKey: "AI.\(provider.id).model") ?? ""
            if !stored.isEmpty { return stored }
            return provider.fallbackModels.first ?? ""
        }
        set { defaults.set(newValue, forKey: "AI.\(provider.id).model") }
    }

    /// The selected provider's id, persisted. Resolves through the store so a
    /// provider removed while selected falls back to OpenRouter rather than
    /// leaving the client pointing at a missing endpoint.
    var providerID: String {
        get { defaults.string(forKey: "AI.providerID") ?? AIProviderConfig.openRouter.id }
        set { defaults.set(newValue, forKey: "AI.providerID") }
    }

    /// The selected provider's configuration.
    var provider: AIProviderConfig {
        get { ProviderStore.shared.provider(id: providerID) ?? .openRouter }
        set { providerID = newValue.id }
    }

    /// The Ollama server URL stored for the Ollama preset. Ollama is shipped
    /// and not user-editable in the provider table, but its URL stays a stored
    /// value so a self-hosted server keeps working.
    var ollamaServerURLString: String {
        get {
            let stored = defaults.string(forKey: "AI.\(AIProviderConfig.ollama.id).baseURL") ?? ""
            if let normalized = ProviderStore.normalizeBaseURL(stored) {
                return normalized
            }
            return Self.ollamaBaseURLString
        }
        set {
            let normalized = ProviderStore.normalizeBaseURL(newValue) ?? Self.ollamaBaseURLString
            defaults.set(normalized, forKey: "AI.\(AIProviderConfig.ollama.id).baseURL")
        }
    }

    /// The active endpoint for the current provider. Ollama's URL is stored
    /// (its preset ships one); every other provider carries its own.
    var baseURL: URL {
        let raw = provider.isOllama ? ollamaServerURLString : provider.baseURL
        return URL(string: raw) ?? URL(string: Self.ollamaBaseURLString)!
    }

    /// True when talking to a local Ollama server.
    var isOllama: Bool { provider.isOllama }

    /// True when the endpoint demands a bearer key.
    var requiresAPIKey: Bool { provider.requiresAPIKey }

    /// True when the AI Assistant has a model picked and, for keyed providers,
    /// an API key entered. Reads the raw stored model (not `selectedModel`) so
    /// an untouched AI Assistant window counts as unconfigured.
    var isConfigured: Bool {
        guard !(defaults.string(forKey: "AI.\(provider.id).model") ?? "").isEmpty else { return false }
        if requiresAPIKey, apiKey.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty { return false }
        return true
    }

    /// In-flight streaming requests, keyed by a per-request token so several can
    /// run concurrently (the AI scanner issues three at a time) without one
    /// request's completion clearing another's slot. Each request carries the
    /// scope of its owner, so cancelling the Assistant's requests cannot kill
    /// the scanner's and vice versa.
    enum AIRequestScope { case assistant, scanner }

    private var activeStreams: [UUID: (stream: OpenRouterStreamDelegate, scope: AIRequestScope)] = [:]
    /// Non-streaming requests (`sendChat` fallback) are plain `URLSession`
    /// tasks with no delegate; they are tracked here so Stop can cancel them.
    private var activeChatTasks: [UUID: (task: URLSessionDataTask, scope: AIRequestScope)] = [:]
    /// Guards the two dictionaries above: requests are started from the main
    /// thread but completed from background URLSession callbacks.
    private let activeRequestLock = NSLock()

    /// True while any request of `scope` (or of any owner when nil) is in flight.
    func hasActiveRequest(scope: AIRequestScope? = nil) -> Bool {
        activeRequestLock.lock()
        defer { activeRequestLock.unlock() }
        if let scope = scope {
            return activeStreams.values.contains { $0.scope == scope }
                || activeChatTasks.values.contains { $0.scope == scope }
        }
        return !activeStreams.isEmpty || !activeChatTasks.isEmpty
    }

    private func registerStream(_ key: UUID, _ delegate: OpenRouterStreamDelegate, _ scope: AIRequestScope) {
        activeRequestLock.lock()
        activeStreams[key] = (delegate, scope)
        activeRequestLock.unlock()
    }

    private func unregisterStream(_ key: UUID) {
        activeRequestLock.lock()
        activeStreams.removeValue(forKey: key)
        activeRequestLock.unlock()
    }

    private func registerChatTask(_ key: UUID, _ task: URLSessionDataTask, _ scope: AIRequestScope) {
        activeRequestLock.lock()
        activeChatTasks[key] = (task, scope)
        activeRequestLock.unlock()
    }

    private func unregisterChatTask(_ key: UUID) {
        activeRequestLock.lock()
        activeChatTasks.removeValue(forKey: key)
        activeRequestLock.unlock()
    }

    /// Applies the endpoint-appropriate auth/identity headers: a keyed service
    /// gets the bearer key (plus OpenRouter's attribution headers, which are
    /// specific to it), local and other keyless servers get neither.
    private func applyCommonHeaders(to request: URLRequest, acceptSSE: Bool) -> URLRequest {
        var request = request
        let trimmedKey = apiKey.trimmingCharacters(in: .whitespacesAndNewlines)
        if !trimmedKey.isEmpty {
            request.setValue("Bearer \(trimmedKey)", forHTTPHeaderField: "Authorization")
        }
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        if acceptSSE {
            request.setValue("text/event-stream", forHTTPHeaderField: "Accept")
        }
        if provider.id == AIProviderConfig.openRouter.id {
            request.setValue("https://karmapro.app", forHTTPHeaderField: "HTTP-Referer")
            request.setValue("Karma Pro", forHTTPHeaderField: "X-Title")
        }
        return request
    }

    /// Sends a streaming (`stream: true`) chat completion. `onPart` fires for
    /// every text delta (answer content or reasoning "thinking" text) as it
    /// arrives (on a background queue); `completion` fires once at the end
    /// with the fully assembled result (content, reasoning, and any tool
    /// calls the model requested), or an error.
    /// Returns false if the request could not be started (completion already
    /// called with the failure reason).
    @discardableResult
    func sendStreamingMessages(messages: [[String: Any]], tools: [[String: Any]]?, model: String,
                               scope: AIRequestScope = .assistant,
                               firstByteTimeout: Double = 60,
                               totalTimeout: Double = 300,
                               onPart: @escaping (OpenRouterStreamPart) -> Void,
                               completion: @escaping (Result<OpenRouterStreamResult, Error>) -> Void) -> Bool {
        let trimmedKey = apiKey.trimmingCharacters(in: .whitespacesAndNewlines)
        if requiresAPIKey && trimmedKey.isEmpty {
            completion(.failure(AIError("No API key set. Enter your API key and click Connect.")))
            return false
        }

        var request = URLRequest(url: baseURL.appendingPathComponent("chat/completions"))
        request.httpMethod = "POST"
        request.timeoutInterval = totalTimeout
        request = applyCommonHeaders(to: request, acceptSSE: true)

        var body: [String: Any] = [
            "model": model,
            "messages": messages,
            "stream": true
        ]
        if let tools = tools, !tools.isEmpty {
            body["tools"] = tools
            body["tool_choice"] = "auto"
        }
        guard let payload = try? JSONSerialization.data(withJSONObject: body) else {
            completion(.failure(AIError("Could not encode the request.")))
            return false
        }
        request.httpBody = payload

        // The delegate MUST be attached here — a plain
        // `URLSession(configuration:)` has no delegate and its callbacks are
        // never delivered (the root cause of responses never appearing).
        let key = UUID()
        let delegate = OpenRouterStreamDelegate(onPart: onPart) { [weak self] result in
            self?.unregisterStream(key)
            completion(result)
        }
        let session = URLSession(configuration: .ephemeral, delegate: delegate, delegateQueue: nil)
        delegate.session = session
        registerStream(key, delegate, scope)
        let task = session.dataTask(with: request)
        delegate.task = task
        task.resume()
        delegate.startWatchdog(seconds: firstByteTimeout)
        return true
    }

    /// Convenience wrapper: system + user message, no tools.
    @discardableResult
    func sendChatStreaming(systemPrompt: String, userPrompt: String, model: String,
                           onPart: @escaping (OpenRouterStreamPart) -> Void,
                           completion: @escaping (Result<OpenRouterStreamResult, Error>) -> Void) -> Bool {
        sendStreamingMessages(
            messages: [["role": "system", "content": systemPrompt],
                       ["role": "user", "content": userPrompt]],
            tools: nil, model: model, onPart: onPart, completion: completion)
    }

    /// Cancels the in-flight requests of `scope` — streaming delegates and
    /// non-streaming fallback tasks alike (e.g. Stop button, window close).
    /// Scoping keeps one window's cancellation from killing another owner's
    /// requests (closing the Assistant must not abort a running AI scan).
    func cancelActiveStream(scope: AIRequestScope) {
        activeRequestLock.lock()
        let streams = activeStreams.filter { $0.value.scope == scope }.values.map(\.stream)
        let tasks = activeChatTasks.filter { $0.value.scope == scope }.values.map(\.task)
        activeRequestLock.unlock()
        for stream in streams { stream.cancel() }
        for task in tasks { task.cancel() }
    }

    /// Sends a (non-streaming) chat completion request and returns the
    /// assistant's message content.
    func sendChat(systemPrompt: String, userPrompt: String, model: String,
                  scope: AIRequestScope = .assistant,
                  completion: @escaping (Result<String, Error>) -> Void) {
        sendChatMessages(messages: [["role": "system", "content": systemPrompt],
                                    ["role": "user", "content": userPrompt]],
                         model: model, scope: scope, completion: completion)
    }

    /// Non-streaming counterpart of `sendStreamingMessages` that carries the
    /// full conversation (system + user + assistant + tool messages), so a
    /// fallback retry keeps the same context as the streaming request.
    func sendChatMessages(messages: [[String: Any]], model: String,
                          scope: AIRequestScope = .assistant,
                          completion: @escaping (Result<String, Error>) -> Void) {
        let trimmedKey = apiKey.trimmingCharacters(in: .whitespacesAndNewlines)
        if requiresAPIKey && trimmedKey.isEmpty {
            completion(.failure(AIError("No API key set. Enter your API key and click Connect.")))
            return
        }

        var request = URLRequest(url: baseURL.appendingPathComponent("chat/completions"))
        request.httpMethod = "POST"
        request.timeoutInterval = 180
        request = applyCommonHeaders(to: request, acceptSSE: false)

        let body: [String: Any] = [
            "model": model,
            "messages": messages,
            "stream": false
        ]
        do {
            request.httpBody = try JSONSerialization.data(withJSONObject: body)
        } catch {
            completion(.failure(error))
            return
        }

        let key = UUID()
        let task = URLSession.shared.dataTask(with: request) { data, _, error in
            self.unregisterChatTask(key)
            if let error = error {
                completion(.failure(error))
                return
            }
            guard let data = data else {
                completion(.failure(AIError("Empty response from the AI endpoint.")))
                return
            }
            if let decoded = try? JSONDecoder().decode(OpenRouterChatResponse.self, from: data),
               let content = decoded.choices?.first?.message?.content, !content.isEmpty {
                completion(.success(content))
                return
            }
            if let decoded = try? JSONDecoder().decode(OpenRouterChatResponse.self, from: data),
               let message = decoded.error?.message {
                completion(.failure(AIError(message)))
                return
            }
            let raw = String(data: data, encoding: .utf8) ?? "(unreadable response)"
            completion(.failure(AIError("Unexpected response from the AI endpoint: \(String(raw.prefix(400)))")))
        }
        registerChatTask(key, task, scope)
        task.resume()
    }

    /// Fetches the available model list; calls back with an empty array when
    /// the request fails (callers fall back to `fallbackModels`).
    func fetchModels(completion: @escaping ([OpenRouterModel]) -> Void) {
        var request = URLRequest(url: baseURL.appendingPathComponent("models"))
        request.httpMethod = "GET"
        request.timeoutInterval = 30
        let trimmedKey = apiKey.trimmingCharacters(in: .whitespacesAndNewlines)
        if !trimmedKey.isEmpty {
            request.setValue("Bearer \(trimmedKey)", forHTTPHeaderField: "Authorization")
        }

        URLSession.shared.dataTask(with: request) { data, _, _ in
            guard let data = data,
                  let decoded = try? JSONDecoder().decode(OpenRouterModelsResponse.self, from: data) else {
                completion([])
                return
            }
            completion(decoded.data)
        }.resume()
    }

    /// Probes a provider's connection for the "Test" button, checking the model
    /// list *and* a one-token chat completion. Both matter: a service can list
    /// models happily while denying every completion (unactivated account,
    /// missing entitlement), so a list-only check would report false success.
    /// Reports the first failure's message, which is what the user needs to act
    /// on. Never uses the stored key/model — it takes them as arguments so an
    /// unsaved row can be tested before it is committed.
    func testConnection(name: String, baseURL: URL, apiKey: String, model: String?,
                        requiresAPIKey: Bool,
                        completion: @escaping (Result<Int, Error>) -> Void) {
        var listRequest = URLRequest(url: baseURL.appendingPathComponent("models"))
        listRequest.httpMethod = "GET"
        listRequest.timeoutInterval = 20
        let trimmedKey = apiKey.trimmingCharacters(in: .whitespacesAndNewlines)
        if requiresAPIKey && trimmedKey.isEmpty {
            completion(.failure(AIError("This provider needs an API key.")))
            return
        }
        if !trimmedKey.isEmpty {
            listRequest.setValue("Bearer \(trimmedKey)", forHTTPHeaderField: "Authorization")
        }
        if name == AIProviderConfig.openRouter.name {
            listRequest.setValue("https://karmapro.app", forHTTPHeaderField: "HTTP-Referer")
            listRequest.setValue("Karma Pro", forHTTPHeaderField: "X-Title")
        }

        URLSession.shared.dataTask(with: listRequest) { data, response, error in
            if let error = error {
                completion(.failure(AIError("Could not reach \(baseURL.host ?? "the endpoint"): \(error.localizedDescription)")))
                return
            }
            let status = (response as? HTTPURLResponse)?.statusCode ?? 0
            guard let data = data,
                  let decoded = try? JSONDecoder().decode(OpenRouterModelsResponse.self, from: data) else {
                completion(.failure(AIError(Self.describeHTTPFailure(status: status, body: data))))
                return
            }
            let count = decoded.data.count
            guard let model = model, !model.isEmpty else {
                // No model chosen yet: the list check is all we can prove.
                completion(.success(count))
                return
            }
            // Confirm the model can actually be used.
            var chatRequest = URLRequest(url: baseURL.appendingPathComponent("chat/completions"))
            chatRequest.httpMethod = "POST"
            chatRequest.timeoutInterval = 60
            if !trimmedKey.isEmpty {
                chatRequest.setValue("Bearer \(trimmedKey)", forHTTPHeaderField: "Authorization")
            }
            chatRequest.setValue("application/json", forHTTPHeaderField: "Content-Type")
            let body: [String: Any] = [
                "model": model,
                "messages": [["role": "user", "content": "ping"]],
                "max_tokens": 1,
                "stream": false
            ]
            chatRequest.httpBody = try? JSONSerialization.data(withJSONObject: body)
            URLSession.shared.dataTask(with: chatRequest) { chatData, chatResponse, chatError in
                if let chatError = chatError {
                    completion(.failure(AIError("Model list OK (\(count) models), but the test request failed: \(chatError.localizedDescription)")))
                    return
                }
                let chatStatus = (chatResponse as? HTTPURLResponse)?.statusCode ?? 0
                if chatStatus == 200, let chatData = chatData,
                   let decoded = try? JSONDecoder().decode(OpenRouterChatResponse.self, from: chatData),
                   decoded.choices != nil {
                    completion(.success(count))
                    return
                }
                let reason = Self.describeHTTPFailure(status: chatStatus, body: chatData)
                completion(.failure(AIError("Model list OK (\(count) models), but \"\(model)\" was refused: \(reason)")))
            }.resume()
        }.resume()
    }

    /// Turns a failed response into the most specific message available, using
    /// the API's own error text when it sent one.
    private static func describeHTTPFailure(status: Int, body: Data?) -> String {
        if let body = body {
            if let decoded = try? JSONDecoder().decode(OpenRouterChatResponse.self, from: body),
               let message = decoded.error?.message {
                return message
            }
            if let object = try? JSONSerialization.jsonObject(with: body) as? [String: Any],
               let error = object["error"] as? [String: Any],
               let message = error["message"] as? String {
                return message
            }
        }
        switch status {
        case 401: return "The API key was rejected (401)."
        case 403: return "The key is valid but not allowed to use this model (403)."
        case 404: return "No such endpoint (404) — check the base URL."
        case 429: return "Rate limited (429)."
        default: return "The endpoint returned HTTP \(status)."
        }
    }
}

/// Convenience error type carrying a human-readable message.
struct AIError: LocalizedError {
    let message: String
    init(_ message: String) { self.message = message }
    var errorDescription: String? { message }
}

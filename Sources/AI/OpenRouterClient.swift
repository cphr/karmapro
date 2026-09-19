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

    /// Arms a timer that force-fails the request when no response headers
    /// arrive within `seconds` (e.g. a firewall silently dropping the
    /// connection), so the UI never waits forever.
    func startWatchdog(seconds: Double = 30) {
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
            // Cancelled: report what streamed so far (if anything) so the
            // partial response is kept in the UI.
            if (error as NSError).code == NSURLErrorCancelled,
               !contentAssembled.isEmpty || !reasoningAssembled.isEmpty || !toolAccums.isEmpty {
                finish(.success(OpenRouterStreamResult(reasoning: reasoningAssembled,
                                                       content: contentAssembled,
                                                       toolCalls: assembledToolCalls())))
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

    /// Materialises the accumulated tool-call fragments.
    private func assembledToolCalls() -> [OpenRouterToolCall] {
        toolAccums.sorted { $0.key < $1.key }.map {
            OpenRouterToolCall(id: $0.value.id.isEmpty ? "call_\($0.key)" : $0.value.id,
                               name: $0.value.name,
                               arguments: $0.value.args.isEmpty ? "{}" : $0.value.args)
        }
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

/// Which AI service the assistant talks to. Both speak the OpenAI-compatible
/// chat-completions protocol.
enum AIProvider: String {
    case openRouter = "OpenRouter"
    case ollama = "Ollama"
}

/// Minimal OpenRouter API client: chat completions + model listing.
/// Two providers are supported: the OpenRouter cloud API (API key required)
/// and a local Ollama server (editable server URL, no key). The provider, the
/// Ollama server URL, the API key and the user's selected model are persisted
/// in UserDefaults so they survive relaunches and can be changed at any time
/// from the AI window.
final class OpenRouterClient {
    static let shared = OpenRouterClient()
    /// Endpoint used for the OpenRouter provider.
    static let openRouterBaseURLString = "https://openrouter.ai/api/v1"
    /// Default value of the editable Ollama server field.
    static let ollamaBaseURLString = "http://localhost:11434/v1"

    /// Used when the model list cannot be fetched (offline / no key yet).
    static let fallbackModels: [String] = [
        "anthropic/claude-3.5-sonnet",
        "anthropic/claude-3.7-sonnet",
        "openai/gpt-4o",
        "openai/gpt-4o-mini",
        "openai/gpt-4-turbo",
        "google/gemini-flash-1.5",
        "google/gemini-pro-1.5",
        "meta-llama/llama-3.1-70b-instruct",
        "deepseek/deepseek-chat",
        "mistralai/mistral-large",
        "qwen/qwen-2.5-72b-instruct"
    ]

    private let defaults: UserDefaults

    init(defaults: UserDefaults = .standard) {
        self.defaults = defaults
    }

    var apiKey: String {
        get { defaults.string(forKey: "OpenRouter.apiKey") ?? "" }
        set { defaults.set(newValue, forKey: "OpenRouter.apiKey") }
    }

    var selectedModel: String {
        get {
            let stored = defaults.string(forKey: "OpenRouter.model") ?? ""
            return stored.isEmpty ? Self.fallbackModels[0] : stored
        }
        set { defaults.set(newValue, forKey: "OpenRouter.model") }
    }

    /// The selected provider ("OpenRouter" or "Ollama"), persisted.
    var provider: AIProvider {
        get { AIProvider(rawValue: defaults.string(forKey: "AI.provider") ?? "") ?? .openRouter }
        set { defaults.set(newValue.rawValue, forKey: "AI.provider") }
    }

    /// The Ollama server URL shown in the editable "Connect" field, persisted.
    /// Normalises common shortcuts (`localhost:11434` gains the required
    /// `/v1`); an OpenRouter URL or empty value falls back to the default.
    var ollamaServerURLString: String {
        get {
            let stored = defaults.string(forKey: "AI.baseURL") ?? ""
            if let normalized = Self.normalizeBaseURLString(stored),
               !normalized.contains("openrouter.ai") {
                return normalized
            }
            return Self.ollamaBaseURLString
        }
        set {
            let normalized = Self.normalizeBaseURLString(newValue) ?? Self.ollamaBaseURLString
            defaults.set(normalized, forKey: "AI.baseURL")
        }
    }

    /// Applies the normalisation rules described on `ollamaServerURLString`.
    static func normalizeBaseURLString(_ raw: String) -> String? {
        var s = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        if s.isEmpty { return nil }
        if !s.contains("://") { s = "http://" + s }
        guard var url = URL(string: s), let host = url.host, !host.isEmpty else { return nil }
        // Ollama's OpenAI-compatible routes live under /v1; accept the bare
        // server address and append it.
        if url.port == 11434 && !url.path.contains("v1") {
            url = URL(string: s.hasSuffix("/") ? s + "v1" : s + "/v1") ?? url
        }
        return url.absoluteString.hasSuffix("/") ? String(url.absoluteString.dropLast()) : url.absoluteString
    }

    /// The active endpoint for the current provider.
    var baseURL: URL {
        provider == .ollama
            ? URL(string: ollamaServerURLString) ?? URL(string: Self.ollamaBaseURLString)!
            : URL(string: Self.openRouterBaseURLString)!
    }

    /// True when talking to a local Ollama server.
    var isOllama: Bool { provider == .ollama }

    /// Only OpenRouter enforces an API key; Ollama needs none.
    var requiresAPIKey: Bool { provider == .openRouter }

    private var activeStream: OpenRouterStreamDelegate?
    /// Non-streaming requests (`sendChat` fallback) are plain `URLSession`
    /// tasks with no delegate; they are tracked here so Stop can cancel them.
    private var activeChatTask: URLSessionDataTask?

    /// True while any request (streaming or fallback) is in flight.
    var hasActiveRequest: Bool { activeStream != nil || activeChatTask != nil }

    /// Applies the endpoint-appropriate auth/identity headers: OpenRouter
    /// requires the bearer key plus its attribution headers, local servers
    /// get neither (an empty key simply sends no Authorization header).
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
        if requiresAPIKey {
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
                               onPart: @escaping (OpenRouterStreamPart) -> Void,
                               completion: @escaping (Result<OpenRouterStreamResult, Error>) -> Void) -> Bool {
        let trimmedKey = apiKey.trimmingCharacters(in: .whitespacesAndNewlines)
        if requiresAPIKey && trimmedKey.isEmpty {
            completion(.failure(AIError("No API key set. Enter your OpenRouter API key and click Connect.")))
            return false
        }

        var request = URLRequest(url: baseURL.appendingPathComponent("chat/completions"))
        request.httpMethod = "POST"
        request.timeoutInterval = 120
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
        let delegate = OpenRouterStreamDelegate(onPart: onPart) { [weak self] result in
            self?.activeStream = nil
            completion(result)
        }
        let session = URLSession(configuration: .ephemeral, delegate: delegate, delegateQueue: nil)
        delegate.session = session
        activeStream = delegate
        let task = session.dataTask(with: request)
        delegate.task = task
        task.resume()
        delegate.startWatchdog()
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

    /// Cancels an in-flight response — the streaming delegate and the
    /// non-streaming fallback task alike (e.g. Stop button, window close).
    func cancelActiveStream() {
        activeStream?.cancel()
        activeChatTask?.cancel()
    }

    /// Sends a (non-streaming) chat completion request and returns the
    /// assistant's message content.
    func sendChat(systemPrompt: String, userPrompt: String, model: String,
                  completion: @escaping (Result<String, Error>) -> Void) {
        sendChatMessages(messages: [["role": "system", "content": systemPrompt],
                                    ["role": "user", "content": userPrompt]],
                         model: model, completion: completion)
    }

    /// Non-streaming counterpart of `sendStreamingMessages` that carries the
    /// full conversation (system + user + assistant + tool messages), so a
    /// fallback retry keeps the same context as the streaming request.
    func sendChatMessages(messages: [[String: Any]], model: String,
                          completion: @escaping (Result<String, Error>) -> Void) {
        let trimmedKey = apiKey.trimmingCharacters(in: .whitespacesAndNewlines)
        if requiresAPIKey && trimmedKey.isEmpty {
            completion(.failure(AIError("No API key set. Enter your OpenRouter API key and click Connect.")))
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

        let task = URLSession.shared.dataTask(with: request) { data, _, error in
            self.activeChatTask = nil
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
        activeChatTask = task
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
}

/// Convenience error type carrying a human-readable message.
struct AIError: LocalizedError {
    let message: String
    init(_ message: String) { self.message = message }
    var errorDescription: String? { message }
}

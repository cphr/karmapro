// by cipher.org.uk
import Foundation

/// A configured OpenAI-compatible endpoint the assistant and scanner can talk
/// to. The two shipped presets are built in and cannot be removed; anything the
/// user adds is stored in `ProviderStore` and fully editable.
///
/// `id` is stable and generated once: keys and models are persisted against it,
/// so renaming or re-pointing a provider never orphans them.
struct AIProviderConfig: Codable, Equatable {
    var id: String
    var name: String
    /// Base URL up to and including `/v1`, e.g. `https://api.example.com/v1`.
    var baseURL: String
    /// Whether requests must carry a bearer key. Local servers (llama.cpp,
    /// LM Studio, vLLM) usually need none.
    var requiresAPIKey: Bool
    /// True for the shipped OpenRouter and Ollama presets: they can be edited
    /// (Ollama's URL, not its name) but not deleted.
    var isBuiltin: Bool

    /// The OpenRouter cloud API preset.
    static let openRouter = AIProviderConfig(
        id: "builtin.openrouter",
        name: "OpenRouter",
        baseURL: "https://openrouter.ai/api/v1",
        requiresAPIKey: true,
        isBuiltin: true)

    /// The local Ollama preset; its URL is editable.
    static let ollama = AIProviderConfig(
        id: "builtin.ollama",
        name: "Ollama",
        baseURL: "http://localhost:11434/v1",
        requiresAPIKey: false,
        isBuiltin: true)

    /// The presets, in the order they appear in the dropdown.
    static let builtins: [AIProviderConfig] = [.openRouter, .ollama]

    /// True for the local Ollama preset, whose server URL is edited in the
    /// bottom bar rather than a modal.
    var isOllama: Bool { id == AIProviderConfig.ollama.id }

    /// Requests the scanner and triage may keep in flight at once. Endpoints
    /// that need no key are assumed to be the user's own machine, which serves
    /// one request at a time; keyed services are assumed to be hosted and
    /// tolerate several.
    var maxConcurrentRequests: Int { requiresAPIKey ? 3 : 1 }

    /// Models to offer before the live catalog is fetched. Only meaningful for
    /// OpenRouter, whose IDs are namespaced and worth hinting; a user-defined
    /// endpoint gets none, like Ollama.
    var fallbackModels: [String] {
        isOllama ? [] : (id == AIProviderConfig.openRouter.id ? AIProviderConfig.openRouterFallbacks : [])
    }

    static let openRouterFallbacks: [String] = [
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
}

/// Persists the user's own endpoints to disk in the Karma Pro application
/// support directory (same pattern as `PromptStore`). The built-in presets are
/// always present and merged in first, so a user file can never hide them.
final class ProviderStore {
    static let shared = ProviderStore()

    /// Built-ins first, then the user's own, in insertion order.
    private(set) var providers: [AIProviderConfig] = []

    private let fileURL: URL

    init() {
        let dir = FileManager.default
            .urls(for: .applicationSupportDirectory, in: .userDomainMask).first!
            .appendingPathComponent("Karma Pro", isDirectory: true)
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        fileURL = dir.appendingPathComponent("ai_providers.json")
        reload()
    }

    private func reload() {
        let stored: [AIProviderConfig]
        if let data = try? Data(contentsOf: fileURL),
           let decoded = try? JSONDecoder().decode([AIProviderConfig].self, from: data) {
            stored = decoded
        } else {
            stored = []
        }
        providers = AIProviderConfig.builtins + stored.filter { !$0.isBuiltin }
    }

    private func persist() {
        let custom = providers.filter { !$0.isBuiltin }
        guard let data = try? JSONEncoder().encode(custom) else { return }
        try? data.write(to: fileURL, options: .atomic)
    }

    func provider(id: String) -> AIProviderConfig? {
        providers.first { $0.id == id }
    }

    /// Adds a user provider (ignoring a duplicate id) and persists.
    func add(_ provider: AIProviderConfig) {
        guard !providers.contains(where: { $0.id == provider.id }) else { return }
        providers.append(provider)
        persist()
    }

    func update(_ provider: AIProviderConfig) {
        guard let index = providers.firstIndex(where: { $0.id == provider.id }) else { return }
        providers[index] = provider
        persist()
    }

    func remove(id: String) {
        providers.removeAll { $0.id == id && !$0.isBuiltin }
        persist()
    }

    /// True when another provider already uses `name` (case-insensitively),
    /// ignoring the provider being edited.
    func nameExists(_ name: String, excluding id: String?) -> Bool {
        providers.contains {
            $0.id != id && $0.name.compare(name, options: .caseInsensitive) == .orderedSame
        }
    }

    /// Normalises a base URL typed by the user: trims whitespace and trailing
    /// slashes, and drops a trailing `/chat/completions` and `/models` (people
    /// paste the full endpoint), so only the API root is stored. Returns nil
    /// when the result is not a usable http(s) endpoint.
    static func normalizeBaseURL(_ raw: String) -> String? {
        var s = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        if s.isEmpty { return nil }
        if !s.contains("://") { s = "https://" + s }
        for suffix in ["/chat/completions", "/models"] where s.hasSuffix(suffix) {
            s = String(s.dropLast(suffix.count))
        }
        while s.hasSuffix("/") { s = String(s.dropLast()) }
        guard let url = URL(string: s), let host = url.host, !host.isEmpty else { return nil }
        guard url.scheme == "http" || url.scheme == "https" else { return nil }
        // `URL` accepts junk as a host (`https://../../etc/passwd` yields ".."),
        // so require something host-shaped: a dotted name, a bare hostname, or
        // a literal address. Reject separators and relative-looking values.
        guard !host.contains("/"), !host.contains("\\"), !host.contains(" ") else { return nil }
        let isLocalhost = host == "localhost"
        let isIPv4 = host.split(separator: ".").count == 4 && host.split(separator: ".").allSatisfy { part in
            !part.isEmpty && part.allSatisfy(\.isNumber) && (Int(part) ?? 999) <= 255
        }
        let isIPv6 = host.contains(":")
        let isDottedName = host.contains(".") && !host.hasPrefix(".") && !host.hasSuffix(".")
            && host.split(separator: ".").allSatisfy { !$0.isEmpty }
        guard isLocalhost || isIPv4 || isIPv6 || isDottedName else { return nil }
        return url.absoluteString
    }
}

// by cipher.org.uk
import Foundation

/// Hosts the MCP endpoint inside the running app. The service is started from
/// Settings; it binds to loopback only and reuses the app's scan engines.
final class MCPService {
    static let shared = MCPService()

    /// Ports tried in order, so a fixed URL stays stable when the first is free.
    private static let firstPort: UInt16 = 8765
    private static let lastPort: UInt16 = 8775

    private let defaults = UserDefaults.standard
    private let server = MCPHTTPServer()
    private let tools = MCPTools()
    private let workQueue = DispatchQueue(label: "app.karmapro.mcp.work", attributes: .concurrent)
    private let lock = NSLock()

    private var sessions: [String: MCPSession] = [:]
    private var streams: [(session: String, stream: MCPHTTPStream)] = []
    private var progressTokens: [String: [(session: String, token: Any)]] = [:]
    private var scans = 0
    private var configured = false

    private(set) var isRunning = false
    private(set) var port: UInt16 = 0
    private(set) var lastError: String?
    private(set) var startedAt: Date?
    /// Called on the main queue whenever the service state changes.
    var onChange: (() -> Void)?

    private init() {}

    // MARK: - Configuration

    /// Token required on the URL path (or as a bearer header). Persisted so a
    /// client config keeps working across launches.
    var token: String {
        if let stored = defaults.string(forKey: "MCP.token"), stored.count >= 16 {
            return stored
        }
        let fresh = Self.makeToken()
        defaults.set(fresh, forKey: "MCP.token")
        return fresh
    }

    /// AI scans cost money against the configured provider, so they are opt-in.
    var allowAI: Bool {
        get { defaults.object(forKey: "MCP.allowAI") as? Bool ?? false }
        set {
            defaults.set(newValue, forKey: "MCP.allowAI")
            notifyChange()
        }
    }

    /// The service never starts on its own: this defaults to false and is only
    /// turned on from Settings, so a fresh install listens for nothing.
    var autoStart: Bool {
        get { defaults.object(forKey: "MCP.autoStart") as? Bool ?? false }
        set {
            defaults.set(newValue, forKey: "MCP.autoStart")
            notifyChange()
        }
    }

    /// The endpoint a client is pointed at, token included.
    var url: String {
        "http://127.0.0.1:\(isRunning ? port : Self.firstPort)/mcp/\(token)"
    }

    var clientConfig: String {
        """
        {
          "mcpServers": {
            "karma-pro": {
              "type": "http",
              "url": "\(url)"
            }
          }
        }
        """
    }

    var scanCount: Int {
        lock.lock()
        defer { lock.unlock() }
        return scans
    }

    func rotateToken() {
        defaults.set(Self.makeToken(), forKey: "MCP.token")
        if isRunning {
            stop()
            try? start()
        } else {
            notifyChange()
        }
    }

    // MARK: - Lifecycle

    func start() throws {
        lock.lock()
        guard !isRunning else {
            lock.unlock()
            return
        }
        lock.unlock()

        configureIfNeeded()
        var failure: Error?
        for candidate in Self.firstPort...Self.lastPort {
            do {
                let bound = try server.start(port: candidate)
                lock.lock()
                port = bound
                isRunning = true
                startedAt = Date()
                lastError = nil
                lock.unlock()
                defaults.set(Int(bound), forKey: "MCP.lastPort")
                notifyChange()
                return
            } catch {
                failure = error
            }
        }
        let message = "Could not listen on 127.0.0.1:\(Self.firstPort)–\(Self.lastPort). "
            + (failure?.localizedDescription ?? "The ports are unavailable.")
        note(message)
        throw NSError(domain: "MCP", code: 1,
                      userInfo: [NSLocalizedDescriptionKey: message])
    }

    func stop() {
        var open: [MCPHTTPStream] = []
        lock.lock()
        open = streams.map { $0.stream }
        streams = []
        progressTokens = [:]
        sessions = [:]
        isRunning = false
        port = 0
        startedAt = nil
        lock.unlock()
        open.forEach { $0.close() }
        server.stop()
        notifyChange()
    }

    func toggle() {
        if isRunning {
            stop()
        } else {
            try? start()
        }
    }

    // MARK: - Wiring

    private func configureIfNeeded() {
        lock.lock()
        let done = configured
        configured = true
        lock.unlock()
        guard !done else { return }

        tools.allowAI = { [weak self] in self?.allowAI ?? false }
        tools.stats = { [weak self] in self?.statusPayload() ?? [:] }
        tools.log = { [weak self] message in self?.note(message) }
        tools.onScanSubmitted = { [weak self] job, session, token in
            guard let self else { return }
            self.lock.lock()
            self.scans += 1
            if let token {
                self.progressTokens[job.id, default: []].append((session.id, token))
            }
            self.lock.unlock()
            self.notifyChange()
        }

        server.handler = { [weak self] request, reply in
            guard let self else {
                reply(.text(503, "The MCP service is stopped."))
                return
            }
            self.workQueue.async { reply(self.handle(request)) }
        }
        server.onStream = { [weak self] request, stream in
            self?.acceptStream(request, stream) ?? false
        }
        server.log = { [weak self] message in self?.note(message) }

        ScanJobRunner.shared.onUpdate = { [weak self] job in
            self?.publish(job)
        }
    }

    // MARK: - HTTP

    private func handle(_ request: MCPHTTPServer.Request) -> MCPHTTPServer.Response {
        guard let route = Self.route(request.path) else {
            return .text(404, "Not found. The MCP endpoint is /mcp/<token>.")
        }
        guard isAuthorized(request, pathToken: route.token) else {
            note("refused a request with a bad or missing token")
            return .text(401, "Unauthorized. Use the URL shown in Karma Pro's Settings.")
        }

        switch request.method {
        case "POST":
            return handlePost(request)
        case "DELETE":
            if let id = request.header("mcp-session-id") {
                lock.lock()
                sessions.removeValue(forKey: id)
                lock.unlock()
            }
            return .init(status: 204)
        case "GET":
            return .text(405, "Open this URL with an MCP client; streams need Accept: text/event-stream.")
        default:
            return .text(405, "Method not allowed.")
        }
    }

    private func handlePost(_ request: MCPHTTPServer.Request) -> MCPHTTPServer.Response {
        guard let parsed = MCPParser.parse(request.body) else {
            return .json(MCPCode.error(nil, MCPCode.parse, "Body is not valid JSON-RPC 2.0."))
        }
        let isInitialize = parsed.envelopes.contains { $0.method == "initialize" }
        let session = session(for: request, isInitialize: isInitialize)

        var responses: [Any] = []
        for envelope in parsed.envelopes {
            if let response = tools.handle(envelope, session: session) {
                responses.append(response)
            }
        }
        guard !responses.isEmpty else { return .init(status: 202) }

        var response = MCPHTTPServer.Response.json(parsed.batch ? responses : responses[0])
        response.headers["Mcp-Session-Id"] = session.id
        response.headers["MCP-Protocol-Version"] = session.protocolVersion
        return response
    }

    private func acceptStream(_ request: MCPHTTPServer.Request, _ stream: MCPHTTPStream) -> Bool {
        guard let route = Self.route(request.path),
              isAuthorized(request, pathToken: route.token) else {
            note("refused an event stream with a bad or missing token")
            return false
        }
        let session = request.header("mcp-session-id") ?? "local"
        lock.lock()
        streams.append((session, stream))
        lock.unlock()
        return true
    }

    /// `/mcp` and `/mcp/<token>` are the only paths; the token is optional in
    /// the path because some clients only send a bearer header.
    private struct Route {
        let token: String?
    }

    private static func route(_ rawPath: String) -> Route? {
        let path = rawPath.split(separator: "?", maxSplits: 1).first.map(String.init) ?? rawPath
        if path == "/mcp" { return Route(token: nil) }
        guard path.hasPrefix("/mcp/") else { return nil }
        return Route(token: String(path.dropFirst("/mcp/".count)))
    }

    private func isAuthorized(_ request: MCPHTTPServer.Request, pathToken: String?) -> Bool {
        let expected = token
        if let pathToken, pathToken == expected { return true }
        if let header = request.header("authorization"), header.lowercased().hasPrefix("bearer ") {
            let supplied = String(header.dropFirst(7)).trimmingCharacters(in: .whitespaces)
            if supplied == expected { return true }
        }
        return false
    }

    private func session(for request: MCPHTTPServer.Request, isInitialize: Bool) -> MCPSession {
        lock.lock()
        defer { lock.unlock() }
        if let id = request.header("mcp-session-id"), let existing = sessions[id] {
            return existing
        }
        // Clients that omit the session header keep one implicit session.
        let key = request.header("mcp-session-id")
            ?? (isInitialize ? Self.makeToken(prefix: "s") : "local")
        if let existing = sessions[key] { return existing }
        let session = MCPSession(id: key)
        sessions[key] = session
        if sessions.count > 32 {
            sessions = [key: session]
        }
        return session
    }

    // MARK: - Job progress

    private func publish(_ job: ScanJob) {
        let info = job.progressInfo
        lock.lock()
        streams.removeAll { $0.stream.isClosed }
        let tokens = progressTokens[job.id] ?? []
        if job.isFinished { progressTokens.removeValue(forKey: job.id) }
        let all = streams.map { $0.stream }
        lock.unlock()

        for entry in tokens {
            let params: [String: Any] = [
                "progressToken": entry.token,
                "progress": (Double(info.progress) * 1000).rounded() / 1000,
                "total": 1,
                "message": "\(job.engine.rawValue): \(info.stage)"
            ]
            let notification = MCPCode.notification("notifications/progress", params)
            send(notification, to: entry.session)
        }
        if job.isFinished {
            let changed = MCPCode.notification("notifications/resources/list_changed", [:])
            all.forEach { $0.send(changed) }
        }
    }

    private func send(_ object: [String: Any], to session: String) {
        lock.lock()
        let targets = streams.filter { $0.session == session && !$0.stream.isClosed }.map { $0.stream }
        lock.unlock()
        targets.forEach { $0.send(object) }
    }

    // MARK: - Status

    private func statusPayload() -> [String: Any] {
        lock.lock()
        let running = isRunning
        let bound = port
        let count = scans
        let error = lastError
        let uptime = startedAt.map { Int(Date().timeIntervalSince($0)) } ?? 0
        let active = sessions.count
        lock.unlock()
        return [
            "running": running,
            "url": running ? "http://127.0.0.1:\(bound)/mcp" : "",
            "port": Int(bound),
            "allow_ai": allowAI,
            "scans": count,
            "sessions": active,
            "uptime_seconds": uptime,
            "last_error": error ?? ""
        ]
    }

    private func note(_ message: String?) {
        lock.lock()
        lastError = message
        lock.unlock()
        notifyChange()
    }

    private func notifyChange() {
        DispatchQueue.main.async { [weak self] in
            self?.onChange?()
        }
    }

    // MARK: - Helpers

    private static func makeToken(prefix: String = "") -> String {
        let raw = UUID().uuidString.replacingOccurrences(of: "-", with: "").lowercased()
        return prefix + raw
    }
}

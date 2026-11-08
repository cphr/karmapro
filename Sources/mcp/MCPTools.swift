// by cipher.org.uk
import Foundation

/// JSON-RPC method dispatch for the MCP endpoint. Scanner work is delegated to
/// ScanJobRunner, so this layer only validates arguments and shapes results.
final class MCPTools {
    static let latestProtocol = "2025-06-18"
    static let supportedProtocols = ["2025-06-18", "2025-03-26", "2024-11-05"]
    static let serverName = "Karma Pro"

    /// SARIF at or below this size rides along in the tool result; above it the
    /// result carries a resource link and the document is read from the URI.
    static let inlineSARIFLimit = 512 * 1024

    var allowAI: () -> Bool = { true }
    var stats: () -> [String: Any] = { [:] }
    /// Registers the caller's progress token so job updates reach its stream.
    var onScanSubmitted: ((ScanJob, MCPSession, Any?) -> Void)?
    var log: ((String) -> Void)?

    // MARK: - Entry

    func handle(_ env: MCPEnvelope, session: MCPSession) -> [String: Any]? {
        guard let method = env.method else { return nil }
        if env.isNotification {
            if method == "notifications/initialized" { session.initialized = true }
            return nil
        }
        let id: Any = env.id ?? NSNull()
        switch method {
        case "initialize":
            return MCPCode.result(id, initialize(env.params, session))
        case "ping":
            return MCPCode.result(id, [:])
        case "tools/list":
            return MCPCode.result(id, ["tools": Self.toolDefinitions])
        case "tools/call":
            return MCPCode.result(id, callTool(env.params, session: session))
        case "resources/list":
            return MCPCode.result(id, ["resources": resources()])
        case "resources/templates/list":
            return MCPCode.result(id, ["resourceTemplates": [resourceTemplate]])
        case "resources/read":
            return readResource(id: id, params: env.params)
        case "logging/setLevel":
            return MCPCode.result(id, [:])
        default:
            return MCPCode.error(id, MCPCode.methodNotFound, "Unknown method: \(method)")
        }
    }

    // MARK: - Handshake

    private func initialize(_ params: [String: Any], _ session: MCPSession) -> [String: Any] {
        let requested = params["protocolVersion"] as? String
        let version = requested.flatMap { Self.supportedProtocols.contains($0) ? $0 : nil }
            ?? Self.latestProtocol
        session.protocolVersion = version
        if let info = params["clientInfo"] as? [String: Any] {
            session.clientName = info["name"] as? String
        }
        return [
            "protocolVersion": version,
            "capabilities": [
                "tools": ["listChanged": false],
                "resources": ["subscribe": false, "listChanged": true],
                "logging": [:]
            ],
            "serverInfo": ["name": Self.serverName, "version": Self.version],
            "instructions": """
                Karma Pro scans a directory with its own analysis engines and returns SARIF 2.1.0.
                Use scan_directory (path must be a directory, engine: static | ai | both).
                AI scans reuse cached results for unchanged code; pass rescan: true to force a fresh pass.
                AI scans can take minutes: the call returns a job_id, then poll get_scan.
                """
        ]
    }

    private static var version: String {
        (Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String) ?? "0"
    }

    // MARK: - Tools

    private func callTool(_ params: [String: Any], session: MCPSession) -> [String: Any] {
        guard let name = params["name"] as? String else {
            return Self.failure("Missing tool name.")
        }
        let args = params["arguments"] as? [String: Any] ?? [:]
        let meta = params["_meta"] as? [String: Any]
        switch name {
        case "scan_directory":
            return scanDirectory(args, session: session, progressToken: meta?["progressToken"])
        case "get_scan":
            return getScan(args)
        case "cancel_scan":
            return cancelScan(args)
        case "list_models":
            return listModels()
        case "server_status":
            return serverStatus()
        default:
            return Self.failure("Unknown tool: \(name)")
        }
    }

    private func scanDirectory(_ args: [String: Any],
                               session: MCPSession,
                               progressToken: Any?) -> [String: Any] {
        guard let raw = args["path"] as? String else {
            return Self.failure("scan_directory needs a \"path\" argument.")
        }
        let path = (raw as NSString).expandingTildeInPath
        guard path.hasPrefix("/") else {
            return Self.failure("path must be absolute: \(raw)")
        }
        var isDirectory: ObjCBool = false
        guard FileManager.default.fileExists(atPath: path, isDirectory: &isDirectory) else {
            return Self.failure("No such path: \(path)")
        }
        guard isDirectory.boolValue else {
            return Self.failure("\(path) is a file. Pass a directory; single-file scans are not supported.")
        }

        let engineName = (args["engine"] as? String ?? "static").lowercased()
        guard let engine = Self.engine(engineName) else {
            return Self.failure("engine must be static, ai or both (got \"\(engineName)\").")
        }
        if engine.usesAI, !allowAI() {
            return Self.failure("AI scans are turned off for MCP in Karma Pro's Settings.")
        }
        let model = (args["model"] as? String)?.trimmingCharacters(in: .whitespacesAndNewlines)
        let rescan = args["rescan"] as? Bool ?? false
        let wait = min(max(args["wait_seconds"] as? Double ?? 10, 0), 120)

        let job = ScanJobRunner.shared.submit(path: path,
                                              engine: engine,
                                              model: (model?.isEmpty ?? true) ? nil : model,
                                              ignoreCache: rescan)
        onScanSubmitted?(job, session, progressToken)
        if wait > 0 { waitForCompletion(job.id, seconds: wait) }

        guard let snapshot = ScanJobRunner.shared.snapshot(id: job.id) else {
            return Self.failure("The scan job could not be created.")
        }
        return success(snapshot, sarif: ScanJobRunner.shared.sarifText(id: job.id))
    }

    private func getScan(_ args: [String: Any]) -> [String: Any] {
        guard let id = args["job_id"] as? String else {
            return Self.failure("get_scan needs a \"job_id\" argument.")
        }
        guard let snapshot = ScanJobRunner.shared.snapshot(id: id) else {
            return Self.failure("Unknown job: \(id)")
        }
        let includeSARIF = args["include_sarif"] as? Bool ?? true
        let sarif = includeSARIF ? ScanJobRunner.shared.sarifText(id: id) : nil
        return success(snapshot, sarif: sarif)
    }

    private func cancelScan(_ args: [String: Any]) -> [String: Any] {
        guard let id = args["job_id"] as? String else {
            return Self.failure("cancel_scan needs a \"job_id\" argument.")
        }
        guard ScanJobRunner.shared.cancel(id: id) != nil,
              let snapshot = ScanJobRunner.shared.snapshot(id: id) else {
            return Self.failure("Unknown job: \(id)")
        }
        return success(snapshot, sarif: nil)
    }

    private func listModels() -> [String: Any] {
        let client = OpenRouterClient.shared
        let payload: [String: Any] = [
            "provider": client.provider.name,
            "provider_id": client.provider.id,
            "model": client.selectedModel,
            "requires_api_key": client.requiresAPIKey,
            "configured": client.isConfigured,
            "worker_pool": client.provider.maxConcurrentRequests,
            "allow_ai_scans": allowAI(),
            "suggested_models": client.provider.fallbackModels
        ]
        let text = "\(client.provider.name) · model \(client.selectedModel.isEmpty ? "(none)" : client.selectedModel) · \(client.provider.maxConcurrentRequests) worker(s) · configured: \(client.isConfigured ? "yes" : "no")"
        return ["content": [["type": "text", "text": text]],
                "structuredContent": payload,
                "isError": false]
    }

    private func serverStatus() -> [String: Any] {
        var payload = stats()
        payload["server"] = Self.serverName
        payload["version"] = Self.version
        payload["protocol"] = Self.latestProtocol
        let status = payload["running"] as? Bool ?? false
        let text = status
            ? "MCP service listening on \(payload["url"] as? String ?? "?")"
            : "MCP service is stopped."
        return ["content": [["type": "text", "text": text]],
                "structuredContent": payload,
                "isError": false]
    }

    // MARK: - Resources

    private var resourceTemplate: [String: Any] {
        [
            "uriTemplate": "sarif://job/{job_id}",
            "name": "SARIF report",
            "description": "SARIF 2.1.0 document for a finished scan.",
            "mimeType": "application/sarif+json"
        ]
    }

    private func resources() -> [[String: Any]] {
        ScanJobRunner.shared.documents().map { doc in
            [
                "uri": "sarif://job/\(doc.id)",
                "name": "SARIF report \(doc.id)",
                "mimeType": "application/sarif+json",
                "size": doc.bytes
            ]
        }
    }

    private func readResource(id: Any, params: [String: Any]) -> [String: Any] {
        guard let uri = params["uri"] as? String else {
            return MCPCode.error(id, MCPCode.invalidParams, "resources/read needs a uri.")
        }
        let prefix = "sarif://job/"
        guard uri.hasPrefix(prefix),
              let text = ScanJobRunner.shared.sarifText(id: String(uri.dropFirst(prefix.count))) else {
            return MCPCode.error(id, MCPCode.resourceNotFound, "Resource not found: \(uri)")
        }
        return MCPCode.result(id, ["contents": [[
            "uri": uri,
            "mimeType": "application/sarif+json",
            "text": text
        ]]])
    }

    // MARK: - Result shaping

    /// Blocks the calling request until the job finishes or the budget expires.
    private func waitForCompletion(_ id: String, seconds: Double) {
        let deadline = Date().addingTimeInterval(seconds)
        while Date() < deadline {
            if let status = ScanJobRunner.shared.snapshot(id: id)?["status"] as? String,
               ["completed", "failed", "cancelled"].contains(status) {
                return
            }
            Thread.sleep(forTimeInterval: 0.1)
        }
    }

    private func success(_ snapshot: [String: Any], sarif: String?) -> [String: Any] {
        var content: [[String: Any]] = [["type": "text", "text": Self.describe(snapshot)]]
        if let sarif, let id = snapshot["job_id"] as? String {
            let uri = "sarif://job/\(id)"
            if sarif.utf8.count <= Self.inlineSARIFLimit {
                content.append([
                    "type": "resource",
                    "resource": ["uri": uri, "mimeType": "application/sarif+json", "text": sarif]
                ])
            } else {
                content.append([
                    "type": "resource_link",
                    "uri": uri,
                    "name": "SARIF report \(id)",
                    "mimeType": "application/sarif+json",
                    "size": sarif.utf8.count
                ])
            }
        }
        return ["content": content, "structuredContent": snapshot, "isError": false]
    }

    private static func failure(_ text: String) -> [String: Any] {
        ["content": [["type": "text", "text": text]], "isError": true]
    }

    private static func describe(_ snapshot: [String: Any]) -> String {
        let status = snapshot["status"] as? String ?? "unknown"
        let path = snapshot["path"] as? String ?? ""
        let id = snapshot["job_id"] as? String ?? ""
        if let error = snapshot["error"] as? String, !error.isEmpty {
            return "Scan \(status): \(error)"
        }
        if status != "completed", status != "failed", status != "cancelled" {
            let stage = snapshot["stage"] as? String ?? status
            let progress = Int((snapshot["progress"] as? Double ?? 0) * 100)
            return "Scan \(status) (\(stage), \(progress)%) for \(path). Poll get_scan with job_id \(id)."
        }
        let summary = snapshot["summary"] as? [String: Any] ?? [:]
        let findings = summary["findings"] as? Int ?? 0
        return "Scan \(status): \(findings) findings in \(path) — "
            + "\(summary["critical"] as? Int ?? 0) critical, "
            + "\(summary["high"] as? Int ?? 0) high, "
            + "\(summary["medium"] as? Int ?? 0) medium, "
            + "\(summary["low"] as? Int ?? 0) low."
    }

    // MARK: - Definitions

    private static func engine(_ raw: String) -> ScanEngine? {
        switch raw {
        case "static", "ast", "heuristic": return .staticScan
        case "ai": return .ai
        case "both": return .both
        default: return nil
        }
    }

    private static let toolDefinitions: [[String: Any]] = [
        [
            "name": "scan_directory",
            "title": "Scan a directory",
            "description": "Scans every source file under a directory and returns SARIF 2.1.0. "
                + "engine: static (AST/heuristic, fast), ai (configured AI model), both (static then merged with AI). "
                + "Set rescan to bypass cached AI results. "
                + "AI scans usually need polling: use get_scan with the returned job_id.",
            "inputSchema": [
                "type": "object",
                "properties": [
                    "path": ["type": "string", "description": "Absolute path of an existing directory."],
                    "engine": [
                        "type": "string",
                        "enum": ["static", "ai", "both"],
                        "default": "static",
                        "description": "static = AST/heuristic, ai = model only, both = merged."
                    ],
                    "model": [
                        "type": "string",
                        "description": "Optional model id for AI scans; defaults to the model selected in Karma Pro."
                    ],
                    "rescan": [
                        "type": "boolean",
                        "default": false,
                        "description": "Ignore cached AI results for unchanged code and re-ask the model, like the Rescan button."
                    ],
                    "wait_seconds": [
                        "type": "number",
                        "minimum": 0,
                        "maximum": 120,
                        "default": 10,
                        "description": "How long to wait for completion before returning a running job."
                    ]
                ],
                "required": ["path"]
            ]
        ],
        [
            "name": "get_scan",
            "title": "Get scan status",
            "description": "Returns status, progress, finding counts and the SARIF document (when finished).",
            "inputSchema": [
                "type": "object",
                "properties": [
                    "job_id": ["type": "string"],
                    "include_sarif": [
                        "type": "boolean",
                        "default": true,
                        "description": "Include the SARIF document in the result."
                    ]
                ],
                "required": ["job_id"]
            ]
        ],
        [
            "name": "cancel_scan",
            "title": "Cancel a scan",
            "description": "Cancels a queued or running scan.",
            "inputSchema": [
                "type": "object",
                "properties": ["job_id": ["type": "string"]],
                "required": ["job_id"]
            ]
        ],
        [
            "name": "list_models",
            "title": "List AI configuration",
            "description": "Shows the provider, selected model, worker pool size and whether AI scans are allowed over MCP.",
            "inputSchema": ["type": "object", "properties": [:]]
        ],
        [
            "name": "server_status",
            "title": "Service status",
            "description": "Reports whether the MCP service is running, its URL, and scan counters.",
            "inputSchema": ["type": "object", "properties": [:]]
        ]
    ]
}

/// Per-client state for one MCP session.
final class MCPSession {
    let id: String
    var initialized = false
    var protocolVersion = MCPTools.latestProtocol
    var clientName: String?

    init(id: String) {
        self.id = id
    }
}

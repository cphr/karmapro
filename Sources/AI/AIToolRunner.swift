// by cipher.org.uk
import Foundation

/// A single tool call requested by the model.
struct OpenRouterToolCall {
    let id: String
    let name: String
    let arguments: String
}

/// Executes the AI assistant's tools, strictly confined to the project
/// directory:
/// - `list_files` / `read_file` / `search_files` resolve every path against
///   the project root (including symlink resolution) and refuse anything
///   that escapes it.
/// - `run_command` executes only an allowlist of read-only inspection
///   commands, with `cwd` set to the project root and — when
///   `/usr/bin/sandbox-exec` is available — inside a macOS Seatbelt profile
///   that denies writes, denies network, and only permits file reads inside
///   the project root plus the system library paths needed to run binaries.
struct AIToolExecutor {
    let projectRoot: URL

    /// Read-only binaries the model may execute.
    static let allowedCommands: Set<String> = [
        "ls", "cat", "head", "tail", "grep", "egrep", "fgrep", "find", "wc",
        "file", "stat", "du", "sort", "uniq", "cut", "diff", "comm"
    ]

    static let excludedDirectoryNames: Set<String> = [
        ".git", "node_modules", ".build", "build", "DerivedData", "Pods",
        ".gradle", "target", "__pycache__", ".venv", "venv", "dist"
    ]

    /// OpenRouter (OpenAI-compatible) tool schemas advertised to the model.
    static let toolDefinitions: [[String: Any]] = [
        ["type": "function", "function": [
            "name": "list_files",
            "description": "List files and folders under a path inside the project directory. Paths are relative to the project root. Use this to explore the project structure.",
            "parameters": [
                "type": "object",
                "properties": [
                    "path": ["type": "string", "description": "Relative path inside the project; empty for the project root"],
                    "recursive": ["type": "boolean", "description": "List recursively (default true)"]
                ],
                "required": []
            ]]],
        ["type": "function", "function": [
            "name": "read_file",
            "description": "Read a text file inside the project directory (relative path). Large files are truncated to the first ~20 KB.",
            "parameters": [
                "type": "object",
                "properties": [
                    "path": ["type": "string", "description": "Relative path of the file inside the project"]
                ],
                "required": ["path"]
            ]]],
        ["type": "function", "function": [
            "name": "search_files",
            "description": "Case-insensitive full-text search across all text files inside the project directory. Returns matches as 'path:line: text'.",
            "parameters": [
                "type": "object",
                "properties": [
                    "query": ["type": "string", "description": "Text to search for"],
                    "max_results": ["type": "integer", "description": "Maximum matches to return (default 40)"]
                ],
                "required": ["query"]
            ]]],
        ["type": "function", "function": [
            "name": "run_command",
            "description": "Run a READ-ONLY inspection command (ls, cat, head, tail, grep, find, wc, file, stat, du, sort, uniq, cut, diff) inside the project directory. Writing, network access, and paths outside the project are blocked.",
            "parameters": [
                "type": "object",
                "properties": [
                    "command": ["type": "string", "description": "The command line to run, e.g. \"grep -rn TODO Sources\""]
                ],
                "required": ["command"]
            ]]]
    ]

    // MARK: - Dispatch

    /// Executes one tool call and returns the result as a JSON string that is
    /// fed back to the model.
    func execute(name: String, argumentsJSON: String) -> String {
        let args = (try? JSONSerialization.jsonObject(with: Data(argumentsJSON.utf8)) as? [String: Any]) ?? [:]
        let result: [String: Any]
        switch name {
        case "list_files":
            result = listFiles(args: args)
        case "read_file":
            result = readFile(args: args)
        case "search_files":
            result = searchFiles(args: args)
        case "run_command":
            result = runCommand(args: args)
        default:
            result = ["ok": false, "error": "Unknown tool '\(name)'."]
        }
        if let data = try? JSONSerialization.data(withJSONObject: result, options: [.sortedKeys]),
           let s = String(data: data, encoding: .utf8) {
            return s
        }
        return "{\"ok\":false,\"error\":\"result encoding failed\"}"
    }

    // MARK: - Path confinement

    /// Resolves a relative path against the project root and refuses anything
    /// that escapes it (including via symlinks or absolute paths).
    private func resolve(_ relative: String) -> URL? {
        guard !relative.hasPrefix("/") else { return nil }   // no absolute paths
        let root = projectRoot.standardizedFileURL.resolvingSymlinksInPath()
        let target = relative.isEmpty
            ? root
            : root.appendingPathComponent(relative).standardizedFileURL.resolvingSymlinksInPath()
        guard target.path == root.path || target.path.hasPrefix(root.path + "/") else { return nil }
        return target
    }

    private func relativePath(for url: URL) -> String {
        let root = projectRoot.standardizedFileURL.resolvingSymlinksInPath().path
        if url.path.hasPrefix(root + "/") {
            return String(url.path.dropFirst(root.count + 1))
        }
        return url.lastPathComponent
    }

    private func isExcluded(_ name: String) -> Bool {
        AIToolExecutor.excludedDirectoryNames.contains(name) || name.hasPrefix(".DS_Store")
    }

    // MARK: - Tools

    private func listFiles(args: [String: Any]) -> [String: Any] {
        let rel = args["path"] as? String ?? ""
        let recursive = args["recursive"] as? Bool ?? true
        guard let base = resolve(rel) else {
            return ["ok": false, "error": "Path '\(rel)' is outside the project directory."]
        }
        var isDir: ObjCBool = false
        guard FileManager.default.fileExists(atPath: base.path, isDirectory: &isDir), isDir.boolValue else {
            return ["ok": false, "error": "'\(rel)' is not a directory inside the project."]
        }
        var lines: [String] = []
        if recursive {
            let enumerator = FileManager.default.enumerator(at: base,
                                                            includingPropertiesForKeys: [.isDirectoryKey],
                                                            options: [.skipsHiddenFiles, .skipsPackageDescendants])
            while let element = enumerator?.nextObject() as? URL {
                let name = element.lastPathComponent
                if isExcluded(name) { enumerator?.skipDescendants(); continue }
                if lines.count >= 500 { lines.append("… (truncated at 500 entries)"); break }
                let isDirectory = (try? element.resourceValues(forKeys: [.isDirectoryKey]))?.isDirectory ?? false
                let relPath = relativePath(for: element)
                lines.append(isDirectory ? relPath + "/" : relPath)
            }
        } else {
            let items = (try? FileManager.default.contentsOfDirectory(at: base,
                                                                     includingPropertiesForKeys: [.isDirectoryKey],
                                                                     options: [.skipsHiddenFiles])) ?? []
            for item in items where !isExcluded(item.lastPathComponent) {
                let isDirectory = (try? item.resourceValues(forKeys: [.isDirectoryKey]))?.isDirectory ?? false
                lines.append(isDirectory ? item.lastPathComponent + "/" : item.lastPathComponent)
            }
        }
        return ["ok": true, "path": rel.isEmpty ? "." : rel, "entries": lines]
    }

    private func readFile(args: [String: Any]) -> [String: Any] {
        guard let rel = args["path"] as? String, !rel.isEmpty else {
            return ["ok": false, "error": "Missing required argument 'path'."]
        }
        guard let url = resolve(rel) else {
            return ["ok": false, "error": "Path '\(rel)' is outside the project directory."]
        }
        var isDir: ObjCBool = false
        guard FileManager.default.fileExists(atPath: url.path, isDirectory: &isDir), !isDir.boolValue else {
            return ["ok": false, "error": "'\(rel)' is not a file inside the project."]
        }
        guard let data = try? Data(contentsOf: url, options: .mappedIfSafe) else {
            return ["ok": false, "error": "Could not read '\(rel)'."]
        }
        let limit = 20_000
        var truncated = false
        var payload = data
        if data.count > limit {
            payload = data.prefix(limit)
            truncated = true
        }
        guard let text = String(data: payload, encoding: .utf8) ?? String(data: payload, encoding: .isoLatin1) else {
            return ["ok": false, "error": "'\(rel)' appears to be binary."]
        }
        var out: [String: Any] = ["ok": true, "path": rel, "content": text]
        if truncated {
            out["note"] = "Truncated to first \(limit) bytes of \(data.count)."
        }
        return out
    }

    private func searchFiles(args: [String: Any]) -> [String: Any] {
        guard let query = args["query"] as? String, !query.isEmpty else {
            return ["ok": false, "error": "Missing required argument 'query'."]
        }
        let maxResults = (args["max_results"] as? Int) ?? 40
        let root = projectRoot.standardizedFileURL.resolvingSymlinksInPath()
        let lowerQuery = query.lowercased()
        var matches: [String] = []
        let enumerator = FileManager.default.enumerator(at: root,
                                                        includingPropertiesForKeys: [.isRegularFileKey, .fileSizeKey],
                                                        options: [.skipsHiddenFiles])
        while let element = enumerator?.nextObject() as? URL {
            let name = element.lastPathComponent
            if isExcluded(name) { enumerator?.skipDescendants(); continue }
            guard let values = try? element.resourceValues(forKeys: [.isRegularFileKey, .fileSizeKey]),
                  values.isRegularFile == true, (values.fileSize ?? 0) < 512_000 else { continue }
            guard let raw = try? Data(contentsOf: element, options: .mappedIfSafe),
                  let text = String(data: raw, encoding: .utf8) else { continue }
            let rel = relativePath(for: element)
            for (idx, line) in text.enumeratedLines().enumerated() {
                if line.lowercased().contains(lowerQuery) {
                    matches.append("\(rel):\(idx + 1): \(line.trimmingCharacters(in: .whitespaces).prefix(200))")
                    if matches.count >= maxResults {
                        return ["ok": true, "matches": matches, "note": "Stopped at \(maxResults) matches."]
                    }
                }
            }
        }
        return ["ok": true, "matches": matches]
    }

    private func runCommand(args: [String: Any]) -> [String: Any] {
        guard let commandLine = args["command"] as? String else {
            return ["ok": false, "error": "Missing required argument 'command'."]
        }
        let parts = commandLine.split(separator: " ", omittingEmptySubsequences: true).map(String.init)
        guard let first = parts.first else {
            return ["ok": false, "error": "Empty command."]
        }
        let binary = (first as NSString).lastPathComponent
        guard AIToolExecutor.allowedCommands.contains(binary) else {
            return ["ok": false,
                    "error": "Command '\(binary)' is not allowed. Only read-only inspection commands are permitted: \(AIToolExecutor.allowedCommands.sorted().joined(separator: ", "))."]
        }

        let launchPath: String
        if binary == first, first.hasPrefix("/") {
            launchPath = first
        } else {
            let candidates = ["/bin/\(binary)", "/usr/bin/\(binary)", "/usr/local/bin/\(binary)", "/sbin/\(binary)"]
            guard let found = candidates.first(where: { FileManager.default.isExecutableFile(atPath: $0) }) else {
                return ["ok": false, "error": "Command '\(binary)' not found."]
            }
            launchPath = found
        }

        let root = projectRoot.standardizedFileURL.resolvingSymlinksInPath().path
        var argv = [launchPath] + Array(parts.dropFirst())

        // Seatbelt profile: reads inside the project root + system libraries
        // only; no writes, no network. Falls back to allowlist-only when
        // sandbox-exec is unavailable.
        let sandboxExec = "/usr/bin/sandbox-exec"
        if FileManager.default.isExecutableFile(atPath: sandboxExec) {
            let profile = """
            (version 1)
            (deny default)
            (allow process-exec)
            (allow process-fork)
            (allow file-read*
              (subpath "\(root)")
              (subpath "/System")
              (subpath "/usr/lib")
              (subpath "/usr/share")
              (subpath "/usr/bin")
              (subpath "/bin")
              (subpath "/usr/sbin")
              (subpath "/sbin")
              (subpath "/usr/local/bin")
              (subpath "/private/etc")
              (subpath "/private/var/db/dyld")
              (subpath "/dev"))
            (allow sysctl-read)
            (deny network*)
            """
            let profileURL = URL(fileURLWithPath: NSTemporaryDirectory()).appendingPathComponent("karmapro-ai-\(UUID().uuidString).sb")
            try? profile.write(to: profileURL, atomically: true, encoding: .utf8)
            defer { try? FileManager.default.removeItem(at: profileURL) }
            argv = [sandboxExec, "-f", profileURL.path] + argv
        }

        let process = Process()
        process.executableURL = URL(fileURLWithPath: argv[0])
        process.arguments = Array(argv.dropFirst())
        process.environment = [
            "PATH": "/usr/bin:/bin:/usr/sbin:/sbin:/usr/local/bin",
            "LANG": "en_US.UTF-8",
            "HOME": root
        ]
        process.currentDirectoryURL = URL(fileURLWithPath: root)

        let outPipe = Pipe()
        let errPipe = Pipe()
        process.standardOutput = outPipe
        process.standardError = errPipe

        do {
            try process.run()
        } catch {
            return ["ok": false, "error": "Could not launch command: \(error.localizedDescription)"]
        }

        // Drain pipes concurrently (prevents deadlock on large output), with
        // a hard timeout so a hung command can never stall the conversation.
        var outData = Data()
        var errData = Data()
        let group = DispatchGroup()
        group.enter()
        DispatchQueue.global().async {
            outData = outPipe.fileHandleForReading.readDataToEndOfFile()
            group.leave()
        }
        group.enter()
        DispatchQueue.global().async {
            errData = errPipe.fileHandleForReading.readDataToEndOfFile()
            group.leave()
        }
        var timedOut = false
        if group.wait(timeout: .now() + 10) == .timedOut {
            timedOut = true
            process.terminate()
            _ = group.wait(timeout: .now() + 2)
        }
        process.waitUntilExit()
        var out = String(data: outData, encoding: .utf8) ?? "(binary output)"
        let err = String(data: errData, encoding: .utf8) ?? ""
        if out.count > 8000 { out = String(out.prefix(8000)) + "\n… (output truncated)" }

        var result: [String: Any] = ["ok": !timedOut, "command": commandLine, "output": out]
        if !err.isEmpty { result["stderr"] = String(err.prefix(2000)) }
        if timedOut { result["error"] = "Command timed out after 10s and was terminated." }
        return result
    }
}

private extension String {
    /// Splits into lines without dropping the final line (Swift's split with
    /// omittingEmptySubsequences handles most cases; this keeps semantics clear).
    func enumeratedLines() -> [Substring] {
        self.split(separator: "\n", omittingEmptySubsequences: false).map { $0 }
    }
}

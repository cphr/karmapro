// by cipher.org.uk
import Foundation
import Network

/// Minimal HTTP/1.1 server for the MCP endpoint: one request per connection,
/// loopback peers only, with an optional server-sent-events stream.
final class MCPHTTPServer {
    struct Request {
        let method: String
        let path: String
        let headers: [String: String]
        let body: Data

        func header(_ name: String) -> String? { headers[name.lowercased()] }
    }

    struct Response {
        var status: Int = 200
        var headers: [String: String] = [:]
        var body: Data = Data()

        static func json(_ object: Any) -> Response {
            Response(status: 200,
                     headers: ["Content-Type": "application/json"],
                     body: MCPCode.json(object))
        }

        static func text(_ status: Int, _ message: String) -> Response {
            Response(status: status,
                     headers: ["Content-Type": "text/plain; charset=utf-8"],
                     body: Data(message.utf8))
        }
    }

    /// Handlers may block (a scan_directory call waits briefly), so they run off
    /// the listener's queue and answer through the callback.
    var handler: ((Request, @escaping (Response) -> Void) -> Void)?
    /// Called for a GET that asks for `text/event-stream`. Return false to
    /// refuse the stream; the peer then gets a plain 401.
    var onStream: ((Request, MCPHTTPStream) -> Bool)?
    var log: ((String) -> Void)?

    private var listener: NWListener?
    private let queue = DispatchQueue(label: "app.karmapro.mcp.http")
    private let lock = NSLock()
    private var streams: [MCPHTTPStream] = []

    var isRunning: Bool { listener != nil }
    var port: UInt16 { listener?.port?.rawValue ?? 0 }

    /// Binds `port` (0 = any free port) to the loopback address. Some systems
    /// refuse a specific local endpoint, so a plain all-interface bind is the
    /// fallback; `accept` still rejects every non-loopback peer.
    func start(port: UInt16) throws -> UInt16 {
        do {
            return try start(port: port, loopbackOnly: true)
        } catch {
            log?("loopback bind failed (\(error.localizedDescription)); trying all interfaces")
        }
        return try start(port: port, loopbackOnly: false)
    }

    private func start(port: UInt16, loopbackOnly: Bool) throws -> UInt16 {
        stop()
        let parameters = NWParameters.tcp
        parameters.allowLocalEndpointReuse = true
        let endpointPort: NWEndpoint.Port = port == 0 ? .any : NWEndpoint.Port(rawValue: port)!
        let listener: NWListener
        if loopbackOnly {
            parameters.requiredLocalEndpoint = .hostPort(host: .ipv4(.loopback), port: endpointPort)
            listener = try NWListener(using: parameters)
        } else {
            listener = try NWListener(using: parameters, on: endpointPort)
        }
        listener.newConnectionHandler = { [weak self] connection in
            self?.accept(connection)
        }
        var started = false
        var thrown: Error?
        let ready = DispatchSemaphore(value: 0)
        listener.stateUpdateHandler = { state in
            switch state {
            case .ready:
                started = true
                ready.signal()
            case .failed(let error):
                thrown = error
                ready.signal()
            default:
                break
            }
        }
        listener.start(queue: queue)
        _ = ready.wait(timeout: .now() + 2)
        guard started, thrown == nil else {
            listener.cancel()
            throw thrown ?? NSError(domain: "MCP", code: 1,
                                    userInfo: [NSLocalizedDescriptionKey: "The listener did not start."])
        }
        self.listener = listener
        return listener.port?.rawValue ?? port
    }

    func stop() {
        listener?.cancel()
        listener = nil
        lock.lock()
        let open = streams
        streams = []
        lock.unlock()
        open.forEach { $0.close() }
    }

    // MARK: - Connections

    private func accept(_ connection: NWConnection) {
        guard isLoopback(connection.endpoint) else {
            log?("refused non-loopback peer \(connection.endpoint)")
            connection.cancel()
            return
        }
        connection.start(queue: queue)
        receive(connection, buffer: Data())
    }

    private func isLoopback(_ endpoint: NWEndpoint) -> Bool {
        guard case let .hostPort(host, _) = endpoint else { return false }
        switch host {
        case .ipv4(let address): return address == .loopback
        case .ipv6(let address): return address == .loopback
        case .name(let name, _):
            return name == "localhost" || name == "127.0.0.1" || name == "::1"
        @unknown default: return false
        }
    }

    private func receive(_ connection: NWConnection, buffer: Data) {
        connection.receive(minimumIncompleteLength: 1, maximumLength: 64 * 1024) { [weak self] data, _, done, error in
            guard let self else { return }
            var buffer = buffer
            if let data { buffer.append(data) }

            if let request = Self.parse(buffer) {
                self.route(request, on: connection)
                return
            }
            if buffer.count > 16 * 1024 * 1024 {
                self.respond(.text(413, "request too large"), on: connection)
                return
            }
            if done || error != nil {
                connection.cancel()
                return
            }
            self.receive(connection, buffer: buffer)
        }
    }

    private static func parse(_ buffer: Data) -> Request? {
        guard let headerEnd = buffer.range(of: Data("\r\n\r\n".utf8)) else { return nil }
        let headerData = buffer[..<headerEnd.lowerBound]
        guard let headerText = String(data: headerData, encoding: .utf8) else { return nil }

        var lines = headerText.components(separatedBy: "\r\n")
        guard !lines.isEmpty else { return nil }
        let requestLine = lines.removeFirst().split(separator: " ")
        guard requestLine.count >= 2 else { return nil }
        let method = String(requestLine[0])
        let path = String(requestLine[1])

        var headers: [String: String] = [:]
        for line in lines {
            guard let colon = line.firstIndex(of: ":") else { continue }
            let name = line[..<colon].trimmingCharacters(in: .whitespaces).lowercased()
            let value = line[line.index(after: colon)...].trimmingCharacters(in: .whitespaces)
            headers[name] = value
        }

        let length = Int(headers["content-length"] ?? "0") ?? 0
        let body = buffer[buffer.index(headerEnd.upperBound, offsetBy: 0)...]
        guard body.count >= length else { return nil }
        return Request(method: method, path: path, headers: headers, body: Data(body.prefix(length)))
    }

    private func route(_ request: Request, on connection: NWConnection) {
        if request.method == "GET",
           (request.header("accept") ?? "").contains("text/event-stream") {
            let stream = MCPHTTPStream(connection: connection, queue: queue)
            guard onStream?(request, stream) == true else {
                respond(.text(401, "unauthorized"), on: connection)
                return
            }
            lock.lock()
            streams.append(stream)
            lock.unlock()
            stream.onClose = { [weak self, weak stream] in
                guard let self, let stream else { return }
                self.lock.lock()
                self.streams.removeAll { $0 === stream }
                self.lock.unlock()
            }
            stream.open()
            return
        }
        guard let handler else {
            respond(.text(503, "no handler"), on: connection)
            return
        }
        let connection = connection
        handler(request) { [weak self] response in
            self?.respond(response, on: connection)
        }
    }

    private func respond(_ response: Response, on connection: NWConnection) {
        var headers = response.headers
        headers["Content-Length"] = String(response.body.count)
        headers["Connection"] = "close"
        var head = "HTTP/1.1 \(response.status) \(Self.reason(response.status))\r\n"
        for (name, value) in headers.sorted(by: { $0.key < $1.key }) {
            head += "\(name): \(value)\r\n"
        }
        head += "\r\n"
        var data = Data(head.utf8)
        data.append(response.body)
        connection.send(content: data, completion: .contentProcessed { _ in
            connection.cancel()
        })
    }

    private static func reason(_ status: Int) -> String {
        switch status {
        case 200: return "OK"
        case 202: return "Accepted"
        case 204: return "No Content"
        case 400: return "Bad Request"
        case 401: return "Unauthorized"
        case 404: return "Not Found"
        case 405: return "Method Not Allowed"
        case 413: return "Payload Too Large"
        case 500: return "Internal Server Error"
        default: return "Status"
        }
    }
}

/// A server-sent-events channel for one client session.
final class MCPHTTPStream {
    fileprivate let connection: NWConnection
    fileprivate let queue: DispatchQueue
    private let lock = NSLock()
    private var closed = false
    var onClose: (() -> Void)?

    var isClosed: Bool {
        lock.lock()
        defer { lock.unlock() }
        return closed
    }

    fileprivate init(connection: NWConnection, queue: DispatchQueue) {
        self.connection = connection
        self.queue = queue
    }

    fileprivate func open() {
        let head = "HTTP/1.1 200 OK\r\n"
            + "Content-Type: text/event-stream\r\n"
            + "Cache-Control: no-cache\r\n"
            + "Connection: close\r\n"
            + "\r\n"
        connection.send(content: Data(head.utf8), completion: .contentProcessed { _ in })
        // Reading is only for noticing the client going away.
        connection.receive(minimumIncompleteLength: 1, maximumLength: 4096) { [weak self] _, _, done, error in
            if done || error != nil { self?.close() }
        }
    }

    func send(_ object: [String: Any]) {
        lock.lock()
        let isClosed = closed
        lock.unlock()
        guard !isClosed else { return }
        var frame = "event: message\ndata: "
        frame += String(data: MCPCode.json(object), encoding: .utf8) ?? "{}"
        frame += "\n\n"
        connection.send(content: Data(frame.utf8), completion: .contentProcessed { _ in })
    }

    func close() {
        lock.lock()
        if closed { lock.unlock(); return }
        closed = true
        lock.unlock()
        connection.cancel()
        onClose?()
    }
}

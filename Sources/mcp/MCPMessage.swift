// by cipher.org.uk
import Foundation

/// JSON-RPC 2.0 envelopes over MCP.
enum MCPCode {
    static let parse = -32700
    static let invalidRequest = -32600
    static let methodNotFound = -32601
    static let invalidParams = -32602
    static let internalError = -32603
    static let resourceNotFound = -32002

    static func result(_ id: Any, _ result: [String: Any]) -> [String: Any] {
        ["jsonrpc": "2.0", "id": id, "result": result]
    }

    static func error(_ id: Any?, _ code: Int, _ message: String, data: Any? = nil) -> [String: Any] {
        var error: [String: Any] = ["code": code, "message": message]
        if let data { error["data"] = data }
        return ["jsonrpc": "2.0", "id": id ?? NSNull(), "error": error]
    }

    static func notification(_ method: String, _ params: [String: Any]) -> [String: Any] {
        ["jsonrpc": "2.0", "method": method, "params": params]
    }

    static func json(_ object: Any) -> Data {
        (try? JSONSerialization.data(withJSONObject: object, options: [])) ?? Data("{}".utf8)
    }
}

struct MCPEnvelope {
    let id: Any?
    let method: String?
    let params: [String: Any]
    let isNotification: Bool
}

enum MCPParser {
    /// Returns the envelopes in a request body, or nil when it is not JSON-RPC.
    static func parse(_ data: Data) -> (envelopes: [MCPEnvelope], batch: Bool)? {
        guard let object = try? JSONSerialization.jsonObject(with: data) else { return nil }
        if let array = object as? [Any] {
            guard !array.isEmpty else { return nil }
            var out: [MCPEnvelope] = []
            for item in array {
                guard let env = envelope(item) else { return nil }
                out.append(env)
            }
            return (out, true)
        }
        guard let env = envelope(object) else { return nil }
        return ([env], false)
    }

    private static func envelope(_ object: Any) -> MCPEnvelope? {
        guard let dict = object as? [String: Any],
              dict["jsonrpc"] as? String == "2.0" else { return nil }
        let method = dict["method"] as? String
        let rawID = dict["id"]
        let id: Any? = (rawID is NSNull) ? nil : rawID
        guard method != nil || dict["result"] != nil || dict["error"] != nil else { return nil }
        let params = dict["params"] as? [String: Any] ?? [:]
        return MCPEnvelope(id: id,
                           method: method,
                           params: params,
                           isNotification: method != nil && id == nil)
    }
}

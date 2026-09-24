// by cipher.org.uk
import Foundation

/// A language family that the entry-point catalog can describe. Roughly mirrors
/// `DiagramLanguage`, with C and C++ sharing one table (as the existing C
/// analyzer does).
enum EPLanguage: String, CaseIterable, Hashable {
    case c
    case objc
    case java
    case kotlin
    case csharp
    case swift
    case javascript
    case python
    case ruby
    case go
    case rust
    case php
    case solidity

    static func from(ext: String) -> EPLanguage? {
        switch ext.lowercased() {
        case "c", "h", "cpp", "cc", "cxx", "hpp", "hxx", "hh": return .c
        case "m", "mm", "objc": return .objc
        case "java": return .java
        case "kt", "kts": return .kotlin
        case "cs", "csx": return .csharp
        case "swift": return .swift
        case "js", "jsx", "ts", "tsx": return .javascript
        case "py": return .python
        case "rb", "rake", "gemspec": return .ruby
        case "go": return .go
        case "rs": return .rust
        case "php", "phtml": return .php
        case "sol": return .solidity
        default: return nil
        }
    }
}

/// Where the value comes from at runtime.
enum EntryOrigin {
    case local
    case internet
}

/// Confidence tier. "Primary" entries are shown by default; "indirect" entries
/// (file reads, persisted data, deserialization) are collected lazily behind the
/// window's toggle.
enum EntryConfidence {
    case primary
    case indirect
}

/// How a catalog entry appears in the token stream. Call-style entries are a
/// method call (`getParameter(...)`); property-style entries are a plain field
/// or property read (`msg.sender`, `request.json`).
enum EntryMatch {
    case call
    case property
    case both
}

/// A single receive-API definition in the catalog.
struct EPEntry {
    /// Trailing identifier of the receive API, e.g. `getParameter` or `sender`.
    let leaf: String

    /// Required receiver path (normalized with `.`), e.g. `msg`, `request`,
    /// `std.env`. The collector matches when the struck chain equals the prefix
    /// or ends with `.prefix`, so `URLSession.shared` satisfies prefix `URLSession`.
    /// When `match` includes `property`, the prefix must be set — that keeps
    /// generic leaves (`query`, `sender`, ...) from matching anywhere.
    let prefix: String?

    /// Grouping label shown in the results window.
    let category: String

    /// local vs internet source.
    let origin: EntryOrigin

    /// primary vs indirect tier.
    let confidence: EntryConfidence

    let match: EntryMatch

    /// Restrict to a subset of languages; nil means any supported language.
    let langs: Set<EPLanguage>?

    /// When true, property-style matching is allowed without a receiver prefix
    /// (for bare identifiers such as `argv`, `environ`, `ENV`, `$argc`).
    let allowBareProperty: Bool

    /// For write-style receive calls whose received data lands in an argument
    /// (fgets, scanf, read/recv, copy_from_user, get_user, ...): the 0-based
    /// index of that buffer/out argument. When set, the argument variable is
    /// the flow source. `nil` for return-style APIs (getenv, getParameter, ...).
    let receiverArg: Int?

    func applies(to lang: EPLanguage) -> Bool {
        langs == nil || langs!.contains(lang)
    }

    static func call(_ leaf: String, prefix: String? = nil,
                     _ category: String, _ origin: EntryOrigin,
                     _ confidence: EntryConfidence = .primary,
                     receiverArg: Int? = nil,
                     langs: Set<EPLanguage>? = nil) -> EPEntry {
        EPEntry(leaf: leaf, prefix: prefix, category: category, origin: origin,
                confidence: confidence, match: .call, langs: langs,
                allowBareProperty: false, receiverArg: receiverArg)
    }

    static func prop(_ leaf: String, prefix: String,
                     _ category: String, _ origin: EntryOrigin,
                     _ confidence: EntryConfidence = .primary,
                     langs: Set<EPLanguage>? = nil) -> EPEntry {
        EPEntry(leaf: leaf, prefix: prefix, category: category, origin: origin,
                confidence: confidence, match: .property, langs: langs,
                allowBareProperty: false, receiverArg: nil)
    }

    static func bare(_ leaf: String,
                     _ category: String, _ origin: EntryOrigin,
                     _ confidence: EntryConfidence = .primary,
                     langs: Set<EPLanguage>? = nil) -> EPEntry {
        EPEntry(leaf: leaf, prefix: nil, category: category, origin: origin,
                confidence: confidence, match: .both, langs: langs,
                allowBareProperty: true, receiverArg: nil)
    }
}

/// The curated receive-API catalog: which calls/properties hand externally (or
/// kernel-provided) values into the program, plus the categories the "Find
/// Entries" window groups them by.
///
/// Categories (group rows):
///   HTTP request (server)                    — internet, primary
///   Web client & WebSocket response          — internet, primary
///   Deep links & push payload                — internet, primary
///   Blockchain transaction input             — internet, primary
///   Kernel: network delivery                 — internet, primary
///   Command line & environment               — local, primary
///   Standard input & stream reads            — local, primary
///   Kernel: userland -> kernel (syscall/ioctl/device) — local, primary
///   File & stream reads                      — local, indirect (toggle)
///   Local storage & persisted data           — local, indirect (toggle)
///   Encoding & serialization decode          — local/indirect (toggle)
enum EntryPointCatalog {

    static let httpRequest = "HTTP request (server)"
    static let webClient = "Web client & WebSocket response"
    static let deepLinks = "Deep links & push payload"
    static let blockchain = "Blockchain transaction input"
    static let kernelNetwork = "Kernel: network delivery"
    static let cliEnv = "Command line & environment"
    static let stdin = "Standard input & stream reads"
    static let kernelUser = "Kernel: userland → kernel (syscall/ioctl/device)"
    static let fileReads = "File & stream reads"
    static let persisted = "Local storage & persisted data"
    static let encoding = "Encoding & serialization decode"

    static let entries: [EPEntry] = {
        var e: [EPEntry] = []

        let javaKotlin: Set<EPLanguage> = [.java, .kotlin]

        // MARK: HTTP request (server)

        // Java / Kotlin servlet & Spring request accessors.
        for leaf in ["getParameter", "getParameterValues", "getParameterMap",
                     "getHeader", "getHeaderNames", "getHeaders", "getIntHeader",
                     "getDateHeader", "getCookies", "getQueryString", "getRequestURI",
                     "getRequestURL", "getServletPath", "getPathInfo", "getPathTranslated",
                     "getInputStream", "getReader", "getContentType", "getRemoteAddr",
                     "getRemoteHost", "getRemoteUser", "getRemotePort", "getMethod",
                     "getServerName", "getRequestedSessionId", "getAttribute"] {
            e.append(.call(leaf, httpRequest, .internet, langs: javaKotlin))
        }
        // Go net/http handlers follow the `r.*` receiver convention.
        for leaf in ["FormValue", "PostFormValue", "PathValue", "QueryValue", "Cookie",
                     "Cookies", "MultipartReader", "ReadForm", "GetBod"] {
            e.append(.call(leaf, httpRequest, .internet, langs: [.go]))
        }
        // `r.URL.Query().Get("k")` is the canonical Go query read; the `.Get`
        // leaf above covers it (the intermediate `Query()` is not itself a
        // receive), so a bare `Query` click (e.g. `db.Query`) is not treated as
        // an HTTP entry.
        for leaf in ["Get", "FormValue", "QueryValue"] {
            e.append(.call(leaf, httpRequest, .internet, langs: [.go]))
        }
        // Python web frameworks (request = Flask/Django style object).
        for leaf in ["args", "form", "json", "values", "files", "cookies", "headers",
                     "data", "query", "params", "body", "GET", "POST", "environ",
                     "make_query_string"] {
            e.append(.prop(leaf, prefix: "request", httpRequest, .internet, langs: [.python]))
        }
        e.append(.call("get_json", prefix: "request", httpRequest, .internet, langs: [.python]))
        // Ruby / Rack request accessors.
        for leaf in ["params", "cookies", "session", "query_string"] {
            e.append(.bare(leaf, httpRequest, .internet, langs: [.ruby]))
        }
        // Node / browser: Express & Fastify style request object.
        for leaf in ["query", "params", "body", "headers", "cookies", "files",
                     "session", "originalUrl", "baseUrl", "route", "hostname",
                     "ip", "protocol"] {
            e.append(.prop(leaf, prefix: "req", httpRequest, .internet, langs: [.javascript]))
            e.append(.prop(leaf, prefix: "request", httpRequest, .internet, langs: [.javascript]))
        }
        e.append(.prop("search", prefix: "document.location", httpRequest, .internet,
                       langs: [.javascript]))
        e.append(.prop("search", prefix: "window.location", httpRequest, .internet,
                       langs: [.javascript]))
        // PHP superglobals and URL handling.
        // PHP superglobals and URL handling.
        e.append(.bare("_GET", httpRequest, .internet, langs: [.php]))
        e.append(.bare("_POST", httpRequest, .internet, langs: [.php]))
        e.append(.bare("_REQUEST", httpRequest, .internet, langs: [.php]))
        e.append(.bare("_COOKIE", httpRequest, .internet, langs: [.php]))
        e.append(.bare("_FILES", httpRequest, .internet, langs: [.php]))
        e.append(.bare("_SERVER", httpRequest, .internet, langs: [.php]))
        e.append(.call("getallheaders", httpRequest, .internet, langs: [.php]))
        e.append(.call("parse_str", httpRequest, .internet, langs: [.php]))
        e.append(.call("parse_url", httpRequest, .internet, langs: [.php]))
        e.append(.call("php_input", httpRequest, .internet, langs: [.php]))
        // PHP frameworks: Laravel/Slim request accessors (`$request->input(…)`).
        // The collector's receiver-path resolves `->` like `.`, so the struck
        // chain is `request`.
        for leaf in ["input", "get", "query", "post", "header", "cookie", "json",
                     "all", "only", "except", "files", "file", "request", "server",
                     "ip", "has", "filled", "boolean", "integer"] {
            e.append(.call(leaf, prefix: "request", httpRequest, .internet, langs: [.php]))
        }
        // Kotlin/Ktor: routing `call.request.*` reads and `call.receive<T>()`.
        for leaf in ["queryParameters", "parameters", "pathParameters", "headers",
                     "cookies", "body", "queryString"] {
            e.append(.prop(leaf, prefix: "call.request", httpRequest, .internet, langs: [.kotlin]))
        }
        e.append(.call("receive", prefix: "call", httpRequest, .internet, langs: [.kotlin]))
        e.append(.call("receiveText", prefix: "call", httpRequest, .internet, langs: [.kotlin]))
        // Python: fully-qualified flask.request reads (when `request` is imported
        // as `flask.request` rather than the bare Flask global).
        for leaf in ["args", "form", "json", "values", "files", "cookies", "headers",
                     "data", "query", "params", "body", "GET", "POST"] {
            e.append(.prop(leaf, prefix: "flask.request", httpRequest, .internet, langs: [.python]))
        }
        // Python: async server (aiohttp/web) and Tornado request reads.
        for leaf in ["query", "json", "post", "rel_url", "text", "read"] {
            e.append(.call(leaf, prefix: "request", httpRequest, .internet, langs: [.python]))
        }
        // Ruby/Rack: request-derived reads beyond the bare `params`.
        for leaf in ["headers", "body", "query_string", "remote_ip", "request_method",
                     "session", "env"] {
            e.append(.prop(leaf, prefix: "request", httpRequest, .internet, langs: [.ruby]))
        }
        // Swift Vapor: content/query decoding off a handler `req`.
        e.append(.call("decode", prefix: "req.query", httpRequest, .internet, langs: [.swift]))
        e.append(.call("decode", prefix: "req.content", httpRequest, .internet, langs: [.swift]))
        e.append(.prop("query", prefix: "req", httpRequest, .internet, langs: [.swift]))
        // C# / ASP.NET request accessors.
        for leaf in ["QueryString", "Form", "Params", "Headers", "Cookies",
                     "ServerVariables", "RequestType", "Url", "RawUrl", "Path",
                     "FilePath", "AppRelativeCurrentExecutionFilePath", "QueryStringPublic"] {
            e.append(.prop(leaf, prefix: "Request", httpRequest, .internet, langs: [.csharp]))
        }
        for leaf in ["get_QueryString", "get_Form", "get_Params", "get_Headers",
                     "get_Cookies", "get_ServerVariables", "get_RawUrl",
                     "get_RequestType", "get_PathInfo"] {
            e.append(.call(leaf, prefix: "Request", httpRequest, .internet, langs: [.csharp]))
        }
        e.append(.call("IsPostBack", prefix: "Request", httpRequest, .internet, langs: [.csharp]))
        e.append(.call("HtmlEncode", httpRequest, .internet, langs: [.csharp]))

        // MARK: Web client & WebSocket response

        // Data received back from network stacks: socket reads and HTTP/fetch
        // bodies arriving into the program. recv/recvfrom/recvmsg fill arg 1;
        // recv_into/recvfrom_into fill their arg 0 buffer.
        let recvWriteArgs: [String: Int] = ["recv": 1, "recvfrom": 1, "recvmsg": 1,
                                            "recv_into": 0, "recvfrom_into": 0]
        for base in ["recv", "recvfrom", "recvmsg", "recv_into", "recvfrom_into"] {
            e.append(.call(base, webClient, .internet, receiverArg: recvWriteArgs[base],
                           langs: [.c, .objc, .go, .python, .ruby, .rust]))
            e.append(.call(base, webClient, .internet, receiverArg: recvWriteArgs[base],
                           langs: [.csharp]))
        }
        e.append(.call("socket_read", webClient, .internet, langs: [.php]))
        e.append(.call("fetch", webClient, .internet, langs: [.javascript]))
        e.append(.call("json", webClient, .internet, langs: [.javascript]))
        e.append(.call("get_headers", webClient, .internet, langs: [.php]))
        // Go HTTP client response bodies (`http.Get(…)`, `client.Do(…)`).
        for leaf in ["Get", "Post", "PostForm", "Do", "Head"] {
            e.append(.call(leaf, prefix: "http", webClient, .internet, langs: [.go]))
        }
        // Python client stacks.
        for leaf in ["get", "post", "put", "delete", "patch", "head"] {
            e.append(.call(leaf, prefix: "requests", webClient, .internet, langs: [.python]))
            e.append(.call(leaf, prefix: "aiohttp.session", webClient, .internet, langs: [.python]))
        }
        e.append(.call("urlopen", prefix: "urllib.request", webClient, .internet, langs: [.python]))
        e.append(.call("urlopen", prefix: "urllib", webClient, .internet, langs: [.python]))
        // JavaScript: response-body readers and TCP socket data callbacks.
        for leaf in ["json", "text", "arrayBuffer", "formData", "blob"] {
            e.append(.call(leaf, prefix: "res", webClient, .internet, langs: [.javascript]))
            e.append(.call(leaf, prefix: "response", webClient, .internet, langs: [.javascript]))
        }
        // Rust: reqwest top-level and per-client receivers.
        for leaf in ["get", "post", "put", "delete", "patch", "head"] {
            e.append(.call(leaf, prefix: "reqwest", webClient, .internet, langs: [.rust]))
        }
        e.append(.call("response", prefix: "reqwest", webClient, .internet, langs: [.rust]))
        for leaf in ["data", "dataTask", "downloadTask", "uploadTask", "bytes",
                     "dataFrom", "dataFromURL", "start", "trigger", "send",
                     "open", "stream"] {
            e.append(.call(leaf, prefix: "URLSession", webClient, .internet, langs: [.swift]))
        }
        e.append(.call("openURL", prefix: "URL", webClient, .internet, langs: [.swift]))

        // MARK: Deep links & push payload

        // Android intents & URI hooks (the receiving side of deep links) and
        // cross-platform deep-link shims.
        for leaf in ["getStringExtra", "getIntExtra", "getLongExtra", "getFloatExtra",
                     "getDoubleExtra", "getBooleanExtra", "getCharSequenceExtra",
                     "getSerializableExtra", "getParcelableExtra", "getBundleExtra",
                     "getExtras", "getData", "getDataString", "getScheme",
                     "getEncodedPath", "getQueryParameter", "getPathSegments",
                     "getCharSequenceArrayExtra", "getStringArrayListExtra",
                     "getIntegerArrayListExtra", "getParcelableArrayListExtra",
                     "getStringArrayExtra", "getClipData", "getInputExtras"] {
            e.append(.call(leaf, deepLinks, .internet, langs: javaKotlin))
        }
        for leaf in ["getInitialLink", "getInitialUri", "streamLinks", "getDeepLink",
                     "deeplink", "uri", "path", "host", "queryParameters"] {
            e.append(.call(leaf, deepLinks, .internet,
                           langs: Set([.csharp, .java, .kotlin, .go, .rust, .php, .ruby, .javascript])))
        }
        // Apple: UIApplication/NSApplication open hooks and userActivity/notification payload.
        e.append(.call("openURL", deepLinks, .internet, langs: [.objc]))
        e.append(.call("open", prefix: "application", deepLinks, .internet,
                       langs: Set([.swift, .objc])))
        e.append(.prop("webpageURL", prefix: "userActivity", deepLinks, .internet,
                       langs: [.swift, .objc]))
        e.append(.prop("userInfo", prefix: "notification", deepLinks, .internet,
                       langs: [.swift, .objc]))

        // MARK: Blockchain transaction input

        for leaf in ["sender", "value", "data", "sig"] {
            e.append(.prop(leaf, prefix: "msg", blockchain, .internet, langs: [.solidity]))
        }
        for leaf in ["origin", "gasprice"] {
            e.append(.prop(leaf, prefix: "tx", blockchain, .internet, langs: [.solidity]))
        }
        for leaf in ["timestamp", "number", "difficulty", "basefee", "coinbase",
                     "prevrandao", "chainid", "gaslimit"] {
            e.append(.prop(leaf, prefix: "block", blockchain, .internet, langs: [.solidity]))
        }
        for leaf in ["blockhash", "call", "delegatecall", "staticcall", "callcode",
                     "extcodesize", "extcodecopy", "mload", "sload"] {
            e.append(.call(leaf, blockchain, .internet, langs: [.solidity]))
        }
        e.append(.call("decode", prefix: "abi", blockchain, .internet, langs: [.solidity]))

        // MARK: Command line & environment

        e.append(.call("getenv", cliEnv, .local, langs: [.c, .objc, .swift, .java, .kotlin]))
        e.append(.call("getenv", prefix: "System", cliEnv, .local, langs: javaKotlin))
        e.append(.call("getProperty", prefix: "System", cliEnv, .local, langs: javaKotlin))
        e.append(.call("GetEnvironmentVariable", cliEnv, .local, langs: [.csharp]))
        e.append(.call("GetCommandLineArgs", cliEnv, .local, langs: [.csharp]))
        e.append(.call("getwd", cliEnv, .local, langs: [.c, .objc]))
        e.append(.bare("argv", cliEnv, .local, langs: [.c, .objc]))
        e.append(.bare("argc", cliEnv, .local, langs: [.c, .objc]))
        e.append(.bare("environ", cliEnv, .local, langs: [.c, .objc, .python]))
        e.append(.bare("ARGV", cliEnv, .local, langs: [.ruby]))
        e.append(.bare("ENV", cliEnv, .local, langs: [.ruby]))
        e.append(.call("getenv", prefix: "os", cliEnv, .local, langs: [.go]))
        e.append(.call("Getenv", prefix: "os", cliEnv, .local, langs: [.go]))
        e.append(.call("LookupEnv", prefix: "os", cliEnv, .local, langs: [.go]))
        e.append(.call("Environ", prefix: "os", cliEnv, .local, langs: [.go]))
        e.append(.prop("Args", prefix: "os", cliEnv, .local, langs: [.go]))
        e.append(.prop("environ", prefix: "os", cliEnv, .local, langs: [.python]))
        e.append(.prop("argv", prefix: "sys", cliEnv, .local, langs: [.python, .csharp, .ruby]))
        e.append(.prop("environ", prefix: "sys", cliEnv, .local, langs: [.python]))
        e.append(.prop("env", prefix: "process", cliEnv, .local, langs: [.javascript]))
        e.append(.call("Getenv", prefix: "os", cliEnv, .local, langs: [.php]))
        e.append(.call("GetENV", prefix: "System.Environment", cliEnv, .local, langs: [.csharp]))
        e.append(.bare("_ENV", cliEnv, .local, langs: [.php]))
        e.append(.prop("arguments", prefix: "CommandLine", cliEnv, .local, langs: [.swift]))
        e.append(.prop("unsafeArgv", prefix: "CommandLine", cliEnv, .local, langs: [.swift]))
        e.append(.prop("environment", prefix: "ProcessInfo.processInfo", cliEnv, .local,
                       langs: [.swift, .objc]))
        e.append(.prop("environment", prefix: "processInfo", cliEnv, .local, langs: [.objc]))
        // Node / Deno.
        e.append(.prop("argv", prefix: "process", cliEnv, .local, langs: [.javascript]))
        e.append(.call("get", prefix: "Deno.env", cliEnv, .local, langs: [.javascript]))
        // Rust: std::env and the env crate.
        for leaf in ["var", "vars", "args"] {
            e.append(.call(leaf, prefix: "std.env", cliEnv, .local, langs: [.rust]))
        }
        for leaf in ["var", "vars", "args"] {
            e.append(.call(leaf, prefix: "env", cliEnv, .local, langs: [.rust]))
        }
        e.append(.call("args", cliEnv, .local, langs: [.rust]))
        e.append(.call("var_os", prefix: "std.env", cliEnv, .local, langs: [.rust]))

        // MARK: Standard input & stream reads

        // gets/fgets/getline fill their buffer (arg 0); scanf-family fill arg 1;
        // read(fd, buf, n) fills arg 1; getchar/fgetc/getc return a value.
        let cWriteArgs: [String: Int] = ["gets": 0, "fgets": 0, "getline": 0,
                                         "scanf": 1, "fscanf": 1, "sscanf": 1, "read": 1]
        for leaf in ["gets", "getchar", "fgets", "fgetc", "getc", "scanf", "fscanf",
                     "sscanf", "getline", "read"] {
            e.append(.call(leaf, stdin, .local, receiverArg: cWriteArgs[leaf], langs: [.c, .objc]))
        }
        e.append(.call("getpass", stdin, .local, langs: [.c, .objc, .python]))
        for leaf in ["nextLine", "next", "nextInt", "nextLong", "nextDouble",
                     "nextBoolean", "nextByte", "nextFloat", "nextShort"] {
            e.append(.call(leaf, stdin, .local, langs: javaKotlin))
        }
        e.append(.call("readLine", stdin, .local, langs: javaKotlin))
        e.append(.call("ReadLine", stdin, .local, langs: [.csharp]))
        e.append(.call("Read", stdin, .local, langs: [.csharp]))
        e.append(.call("input", stdin, .local, langs: [.python]))
        e.append(.call("raw_input", stdin, .local, langs: [.python]))
        e.append(.call("gets", stdin, .local, langs: [.ruby]))
        e.append(.call("readline", stdin, .local, langs: [.ruby]))
        e.append(.call("getc", stdin, .local, langs: [.ruby]))
        e.append(.call("read_line", stdin, .local, langs: [.rust]))
        e.append(.call("read_to_string", stdin, .local, langs: [.rust]))
        e.append(.call("stdin", stdin, .local, langs: [.rust]))
        e.append(.prop("stdin", prefix: "sys", stdin, .local, langs: [.python]))
        e.append(.bare("stdin", stdin, .local, langs: [.c, .objc, .swift, .rust]))
        e.append(.call("Scan", prefix: "fmt", stdin, .local, langs: [.go]))
        e.append(.call("Scanln", prefix: "fmt", stdin, .local, langs: [.go]))
        e.append(.call("Scanf", prefix: "fmt", stdin, .local, langs: [.go]))
        e.append(.call("NewScanner", prefix: "bufio", stdin, .local, langs: [.go]))
        e.append(.call("NewReader", prefix: "bufio", stdin, .local, langs: [.go]))
        e.append(.bare("STDIN", stdin, .local, langs: [.php]))
        e.append(.bare("argv", stdin, .local, langs: [.php]))
        e.append(.call("readline", stdin, .local, langs: [.php]))
        e.append(.call("readLine", stdin, .local, langs: [.swift]))

        // MARK: Kernel: userland → kernel (syscall/ioctl/device)

        // copy*/get_user/strncpy_from_user fill their destination arg 0; kstrto*
        // fill their out-pointer arg; simple_write_to_buffer writes arg 0.
        let kernelWriteArgs: [String: Int] = [
            "copy_from_user": 0, "__copy_from_user": 0, "copy_from_user_nofault": 0,
            "copy_from_user_user": 0, "get_user": 0, "__get_user": 0,
            "strncpy_from_user": 0, "kstrtoint": 2, "kstrtouint": 2, "kstrtol": 2,
            "kstrtoul": 2, "kstrtoll": 2, "kstrtoull": 2, "kstrtobool": 1,
            "simple_write_to_buffer": 0
        ]
        for leaf in ["copy_from_user", "__copy_from_user", "copy_from_user_nofault",
                     "copy_from_user_user", "get_user", "__get_user", "strncpy_from_user",
                     "strnlen_user", "memdup_user", "memdup_user_nul", "kvmemdup",
                     "kstrtoint", "kstrtouint", "kstrtol", "kstrtoul", "kstrtoll",
                     "kstrtoull", "kstrtobool", "simple_write_to_buffer"] {
            e.append(.call(leaf, kernelUser, .local, receiverArg: kernelWriteArgs[leaf],
                           langs: [.c]))
        }
        e.append(.call("unlocked_ioctl", kernelUser, .local, langs: [.c]))
        e.append(.call("compat_ioctl", kernelUser, .local, langs: [.c]))

        // MARK: Kernel: network delivery

        e.append(.call("netlink_kernel_create", kernelNetwork, .internet, langs: [.c]))
        e.append(.call("recvmsg", kernelNetwork, .internet, receiverArg: 1, langs: [.c]))
        e.append(.call("skb_recv_datagram", kernelNetwork, .internet, langs: [.c]))
        e.append(.call("skb_copy_datagram_iter", kernelNetwork, .internet, receiverArg: 2, langs: [.c]))
        e.append(.call("skb_copy_datagram_from_iter", kernelNetwork, .internet, langs: [.c]))
        e.append(.call("memcpy_from_msg", kernelNetwork, .internet, langs: [.c]))
        e.append(.call("memcpy_from_iter", kernelNetwork, .internet, langs: [.c]))

        // MARK: File & stream reads (indirect)

        e.append(.call("readAllBytes", fileReads, .local, .indirect, langs: javaKotlin))
        e.append(.call("readAllLines", fileReads, .local, .indirect, langs: javaKotlin))
        e.append(.call("readString", fileReads, .local, .indirect, langs: javaKotlin))
        e.append(.call("readText", fileReads, .local, .indirect, langs: javaKotlin))
        e.append(.call("readLines", fileReads, .local, .indirect, langs: javaKotlin))
        e.append(.call("readBytes", fileReads, .local, .indirect, langs: javaKotlin))
        e.append(.call("readline", fileReads, .local, .indirect, langs: [.python, .ruby, .javascript]))
        e.append(.call("readlines", fileReads, .local, .indirect, langs: [.python, .ruby]))
        e.append(.call("read", fileReads, .local, .indirect, langs: [.python, .ruby, .javascript]))
        e.append(.call("ReadFile", prefix: "os", fileReads, .local, .indirect, langs: [.go]))
        e.append(.call("Open", prefix: "os", fileReads, .local, .indirect, langs: [.go]))
        e.append(.call("OpenFile", prefix: "os", fileReads, .local, .indirect, langs: [.go]))
        e.append(.call("ReadDir", prefix: "os", fileReads, .local, .indirect, langs: [.go]))
        e.append(.call("Readlink", prefix: "os", fileReads, .local, .indirect, langs: [.go]))
        e.append(.call("ReadFile", prefix: "ioutil", fileReads, .local, .indirect, langs: [.go]))
        e.append(.call("ReadAll", prefix: "ioutil", fileReads, .local, .indirect, langs: [.go]))
        e.append(.call("ReadDir", prefix: "ioutil", fileReads, .local, .indirect, langs: [.go]))
        e.append(.call("ReadAll", prefix: "io", fileReads, .local, .indirect, langs: [.go]))
        e.append(.call("ReadString", prefix: "bufio", fileReads, .local, .indirect, langs: [.go]))
        e.append(.call("file_get_contents", fileReads, .local, .indirect, langs: [.php]))
        e.append(.call("file", fileReads, .local, .indirect, langs: [.php]))
        e.append(.call("fgets", fileReads, .local, .indirect, langs: [.php]))
        e.append(.call("fscanf", fileReads, .local, .indirect, langs: [.php]))
        e.append(.call("fread", fileReads, .local, .indirect, langs: [.php]))
        e.append(.call("readfile", fileReads, .local, .indirect, langs: [.php]))
        e.append(.call("stream_get_contents", fileReads, .local, .indirect, langs: [.php]))
        e.append(.call("ReadAllText", fileReads, .local, .indirect, langs: [.csharp]))
        e.append(.call("ReadLine", fileReads, .local, .indirect, langs: [.csharp]))
        e.append(.call("ReadToEnd", fileReads, .local, .indirect, langs: [.csharp]))
        e.append(.call("ReadAllBytes", fileReads, .local, .indirect, langs: [.csharp]))
        e.append(.call("Read", prefix: "File", fileReads, .local, .indirect, langs: [.csharp]))
        e.append(.prop("contentsOfDirectory", prefix: "FileManager", fileReads, .local, .indirect,
                       langs: [.swift]))
        e.append(.prop("subpathsOfDirectory", prefix: "FileManager", fileReads, .local, .indirect,
                       langs: [.swift]))
        e.append(.call("contentsAtPath", prefix: "FileManager", fileReads, .local, .indirect,
                       langs: [.swift]))
        e.append(.call("contentsOfFile", prefix: "FileManager", fileReads, .local, .indirect,
                       langs: [.swift]))
        e.append(.call("dataWithContentsOfFile", prefix: "FileManager", fileReads, .local, .indirect,
                       langs: [.swift]))
        e.append(.call("contentsOf", prefix: "String", fileReads, .local, .indirect, langs: [.swift]))
        e.append(.call("contentsOf", prefix: "Data", fileReads, .local, .indirect, langs: [.swift]))
        e.append(.call("resumeData", prefix: "NSData", fileReads, .local, .indirect, langs: [.swift, .objc]))
        e.append(.call("contents", prefix: "File", fileReads, .local, .indirect, langs: [.ruby]))
        e.append(.call("read", prefix: "File", fileReads, .local, .indirect, langs: [.ruby]))
        e.append(.call("foreach", prefix: "File", fileReads, .local, .indirect, langs: [.ruby]))
        e.append(.call("read", prefix: "std.fs", fileReads, .local, .indirect, langs: [.rust]))
        e.append(.call("read_to_string", prefix: "fs", fileReads, .local, .indirect, langs: [.rust]))
        e.append(.call("read", prefix: "fs", fileReads, .local, .indirect, langs: [.rust]))
        e.append(.call("open", prefix: "File", fileReads, .local, .indirect, langs: [.rust]))
        e.append(.call("Open", prefix: "path", fileReads, .local, .indirect, langs: [.go]))
        // Node / Deno file readers.
        for leaf in ["readFile", "readFileSync", "createReadStream", "readdirSync"] {
            e.append(.call(leaf, prefix: "fs", fileReads, .local, .indirect, langs: [.javascript]))
        }
        e.append(.call("readTextFile", prefix: "Deno", fileReads, .local, .indirect, langs: [.javascript]))

        // MARK: Local storage & persisted data (indirect)

        e.append(.call("getItem", prefix: "localStorage", persisted, .local, .indirect,
                       langs: [.javascript]))
        e.append(.call("getItem", prefix: "sessionStorage", persisted, .local, .indirect,
                       langs: [.javascript]))
        for leaf in ["string", "object", "array", "dictionary", "data", "stringArray",
                     "integer", "double", "bool"] {
            e.append(.call(leaf, prefix: "UserDefaults", persisted, .local, .indirect,
                           langs: [.swift]))
        }
        e.append(.call("Get", prefix: "UserDefaults", persisted, .local, .indirect, langs: [.csharp]))
        e.append(.call("GetString", prefix: "UserDefaults", persisted, .local, .indirect,
                       langs: [.csharp]))
e.append(.call("standardUserDefaults", prefix: "NSUserDefaults", persisted, .local,
                        .indirect, langs: [.objc]))
        e.append(.call("value", prefix: "UserDefaults", persisted, .local, .indirect, langs: [.csharp]))
        e.append(.bare("_SESSION", persisted, .local, .indirect, langs: [.php]))
        e.append(.call("getSession", prefix: "req", persisted, .local, .indirect, langs: [.php]))

        // MARK: Encoding & serialization decode (indirect)

        e.append(.call("decode", prefix: "URLDecoder", encoding, .local, .indirect, langs: javaKotlin))
        e.append(.call("Unmarshal", encoding, .local, .indirect, langs: [.go]))
        e.append(.call("loads", encoding, .local, .indirect, langs: [.python]))
        e.append(.call("load", encoding, .local, .indirect, langs: [.python]))
        e.append(.call("safe_load", encoding, .local, .indirect, langs: [.python]))
        e.append(.call("load_all", encoding, .local, .indirect, langs: [.python]))
        e.append(.call("parse", prefix: "JSON", encoding, .local, .indirect, langs: [.javascript]))
        e.append(.call("parse", prefix: "JSON", encoding, .local, .indirect, langs: [.ruby]))
        e.append(.call("load", prefix: "Marshal", encoding, .local, .indirect, langs: [.ruby]))
        e.append(.call("load", prefix: "YAML", encoding, .local, .indirect, langs: [.ruby]))
        e.append(.call("parse", prefix: "Nokogiri.XML", encoding, .local, .indirect, langs: [.ruby]))
        e.append(.call("json_decode", encoding, .local, .indirect, langs: [.php]))
        e.append(.call("DeserializeObject", prefix: "JsonConvert", encoding, .local, .indirect,
                       langs: [.csharp]))
        e.append(.call("Deserialize", prefix: "XmlSerializer", encoding, .local, .indirect,
                       langs: [.csharp]))
        e.append(.call("from_str", prefix: "serde_json", encoding, .local, .indirect, langs: [.rust]))
        e.append(.call("from_str", prefix: "serde_yaml", encoding, .local, .indirect, langs: [.rust]))
        e.append(.call("ReadValue", prefix: "Json", encoding, .local, .indirect, langs: [.csharp]))
        e.append(.call("decode", prefix: "JSONDecoder", encoding, .local, .indirect, langs: [.swift]))
        e.append(.call("decode", prefix: "PropertyListDecoder", encoding, .local, .indirect,
                       langs: [.swift]))
        e.append(.call("propertyList", prefix: "PropertyListSerialization", encoding, .local,
                       .indirect, langs: [.swift]))
        e.append(.call("unarchiveTopLevelObjectWithData", prefix: "NSKeyedUnarchiver",
                       encoding, .local, .indirect, langs: [.swift, .objc]))
        e.append(.call("unarchiveObject", prefix: "NSKeyedUnarchiver", encoding, .local,
                       .indirect, langs: [.swift, .objc]))
        e.append(.call("UrlDecode", encoding, .local, .indirect, langs: [.csharp]))
        e.append(.call("HtmlDecode", encoding, .local, .indirect, langs: [.csharp]))
        e.append(.call("UnescapeDataString", encoding, .local, .indirect, langs: [.csharp]))

        return e
    }()
}
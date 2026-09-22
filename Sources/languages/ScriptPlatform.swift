// by cipher.org.uk
import Foundation

/// Go / Kotlin APIs that return untrusted / attacker-controlled data. These
/// seed the Go and Kotlin AST taint pass, mirroring the scanner's taint-return
/// set for the heuristic (non-AST) path of those languages.
let goSourceAPIs: Set<String> = [
    // Environment / args.
    "os.Getenv", "os.LookupEnv", "os.Getenvs",
    // Files / streams.
    "os.ReadFile", "os.Open", "os.OpenFile", "os.ReadDir", "os.Readlink",
    "ioutil.ReadFile", "ioutil.ReadDir", "ioutil.ReadAll", "io.ReadAll",
    "io.ReadString", "bufio.Scanner", "bufio.NewScanner", "scanner.Text", "scanner.Bytes",
    // Console input.
    "fmt.Scan", "fmt.Scanln", "fmt.Scanf",
    // Decoders (network/file payloads are attacker-controlled).
    "json.Unmarshal", "xml.Unmarshal", "yaml.Unmarshal",
    // net/http request readers: `r.URL.Query().Get(..)`, `r.FormValue(..)`,
    // `r.PathValue(..)`, header/cookie reads all return attacker-controlled data.
    "Get", "FormValue", "PostFormValue", "PathValue", "QueryValue",
    "Query", "Form", "Header", "URL", "Cookie", "Cookies", "Body", "Referer",
]

/// Sinks that WRITE untrusted data into a mutable argument (the write-through
/// concept), for the Go AST pass.
let goWriteThroughSinks: Set<String> = [
    "Scan", "Scanln", "Scanf", "Read", "ReadAt", "ReadFull", "Decode", "Unmarshal", "Parse",
]

/// Kotlin APIs that return untrusted / attacker-controlled data. Kotlin runs on
/// the JVM and re-uses the Java source set plus Kotlin-standard reader helpers.
let kotlinSourceAPIs: Set<String> = javaSourceAPIs.union([
    "readLine", "readText", "readBytes", "readLines", "readLinesSequence",
    "System.getenv", "System.getProperty",
    "readBytes", "readLong", "readInt", "readFully", "readUnsignedByte",
    // Android: values carried in an incoming Intent/Bundle/clipboard are user
    // data and seed the mobile AST taint pass (mirrors taintReturnFunctions).
    "getStringExtra", "getIntExtra", "getLongExtra", "getBooleanExtra",
    "getDoubleExtra", "getStringArrayExtra", "getStringArrayListExtra",
    "getSerializableExtra", "getParcelableExtra", "getExtras", "getIntent",
    "getPrimaryClip", "getItemAt",
])

/// Write-through sinks for the Kotlin AST pass (reads that fill a parameter).
let kotlinWriteThroughSinks: Set<String> = javaWriteThroughSinks.union([
    "readLine", "readText", "readBytes", "readLines",
])

/// Python APIs that return untrusted / attacker-controlled data. Seeds the
/// Python AST taint pass; function parameters already seed taint directly, so
/// this mirrors the common web/env input readers.
let pythonSourceAPIs: Set<String> = [
    "getenv", "getpass", "input", "raw_input", "sys.argv", "os.environ",
    "request", "request.args", "request.form", "request.json", "request.values",
    "read", "readline", "readlines", "recv", "stdin", "environ",
    "urllib.request", "urlopen", "parse_qs",
]

/// Write-through sinks for the Python AST pass (reads that fill a parameter).
let pythonWriteThroughSinks: Set<String> = ["read", "readline", "readlines", "recv", "input"]

/// Ruby APIs that return untrusted / attacker-controlled data for the Ruby AST pass.
let rubySourceAPIs: Set<String> = [
    "gets", "readline", "readlines", "getc", "read", "recv", "STDIN",
    "ARGV", "ENV", "request", "params", "cookies",
]

/// Write-through sinks for the Ruby AST pass (reads that fill a parameter).
let rubyWriteThroughSinks: Set<String> = ["gets", "readline", "readlines", "read", "recv"]

/// Rust APIs that return untrusted / attacker-controlled data for the Rust AST pass.
/// Names are listed in both Rust `::` path form and the `.` form the shared AST
/// parser produces for qualified calls (`env::var` -> `env.var`).
let rustSourceAPIs: Set<String> = [
    "std.env.var", "std.env.args", "std.env.vars", "env.var", "env.args",
    "std.io.stdin", "read_line", "read_to_string", "stdin", "env",
    "get_input", "std.fs.read", "fs.read",
    "std::env::var", "std::env::args", "std::env::vars", "env::var", "env::args",
    "std::io::stdin", "std::fs::read", "fs::read",
]

/// Write-through sinks for the Rust AST pass (reads that fill a parameter/buffer).
let rustWriteThroughSinks: Set<String> = ["read_line", "read_to_string", "fill_buf", "read_exact"]

/// PHP APIs that return untrusted / attacker-controlled data for the PHP AST pass.
/// Superglobals and common request/env/file/network readers seed the taint pass.
let phpSourceAPIs: Set<String> = [
    "_GET", "_POST", "_REQUEST", "_COOKIE", "_FILES", "_SERVER", "_ENV",
    "getenv", "file_get_contents", "file", "fgets", "fgetc", "readfile", "readline",
    "fread", "parse_str", "parse_url", "getallheaders", "get_headers",
    "stream_get_contents", "php_input", "STDIN", "argv", "argc",
]

/// Write-through sinks for the PHP AST pass (reads that fill a parameter/buffer).
let phpWriteThroughSinks: Set<String> = [
    "fgets", "fgetc", "fread", "readline", "stream_get_contents", "scanf", "sscanf",
]
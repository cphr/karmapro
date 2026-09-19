// by cipher.org.uk
import Foundation

/// JavaScript/TypeScript APIs that return untrusted / attacker-controlled data.
/// Seeds the JS AST taint pass; mirrors the scanner's taint-returning set.
let jsSourceAPIs: Set<String> = [
    // Environment / args.
    "process.env", "process.argv", "process.stdin", "env",
    // Network / request data.
    "fetch", "XMLHttpRequest", "axios", "got", "superagent", "request",
    // Express-style request objects and their common accessors.
    "req", "params", "query", "body", "cookies", "headers",
    // File reads.
    "readFile", "readFileSync", "readdir", "readdirSync", "createReadStream",
    "open", "openSync",
    // URL / query parsing.
    "URL", "parse", "qs", "querystring",
    // Eval-family (dangerous sinks that also act as taint amplifiers).
    "eval", "Function", "exec", "execSync", "spawn", "spawnSync",
    // DOM / storage.
    "innerHTML", "outerHTML", "document", "localStorage", "sessionStorage",
]

/// Write-through sinks for the JS AST pass (reads that fill a parameter).
let jsWriteThroughSinks: Set<String> = [
    "readFile", "readFileSync", "read", "on", "once",
    "getline", "stdin", "input", "prompt",
]

// by cipher.org.uk
import Foundation

/// Swift / Foundation / AppKit / UIKit APIs that return untrusted, externally
/// controlled data. These seed the Swift AST taint pass and the three-walk
/// security detector. Names are matched on the qualified dotted call name as
/// written in source (`UserDefaults.standard.string`) and on the trailing
/// leaf name (`string(forKey:)`), so both spellings propagate taint.
let swiftSourceAPIs: Set<String> = [
    // Command-line / environment (macOS command-line tools and scripts).
    "CommandLine.arguments", "CommandLine.unsafeArgv", "arguments",
    "ProcessInfo.processInfo.environment", "environment", "getenv",
    "readLine", "readline", "stdin",
    // UserDefaults: an iOS/macOS key-value store a local attacker can modify.
    "UserDefaults.standard.string", "UserDefaults.standard.object",
    "UserDefaults.standard.array", "UserDefaults.standard.dictionary",
    "UserDefaults.standard.data", "UserDefaults.standard.stringArray",
    "UserDefaults.standard.integer", "UserDefaults.standard.double",
    "UserDefaults.standard.bool",
    "string", "stringForKey", "object", "array", "dictionary", "data",
    "stringArray", "integer", "double", "bool",
    // File reads.
    "FileManager.contentsOfDirectory", "FileManager.contentsAtPath",
    "FileManager.dataWithContentsOfFile", "FileManager.contentsOfFile",
    "FileManager.subpathsOfDirectory", "FileManager.enumerator",
    "Data.contentsOf", "contentsOf", "String.contentsOf",
    "try", "getContents", "readFile",
    // Network / remote payloads.
    "URLSession.data", "URLSession.dataTask", "dataTask",
    "URLSession.downloadTask", "downloadTask", "URLSession.uploadTask",
    "URLSessionStream", "data", "response", "URLResponse",
    "URL", "URLSession", "WebSocket",
    // Decoders: bytes from an untrusted container (network, cache, pasteboard,
    // or another app via an extension / custom URL scheme).
    "JSONDecoder.decode", "decode", "PropertyListDecoder.decode",
    "JSONSerialization", "PropertyListSerialization.propertyList",
    "NSKeyedUnarchiver.unarchiveTopLevelObjectWithData", "unarchiveTopLevelObjectWithData",
    "NSKeyedUnarchiver.unarchiveObject", "unarchiveObject",
    "NSUnarchiver", "NSCoder", "decoder",
    // Pasteboard: another app can place arbitrary text/data here.
    "UIPasteboard.general.string", "NSPasteboard.general.string",
    "UIPasteboard", "NSPasteboard", "pasteboard",
    // App inter-communication: custom URL schemes, extensions, notifications.
    "application.open", "openURL", "uri", "deeplink",
    "NotificationCenter.userInfo", "userInfo", "UNPushNotificationTrigger",
    "NSExtensionContext.inputItems", "inputItems",
    "MFMessageComposeViewController", "messageBody",
    "readFromURL", "read", "receiveMessage", "messages",
]

/// Sinks that WRITE untrusted data into a mutable parameter (the write-through
/// concept) for the Swift pass. When such a call targets a function parameter,
/// the caller's argument becomes tainted.
let swiftWriteThroughSinks: Set<String> = [
    "readLine", "read", "getData", "getBytes", "withUnsafeMutableBytes",
    "open", "init", "decode",
]

/// Names of Swift / Foundation / UIKit sinks that persist data, used by the
/// mobile-sensitive-storage checks.
let swiftSensitiveStoreSinks: Set<String> = [
    "set", "write", "writeToFile", "writeToURL", "createFile",
    "createDirectory", "SecItemAdd", "setValue", "setObject",
]

/// Weak / deprecated cryptographic primitives commonly misused in Swift
/// (see also the `Insecure.*` family from CryptoKit and CryptoSwift's
/// `.md5()` / `.sha1()` member extensions).
let swiftWeakCryptoNames: Set<String> = [
    "md5", "MD5", "sha1", "SHA1", "des", "DES", "rc4", "RC4",
    "Insecure.MD5", "Insecure.SHA1",
    "CryptoKit", "CC_MD5", "CC_SHA1", "CommonCrypto",
]

/// Sinks that execute a string as code or run an OS-level command.
let swiftExecSinks: Set<String> = [
    "Process", "NSTask", "run", "launch", "execute",
    "evaluateScript", "evaluateJavaScript", "evaluate", "performSelector",
    "NSExpression", "NSRegularExpression", "system",
]

/// Sources of sensitive data whose insecure storage is flagged by the mobile
/// checks (auth tokens, passwords, keys, user data).
let swiftSensitiveDataNames: Set<String> = [
    "password", "passwd", "pass", "pwd", "secret", "token", "auth",
    "apikey", "api_key", "apisecret", "api_secret", "accessToken",
    "refreshToken", "credential", "credentials", "keychain", "privateKey",
    "session", "ssn", "card", "pin", "authToken", "bearer",
]
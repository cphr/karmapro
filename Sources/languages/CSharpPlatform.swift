// by cipher.org.uk
import Foundation

/// Returns true if the URL points at a C# source file.
func isCSharpFile(_ url: URL) -> Bool {
    let ext = url.pathExtension.lowercased()
    return ext == "cs" || ext == "csx"
}

/// C# APIs that return untrusted/attacker-controlled data. These seed the C#
/// AST taint pass, mirroring the heuristic scanner's taint-return set. They
/// cover request/context input, console/stream readers and common .NET
/// getters that surface user-supplied values.
let csharpSourceAPIs: Set<String> = [
    // ASP.NET request / context input.
    "Request.QueryString", "Request.Form", "Request.Params", "Request.Headers",
    "Request.Cookies", "Request.ServerVariables", "QueryString", "Form", "Params",
    "Request.QueryString.Get", "Request.Form.Get", "get_QueryString", "get_Form",
    "HttpContext.Current.Request",
    "get_Request", "get_User", "get_QueryString", "get_Form",
    // Console / stream readers.
    "Console.ReadLine", "ReadLine", "Read", "ReadToEnd", "ReadAllText",
    "ReadAllLines", "ReadAllBytes", "StreamReader.ReadLine", "MyReader.ReadLine",
    "NextLine", "Next", "nextLine",
    // Environment / decode.
    "Environment.GetEnvironmentVariable", "GetEnvironmentVariable",
    "Environment.GetCommandLineArgs", "UrlDecode", "WebUtility.HtmlDecode",
    "Uri.UnescapeDataString", "get_Path", "get_FileName",
    // Framework getters that return user-supplied values.
    "get_Value", "get_Text", "get_Content", "get_InnerText", "get_InnerXml",
    "GetValue",
]

/// Sinks that WRITE untrusted data into a mutable argument / target (the
/// write-through concept). For C# this mostly maps to reader methods that fill
/// a result / buffer or return read data through `out`/stream parameters.
let csharpWriteThroughSinks: Set<String> = [
    "ReadLine", "Read", "ReadToEnd", "ReadAllText", "ReadAllLines", "ReadAllBytes",
    "ReadAsync", "ReadToEndAsync", "Next", "NextLine", "get_Value",
]

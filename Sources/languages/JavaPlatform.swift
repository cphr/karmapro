// by cipher.org.uk
import Foundation

/// Returns true if the URL points at a Java source file.
func isJavaFile(_ url: URL) -> Bool {
    url.pathExtension.lowercased() == "java"
}

/// Java APIs that return untrusted/attacker-controlled data (environment,
/// network, request, file or user input). These seed the Java AST taint pass,
/// mirroring the scanner's taint-return set for the non-AST path.
let javaSourceAPIs: Set<String> = [
    // Servlet / request input.
    "getParameter", "getParameterValues", "getHeader", "getHeaderNames", "getHeaderValues",
    "getQueryString", "getRequestURI", "getRequestURL", "getRemoteAddr", "getRemoteHost",
    "getPathInfo", "getServletPath", "getInputStream", "getSession", "getAttribute",
    "getCookies", "getParameterMap", "getUserPrincipal", "getUserPrincipalRequest",
    "request.getParameter",
    // Scanner / console / stream reading.
    "nextLine", "next", "nextInt", "nextLong", "nextDouble", "readLine", "read",
    "readObject", "readUTF", "readAllBytes", "readAllLines", "lines",
    // Framework getters that return user-supplied raw values.
    "getText", "getRawValue", "getUserInput",
    // Environment / system properties / decoding.
    "getenv", "getProperty", "System.getProperty", "System.getenv", "URLDecoder.decode",
    // C-ish buffer readers that also apply to Java streams.
    "fgets", "fgetc", "recv", "recvfrom", "fread", "scanf", "fscanf", "sscanf", "getwd", "getpass", "strdup"
]

/// Sinks that WRITE untrusted data into a mutable argument (the write-through
/// concept). For Java this maps mostly to buffer/stream reading that fills a
/// parameter; seeded with the C buffer sinks plus Java reading methods.
let javaWriteThroughSinks: Set<String> = [
    "fgets", "gets", "fgetc", "scanf", "fscanf", "sscanf",
    "read", "recv", "recvfrom", "fread",
    "nextLine", "next", "nextInt", "nextLong", "nextDouble", "readLine", "readUTF"
]

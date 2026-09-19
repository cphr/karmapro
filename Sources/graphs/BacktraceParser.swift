// by cipher.org.uk
import Foundation

/// One frame parsed out of a pasted stacktrace/backtrace.
struct BacktraceFrame {
    let functionName: String
    let fileHint: String
    let line: Int
}

/// Parses stacktrace text pasted by the user into discrete frames.
///
/// Handles the most common formats seen in real crashes:
///   - C / Objective-C / Swift (LLDB): `processRequest (src/main.c:4)`, `foo at src/main.c:4`
///   - Rust: `std::panicking::begin_panic` followed by `at /rustc/.../panicking.rs:554`
///   - Java / Kotlin: `at pkg.Class.method(File.java:7)`
///   - Python: `File "x.py", line 5, in main`
///   - Node / JavaScript: `at main (src/app.js:12:5)`
///   - GDB: `#0 0x0000555... in main (...) at src/main.c:18`
///   - Bare: `src/main.c:4`
final class BacktraceParser {

    private struct Pattern {
        let regex: NSRegularExpression
        /// Capture-group index of the function name (-1 if none).
        let functionGroup: Int
        let fileGroup: Int
        let lineGroup: Int
    }

    private lazy var patterns: [Pattern] = buildPatterns()

    func parse(_ text: String) -> [BacktraceFrame] {
        var frames: [BacktraceFrame] = []
        var pendingSymbol: String?

        for rawLine in text.components(separatedBy: .newlines) {
            let line = rawLine.trimmingCharacters(in: .whitespacesAndNewlines)
            if line.isEmpty { continue }

            // Rust backtraces print the frame symbol on its own line, followed by
            // an "at <path>:<line>" line. Remember the symbol so the following
            // frame can use it as its function name.
            if let symbol = symbolLine(line) {
                pendingSymbol = symbol
                continue
            }

            guard let frame = frameFromLine(line) else { continue }
            var functionName = frame.functionName
            if functionName.isEmpty {
                functionName = pendingSymbol ?? ""
            }
            let frameToAppend = BacktraceFrame(
                functionName: functionName,
                fileHint: frame.fileHint,
                line: frame.line
            )
            frames.append(frameToAppend)
            pendingSymbol = nil
        }

        return frames
    }

    private func frameFromLine(_ line: String) -> BacktraceFrame? {
        let ns = line as NSString
        for pattern in patterns {
            guard let match = pattern.regex.firstMatch(in: line, options: [], range: NSRange(location: 0, length: ns.length)) else {
                continue
            }
            let functionName = groupToString(match, group: pattern.functionGroup, ns: ns)
            let fileHint = groupToString(match, group: pattern.fileGroup, ns: ns)
            guard !fileHint.isEmpty, let lineNumber = groupToInt(match, group: pattern.lineGroup, ns: ns) else {
                continue
            }
            // Bare "<file>:<line>" matches too eagerly; require a path-like hint.
            guard fileHint.contains(".") || fileHint.contains("/") || fileHint.contains("\\") else {
                continue
            }
            return BacktraceFrame(functionName: cleanedFunctionName(functionName), fileHint: fileHint, line: lineNumber)
        }
        return nil
    }

    private func cleanedFunctionName(_ name: String) -> String {
        var result = name.trimmingCharacters(in: .whitespacesAndNewlines)
        // Strip Java package/class prefix, keeping only the method name.
        if let lastDot = result.lastIndex(of: "."),
           result.prefix(upTo: lastDot).contains(".") || result.contains("(") == false {
            let tail = result[result.index(after: lastDot)...]
            result = String(tail)
        }
        return result
    }

    private func symbolLine(_ line: String) -> String? {
        // "12: std::panicking::begin_panic"
        let framePrefix = try? NSRegularExpression(pattern: "^\\d+:(.+)$")
        if let match = framePrefix?.firstMatch(in: line, options: [], range: NSRange(location: 0, length: (line as NSString).length)) {
            let symbol = (line as NSString).substring(with: match.range(at: 1)).trimmingCharacters(in: .whitespaces)
            if symbol.contains("::") || symbol.contains(".") {
                return symbol
            }
        }
        // A bare module path like "main::handler" or "crate::foo::bar"
        if line.range(of: "::") != nil, !line.contains("("), !line.contains(" at ") {
            return line
        }
        return nil
    }

    private func groupToString(_ match: NSTextCheckingResult, group: Int, ns: NSString) -> String {
        guard group > 0, group < match.numberOfRanges else { return "" }
        let range = match.range(at: group)
        guard range.location != NSNotFound else { return "" }
        return ns.substring(with: range)
    }

    private func groupToInt(_ match: NSTextCheckingResult, group: Int, ns: NSString) -> Int? {
        Int(groupToString(match, group: group, ns: ns))
    }

    private func makePattern(_ expression: String, functionGroup: Int, fileGroup: Int, lineGroup: Int) -> Pattern {
        Pattern(
            regex: try! NSRegularExpression(pattern: expression, options: []),
            functionGroup: functionGroup,
            fileGroup: fileGroup,
            lineGroup: lineGroup
        )
    }

    private func buildPatterns() -> [Pattern] {
        // Ordered — most specific first.
        [
            // Node / JS:  at main (src/app.js:12:5)
            makePattern("^\\s*at\\s+(\\S+)\\s+\\(([^:()]+):(\\d+)(?::\\d+)?\\)\\s*$",
                        functionGroup: 1, fileGroup: 2, lineGroup: 3),
            // Java / Kotlin:  at pkg.Class.method(File.java:7)
            makePattern("^\\s*at\\s+([\\w$<>]+(?:\\.[\\w$<>]+)*)\\(([^:()]+):(\\d+)\\)\\s*$",
                        functionGroup: 1, fileGroup: 2, lineGroup: 3),
            // GDB:  #0 0x… in main (…) at src/main.c:18
            makePattern("^\\s*#\\d+\\s+.*?\\bin\\s+([\\w:]+)\\s+\\(.*?\\)\\s+at\\s+([^:() ]+):(\\d+)\\s*$",
                        functionGroup: 1, fileGroup: 2, lineGroup: 3),
            // Python:  File "x.py", line 5, in main
            makePattern("File \"([^\"]+)\", line (\\d+)(?:, in ([^ ]+))?",
                        functionGroup: 3, fileGroup: 1, lineGroup: 2),
            // C / ObjC / Swift (LLDB):  processRequest (src/main.c:4)
            makePattern("^\\s*([A-Za-z_][A-Za-z0-9_:]*[+\\-]?)\\s+\\(([^:()]+):(\\d+)(?::\\d+)?\\)\\s*$",
                        functionGroup: 1, fileGroup: 2, lineGroup: 3),
            // Rust prints frames as:  at /rustc/…/library/std/src/panicking.rs:554
            makePattern("^\\s*at\\s+([^:() ]+):(\\d+)(?::\\d+)?\\s*$",
                        functionGroup: -1, fileGroup: 1, lineGroup: 2),
            // foo at src/main.c:4
            makePattern("^\\s*([A-Za-z0-9_:]+)\\s+at\\s+([^:() ]+):(\\d+)(?::\\d+)?\\s*$",
                        functionGroup: 1, fileGroup: 2, lineGroup: 3),
            // Bare:  src/main.c:4
            makePattern("^\\s*([^:() ]+):(\\d+)(?::\\d+)?\\s*$",
                        functionGroup: -1, fileGroup: 1, lineGroup: 2)
        ]
    }
}
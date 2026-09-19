// by cipher.org.uk
import Foundation

/// A lightweight JavaScript/TypeScript parser that extracts function definitions
/// and call relationships. Handles function declarations, arrow functions,
/// async functions, class methods, and generators.
public final class JSFunctionParser {

    /// A located function/method definition.
    public struct FunctionDef {
        public let name: String
        public let bodyRange: NSRange
        public let signatureRange: NSRange
        public let nameRange: NSRange
        public let isAsync: Bool
        public let isGenerator: Bool
    }

    private let source: String
    private let ns: NSString
    private let length: Int

    public init(source: String) {
        self.source = source
        self.ns = source as NSString
        self.length = ns.length
    }

    /// Returns parsed function/method definitions including arrow functions and class methods.
    public func parseDefinitions() -> [FunctionDef] {
        // Top-level safety net: guard against unexpected source state
        guard !source.isEmpty else { return [] }
        guard length > 0 else { return [] }
        guard ns.length > 0 else { return [] }
        
        var defs: [FunctionDef] = []
        
        // ... rest of function

        var i = 0
        var braceDepth = 0
        var parenDepth = 0
        var inClass = false
        var classBraceDepth = 0

        while i < length {
            // Defensively check bounds before every character access
            guard i < length else { break }
            let ch = ns.character(at: i)

            // Skip whitespace
            if isWhitespace(ch) { i += 1; continue }

            // Skip comments
            if ch == 0x2F && i + 1 < length {
                let next = ns.character(at: i + 1)
                if next == 0x2F { i = skipToLineEnd(i); continue }
                if next == 0x2A { i = skipBlockComment(i); continue }
            }

            // Skip strings (including template literals)
            if ch == 0x22 || ch == 0x27 || ch == 0x60 { // " ' `
                guard i + 1 < length else { break }
                i = skipString(i, quote: ch)
                continue
            }

            // Braces
            if ch == 0x7B { // {
                braceDepth += 1
                if inClass && classBraceDepth == 0 { classBraceDepth = braceDepth }
                i += 1
                continue
            }
            if ch == 0x7D { // }
                if inClass && braceDepth == classBraceDepth { inClass = false; classBraceDepth = 0 }
                braceDepth -= 1
                i += 1
                continue
            }

            // Parentheses
            if ch == 0x28 { // (
                parenDepth += 1
                i += 1
                continue
            }
            if ch == 0x29 { // )
                parenDepth = max(0, parenDepth - 1)
                i += 1
                continue
            }

            // Identifier / keyword
            if isIdentifierStart(ch) {
                let start = i
                guard i + 1 < length else { break }
                while i < length && isIdentifierChar(ns.character(at: i)) { i += 1 }
                let token = ns.substring(with: NSRange(location: start, length: i - start))
                let tokenRange = NSRange(location: start, length: i - start)

                // Check for class keyword
                if token == "class" {
                    inClass = true
                }

                // Check for function keyword
                if token == "function" {
                    // Look ahead for * (generator) and name
                    let afterFunc = i
                    var j = afterFunc
                    while j < length && isWhitespace(ns.character(at: j)) { j += 1 }
                    var isGenerator = false
                    if j < length && ns.character(at: j) == 0x2A { // *
                        isGenerator = true
                        j += 1
                        while j < length && isWhitespace(ns.character(at: j)) { j += 1 }
                    }
                    // Next identifier is the name (if present)
                    if j < length && isIdentifierStart(ns.character(at: j)) {
                        let nameStart = j
                        guard j + 1 < length else { break }
                        while j < length && isIdentifierChar(ns.character(at: j)) { j += 1 }
                        let name = ns.substring(with: NSRange(location: nameStart, length: j - nameStart))
                        // Look for opening paren
                        var k = j
                        while k < length && isWhitespace(ns.character(at: k)) { k += 1 }
                        if k < length && ns.character(at: k) == 0x28 {
                            // Found function declaration
                            let parenStart = k
                            let bodyStart = findMatchingBrace(from: k + 1)
                            if bodyStart != -1 {
                                let bodyEnd = findMatchingBraceEnd(from: bodyStart + 1)
                                if bodyEnd != -1 && bodyEnd < length {
                                    defs.append(FunctionDef(
                                        name: name,
                                        bodyRange: NSRange(location: parenStart, length: bodyEnd + 1 - parenStart),
                                        signatureRange: NSRange(location: start, length: parenStart - start),
                                        nameRange: NSRange(location: nameStart, length: j - nameStart),
                                        isAsync: false,
                                        isGenerator: isGenerator
                                    ))
                                    i = bodyEnd + 1
                                    continue
                                }
                            }
                        }
                    } else if j < length && ns.character(at: j) == 0x28 {
                        // Anonymous function - skip for now
                    }
                }

                // Check for async keyword
                if token == "async" {
                    // Look ahead for function or arrow
                    var j = i
                    guard j + 1 < length else { break }
                    while j < length && isWhitespace(ns.character(at: j)) { j += 1 }
                    if j < length {
                        // async function ...
                        if j + 8 < length && ns.substring(with: NSRange(location: j, length: 8)) == "function" {
                            let afterFunc = j + 8
                            guard afterFunc + 1 < length else { break }
                            var k = afterFunc
                            while k < length && isWhitespace(ns.character(at: k)) { k += 1 }
                            var isGenerator = false
                            if k < length && ns.character(at: k) == 0x2A { // *
                        isGenerator = true
                        k += 1
                        while k < length && isWhitespace(ns.character(at: k)) { k += 1 }
                    }
                            if k < length && isIdentifierStart(ns.character(at: k)) {
                                let nameStart = k
                                guard k + 1 < length else { break }
                                while k < length && isIdentifierChar(ns.character(at: k)) { k += 1 }
                                let name = ns.substring(with: NSRange(location: nameStart, length: k - nameStart))
                                var m = k
                                guard m + 1 < length else { break }
                                while m < length && isWhitespace(ns.character(at: m)) { m += 1 }
                                if m < length && ns.character(at: m) == 0x28 {
                                    let parenStart = m
                                    let bodyStart = findMatchingBrace(from: m + 1)
                                    if bodyStart != -1 {
                                        let bodyEnd = findMatchingBraceEnd(from: bodyStart + 1)
                                        if bodyEnd != -1 && bodyEnd < length {
                                            defs.append(FunctionDef(
                                                name: name,
                                                bodyRange: NSRange(location: parenStart, length: bodyEnd + 1 - parenStart),
                                                signatureRange: NSRange(location: start, length: parenStart - start),
                                                nameRange: NSRange(location: nameStart, length: k - nameStart),
                                                isAsync: true,
                                                isGenerator: isGenerator
                                            ))
                                            i = bodyEnd + 1
                                            continue
                                        }
                                    }
                                }
                            }
                        }
                        // async arrow: async () => or async x =>
                        else if j + 1 < length && ns.character(at: j) == 0x28 { // async (
                            // async arrow function expression - find the =>
                            guard j + 2 < length else { break }
                            let arrowIdx = findArrow(j)
                            if arrowIdx != -1 && arrowIdx < length {
                                guard arrowIdx + 2 < length else { break }
                                let bodyStart = findMatchingBraceOrExpression(from: arrowIdx + 2)
                                if bodyStart != -1 && bodyStart < length {
                                    let bodyEnd = findArrowBodyEnd(from: bodyStart)
                                    if bodyEnd != -1 && bodyEnd >= bodyStart && bodyEnd < length {
                                        let name = "async_arrow_\(defs.count)"
                                        defs.append(FunctionDef(
                                            name: name,
                                            bodyRange: NSRange(location: i, length: bodyEnd + 1 - i),
                                            signatureRange: NSRange(location: start, length: arrowIdx + 2 - start),
                                            nameRange: NSRange(location: start, length: i - start),
                                            isAsync: true,
                                            isGenerator: false
                                        ))
                                        i = bodyEnd + 1
                                        continue
                                    }
                                }
                            }
                        }
                    }
                }

                // Check for arrow function: identifier => or (params) =>
                if let firstChar = token.unicodeScalars.first?.value, isIdentifierStart(unsafeBitCast(firstChar, to: unichar.self)) {
                    guard i < length else { break }
                    var j = i
                    while j < length && isWhitespace(ns.character(at: j)) { j += 1 }
                    guard j + 1 < length else { break }
                    if ns.character(at: j) == 0x3D && ns.character(at: j + 1) == 0x3E { // =>
                        // Arrow function expression
                        let name = token
                        let sigEnd = j + 2
                        guard sigEnd < length else { break }
                        let bodyStart = findMatchingBraceOrExpression(from: sigEnd)
                        var bodyEnd = length - 1
                        if bodyStart != -1 && bodyStart < length {
                            bodyEnd = findArrowBodyEnd(from: bodyStart)
                            if bodyEnd == -1 || bodyEnd >= length { bodyEnd = length - 1 }
                        }
                        // Ensure bodyEnd is valid and >= i
                        if bodyEnd < i { bodyEnd = i }
                        let bodyLen = bodyEnd + 1 - i
                        defs.append(FunctionDef(
                            name: name,
                            bodyRange: NSRange(location: i, length: bodyLen),
                            signatureRange: NSRange(location: start, length: sigEnd - start),
                            nameRange: tokenRange,
                            isAsync: false,
                            isGenerator: false
                        ))
                        i = bodyEnd + 1
                        continue
                    }
                    // Check for method shorthand in class/object: method() {}
                    guard j < length else { break }
                    if ns.character(at: j) == 0x28 {
                        let parenStart = j
                        let bodyStart = findMatchingBrace(from: j + 1)
                        if bodyStart != -1 && (inClass || braceDepth > 0) {
                            let bodyEnd = findMatchingBraceEnd(from: bodyStart + 1)
                            if bodyEnd != -1 && bodyEnd < length {
                                defs.append(FunctionDef(
                                    name: token,
                                    bodyRange: NSRange(location: parenStart, length: bodyEnd + 1 - parenStart),
                                    signatureRange: NSRange(location: start, length: parenStart - start),
                                    nameRange: tokenRange,
                                    isAsync: false,
                                    isGenerator: false
                                ))
                                i = bodyEnd + 1
                                continue
                            }
                        }
                    }
                }

                continue
            }

            // Other characters
            i += 1
        }

        // Deduplicate by name
        var seen = Set<String>()
        var result: [FunctionDef] = []
        for def in defs {
            if !seen.contains(def.name) {
                seen.insert(def.name)
                result.append(def)
            }
        }
        return result
    }

    /// Returns class name ranges for clickable class names.
    public func parseClassNames() -> [(name: String, range: NSRange)] {
        var result: [(String, NSRange)] = []
        var i = 0
        var lastIdent: String? = nil

        while i < length {
            let ch = ns.character(at: i)

            if isWhitespace(ch) { i += 1; continue }
            if ch == 0x2F && i + 1 < length {
                let next = ns.character(at: i + 1)
                if next == 0x2F { i = skipToLineEnd(i); continue }
                if next == 0x2A { i = skipBlockComment(i); continue }
            }
            if ch == 0x22 || ch == 0x27 || ch == 0x60 { i = skipString(i, quote: ch); continue }

            if isIdentifierStart(ch) {
                let start = i
                while i < length && isIdentifierChar(ns.character(at: i)) { i += 1 }
                let ident = ns.substring(with: NSRange(location: start, length: i - start))

                if let kw = lastIdent, (kw == "class" || kw == "interface" || kw == "type") {
                    result.append((ident, NSRange(location: start, length: i - start)))
                }
                lastIdent = ident
                continue
            }

            lastIdent = nil
            i += 1
        }
        return result
    }

    /// Builds call graph (caller -> callee) from function bodies.
    public func buildGraph() -> (calls: [(from: String, to: String)], data: [(from: String, to: String)]) {
        let defs = parseDefinitions()
        let definedNames = Set(defs.map { $0.name })

        var calls: [(String, String)] = []
        var data: [(String, String)] = []

        for def in defs {
            let bodyStart = def.bodyRange.location
            let bodyEnd = bodyStart + def.bodyRange.length
            guard bodyStart >= 0, bodyEnd <= length, bodyEnd > bodyStart else { continue }

            var i = bodyStart
            while i < bodyEnd {
                let ch = ns.character(at: i)
                if isIdentifierStart(ch) {
                    let start = i
                    while i < bodyEnd && isIdentifierChar(ns.character(at: i)) { i += 1 }
                    let ident = ns.substring(with: NSRange(location: start, length: i - start))

                    // Look ahead for '('
                    var j = i
                    while j < bodyEnd && isWhitespace(ns.character(at: j)) { j += 1 }
                    if j < bodyEnd && ns.character(at: j) == 0x28 && definedNames.contains(ident) {
                        if ident != def.name {
                            calls.append((def.name, ident))
                            data.append((def.name, ident))
                        }
                        i = j + 1
                        continue
                    }
                }
                i += 1
            }
        }

        calls = dedupe(calls)
        data = dedupe(data)
        return (calls, data)
    }

    private func dedupe(_ pairs: [(String, String)]) -> [(String, String)] {
        var seen = Set<String>()
        var result: [(String, String)] = []
        for p in pairs {
            let key = p.0 + "\u{1}" + p.1
            if !seen.contains(key) {
                seen.insert(key)
                result.append(p)
            }
        }
        return result
    }

    // MARK: - Helpers

    private func isWhitespace(_ c: unichar) -> Bool {
        c == 0x20 || c == 0x09 || c == 0x0A || c == 0x0D
    }

    private func isIdentifierStart(_ c: unichar) -> Bool {
        (c >= 0x41 && c <= 0x5A) || (c >= 0x61 && c <= 0x7A) || c == 0x5F || c == 0x24 // $ for jQuery etc
    }

    private func isIdentifierChar(_ c: unichar) -> Bool {
        isIdentifierStart(c) || (c >= 0x30 && c <= 0x39)
    }

    private func skipToLineEnd(_ i: Int) -> Int {
        var j = i
        while j < length && ns.character(at: j) != 0x0A { j += 1 }
        return j
    }

    private func skipBlockComment(_ i: Int) -> Int {
        var j = i + 2
        while j + 1 < length && !(ns.character(at: j) == 0x2A && ns.character(at: j + 1) == 0x2F) {
            if ns.character(at: j) == 0x0A { }
            j += 1
        }
        return min(j + 2, length)
    }

    private func skipString(_ i: Int, quote: unichar) -> Int {
        var j = i + 1
        while j < length {
            if ns.character(at: j) == 0x5C { j += 2; continue } // backslash escape
            if ns.character(at: j) == quote { return j + 1 }
            if ns.character(at: j) == 0x0A && quote != 0x60 { break } // template literal allows newlines
            j += 1
        }
        return j
    }

    private func findMatchingBrace(from i: Int) -> Int {
        var depth = 0
        var j = i
        while j < length {
            let ch = ns.character(at: j)
            if ch == 0x7B { depth += 1 }
            else if ch == 0x7D {
                depth -= 1
                if depth == 0 { return j }
            }
            else if ch == 0x22 || ch == 0x27 || ch == 0x60 { j = skipString(j, quote: ch); continue }
            else if ch == 0x2F && j + 1 < length {
                let next = ns.character(at: j + 1)
                if next == 0x2F { j = skipToLineEnd(j); continue }
                if next == 0x2A { j = skipBlockComment(j); continue }
            }
            j += 1
        }
        return -1
    }

    private func findMatchingBraceEnd(from i: Int) -> Int {
        var depth = 1
        var j = i
        while j < length {
            let ch = ns.character(at: j)
            if ch == 0x7B { depth += 1 }
            else if ch == 0x7D {
                depth -= 1
                if depth == 0 { return j }
            }
            else if ch == 0x22 || ch == 0x27 || ch == 0x60 { j = skipString(j, quote: ch); continue }
            else if ch == 0x2F && j + 1 < length {
                let next = ns.character(at: j + 1)
                if next == 0x2F { j = skipToLineEnd(j); continue }
                if next == 0x2A { j = skipBlockComment(j); continue }
            }
            j += 1
        }
        return -1
    }

    private func findArrow(_ i: Int) -> Int {
        var j = i
        while j + 1 < length {
            if ns.character(at: j) == 0x3D && ns.character(at: j + 1) == 0x3E { return j }
            j += 1
        }
        return -1
    }

    private func findMatchingBraceOrExpression(from i: Int) -> Int {
        if i < length && ns.character(at: i) == 0x7B { // { ... }
            return findMatchingBraceEnd(from: i)
        }
        // Expression body - find end of expression (semicolon or end of file or } of enclosing)
        var j = i
        var parenDepth = 0
        while j < length {
            let ch = ns.character(at: j)
            if ch == 0x3B && parenDepth == 0 { return max(i, j - 1) } // ;
            if ch == 0x7D && parenDepth == 0 { return max(i, j - 1) } // }
            if ch == 0x28 { parenDepth += 1 }
            else if ch == 0x29 { parenDepth = max(0, parenDepth - 1) }
            else if ch == 0x22 || ch == 0x27 || ch == 0x60 { j = skipString(j, quote: ch); continue }
            else if ch == 0x2F && j + 1 < length {
                let next = ns.character(at: j + 1)
                if next == 0x2F { j = skipToLineEnd(j); continue }
                if next == 0x2A { j = skipBlockComment(j); continue }
            }
            j += 1
        }
        return length - 1
    }

    private func findArrowBodyEnd(from i: Int) -> Int {
        if i < length && ns.character(at: i) == 0x7B {
            return findMatchingBraceEnd(from: i)
        }
        // Expression body ends at semicolon or closing brace of enclosing scope
        var j = i
        var parenDepth = 0
        while j < length {
            let ch = ns.character(at: j)
            if ch == 0x3B && parenDepth == 0 { return max(i, j - 1) } // ;
            if ch == 0x7D && parenDepth == 0 { return max(i, j - 1) } // }
            if ch == 0x28 { parenDepth += 1 }
            else if ch == 0x29 { parenDepth = max(0, parenDepth - 1) }
            else if ch == 0x22 || ch == 0x27 || ch == 0x60 { j = skipString(j, quote: ch); continue }
            else if ch == 0x2F && j + 1 < length {
                let next = ns.character(at: j + 1)
                if next == 0x2F { j = skipToLineEnd(j); continue }
                if next == 0x2A { j = skipBlockComment(j); continue }
            }
            j += 1
        }
        return length - 1
    }
}
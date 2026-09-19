// by cipher.org.uk
import Foundation

/// Locates Objective-C method definitions that have a `{ ... }` body and are
/// therefore analyzable for flowcharts/dataflow. Recognizes the `- (ReturnType)
/// selector:(Type)arg ... { }` syntax used in `.m`/`.mm`/`.objc` files, skipping
/// method *declarations* (`;`-terminated), protocols, and properties.
public final class ObjCMethodParser {

    /// A located Objective-C method definition.
    public struct ObjCMethodDef {
        public let name: String
        public let bodyRange: NSRange      // introducer (-) .. closing '}' (inclusive)
        public let signatureRange: NSRange // introducer (-) .. opening '{'
        public let nameRange: NSRange      // exact range of the first selector segment
    }

    private let source: String
    private let ns: NSString
    private let length: Int

    public init(source: String) {
        self.source = source
        self.ns = source as NSString
        self.length = ns.length
    }

    public func parseDefinitions() -> [ObjCMethodDef] {
        var defs: [ObjCMethodDef] = []
        var i = 0
        while i < length {
            guard let intro = indexOfMethodIntro(from: i) else { break }
            if let def = parseMethod(at: intro) {
                defs.append(def)
                i = def.bodyRange.location + def.bodyRange.length
            } else {
                i = intro + 1
            }
        }

        // Deduplicate by name, keeping the first (body-bearing) definition so
        // duplicate signatures (e.g. in .h + @implementation duplicates) don't
        // produce duplicate diagram nodes.
        var seen = Set<String>()
        var result: [ObjCMethodDef] = []
        for def in defs where seen.insert(def.name).inserted {
            result.append(def)
        }
        return result
    }

    // MARK: - Scanning

    /// Returns the index of the next `-`/`+` that begins a method introducer,
    /// i.e. it is at a statement boundary and outside strings/comments.
    private func indexOfMethodIntro(from start: Int) -> Int? {
        var i = start
        var prev: unichar = 0
        while i < length {
            let c = ns.character(at: i)
            let next = i + 1 < length ? ns.character(at: i + 1) : 0

            if c == 0x2F && next == 0x2F { i = skipToLineEnd(i); prev = 0x0A; continue }
            if c == 0x2F && next == 0x2A { i = skipBlockComment(i); prev = 0x0A; continue }
            if c == 0x22 || c == 0x27 { i = skipString(i, quote: c); prev = 0x22; continue }

            if (c == 0x2D || c == 0x2B) && isMethodBoundary(prev) {
                // Must actually open a method: the next non-ws char is '(' or an identifier.
                let j = skipWhitespace(i + 1)
                if j < length && (isIdentStart(ns.character(at: j)) || ns.character(at: j) == 0x28) {
                    return i
                }
            }
            prev = c
            i += 1
        }
        return nil
    }

    private func isMethodBoundary(_ prev: unichar) -> Bool {
        // Introducers start a line/member: after newline/space/{/}/;/@ or at file start.
        if prev == 0 { return true }
        let ws: Set<UInt16> = [0x20, 0x09, 0x0A, 0x0D]
        if ws.contains(prev) { return true }
        return prev == 0x7B || prev == 0x7D || prev == 0x3B // { } ;
    }

    // MARK: - Single method

    private func parseMethod(at intro: Int) -> ObjCMethodDef? {
        var j = skipWhitespace(intro + 1)

        // Optional return type in parens.
        if j < length && ns.character(at: j) == 0x28 {
            guard let close = skipBalancedParen(j) else { return nil }
            j = skipWhitespace(close)
        }

        // First selector segment = the method name. The return type may be either
        // in parens (handled above) or bare (`- void foo`, `- NSData *data`), so
        // resolve the name as the LAST identifier before the first top-level ':'
        // (first parameter introducer) or the body '{'. A bare return type
        // identifier preceding the name is thereby skipped instead of being
        // mistaken for the method name (which previously made such methods
        // unparsable and therefore not clickable).
        var scan = j
        var lastIdent: (start: Int, end: Int)? = nil
        while scan < length {
            let c = ns.character(at: scan)
            let next = scan + 1 < length ? ns.character(at: scan + 1) : 0
            if c == 0x2F && (next == 0x2F || next == 0x2A) { break } // comment
            if isIdentStart(c) {
                let s = scan
                while scan < length && isIdentChar(ns.character(at: scan)) { scan += 1 }
                lastIdent = (s, scan)
                continue
            }
            if c == 0x3A || c == 0x7B { break } // ':' or '{' ends the name region
            scan += 1
        }
        guard let li = lastIdent else { return nil }
        let nameStart = li.start
        let name = ns.substring(with: NSRange(location: li.start, length: li.end - li.start))
        j = li.end

        // Remaining selector parts: `name:(type)arg part2:(type)arg2 ...`
        // A multi-argument method alternates `label:(Type)arg label:(Type)arg ...`,
        // so after each parameter we must also skip the next selector *label*
        // (an identifier that immediately precedes a ':') before finding the ':'.
        var k = j
        while true {
            let s = skipWhitespace(k)
            if s < length && ns.character(at: s) == 0x3A { // ':'
                k = s + 1
                var t = skipWhitespace(k)
                if t < length && ns.character(at: t) == 0x28 {
                    t = skipBalancedParen(t) ?? t + 1
                }
                t = skipWhitespace(t)
                if t < length && isIdentStart(ns.character(at: t)) {
                    while t < length && isIdentChar(ns.character(at: t)) { t += 1 }
                } else if t < length && ns.character(at: t) == 0x2E { // ... variadic
                    t += 3
                }
                k = t
                continue
            }
            // Skip a selector label (identifier) when a ':' follows it, so the
            // loop can continue parsing the next `label:(Type)name` argument.
            if s < length && isIdentStart(ns.character(at: s)) {
                var e = s
                while e < length && isIdentChar(ns.character(at: e)) { e += 1 }
                let afterLabel = skipWhitespace(e)
                if afterLabel < length && ns.character(at: afterLabel) == 0x3A {
                    k = afterLabel
                    continue
                }
            }
            break
        }

        let signatureEnd = skipWhitespace(k)
        guard signatureEnd < length, ns.character(at: signatureEnd) == 0x7B else { return nil }
        let bodyOpen = signatureEnd

        // Match the closing '}' of the body.
        var depth = 1
        var m = bodyOpen + 1
        while m < length && depth > 0 {
            let c = ns.character(at: m)
            let next = m + 1 < length ? ns.character(at: m + 1) : 0
            if c == 0x2F && next == 0x2A { m = skipBlockComment(m); continue }
            if c == 0x22 || c == 0x27 { m = skipString(m, quote: c); continue }
            if c == 0x7B { depth += 1 }
            else if c == 0x7D {
                depth -= 1
                if depth == 0 { break }
            }
            m += 1
        }
        guard depth == 0 else { return nil }

        let endOffset = m + 1
        return ObjCMethodDef(
            name: name,
            bodyRange: NSRange(location: intro, length: endOffset - intro),
            signatureRange: NSRange(location: intro, length: bodyOpen - intro),
            nameRange: NSRange(location: nameStart, length: j - nameStart)
        )
    }

    // MARK: - Helpers

    private func skipWhitespace(_ i: Int) -> Int {
        var j = i
        while j < length {
            let c = ns.character(at: j)
            if c == 0x20 || c == 0x09 || c == 0x0A || c == 0x0D { j += 1 } else { break }
        }
        return j
    }

    /// Returns the index just past the closing ')' matching the '(' at `i`.
    private func skipBalancedParen(_ i: Int) -> Int? {
        var depth = 1
        var j = i + 1
        while j < length {
            let c = ns.character(at: j)
            let next = j + 1 < length ? ns.character(at: j + 1) : 0
            if c == 0x2F && next == 0x2A { j = skipBlockComment(j); continue }
            if c == 0x22 || c == 0x27 { j = skipString(j, quote: c); continue }
            if c == 0x28 { depth += 1 }
            else if c == 0x29 {
                depth -= 1
                if depth == 0 { return j + 1 }
            }
            j += 1
        }
        return nil
    }

    private func skipString(_ i: Int, quote: unichar) -> Int {
        var j = i + 1
        while j < length {
            if ns.character(at: j) == 0x5C { j += 2; continue }
            if ns.character(at: j) == quote { return j + 1 }
            j += 1
        }
        return length
    }

    private func skipBlockComment(_ i: Int) -> Int {
        var j = i + 2
        while j + 1 < length && !(ns.character(at: j) == 0x2A && ns.character(at: j + 1) == 0x2F) {
            j += 1
        }
        return min(j + 2, length)
    }

    private func skipToLineEnd(_ i: Int) -> Int {
        var j = i
        while j < length && ns.character(at: j) != 0x0A { j += 1 }
        return j
    }

    private func isIdentStart(_ c: unichar) -> Bool {
        (c >= 0x41 && c <= 0x5A) || (c >= 0x61 && c <= 0x7A) || c == 0x5F
    }
    private func isIdentChar(_ c: unichar) -> Bool {
        isIdentStart(c) || (c >= 0x30 && c <= 0x39)
    }
}
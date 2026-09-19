// by cipher.org.uk
import AppKit

/// A lightweight syntax highlighter that colors a source string into an
/// attributed string. Supports a small set of common languages via keywords.
public struct SyntaxHighlighter {

    /// Theme colors for keywords, comments, strings, etc.
    public struct Colors {
        public var keyword: NSColor
        public var string: NSColor
        public var comment: NSColor
        public var number: NSColor
        public var type: NSColor
        public var identifier: NSColor
        public var plain: NSColor

        public init(
            keyword: NSColor? = nil,
            string: NSColor? = nil,
            comment: NSColor? = nil,
            number: NSColor? = nil,
            type: NSColor? = nil,
            identifier: NSColor? = nil,
            plain: NSColor? = nil
        ) {
            self.keyword = keyword ?? Colors.adaptive(light: (0.60, 0.23, 0.90), dark: (0.78, 0.58, 1.00))
            self.string = string ?? Colors.adaptive(light: (0.10, 0.48, 0.12), dark: (0.62, 0.86, 0.45))
            self.comment = comment ?? Colors.adaptive(light: (0.40, 0.42, 0.46), dark: (0.50, 0.54, 0.60))
            self.number = number ?? Colors.adaptive(light: (0.80, 0.42, 0.05), dark: (0.94, 0.68, 0.36))
            self.type = type ?? Colors.adaptive(light: (0.00, 0.40, 0.72), dark: (0.49, 0.80, 1.00))
            self.identifier = identifier ?? Colors.adaptive(light: (0.13, 0.14, 0.16), dark: (0.90, 0.90, 0.90))
            self.plain = plain ?? Colors.adaptive(light: (0.13, 0.14, 0.16), dark: (0.88, 0.88, 0.88))
        }

        /// Builds a dynamic color that resolves to the dark value in dark mode and light in light mode.
        static func adaptive(light: (CGFloat, CGFloat, CGFloat), dark: (CGFloat, CGFloat, CGFloat)) -> NSColor {
            func toColor(_ c: (CGFloat, CGFloat, CGFloat)) -> NSColor {
                NSColor(calibratedRed: c.0, green: c.1, blue: c.2, alpha: 1)
            }
            return NSColor(name: nil) { appearance in
                let isDark = appearance.bestMatch(from: [.darkAqua, .aqua]) == .darkAqua
                return isDark ? toColor(dark) : toColor(light)
            }
        }
    }

    public var colors = Colors()

    public init() {}

    // Common keyword sets per language.
    let swiftyKeywords: Set<String> = [
        "func", "var", "let", "if", "else", "guard", "return", "class", "struct", "enum",
        "protocol", "extension", "for", "while", "repeat", "switch", "case", "break",
        "continue", "in", "where", "public", "private", "internal", "fileprivate", "open",
        "static", "final", "override", "init", "deinit", "import", "typealias", "self",
        "super", "nil", "true", "false", "throws", "throw", "try", "catch", "do", "defer",
        "async", "await", "actor", "mutating", "associatedtype", "lazy", "weak", "unowned",
        "nonisolated"
    ]

    let goKeywords: Set<String> = [
        "func", "var", "const", "type", "struct", "interface", "package", "import", "return",
        "if", "else", "for", "range", "switch", "case", "break", "continue", "defer", "go",
        "chan", "map", "select", "default", "fallthrough", "goto"
    ]

    let pythonKeywords: Set<String> = [
        "def", "class", "if", "elif", "else", "for", "while", "return", "import", "from",
        "as", "try", "except", "finally", "with", "lambda", "pass", "break", "continue",
        "yield", "raise", "global", "nonlocal", "None", "True", "False", "and", "or", "not",
        "in", "is", "del", "assert"
    ]

    let cKeywords: Set<String> = [
        "int", "char", "float", "double", "void", "long", "short", "unsigned", "signed",
        "struct", "union", "enum", "typedef", "const", "static", "extern", "register",
        "volatile", "return", "if", "else", "for", "while", "do", "switch", "case", "break",
        "continue", "goto", "sizeof"
    ]

    let javaKeywords: Set<String> = [
        "abstract", "assert", "boolean", "break", "byte", "case", "catch", "char",
        "class", "const", "continue", "default", "do", "double", "else", "enum",
        "extends", "final", "finally", "float", "for", "goto", "if", "implements",
        "import", "instanceof", "int", "interface", "long", "native", "new", "null",
        "package", "private", "protected", "public", "return", "short", "static",
        "strictfp", "super", "switch", "synchronized", "this", "throw", "throws",
        "transient", "try", "void", "volatile", "while", "true", "false", "var",
        "record", "yield", "sealed", "permits", "non-sealed", "module", "exports",
        "opens", "requires", "uses", "provides", "with", "to", "of"
    ]

    let rustKeywords: Set<String> = [
        "fn", "let", "const", "static", "mut", "pub", "use", "mod", "struct", "enum", "trait",
        "impl", "fn", "return", "if", "else", "match", "for", "while", "loop", "break",
        "continue", "in", "where", "type", "move", "ref", "as", "async", "await", "unsafe"
    ]

    let rubyKeywords: Set<String> = [
        "def", "class", "if", "elsif", "else", "end", "for", "while", "until", "return",
        "module", "require", "begin", "rescue", "ensure", "case", "when", "then", "yield",
        "do", "lambda", "proc", "super", "self", "nil", "true", "false", "and", "or", "not",
        "break", "next", "redo", "retry"
    ]

    let phpKeywords: Set<String> = [
        "php", "function", "class", "interface", "trait", "abstract", "final", "extends",
        "implements", "namespace", "use", "public", "private", "protected", "static",
        "const", "var", "if", "else", "elseif", "endif", "for", "endforeach", "foreach",
        "as", "while", "endwhile", "do", "switch", "endswitch", "case", "default", "break",
        "continue", "return", "global", "echo", "print", "print_r", "var_dump", "require",
        "require_once", "include", "include_once", "new", "clone", "instanceof", "try",
        "catch", "finally", "throw", "isset", "unset", "empty", "exit", "die", "yield",
        "match", "fn", "self", "parent", "this", "null", "true", "false", "and", "or", "not"
    ]

    let shellKeywords: Set<String> = [
        "if", "then", "else", "elif", "fi", "for", "while", "until", "do", "done", "case",
        "esac", "function", "return", "local", "export", "readonly", "shift", "exit", "in"
    ]

    let solidityKeywords: Set<String> = [
        "pragma", "contract", "interface", "library", "abstract", "is", "function", "modifier",
        "constructor", "fallback", "receive", "event", "error", "struct", "enum", "mapping",
        "public", "private", "internal", "external", "view", "pure", "payable", "constant",
        "returns", "return", "emit", "require", "assert", "revert", "if", "else", "for",
        "while", "do", "break", "continue", "new", "delete", "throw", "try", "catch",
        "address", "bool", "string", "bytes", "bytes32", "uint", "uint8", "uint16", "uint32",
        "uint64", "uint128", "uint256", "int", "int8", "int16", "int32", "int64", "int128",
        "int256", "fixed", "ufixed", "var", "memory", "storage", "calldata", "this", "super",
        "msg", "tx", "block", "abi", "now", "keccak256", "sha256", "ripemd160", "ecrecover",
        "selfdestruct", "suicide", "send", "transfer", "call", "delegatecall", "staticcall",
        "blockhash", "gasleft", "asm", "unchecked", "using", "for", "global", "immutable"
    ]

    let sqlKeywords: Set<String> = [
        "SELECT", "FROM", "WHERE", "INSERT", "UPDATE", "DELETE", "CREATE", "TABLE", "DROP",
        "ALTER", "JOIN", "INNER", "OUTER", "LEFT", "RIGHT", "ON", "AND", "OR", "NOT", "NULL",
        "GROUP", "ORDER", "BY", "HAVING", "LIMIT", "OFFSET", "INTO", "VALUES", "SET", "PRIMARY",
        "KEY", "FOREIGN", "REFERENCES", "UNIQUE", "INDEX", "VIEW", "AS", "DISTINCT"
    ]

    let csharpKeywords: Set<String> = [
        // Value types
        "int", "long", "short", "byte", "sbyte", "uint", "ulong", "ushort",
        "char", "float", "double", "bool", "void", "decimal", "object", "string",
        // Modifiers
        "public", "private", "protected", "internal", "static", "const", "readonly",
        "abstract", "sealed", "virtual", "override", "new", "extern", "unsafe",
        "partial", "ref", "out", "in", "params", "async", "await", "volatile",
        // Type declarations
        "class", "struct", "interface", "enum", "record", "namespace", "using", "delegate",
        // Flow control
        "if", "else", "for", "foreach", "while", "do", "switch", "case", "default",
        "break", "continue", "return", "goto", "throw", "try", "catch", "finally",
        "lock", "checked", "unchecked", "yield", "when", "where", "is", "as",
        // Object/misc
        "this", "base", "null", "true", "false", "var", "dynamic", "sizeof", "typeof",
        "nameof", "stackalloc", "fixed", "operator", "event", "get", "set", "value",
        "init", "required", "global", "using", "with", "not", "and", "or"
    ]

    let kotlinKeywords: Set<String> = [
        "package", "import", "class", "object", "interface", "fun", "val", "var",
        "private", "public", "protected", "internal", "override", "abstract", "final",
        "open", "lateinit", "data", "sealed", "enum", "annotation", "companion", "init",
        "constructor", "if", "else", "when", "for", "while", "do", "return", "break",
        "continue", "try", "catch", "finally", "throw", "typealias", "operator", "infix",
        "inline", "noinline", "crossinline", "vararg", "reified", "suspend", "tailrec",
        "external", "by", "get", "set", "null", "true", "false", "this", "super", "is",
        "in", "as", "out", "inner", "expect", "actual", "const", "yield", "field",
        "it", "dynamic", "param", "receiver", "setparam", "delegate"
    ]

    let cocoaKeywords: Set<String> = [
        "@interface", "@implementation", "@end", "@property", "@synthesize",
        "@dynamic", "@class", "@selector", "@protocol", "@optional", "@required",
        "@public", "@private", "@protected", "@package", "@try", "@catch",
        "@finally", "@throw", "@synchronized", "@autoreleasepool", "@available",
        "@encode", "@compatibility_alias", "@defs",
        "typedef", "enum", "struct", "union", "const", "static", "extern", "auto",
        "register", "volatile", "inline", "restrict", "return", "if", "else", "for",
        "while", "do", "switch", "case", "break", "continue", "default", "goto",
        "sizeof", "self", "super", "nil", "NULL", "YES", "NO", "true", "false",
        "BOOL", "instancetype", "id", "void", "int", "char", "float", "double",
        "long", "short", "unsigned", "signed", "readonly", "readwrite", "nonatomic",
        "atomic", "retain", "copy", "assign", "strong", "weak", "unsafe_unretained",
        "getter", "setter", "in", "out", "inout", "bycopy", "byref", "oneway"
    ]

    let javascriptKeywords: Set<String> = [
        "function", "return", "if", "else", "for", "while", "do", "switch", "case",
        "default", "break", "continue", "const", "let", "var", "class", "extends",
        "super", "this", "new", "delete", "typeof", "instanceof", "in", "of",
        "try", "catch", "finally", "throw", "async", "await", "yield", "static",
        "get", "set", "import", "export", "from", "as", "null", "undefined",
        "true", "false", "void", "debugger", "with", "arguments"
    ]

    /// TypeScript is a superset of JavaScript: extra keywords for type-level
    /// syntax. Applied to .ts/.tsx only, so plain `.js` files don't mis-color
    /// identifiers named `type`, `interface`, etc.
    var typescriptKeywords: Set<String> {
        javascriptKeywords.union([
            "interface", "type", "enum", "implements", "readonly", "namespace",
            "declare", "abstract", "public", "private", "protected", "keyof",
            "infer", "is", "unknown", "never", "any", "string", "number",
            "boolean", "symbol", "object", "satisfies", "accessor"
        ])
    }

    /// Returns the keyword set for a given file extension, or nil if unhighlighted.
    func keywordSet(for ext: String) -> Set<String>? {
        switch ext.lowercased() {
        case "swift": return swiftyKeywords
        case "go": return goKeywords
        case "py": return pythonKeywords
        case "c", "h", "cpp", "cc", "cxx", "hpp": return cKeywords
        case "java": return javaKeywords
        case "cs", "csx": return csharpKeywords
        case "kt", "kts": return kotlinKeywords
        case "m", "mm", "objc": return cocoaKeywords
        case "rs": return rustKeywords
        case "rb": return rubyKeywords
        case "php", "phtml": return phpKeywords
        case "sol": return solidityKeywords
        case "sh", "bash", "zsh": return shellKeywords
        case "sql": return sqlKeywords
        case "js", "jsx": return javascriptKeywords
        case "ts", "tsx": return typescriptKeywords
        default: return nil
        }
    }

    /// Token types produced by the lexer.
    enum TokenType {
        case comment
        case string
        case number
        case keyword
        case type
        case plain
    }

    /// Highlights the given source text. Returns nil if the extension is unsupported.
    public func highlight(_ source: String, for ext: String) -> NSAttributedString? {
        let font = NSFont.monospacedSystemFont(ofSize: 13, weight: .regular)
        let baseAttrs: [NSAttributedString.Key: Any] = [
            .font: font,
            .foregroundColor: colors.plain
        ]

        guard let keywords = keywordSet(for: ext), !source.isEmpty else {
            return NSAttributedString(string: source, attributes: baseAttrs)
        }

        let result = NSMutableAttributedString(string: source, attributes: baseAttrs)
        let extLower = ext.lowercased()
        let isPHP = extLower == "php" || extLower == "phtml"
        let isJS = ["js", "jsx", "ts", "tsx"].contains(extLower)
        let tokens = tokenize(source, keywords: keywords, isPHP: isPHP, isJS: isJS)

        for (range, type) in tokens {
            let color: NSColor
            switch type {
            case .keyword: color = colors.keyword
            case .string: color = colors.string
            case .comment: color = colors.comment
            case .number: color = colors.number
            case .type: color = colors.type
            case .plain: color = colors.plain
            }
            result.addAttribute(.foregroundColor, value: color, range: range)
        }

        return result
    }

    private func tokenize(_ source: String, keywords: Set<String>, isPHP: Bool = false, isJS: Bool = false) -> [(NSRange, TokenType)] {
        var tokens: [(NSRange, TokenType)] = []
        let ns = source as NSString
        let length = ns.length
        var i = 0

        let uppercaseKeywords = Set(keywords.map { $0.uppercased() })

        // ASCII char codes used by the lexer.
        let slash: unichar = 0x2F   // /
        let star: unichar = 0x2A    // *
        let newline: unichar = 0x0A // \n
        let dquote: unichar = 0x22  // "
        let squote: unichar = 0x27  // '
        let backslash: unichar = 0x5C
        let underscore: unichar = 0x5F
        let dot: unichar = 0x2E
        let ex: unichar = 0x78 // x
        let at: unichar = 0x40 // @
        let dollar: unichar = 0x24 // $

        while i < length {
            let ch = ns.character(at: i)

            // Line comment // or #
            if ch == slash && i + 1 < length && ns.character(at: i + 1) == slash {
                let start = i
                while i < length && ns.character(at: i) != newline { i += 1 }
                tokens.append((NSRange(location: start, length: i - start), .comment))
                continue
            }

            // Block comment /* ... */
            if ch == slash && i + 1 < length && ns.character(at: i + 1) == star {
                let start = i
                while i + 1 < length && !(ns.character(at: i) == star && ns.character(at: i + 1) == slash) {
                    i += 1
                }
                if i + 1 < length {
                    i += 2
                } else {
                    i = length
                }
                tokens.append((NSRange(location: start, length: i - start), .comment))
                continue
            }

            // C# verbatim/interpolated string prefixes: @"..." / $@"..." / $"..." ...
            if (ch == at || ch == dollar) && i + 1 < length && ns.character(at: i + 1) == dquote {
                // Determine verbatim-ness (flat interpolation is handled best-effort).
                let prefixStart = i
                var j = i
                var verbatim = false
                if ns.character(at: j) == at { verbatim = true; j += 1 }
                while j < length && ns.character(at: j) == dollar { j += 1 }
                if j < length && ns.character(at: j) == at { verbatim = true; j += 1 }
                // j now points at the opening quote.
                if j < length && ns.character(at: j) == dquote {
                    j += 1
                    while j < length {
                        if verbatim {
                            // Verbatim: "…" escapes a quote; only a lone " closes.
                            if ns.character(at: j) == dquote {
                                if j + 1 < length && ns.character(at: j + 1) == dquote {
                                    j += 2
                                    continue
                                }
                                j += 1
                                break
                            }
                            j += 1
                        } else {
                            if ns.character(at: j) == backslash {
                                j += 2
                                continue
                            }
                            if ns.character(at: j) == dquote {
                                j += 1
                                break
                            }
                            j += 1
                        }
                    }
                    tokens.append((NSRange(location: prefixStart, length: j - prefixStart), .string))
                    i = j
                    continue
                }
            }

            // String literal "..."
            if ch == dquote || ch == squote {
                let quote = ch
                let start = i
                i += 1
                while i < length {
                    if ns.character(at: i) == backslash {
                        i += 2
                        continue
                    }
                    if ns.character(at: i) == quote {
                        i += 1
                        break
                    }
                    i += 1
                }
                tokens.append((NSRange(location: start, length: i - start), .string))
                continue
            }

            // JavaScript/TypeScript template literal `...` with ${...}
            // interpolation. Literal parts are colored as strings; each
            // `${expr}` is re-lexed (shifted back to absolute offsets) so
            // keywords/types inside interpolations keep their colors.
            if isJS && ch == 0x60 {
                var segments: [(NSRange, TokenType)] = []
                var litStart = i
                i += 1
                while i < length {
                    let c = ns.character(at: i)
                    if c == backslash { i += 2; continue }
                    if c == dollar && i + 1 < length && ns.character(at: i + 1) == 0x7B { // ${
                        if i > litStart {
                            segments.append((NSRange(location: litStart, length: i - litStart), .string))
                        }
                        let interpStart = i
                        i += 2
                        var depth = 1
                        while i < length && depth > 0 {
                            let d = ns.character(at: i)
                            if d == backslash { i += 2; continue }
                            if d == dquote || d == squote || d == 0x60 {
                                let q = d
                                i += 1
                                while i < length {
                                    if ns.character(at: i) == backslash { i += 2; continue }
                                    if ns.character(at: i) == q { i += 1; break }
                                    if ns.character(at: i) == newline && q != 0x60 { break }
                                    i += 1
                                }
                                continue
                            }
                            if d == 0x7B { depth += 1 }
                            else if d == 0x7D { depth -= 1 }
                            i += 1
                        }
                        // Re-lex the interpolation body (between "${" and "}").
                        let exprOpen = interpStart + 2
                        let exprClose = i - 1
                        if exprClose > exprOpen && exprOpen < length {
                            let sub = ns.substring(with: NSRange(location: exprOpen,
                                                                 length: exprClose - exprOpen))
                            for (r, t) in tokenize(sub, keywords: keywords, isPHP: false, isJS: isJS) {
                                segments.append((NSRange(location: r.location + exprOpen, length: r.length), t))
                            }
                        }
                        // The delimiters themselves stay plain.
                        segments.append((NSRange(location: interpStart, length: 2), .plain))
                        if i > interpStart + 1 {
                            segments.append((NSRange(location: i - 1, length: 1), .plain))
                        }
                        litStart = i
                        continue
                    }
                    if c == 0x60 { // `
                        i += 1
                        break
                    }
                    i += 1
                }
                if i > litStart {
                    segments.append((NSRange(location: litStart, length: i - litStart), .string))
                }
                tokens.append(contentsOf: segments)
                continue
            }

            // Alphanumeric identifiers / keywords. PHP variables start with `$`
            // (e.g. `$foo`); for PHP the `$` is folded into the identifier so the
            // whole `$name` is colored as one token (not keyword-split). JS/TS
            // identifiers may also contain `$` (jQuery-style `$foo`, `foo$bar`).
            if isAlpha(ch) || ch == underscore || (isPHP && ch == dollar) || (isJS && ch == dollar) {
                let start = i
                if isPHP && ch == dollar { i += 1 }
                while i < length && (isAlpha(ns.character(at: i)) || isDigit(ns.character(at: i)) || ns.character(at: i) == underscore || (isJS && ns.character(at: i) == dollar)) {
                    i += 1
                }
                let word = ns.substring(with: NSRange(location: start, length: i - start))

                if isPHP && word.hasPrefix("$") {
                    // Treat `$this` without the leading `$` for keyword matching so
                    // `$`-prefixed keywords (e.g. `$this`) keep their type color.
                    let base = String(word.dropFirst())
                    if base == "this" {
                        tokens.append((NSRange(location: start, length: i - start), .type))
                        continue
                    }
                    if keywords.contains(base) || uppercaseKeywords.contains(base) {
                        tokens.append((NSRange(location: start, length: i - start), .keyword))
                    } else if let first = base.first, first.isUppercase {
                        tokens.append((NSRange(location: start, length: i - start), .type))
                    }
                    continue
                }

                if keywords.contains(word) || uppercaseKeywords.contains(word) {
                    tokens.append((NSRange(location: start, length: i - start), .keyword))
                }
                // Capitalized identifiers -> type
                else if let first = word.first, first.isUppercase {
                    tokens.append((NSRange(location: start, length: i - start), .type))
                }
                continue
            }

            // Numbers
            if isDigit(ch) {
                let start = i
                while i < length && (isDigit(ns.character(at: i)) || ns.character(at: i) == dot || ns.character(at: i) == ex || ns.character(at: i) == underscore) {
                    i += 1
                }
                tokens.append((NSRange(location: start, length: i - start), .number))
                continue
            }

            i += 1
        }

        return tokens
    }

    private func isAlpha(_ c: unichar) -> Bool {
        return (c >= 0x41 && c <= 0x5A) || (c >= 0x61 && c <= 0x7A)
    }

    private func isDigit(_ c: unichar) -> Bool {
        return c >= 0x30 && c <= 0x39
    }
}

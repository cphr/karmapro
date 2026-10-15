// by cipher.org.uk
import Foundation

/// A richly-typed token for the C/C++ AST frontend.
/// Unlike the scanner's lightweight symbol tokenizer, this carries source
/// position info and a precise kind, which is essential for accurate,
/// line-compatible findings and AST construction.
public struct CAstToken {
    public enum Kind: Equatable {
        case identifier
        case keyword
        case number
        case string
        case character
        case `operator`   // multi-char operators: ->, ::, ==, etc.
        case punct        // single-char punctuation: ( ) { } [ ] ; , etc.
        case eof
    }

    public let kind: Kind
    public let text: String
    public let line: Int      // 1-based
    public let column: Int    // 1-based
    public let offset: Int    // UTF-16 offset into the source

    /// C preprocessing keyword and storage/type keywords.
    public static func classify(_ text: String) -> Kind {
        switch text {
        case "int","char","short","long","float","double","void","signed","unsigned",
             "bool","struct","union","enum","class","typename","const","volatile",
             "static","extern","register","auto","inline","typedef","constexpr",
             "restrict","mutable","explicit","virtual","override","final","friend",
             "namespace","using","template","operator","new","delete","this","sizeof",
             "return","if","else","for","while","do","switch","case","default","break",
             "continue","goto","try","catch","throw","throws","public","private",
             "protected","and","or","not","true","false","nullptr","NULL",
             "alignas","alignof","decltype","static_assert","thread_local","noexcept",
             "wchar_t","char16_t","char32_t",
             // Java-only keywords.
             "package","import","interface","extends","implements","abstract","synchronized",
             "transient","instanceof","super","assert","strictfp",
             "finally","native","boolean","byte":
            return .keyword
        default:
            // Every non-keyword word-like token is an identifier; the old
            // `CharacterSet.alphanumerics` check (re)created the set per call
            // and returned `.identifier` on both branches anyway.
            return .identifier
        }
    }
}

extension Array where Element == CAstToken {
    /// Tokens with offset in `[lo, hi)`; two binary searches (offsets ascend).
    public func tokens(from lo: Int, to hi: Int) -> [CAstToken] {
        var l = 0, r = count
        while l < r { let m = (l + r) / 2; if self[m].offset < lo { l = m + 1 } else { r = m } }
        let start = l
        var h = l, hr = count
        while h < hr { let m = (h + hr) / 2; if self[m].offset < hi { h = m + 1 } else { hr = m } }
        return Array(self[start..<h])
    }
}

/// The set of C/C++ operators we keep as single tokens.
public let cMultiCharOperators: Set<String> = [
    "->", "::", "==", "!=", ">=", "<=", "&&", "||", "++", "--",
    "+=", "-=", "*=", "/=", "%=", "&=", "|=", "^=", "<<", ">>",
    "<<=", ">>=", "->*", ".*", "...", "##", "+", "-", "*", "/", "%",
    "&", "|", "^", "!", "~", "=", "<", ">", "?", ":", ";", ",", ".",
    "(", ")", "[", "]", "{", "}", "@", "$"
]

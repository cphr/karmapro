// by cipher.org.uk
import Foundation

/// A user-selectable programming language for filtering the file browser.
public struct Language {
    public let name: String
    public let extensions: Set<String>

    public init(name: String, extensions: Set<String>) {
        self.name = name
        self.extensions = extensions
    }

    /// Returns true if a file path belongs to this language.
    public func contains(_ url: URL) -> Bool {
        extensions.contains(url.pathExtension.lowercased())
    }
}

extension Language {
    /// Whether a path should be considered a source file at all.
    public static func isSourceFile(_ url: URL) -> Bool {
        supported.contains { $0.contains(url) } || genericSourceExtensions.contains(url.pathExtension.lowercased())
    }

    private static let genericSourceExtensions: Set<String> = [
        "c", "h", "cpp", "cc", "cxx", "hpp", "java", "rs", "rb",
        "sh", "bash", "zsh", "php", "kt", "kts", "lua", "m", "mm",
        "cs", "scala", "pl", "pm", "r", "dart", "hs", "erl", "ex", "exs",
        "clj", "cljs", "el", "ml", "sql", "graphql", "gql", "proto",
        "dockerfile", "cmake", "make", "m4", "pod", "raku", "sol", "js", "jsx", "ts", "tsx", "swift"
    ]

    /// The complete list of languages offered in the dropdown.
    public static let supported: [Language] = [
        Language(name: "All Languages", extensions: []),
        Language(name: "C", extensions: ["c", "h"]),
        Language(name: "C++", extensions: ["cpp", "cc", "cxx", "hpp", "hxx", "hh"]),
        Language(name: "Java", extensions: ["java"]),
        Language(name: "C#", extensions: ["cs", "csx"]),
        Language(name: "Go", extensions: ["go"]),
        Language(name: "Kotlin", extensions: ["kt", "kts"]),
        Language(name: "Ruby", extensions: ["rb", "rake", "gemspec"]),
        Language(name: "PHP", extensions: ["php", "phtml", "inc"]),
        Language(name: "Python", extensions: ["py"]),
        Language(name: "Cocoa", extensions: ["m", "mm", "objc"]),
        Language(name: "Rust", extensions: ["rs"]),
        Language(name: "Solidity", extensions: ["sol"]),
        Language(name: "JavaScript", extensions: ["js", "jsx", "ts", "tsx"]),
        Language(name: "Swift", extensions: ["swift"])
    ]
}

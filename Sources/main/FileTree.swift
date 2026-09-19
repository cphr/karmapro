// by cipher.org.uk
import Foundation

/// A node in the file tree, suitable for display in an NSOutlineView.
public final class FileNode {
    public let url: URL
    public let name: String
    public let isDirectory: Bool
    public var children: [FileNode] = []

    public init(url: URL, isDirectory: Bool) {
        self.url = url
        self.name = url.lastPathComponent
        self.isDirectory = isDirectory
    }

    /// Lazily loads direct children (non-recursive) so we can expand dirs on demand.
    public func loadChildren() {
        guard isDirectory, children.isEmpty else { return }
        let fm = FileManager.default
        guard let contents = try? fm.contentsOfDirectory(
            at: url,
            includingPropertiesForKeys: [.isDirectoryKey, .isHiddenKey],
            options: [.skipsHiddenFiles]
        ) else { return }

        var nodes: [FileNode] = []
        for item in contents {
            guard !FileNode.ignored.contains(item.lastPathComponent) else { continue }
            let isDir = (try? item.resourceValues(forKeys: [.isDirectoryKey]).isDirectory) ?? false
            nodes.append(FileNode(url: item, isDirectory: isDir))
        }

        nodes.sort { a, b in
            if a.isDirectory != b.isDirectory { return a.isDirectory }
            return a.name.localizedCaseInsensitiveCompare(b.name) == .orderedAscending
        }
        children = nodes
    }

    /// Recursively loads the whole subtree (used for search).
    public func loadDeeply() {
        guard isDirectory else { return }
        loadChildren()
        for child in children where child.isDirectory {
            child.loadDeeply()
        }
    }

    public static let ignored: Set<String> = [
        ".git", ".hg", ".svn", ".DS_Store",
        "node_modules", "vendor", "dist", "build",
        ".idea", ".vscode", "__pycache__", ".cache"
    ]

    /// Creates a lightweight copy of a node with the same identity info but no children.
    /// Used to build a pruned (language-filtered) tree.
    public static func prunedCopy(of node: FileNode) -> FileNode {
        let copy = FileNode(url: node.url, isDirectory: node.isDirectory)
        return copy
    }
}

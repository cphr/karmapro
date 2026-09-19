// by cipher.org.uk
import AppKit

/// Window that shows every place a Java class is instantiated (`new ClassName(...)`)
/// across the opened project, rendered as an animated graph: the class is the central
/// (highlighted) node and each instantiation site is a node below it, with animated
/// dashed edges flowing from the class into each site. Clicking a site node opens
/// that file at the instantiation line in the main source viewer.
final class ClassUsageWindowController: NSWindowController {
    private struct Occurrence {
        let fileURL: URL
        let line: Int
        let snippet: String
    }

    var requestedClass = ""
    private var occurrences: [Occurrence] = []
    /// Maps a graph node name (e.g. "Main.java:5") back to its occurrence.
    private var nodeToOccurrence: [String: Occurrence] = [:]

    private let titleLabel = NSTextField(labelWithString: "")
    private let statusLabel = NSTextField(wrappingLabelWithString: "")
    private let diagramView = DataFlowDiagramView()
    private let emptyLabel = NSTextField(wrappingLabelWithString: "")

    /// Fired when the user wants to open a file at a given line in the main viewer.
    var onOpenFile: ((URL, Int) -> Void)?

    convenience init(className: String) {
        let window = EscClosableWindow(
            contentRect: NSRect(x: 0, y: 0, width: 900, height: 600),
            styleMask: [.titled, .closable, .resizable],
            backing: .buffered,
            defer: false
        )
        window.title = "Instantiations of \(className)"
        window.minSize = NSSize(width: 560, height: 360)
        self.init(window: window)
        self.requestedClass = className
        buildContent()
    }

    /// Scans the project under `root` for `new <className>(` occurrences and renders
    /// them as an animated graph.
    func load(root: URL) {
        occurrences = Self.scanInstantiations(of: requestedClass, in: root)
        nodeToOccurrence.removeAll()

        if occurrences.isEmpty {
            diagramView.isHidden = true
            emptyLabel.isHidden = false
            statusLabel.stringValue = "No instantiations of “\(requestedClass)” found."
            return
        }

        emptyLabel.isHidden = true
        diagramView.isHidden = false

        // Build a graph: class node (highlighted) + one node per instantiation site.
        let graph = CallGraph()
        let classNode = requestedClass
        _ = graph.node(for: classNode)

        var layoutEdges: [(String, String)] = [] // site -> class  (for layout ranking, class on top)
        var dataEdges: [(String, String)] = []   // class -> site  (for animated arrows)
        for o in occurrences {
            // Keep node names unique by including the line number.
            let nodeName = "\(o.fileURL.lastPathComponent):\(o.line)"
            var unique = nodeName
            var counter = 1
            while graph.hasNode(unique) {
                counter += 1
                unique = "\(nodeName) (\(counter))"
            }
            _ = graph.node(for: unique)
            nodeToOccurrence[unique] = o
            layoutEdges.append((unique, classNode))
            dataEdges.append((classNode, unique))
        }

        diagramView.animatedOnlyEdges = true
        diagramView.onNodeClick = { [weak self] nodeName in
            guard let self = self else { return }
            if nodeName == classNode { return }
            if let occ = self.nodeToOccurrence[nodeName] {
                self.onOpenFile?(occ.fileURL, occ.line)
            }
        }
        diagramView.display(graph: graph, callEdges: layoutEdges, dataEdges: dataEdges, highlight: classNode)

        statusLabel.stringValue = "\(occurrences.count) instantiation(s) of “\(requestedClass)” — click a node to open it"
    }

    private func buildContent() {
        guard let content = window?.contentView else { return }

        titleLabel.font = NSFont.systemFont(ofSize: 16, weight: .semibold)
        titleLabel.textColor = .labelColor
        titleLabel.stringValue = "Where is “\(requestedClass)” instantiated?"
        titleLabel.translatesAutoresizingMaskIntoConstraints = false
        content.addSubview(titleLabel)

        statusLabel.font = NSFont.systemFont(ofSize: 12)
        statusLabel.textColor = .secondaryLabelColor
        statusLabel.translatesAutoresizingMaskIntoConstraints = false
        content.addSubview(statusLabel)

        diagramView.translatesAutoresizingMaskIntoConstraints = false
        content.addSubview(diagramView)

        emptyLabel.font = NSFont.systemFont(ofSize: 14)
        emptyLabel.textColor = .secondaryLabelColor
        emptyLabel.alignment = .center
        emptyLabel.stringValue = "No instantiations of “\(requestedClass)” found."
        emptyLabel.translatesAutoresizingMaskIntoConstraints = false
        content.addSubview(emptyLabel)
        emptyLabel.isHidden = true

        NSLayoutConstraint.activate([
            titleLabel.topAnchor.constraint(equalTo: content.topAnchor, constant: 16),
            titleLabel.leadingAnchor.constraint(equalTo: content.leadingAnchor, constant: 20),
            titleLabel.trailingAnchor.constraint(lessThanOrEqualTo: content.trailingAnchor, constant: -20),
            statusLabel.topAnchor.constraint(equalTo: titleLabel.bottomAnchor, constant: 4),
            statusLabel.leadingAnchor.constraint(equalTo: content.leadingAnchor, constant: 20),
            statusLabel.trailingAnchor.constraint(lessThanOrEqualTo: content.trailingAnchor, constant: -20),
            diagramView.topAnchor.constraint(equalTo: statusLabel.bottomAnchor, constant: 10),
            diagramView.bottomAnchor.constraint(equalTo: content.bottomAnchor, constant: -12),
            diagramView.leadingAnchor.constraint(equalTo: content.leadingAnchor, constant: 20),
            diagramView.trailingAnchor.constraint(equalTo: content.trailingAnchor, constant: -20),
            emptyLabel.centerXAnchor.constraint(equalTo: content.centerXAnchor),
            emptyLabel.centerYAnchor.constraint(equalTo: content.centerYAnchor)
        ])
    }

    /// Finds all `new <className>(` occurrences in `.java`/`.cs` files under `root`.
    private static func scanInstantiations(of className: String, in root: URL) -> [Occurrence] {
        var hits: [Occurrence] = []
        for url in SourceTree.enumerate(extensions: ["java", "cs", "csx"], in: root) {
            // Keep the window's own test-directory exclusion on top of the
            // shared walker's build/vendor/node_modules/.git skip list.
            if url.path.contains("/test/") { continue }
            guard let text = try? String(contentsOf: url, encoding: .utf8) else { continue }
            hits.append(contentsOf: findOccurrences(of: className, in: text, inFile: url))
        }
        return hits
    }

    /// Locates `new <className>(`/`new <className><Type>(` matches with their line + snippet.
    private static func findOccurrences(of className: String, in text: String, inFile url: URL) -> [Occurrence] {
        var out: [Occurrence] = []
        let ns = text as NSString
        let pattern = "new\\s+\(NSRegularExpression.escapedPattern(for: className))(?:\\s*<[^;]*?>)?\\s*\\("
        guard let regex = try? NSRegularExpression(pattern: pattern, options: [.dotMatchesLineSeparators]) else { return [] }

        regex.enumerateMatches(in: text, options: [], range: NSRange(location: 0, length: ns.length)) { match, _, _ in
            guard let match = match else { return }
            let r = match.range
            // Compute the 1-based line number of the match start.
            let prefix = ns.substring(with: NSRange(location: 0, length: r.location))
            let line = prefix.reduce(0) { $1 == "\n" ? $0 + 1 : $0 } + 1
            // A short snippet around the instantiation.
            let snippetLoc = max(0, r.location)
            let snippetLen = min(ns.length - snippetLoc, 80)
            let snippet = ns.substring(with: NSRange(location: snippetLoc, length: snippetLen))
            out.append(Occurrence(fileURL: url, line: line, snippet: snippet))
        }
        return out
    }
}

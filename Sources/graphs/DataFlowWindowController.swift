// by cipher.org.uk
import AppKit

/// Window that shows the animated dataflow diagram for a clicked function.
final class DataFlowWindowController: NSWindowController {
    private let diagramView = DataFlowDiagramView()
    private let titleLabel = NSTextField(labelWithString: "")
    private let captionLabel = NSTextField(wrappingLabelWithString: "")
    private let emptyLabel = NSTextField(wrappingLabelWithString: "")

    convenience init(fileURL: URL, functionName: String) {
        let window = EscClosableWindow(
            contentRect: NSRect(x: 0, y: 0, width: 900, height: 700),
            styleMask: [.titled, .closable, .resizable],
            backing: .buffered,
            defer: false
        )
        window.title = "Dataflow: \(functionName) — \(fileURL.lastPathComponent)"
        window.minSize = NSSize(width: 600, height: 400)
        self.init(window: window)
        buildContent()
        loadGraph(fileURL: fileURL, functionName: functionName)
    }

    /// Centers the window on screen every time it is shown.
    override func showWindow(_ sender: Any?) {
        window?.center()
        super.showWindow(sender)
    }

    private func buildContent() {
        guard let content = window?.contentView else { return }

        // Header
        titleLabel.font = NSFont.systemFont(ofSize: 16, weight: .semibold)
        titleLabel.textColor = .labelColor
        titleLabel.translatesAutoresizingMaskIntoConstraints = false
        content.addSubview(titleLabel)

        captionLabel.font = NSFont.systemFont(ofSize: 12)
        captionLabel.textColor = .secondaryLabelColor
        captionLabel.translatesAutoresizingMaskIntoConstraints = false
        content.addSubview(captionLabel)

        // Diagram fills the remaining area of the frame.
        diagramView.translatesAutoresizingMaskIntoConstraints = false
        content.addSubview(diagramView)

        emptyLabel.font = NSFont.systemFont(ofSize: 14)
        emptyLabel.textColor = .secondaryLabelColor
        emptyLabel.alignment = .center
        emptyLabel.isHidden = true
        emptyLabel.translatesAutoresizingMaskIntoConstraints = false
        content.addSubview(emptyLabel)

        NSLayoutConstraint.activate([
            titleLabel.topAnchor.constraint(equalTo: content.topAnchor, constant: 16),
            titleLabel.leadingAnchor.constraint(equalTo: content.leadingAnchor, constant: 20),
            titleLabel.trailingAnchor.constraint(lessThanOrEqualTo: content.trailingAnchor, constant: -20),
            captionLabel.topAnchor.constraint(equalTo: titleLabel.bottomAnchor, constant: 4),
            captionLabel.leadingAnchor.constraint(equalTo: content.leadingAnchor, constant: 20),
            captionLabel.trailingAnchor.constraint(lessThanOrEqualTo: content.trailingAnchor, constant: -20),
            diagramView.topAnchor.constraint(equalTo: captionLabel.bottomAnchor, constant: 12),
            diagramView.bottomAnchor.constraint(equalTo: content.bottomAnchor),
            diagramView.leadingAnchor.constraint(equalTo: content.leadingAnchor),
            diagramView.trailingAnchor.constraint(equalTo: content.trailingAnchor),
            emptyLabel.centerXAnchor.constraint(equalTo: content.centerXAnchor),
            emptyLabel.centerYAnchor.constraint(equalTo: content.centerYAnchor),
            emptyLabel.leadingAnchor.constraint(greaterThanOrEqualTo: content.leadingAnchor, constant: 40),
            emptyLabel.trailingAnchor.constraint(lessThanOrEqualTo: content.trailingAnchor, constant: -40)
        ])
    }

    /// Parses the file and populates the diagram.
    private func loadGraph(fileURL: URL, functionName: String) {
        guard let text = try? String(contentsOf: fileURL, encoding: .utf8) else {
            titleLabel.stringValue = "Unable to read file"
            return
        }

        let defs = diagramDefinitions(source: text, ext: fileURL.pathExtension)
        let (calls, data) = diagramCallGraph(source: text, definitions: defs)

        let graph = CallGraph()
        for (from, to) in calls {
            graph.addCall(from: from, to: to)
        }
        for (from, to) in data {
            graph.addDataFlow(from: from, to: to)
        }

        // Only keep nodes that are actually defined functions in this file.
        for def in defs { _ = graph.node(for: def.name) }
        graph.pruneTo(defined: Set(defs.map { $0.name }))

        titleLabel.stringValue = "Dataflow around “\(functionName)”"

        let centerName: String?
        if defs.contains(where: { $0.name == functionName }) {
            centerName = functionName
        } else {
            centerName = graph.functionNames.first
        }

        // Direct-neighbour scope: keep only the selected function plus its
        // immediate callers and callees within this file. Transitive
        // callees-of-callees (and unrelated in-file functions) are dropped so
        // the diagram shows a single hop instead of the whole file's call graph.
        if let center = centerName {
            var keep: Set<String> = [center]
            for (from, to) in calls where graph.hasNode(from) && graph.hasNode(to) {
                if to == center || from == center {
                    keep.insert(from)
                    keep.insert(to)
                }
            }
            graph.pruneTo(defined: keep)
        }

        captionLabel.stringValue = "Callers to the left · Callees to the right · Solid arrows: function calls · Animated dashed arrows: data flow · Direct callees only"

        let visibleCalls = calls.filter { graph.hasNode($0.0) && graph.hasNode($0.1) }
        let visibleData = data.filter { graph.hasNode($0.0) && graph.hasNode($0.1) }

        guard !visibleCalls.isEmpty || !visibleData.isEmpty else {
            emptyLabel.stringValue = "No direct flow was identified within the same file, try the reachability diagram if you want cross-file"
            emptyLabel.isHidden = false
            diagramView.clear()
            return
        }
        emptyLabel.isHidden = true

        diagramView.layoutCenterNode = centerName
        diagramView.display(
            graph: graph,
            callEdges: visibleCalls,
            dataEdges: visibleData,
            highlight: centerName
        )
    }
}

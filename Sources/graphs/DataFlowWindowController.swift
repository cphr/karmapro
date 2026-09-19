// by cipher.org.uk
import AppKit

/// Window that shows the animated dataflow diagram for a clicked function.
final class DataFlowWindowController: NSWindowController {
    private let diagramView = DataFlowDiagramView()
    private let titleLabel = NSTextField(labelWithString: "")
    private let captionLabel = NSTextField(wrappingLabelWithString: "")

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
            diagramView.trailingAnchor.constraint(equalTo: content.trailingAnchor)
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
        graph.pruneTo(defined: Set(defs.map { $0.name }))

        titleLabel.stringValue = "Dataflow around “\(functionName)”"
        captionLabel.stringValue = "Solid arrows: function calls · Animated dashed arrows: data flow"

        diagramView.display(
            graph: graph,
            callEdges: calls.filter { graph.hasNode($0.0) && graph.hasNode($0.1) },
            dataEdges: data.filter { graph.hasNode($0.0) && graph.hasNode($0.1) },
            highlight: graph.hasNode(functionName) ? functionName : graph.functionNames.first
        )
    }
}

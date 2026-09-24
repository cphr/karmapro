// by cipher.org.uk
import AppKit

/// Window that shows the project-wide reachability diagram for a function,
/// right-clicked from the source viewer. One combined diagram per search: the
/// full reverse caller chain up to the Remote / Local entry boxes (or an amber
/// "Topmost" terminal box when no entry point reaches the function), with the
/// functions it calls directly overlaid on the same canvas as grey boxes with
/// black text. While the project index is being built it shows a determinate
/// progress bar; closing the window at that point cancels the work so it does
/// not keep running in the background.
final class ReachabilityWindowController: NSWindowController {
    private let diagramView = DataFlowDiagramView()
    private let titleLabel = NSTextField(labelWithString: "")
    private let captionLabel = NSTextField(wrappingLabelWithString: "")
    private let progressBar = NSProgressIndicator()
    private let progressLabel = NSTextField(labelWithString: "")
    private let progressStack = NSStackView()

    /// Fired when a diagram node is clicked — opens the node's file/line.
    var onOpenLocation: ((URL, Int) -> Void)?

    /// Fired if the window is closed while a search is still running.
    var onCancel: (() -> Void)?

    /// True between `beginProgress` and the matching result display.
    private var isBusy = false

    private var nodeLocations: [String: (URL, Int)] = [:]

    convenience init() {
        let window = EscClosableWindow(
            contentRect: NSRect(x: 0, y: 0, width: 1000, height: 720),
            styleMask: [.titled, .closable, .resizable],
            backing: .buffered,
            defer: false
        )
        window.title = "Reachability"
        window.minSize = NSSize(width: 640, height: 420)
        self.init(window: window)
        buildContent()
    }

    /// Centers the window on screen whenever it is shown.
    override func showWindow(_ sender: Any?) {
        super.showWindow(sender)
        window?.center()
    }

    private func buildContent() {
        guard let content = window?.contentView else { return }
        window?.delegate = self

        titleLabel.font = NSFont.systemFont(ofSize: 16, weight: .semibold)
        titleLabel.textColor = .labelColor
        titleLabel.translatesAutoresizingMaskIntoConstraints = false
        content.addSubview(titleLabel)

        captionLabel.font = NSFont.systemFont(ofSize: 12)
        captionLabel.textColor = .secondaryLabelColor
        captionLabel.translatesAutoresizingMaskIntoConstraints = false
        content.addSubview(captionLabel)

        let controlRow = NSStackView()
        controlRow.orientation = .horizontal
        controlRow.alignment = .centerY
        controlRow.spacing = 12
        controlRow.translatesAutoresizingMaskIntoConstraints = false

        progressBar.style = .bar
        progressBar.isIndeterminate = false
        progressBar.minValue = 0
        progressBar.maxValue = 1
        progressBar.doubleValue = 0
        progressBar.controlSize = .small
        progressBar.setContentHuggingPriority(.defaultLow, for: .horizontal)

        progressLabel.font = NSFont.systemFont(ofSize: 11)
        progressLabel.textColor = .secondaryLabelColor
        progressLabel.lineBreakMode = .byTruncatingMiddle

        progressStack.orientation = .horizontal
        progressStack.alignment = .centerY
        progressStack.spacing = 8
        progressStack.isHidden = true
        progressBar.widthAnchor.constraint(equalToConstant: 180).isActive = true
        progressStack.addArrangedSubview(progressBar)
        progressStack.addArrangedSubview(progressLabel)
        content.addSubview(progressStack)

        controlRow.addArrangedSubview(NSView())
        controlRow.addArrangedSubview(progressStack)
        content.addSubview(controlRow)

        diagramView.translatesAutoresizingMaskIntoConstraints = false
        content.addSubview(diagramView)

        NSLayoutConstraint.activate([
            titleLabel.topAnchor.constraint(equalTo: content.topAnchor, constant: 16),
            titleLabel.leadingAnchor.constraint(equalTo: content.leadingAnchor, constant: 20),
            titleLabel.trailingAnchor.constraint(lessThanOrEqualTo: content.trailingAnchor, constant: -20),
            captionLabel.topAnchor.constraint(equalTo: titleLabel.bottomAnchor, constant: 4),
            captionLabel.leadingAnchor.constraint(equalTo: content.leadingAnchor, constant: 20),
            captionLabel.trailingAnchor.constraint(lessThanOrEqualTo: content.trailingAnchor, constant: -20),
            controlRow.topAnchor.constraint(equalTo: captionLabel.bottomAnchor, constant: 10),
            controlRow.leadingAnchor.constraint(equalTo: content.leadingAnchor, constant: 20),
            controlRow.trailingAnchor.constraint(equalTo: content.trailingAnchor, constant: -20),
            diagramView.topAnchor.constraint(equalTo: controlRow.bottomAnchor, constant: 12),
            diagramView.bottomAnchor.constraint(equalTo: content.bottomAnchor),
            diagramView.leadingAnchor.constraint(equalTo: content.leadingAnchor),
            diagramView.trailingAnchor.constraint(equalTo: content.trailingAnchor)
        ])

        diagramView.onNodeClick = { [weak self] name in
            guard let self = self, let loc = self.nodeLocations[name] else { return }
            self.onOpenLocation?(loc.0, loc.1)
        }
    }

    // MARK: - Progress

    /// Switches the window into its "searching" state and shows the progress bar.
    func beginProgress(functionName: String) {
        isBusy = true
        window?.title = "Reachability — \(functionName)"
        titleLabel.stringValue = "Reachability of “\(functionName)”"
        captionLabel.stringValue = "Building the project call graph…"
        progressBar.doubleValue = 0
        progressLabel.stringValue = "Enumerating source files…"
        progressStack.isHidden = false
        diagramView.clear()
    }

    /// Updates the determinate bar and the estimated time remaining.
    func updateProgress(done: Int, total: Int, startedAt: Date) {
        guard isBusy else { return }
        if total > 0 { progressBar.doubleValue = Double(done) / Double(total) }
        let elapsed = Date().timeIntervalSince(startedAt)
        let eta: String
        if done <= 0 {
            eta = "estimating time…"
        } else if done >= total {
            eta = "finishing…"
        } else {
            let remaining = elapsed * Double(total - done) / Double(done)
            eta = "about \(Self.format(seconds: remaining)) left"
        }
        progressLabel.stringValue = "Indexed \(done) of \(total) source files — \(eta)"
    }

    private static func format(seconds: Double) -> String {
        if seconds < 1 { return "1s" }
        if seconds < 60 { return "\(Int(seconds.rounded()))s" }
        let minutes = Int((seconds / 60).rounded())
        return "\(minutes) min"
    }

    // MARK: - Result

    /// Renders a finished reachability walk in this (reused) window.
    func display(result: ReachabilityResult,
                 graph: ProjectCallGraph,
                 fileURL: URL,
                 functionName: String) {
        isBusy = false
        progressStack.isHidden = true
        present(result: result)
    }

    private func present(result: ReachabilityResult) {
        window?.title = "Reachability — \(result.functionName)"

        guard !result.nodes.isEmpty else {
            titleLabel.stringValue = "No reachability data"
            captionLabel.stringValue = result.warnings.joined(separator: " ")
            diagramView.clear()
            nodeLocations = [:]
            return
        }

        let graph = CallGraph()
        var locations: [String: (URL, Int)] = [:]
        for node in result.nodes { _ = graph.node(for: node.displayName) }
        for node in result.nodes {
            locations[node.displayName] = (node.fileURL, node.line)
        }

        var edges = result.edges.filter { graph.hasNode($0.0) && graph.hasNode($0.1) }

        // Forward overlay: every node that is only in the callee closure is
        // drawn grey with black text on top of the reverse chain.
        diagramView.greyedNodeNames = Set(result.nodes.filter { $0.isForwardOverlay }.map { $0.displayName })

        // Origin boxes: Remote / Local when the reverse chain reaches an entry,
        // otherwise a single amber "Unverified" terminal box. Both are pinned to
        // rank 0 so the diagram reads top-down from the source.
        var sourceNodes = Set<String>()
        diagramView.layoutDirection = .topToBottom
        if result.unverified {
            sourceNodes.insert("Topmost")
            for node in result.nodes where node.isTopmost && !node.isForwardOverlay {
                graph.addCall(from: "Topmost", to: node.displayName)
                edges.insert(("Topmost", node.displayName), at: edges.startIndex)
            }
            diagramView.outlinedNodeNames = Set(result.nodes.filter { $0.isTopmost && !$0.isForwardOverlay }.map { $0.displayName })
            diagramView.originNodeColors = ["Topmost": .systemOrange]
        } else {
            var remoteInShow = false
            var localInShow = false
            for node in result.nodes {
                if node.entryKinds.contains(.remote) { remoteInShow = true }
                if node.entryKinds.contains(.local) { localInShow = true }
            }
            if remoteInShow { sourceNodes.insert("Remote") }
            if localInShow { sourceNodes.insert("Local") }
            for node in result.nodes {
                if node.entryKinds.contains(.remote), sourceNodes.contains("Remote") {
                    graph.addCall(from: "Remote", to: node.displayName)
                    edges.insert(("Remote", node.displayName), at: edges.startIndex)
                }
                if node.entryKinds.contains(.local), sourceNodes.contains("Local") {
                    graph.addCall(from: "Local", to: node.displayName)
                    edges.insert(("Local", node.displayName), at: edges.startIndex)
                }
            }
            diagramView.outlinedNodeNames = []
            diagramView.originNodeColors = [:]
        }

        for name in sourceNodes.sorted() { _ = graph.node(for: name) }
        diagramView.originNodeNames = sourceNodes
        diagramView.layoutSourceNodes = sourceNodes

        for e in edges { graph.addCall(from: e.0, to: e.1) }

        nodeLocations = locations
        diagramView.display(graph: graph,
                            callEdges: edges,
                            dataEdges: [],
                            highlight: result.nodes.first(where: { $0.isStart })?.displayName)

        titleLabel.stringValue = "Reachability of “\(result.functionName)”"

        let fileCount = Set(result.nodes.map { $0.fileURL.path }).count
        let base = "\(result.nodes.count) function\(result.nodes.count == 1 ? "" : "s") "
            + "across \(fileCount) file\(fileCount == 1 ? "" : "s"). "
            + "Click any node to open it."

        let note: String
        if result.unverified {
            note = "No path from any entry point in the project reaches “\(result.functionName)”. "
                + "The reverse chain dead-ends at the amber “Topmost” box — nothing else in the project calls those functions. "
        } else if result.remoteReachable && result.localReachable {
            note = "“\(result.functionName)” is reachable from both outside (Remote) and local (Local) entry points. "
        } else if result.remoteReachable {
            note = "“\(result.functionName)” is reachable from outside — the Remote box is a chain into it from an external entry point. "
        } else {
            note = "“\(result.functionName)” is reachable from a local entry point (main etc.) only — the Local box is the chain into it. "
        }
        let overlay = result.nodes.contains(where: { $0.isForwardOverlay })
            ? " Grey boxes are the functions it calls directly. "
            : ""
        var caption = note + base + overlay
        if !result.warnings.isEmpty {
            caption += "\n\nNote: " + result.warnings.joined(separator: " ")
        }
        captionLabel.stringValue = caption
    }
}

extension ReachabilityWindowController: NSWindowDelegate {
    func windowWillClose(_ notification: Notification) {
        guard isBusy else { return }
        isBusy = false
        onCancel?()
    }
}
// by cipher.org.uk
import AppKit

/// Window that shows the variable-flow diagram for a highlighted variable.
/// While the project index is being built it shows a determinate progress bar
/// with an estimated time remaining; closing the window at that point cancels
/// the search so it does not keep running in the background.
final class VariableFlowWindowController: NSWindowController {
    private let diagramView = VariableFlowDiagramView()
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

    convenience init() {
        let window = EscClosableWindow(
            contentRect: NSRect(x: 0, y: 0, width: 1000, height: 720),
            styleMask: [.titled, .closable, .resizable],
            backing: .buffered,
            defer: false
        )
        window.title = "Variable Flow"
        window.minSize = NSSize(width: 640, height: 420)
        self.init(window: window)
        buildContent()
    }

    /// Centers the flow window on screen whenever it is shown.
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

        progressBar.style = .bar
        progressBar.isIndeterminate = false
        progressBar.minValue = 0
        progressBar.maxValue = 1
        progressBar.doubleValue = 0
        progressBar.controlSize = .regular
        progressBar.setContentHuggingPriority(.defaultLow, for: .horizontal)

        progressLabel.font = NSFont.systemFont(ofSize: 11)
        progressLabel.textColor = .secondaryLabelColor
        progressLabel.lineBreakMode = .byTruncatingMiddle

        progressStack.orientation = .vertical
        progressStack.alignment = .leading
        progressStack.spacing = 4
        progressStack.isHidden = true
        progressStack.translatesAutoresizingMaskIntoConstraints = false
        progressStack.addArrangedSubview(progressBar)
        progressStack.addArrangedSubview(progressLabel)
        content.addSubview(progressStack)

        diagramView.translatesAutoresizingMaskIntoConstraints = false
        content.addSubview(diagramView)

        NSLayoutConstraint.activate([
            titleLabel.topAnchor.constraint(equalTo: content.topAnchor, constant: 16),
            titleLabel.leadingAnchor.constraint(equalTo: content.leadingAnchor, constant: 20),
            titleLabel.trailingAnchor.constraint(lessThanOrEqualTo: content.trailingAnchor, constant: -20),
            captionLabel.topAnchor.constraint(equalTo: titleLabel.bottomAnchor, constant: 4),
            captionLabel.leadingAnchor.constraint(equalTo: content.leadingAnchor, constant: 20),
            captionLabel.trailingAnchor.constraint(lessThanOrEqualTo: content.trailingAnchor, constant: -20),
            progressStack.topAnchor.constraint(equalTo: captionLabel.bottomAnchor, constant: 10),
            progressStack.leadingAnchor.constraint(equalTo: content.leadingAnchor, constant: 20),
            progressStack.trailingAnchor.constraint(equalTo: content.trailingAnchor, constant: -20),
            progressBar.widthAnchor.constraint(equalTo: progressStack.widthAnchor),
            diagramView.topAnchor.constraint(equalTo: progressStack.bottomAnchor, constant: 12),
            diagramView.bottomAnchor.constraint(equalTo: content.bottomAnchor),
            diagramView.leadingAnchor.constraint(equalTo: content.leadingAnchor),
            diagramView.trailingAnchor.constraint(equalTo: content.trailingAnchor)
        ])

        diagramView.onOpenLocation = { [weak self] url, line in
            guard let self = self else { return }
            self.onOpenLocation?(url, line)
        }
    }

    // MARK: - Progress

    /// Switches the window into its "searching" state and shows the progress bar.
    func beginProgress(variableName: String) {
        isBusy = true
        window?.title = "Variable Flow — \(variableName)"
        titleLabel.stringValue = "Flow of “\(variableName)”"
        captionLabel.stringValue = "Searching the project for “\(variableName)”…"
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

    /// Shows a new trace result in this window (reused across requests).
    func display(result: VariableFlowResult, variableName: String) {
        isBusy = false
        progressStack.isHidden = true
        window?.title = "Variable Flow — \(variableName)"

        guard !result.nodes.isEmpty else {
            titleLabel.stringValue = "No flow found for “\(variableName)”"
            captionLabel.stringValue = result.warnings.joined(separator: " ")
                .isEmpty ? "The variable was not found in the enclosing function." : result.warnings.joined(separator: " ")
            diagramView.display(result: result)
            return
        }

        titleLabel.stringValue = "Flow of “\(variableName)” in \(result.startFunction)"

        let calloutCount = result.edges.count
        let fileCount = Set(result.nodes.map { $0.fileURL.path }).count
        var caption = "Flowchart of the enclosing function; highlighted statements use “\(variableName)”. "
        caption += "\(calloutCount) call-out\(calloutCount == 1 ? "" : "s") "
            + "across \(fileCount) file\(fileCount == 1 ? "" : "s"). "
        caption += "Blue “call” arrows leave the call; purple “return” arrows rejoin the caller. "
            + "Click a statement or source line to open it."
        if !result.warnings.isEmpty {
            caption += "\n\nNote: " + result.warnings.joined(separator: " ")
        }
        captionLabel.stringValue = caption
        diagramView.display(result: result)
    }
}

extension VariableFlowWindowController: NSWindowDelegate {
    func windowWillClose(_ notification: Notification) {
        guard isBusy else { return }
        isBusy = false
        onCancel?()
    }
}

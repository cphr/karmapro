// by cipher.org.uk
import AppKit

/// A small, centered, modal-feeling window shown while the load-time project
/// index is being built. Titled "Building project's index", it reports the
/// file count and an estimated time remaining, and closes itself when the
/// build finishes or is cancelled.
final class IndexBuildWindowController: NSWindowController {
    private let progressBar = NSProgressIndicator()
    private let statusLabel = NSTextField(labelWithString: "")

    convenience init() {
        let window = NSWindow(
            contentRect: NSRect(x: 0, y: 0, width: 360, height: 96),
            styleMask: [.titled],
            backing: .buffered,
            defer: false
        )
        window.title = "Building project's index"
        window.isReleasedWhenClosed = false
        // Keep the modal visible above every other window until the index
        // build completes and closes it.
        window.level = .floating
        self.init(window: window)
        buildContent()
    }

    private func buildContent() {
        guard let content = window?.contentView else { return }

        progressBar.style = .bar
        progressBar.isIndeterminate = false
        progressBar.minValue = 0
        progressBar.maxValue = 1
        progressBar.doubleValue = 0
        progressBar.controlSize = .regular
        progressBar.translatesAutoresizingMaskIntoConstraints = false
        content.addSubview(progressBar)

        statusLabel.font = NSFont.systemFont(ofSize: 11)
        statusLabel.textColor = .secondaryLabelColor
        statusLabel.lineBreakMode = .byTruncatingMiddle
        statusLabel.translatesAutoresizingMaskIntoConstraints = false
        content.addSubview(statusLabel)

        NSLayoutConstraint.activate([
            progressBar.topAnchor.constraint(equalTo: content.topAnchor, constant: 20),
            progressBar.leadingAnchor.constraint(equalTo: content.leadingAnchor, constant: 20),
            progressBar.trailingAnchor.constraint(equalTo: content.trailingAnchor, constant: -20),

            statusLabel.topAnchor.constraint(equalTo: progressBar.bottomAnchor, constant: 8),
            statusLabel.leadingAnchor.constraint(equalTo: content.leadingAnchor, constant: 20),
            statusLabel.trailingAnchor.constraint(equalTo: content.trailingAnchor, constant: -20)
        ])
    }

    func begin(parent: NSWindow?, projectName: String) {
        guard let window = window else { return }
        window.title = "Building project's index"
        statusLabel.stringValue = "Indexing \(projectName)…"
        progressBar.doubleValue = 0

        if let parent = parent, parent.isVisible {
            let pf = parent.frame
            let size = window.frame.size
            let x = pf.midX - size.width / 2
            let y = pf.midY - size.height / 2
            window.setFrameOrigin(NSPoint(x: x, y: y))
        } else {
            window.center()
        }
        showWindow(nil)
        window.makeKeyAndOrderFront(nil)
    }

    func update(done: Int, total: Int, startedAt: Date) {
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
        statusLabel.stringValue = "Indexed \(done) of \(total) source files — \(eta)"
    }

    private static func format(seconds: Double) -> String {
        if seconds < 1 { return "1s" }
        if seconds < 60 { return "\(Int(seconds.rounded()))s" }
        return "\(Int((seconds / 60).rounded())) min"
    }

    func end() {
        close()
    }
}
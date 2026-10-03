// by cipher.org.uk
import AppKit

/// The small "Preparing review…" window shown while a pull request is fetched.
///
/// This replaces an NSAlert with a determinate bar in its accessory view, which
/// put the pull request's own title, the progress bar and the stage text into a
/// box that sized itself around the title. A long title therefore grew the box
/// downward through the bar and the two overlapped, and no amount of label
/// trimming fixed it: the accessory view is measured against a dialog whose
/// height had already been decided from the message text.
///
/// Nothing here depends on the length of a string. Every row has a fixed height,
/// the rows form one column chained from the top edge, and the window is sized
/// from those same constants, so the bar has a row to itself with clear space
/// above and below it and no two rows can ever occupy the same pixels. Titles are
/// shortened in code as well, purely so the text that does fit reads sensibly.
final class PRProgressPanelController {
    private enum Metrics {
        static let width: CGFloat = 440
        static let inset: CGFloat = 20
        static let topInset: CGFloat = 18
        static let titleHeight: CGFloat = 18
        static let titleGap: CGFloat = 3
        static let repoHeight: CGFloat = 15
        static let repoGap: CGFloat = 14
        static let barHeight: CGFloat = 12
        static let barGap: CGFloat = 10
        static let stageHeight: CGFloat = 15
        static let stageGap: CGFloat = 16
        static let cancelHeight: CGFloat = 24
        static let bottomInset: CGFloat = 18

        static let contentWidth = width - inset * 2
        /// The window is this tall because these rows stack to exactly this, not
        /// by a guess: change a height above and the window follows.
        static let total: CGFloat = topInset + titleHeight + titleGap + repoHeight
            + repoGap + barHeight + barGap + stageHeight + stageGap
            + cancelHeight + bottomInset
    }

    let window: PRProgressPanel
    private let bar = NSProgressIndicator()
    private let stage = NSTextField(labelWithString: "Starting\u{2026}")
    private var onCancel: (() -> Void)?
    private weak var sheetParent: NSWindow?

    /// Set once the user has asked to stop, so a late completion cannot reopen
    /// the review behind a window they already dismissed.
    private var cancelled = false

    init(for item: PRActionItem) {
        let title = NSTextField(labelWithString: "#\(item.pr.number) "
            + item.pr.title.shortened(to: 72))
        title.font = .systemFont(ofSize: 13, weight: .semibold)
        title.textColor = .labelColor

        let repo = NSTextField(labelWithString: "\(item.repo.repoSlug)  \u{00B7}  "
            + "\(item.pr.headBranch.shortened(to: 28)) \u{2192} \(item.pr.baseBranch)")
        repo.font = .systemFont(ofSize: 11)
        repo.textColor = .secondaryLabelColor

        bar.style = .bar
        bar.isIndeterminate = false
        bar.minValue = 0
        bar.maxValue = 1
        bar.doubleValue = 0.02
        bar.controlSize = .small

        stage.font = .systemFont(ofSize: 11)
        stage.textColor = .secondaryLabelColor

        // Single line, truncate the tail, and never let the label ask for more
        // room than the row it is in.
        for label in [title, repo, stage] {
            label.lineBreakMode = .byTruncatingTail
            label.usesSingleLineMode = true
            label.cell?.wraps = false
            label.setContentHuggingPriority(.defaultLow, for: .vertical)
            label.setContentCompressionResistancePriority(.defaultLow, for: .vertical)
        }

        let cancel = NSButton(title: "Cancel", target: nil, action: nil)
        cancel.bezelStyle = .rounded

        for view in [title, repo, bar, stage, cancel] as [NSView] {
            view.translatesAutoresizingMaskIntoConstraints = false
        }

        let content = NSView(frame: NSRect(origin: .zero,
                                            size: NSSize(width: Metrics.width, height: Metrics.total)))
        for view in [title, repo, bar, stage, cancel] as [NSView] {
            content.addSubview(view)
        }

        NSLayoutConstraint.activate([
            title.topAnchor.constraint(equalTo: content.topAnchor, constant: Metrics.topInset),
            title.leadingAnchor.constraint(equalTo: content.leadingAnchor, constant: Metrics.inset),
            title.widthAnchor.constraint(equalToConstant: Metrics.contentWidth),
            title.heightAnchor.constraint(equalToConstant: Metrics.titleHeight),

            repo.topAnchor.constraint(equalTo: title.bottomAnchor, constant: Metrics.titleGap),
            repo.leadingAnchor.constraint(equalTo: title.leadingAnchor),
            repo.widthAnchor.constraint(equalToConstant: Metrics.contentWidth),
            repo.heightAnchor.constraint(equalToConstant: Metrics.repoHeight),

            // The bar's own row, with clear space on both sides so it cannot touch
            // the text above or below it.
            bar.topAnchor.constraint(equalTo: repo.bottomAnchor, constant: Metrics.repoGap),
            bar.leadingAnchor.constraint(equalTo: title.leadingAnchor),
            bar.widthAnchor.constraint(equalToConstant: Metrics.contentWidth),
            bar.heightAnchor.constraint(equalToConstant: Metrics.barHeight),

            stage.topAnchor.constraint(equalTo: bar.bottomAnchor, constant: Metrics.barGap),
            stage.leadingAnchor.constraint(equalTo: title.leadingAnchor),
            stage.widthAnchor.constraint(equalToConstant: Metrics.contentWidth),
            stage.heightAnchor.constraint(equalToConstant: Metrics.stageHeight),

            cancel.topAnchor.constraint(equalTo: stage.bottomAnchor, constant: Metrics.stageGap),
            cancel.trailingAnchor.constraint(equalTo: content.trailingAnchor, constant: -Metrics.inset),
            cancel.heightAnchor.constraint(equalToConstant: Metrics.cancelHeight),
            cancel.widthAnchor.constraint(greaterThanOrEqualToConstant: 84),
            cancel.bottomAnchor.constraint(equalTo: content.bottomAnchor, constant: -Metrics.bottomInset)
        ])

        window = PRProgressPanel(contentRect: content.frame,
                                 styleMask: [.titled],
                                 backing: .buffered,
                                 defer: false)
        window.title = "Preparing review"
        window.contentView = content
        window.isReleasedWhenClosed = false
        // No close button: the only ways out are Cancel or Escape, both of which
        // mean the same thing.
        window.standardWindowButton(.closeButton)?.isHidden = true
        window.standardWindowButton(.zoomButton)?.isHidden = true
        window.standardWindowButton(.miniaturizeButton)?.isHidden = true
        window.center()

        cancel.target = self
        cancel.action = #selector(cancelTapped)
        // Escape reaches the same place as the button.
        window.onCancel = { [weak self] in self?.dismissedByUser() }
    }

    /// Called once, from the background fetch, for each step.
    func update(fraction: Double, stage text: String) {
        bar.doubleValue = max(0, min(1, fraction))
        stage.stringValue = text
    }

    /// Shows the window in front of the main window, whatever brought us here.
    ///
    /// A Review usually starts from a notification, which does not activate the
    /// app, so the main window can be behind whatever the user is looking at and
    /// simply attaching a sheet to a window nobody can see looks like nothing
    /// opened. The app is activated and the main window is brought forward
    /// first.
    ///
    /// The window is then attached as a *child* of the main window. A child
    /// window is always drawn above its parent and moves with it, so the
    /// progress window cannot end up behind the window it belongs to.
    ///
    /// The direction of that relationship matters and is easy to invert:
    /// `addChildWindow(_:ordered:)` names the *child* as its argument, so
    /// `panel.addChildWindow(mainWindow)` registers the main window as the
    /// panel's child. That raises the main window to the panel's level and ties
    /// its ordering to a transient panel, and the app then behaves as though
    /// the main window is permanently on top of every dialog. The main window
    /// is the parent here and the progress window is the child.
    func present(over parent: NSWindow?, onCancel handler: @escaping () -> Void) {
        onCancel = handler
        cancelled = false
        NSApp.activate(ignoringOtherApps: true)
        if let parent = parent {
            parent.makeKeyAndOrderFront(nil)
            if parent.isVisible {
                sheetParent = parent
                parent.addChildWindow(window, ordered: .above)
            }
        }
        window.makeKeyAndOrderFront(nil)
    }

    /// Takes the window away and stops caring about the outcome, so a completion
    /// that arrives after a cancel cannot put the review back on screen.
    func dismiss(cancelledByUser: Bool) {
        cancelled = cancelled || cancelledByUser
        onCancel = nil
        if let parent = sheetParent {
            parent.removeChildWindow(window)
        }
        window.orderOut(nil)
        sheetParent = nil
    }

    var wasCancelled: Bool { cancelled }

    @objc private func cancelTapped() {
        guard !cancelled else { return }
        dismissedByUser()
    }

    private func dismissedByUser() {
        cancelled = true
        let handler = onCancel
        onCancel = nil
        dismiss(cancelledByUser: true)
        handler?()
    }
}

/// Escape cancels, rather than closing the window and leaving the download
/// running with nothing on screen to say so.
final class PRProgressPanel: NSPanel {
    /// Set by the controller; Escape and the Cancel button share one path.
    var onCancel: (() -> Void)?

    override func cancelOperation(_ sender: Any?) {
        onCancel?()
    }
}

extension String {
    /// Cuts a long string to a fixed length with an ellipsis, so a window whose
    /// rows are all a fixed height can be given text it can actually fit.
    func shortened(to limit: Int) -> String {
        count <= limit ? self : String(prefix(limit - 1)) + "\u{2026}"
    }
}

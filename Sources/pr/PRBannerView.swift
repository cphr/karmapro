// by cipher.org.uk
import AppKit

/// The strip shown at the top of the main window while a pull request review is
/// open.
///
/// Its job is to remove ambiguity: without it, a filtered tree looks exactly
/// like a normal project and the user could easily review three files and
/// believe they had reviewed the change. It states which PR is open, how many
/// files it touches, and offers the two actions that belong to review mode
/// (run the scan, produce the report) alongside the way out.
final class PRBannerView: NSView {
    var onReview: (() -> Void)?
    var onShowReport: (() -> Void)?
    var onShowAll: (() -> Void)?
    var onShowChanges: (() -> Void)?
    var onClose: (() -> Void)?

    /// Row height. Named so the window that places the banner and the banner
    /// itself cannot disagree about it.
    static let height: CGFloat = 56

    private let titleLabel = NSTextField(labelWithString: "")
    private let subtitleLabel = NSTextField(labelWithString: "")
    private var showAllButton: NSButton?

    override init(frame frameRect: NSRect) {
        super.init(frame: frameRect)
        build()
    }

    required init?(coder: NSCoder) {
        super.init(coder: coder)
        build()
    }

    private func build() {
        wantsLayer = true
        // The banner's whole purpose is to be noticed, and a strip painted in
        // the window background colour is invisible. It gets the control
        // background plus a rule underneath, and every label an explicit
        // colour: the defaults track the window background, which is what made
        // the text look absent rather than faint.
        layer?.backgroundColor = NSColor.controlBackgroundColor.cgColor
        layer?.borderColor = NSColor.separatorColor.cgColor
        layer?.borderWidth = 1

        // A short accent-coloured edge, so the strip cannot be mistaken for part
        // of the file tree even when the window is narrow.
        let edge = NSView()
        edge.wantsLayer = true
        edge.layer?.backgroundColor = NSColor.controlAccentColor.cgColor
        edge.translatesAutoresizingMaskIntoConstraints = false
        addSubview(edge)
        NSLayoutConstraint.activate([
            edge.leadingAnchor.constraint(equalTo: leadingAnchor),
            edge.topAnchor.constraint(equalTo: topAnchor),
            edge.bottomAnchor.constraint(equalTo: bottomAnchor),
            edge.widthAnchor.constraint(equalToConstant: 3)
        ])

        titleLabel.font = .systemFont(ofSize: 13, weight: .semibold)
        titleLabel.setContentCompressionResistancePriority(.required, for: .vertical)
        titleLabel.textColor = .labelColor
        subtitleLabel.font = .systemFont(ofSize: 11)
        subtitleLabel.setContentCompressionResistancePriority(.defaultLow, for: .horizontal)
        subtitleLabel.textColor = .labelColor
        // The labels are the only thing in the banner allowed to lose width.
        //
        // They truncate rather than wrap, and they are given *low* compression
        // resistance on purpose: the action buttons are the part of this strip
        // the user has to be able to reach, so when the window is narrow the
        // pull request identification yields and the buttons keep their real
        // sizes. The opposite trade was in place here, which pushed the last
        // button off the right edge of a ~700pt window instead of shortening
        // the PR title.
        for label in [titleLabel, subtitleLabel] {
            label.lineBreakMode = .byTruncatingTail
            label.setContentHuggingPriority(.defaultHigh, for: .horizontal)
            label.setContentCompressionResistancePriority(.defaultLow, for: .horizontal)
        }

        let icon = NSImageView()
        icon.image = NSImage(systemSymbolName: "arrow.triangle.pull", accessibilityDescription: nil)
        icon.contentTintColor = .controlAccentColor

        // Named for what it does: this button runs the vulnerability scan, the
        // same scan the Security Scanner button runs, and not a separate "review"
        // pass the user has to learn.
        let scanButton = makeButton("Run a Scan", action: #selector(reviewTapped))
        let reportButton = makeButton("Report…", action: #selector(reportTapped))
        let changesButton = makeButton("Show Changes\u{2026}", action: #selector(changesTapped))
        let showAllButton = makeButton("Show All Files", action: #selector(showAllTapped))
        let closeButton = makeButton("Close Review", action: #selector(closeTapped))
        showAllButton.isHidden = true
        self.showAllButton = showAllButton

        // Actions last and pinned to the trailing edge, so the buttons read as
        // one group and the pull request identification never pushes them out
        // of view.
        let spacer = NSView()
        spacer.setContentHuggingPriority(.defaultLow, for: .horizontal)
        spacer.setContentCompressionResistancePriority(.defaultLow, for: .horizontal)
        let actions = NSStackView(views: [scanButton, changesButton, reportButton,
                                          showAllButton, closeButton])
        actions.orientation = .horizontal
        actions.spacing = 8
        // The group as a whole is what must never be squeezed, otherwise the
        // individual buttons keep their widths and overlap each other instead
        // of the title being shortened to make room.
        actions.setContentHuggingPriority(.required, for: .horizontal)
        actions.setContentCompressionResistancePriority(.required, for: .horizontal)
        for button in [scanButton, changesButton, reportButton, showAllButton, closeButton] {
            button.setContentHuggingPriority(.required, for: .horizontal)
            button.setContentCompressionResistancePriority(.required, for: .horizontal)
        }

        let stack = NSStackView(views: [icon, titleLabel, subtitleLabel, spacer, actions])
        stack.orientation = .horizontal
        stack.spacing = 10
        stack.alignment = .centerY
        stack.translatesAutoresizingMaskIntoConstraints = false
        addSubview(stack)

        NSLayoutConstraint.activate([
            icon.widthAnchor.constraint(equalToConstant: 18),
            icon.heightAnchor.constraint(equalToConstant: 18),
            stack.leadingAnchor.constraint(equalTo: leadingAnchor, constant: 16),
            stack.trailingAnchor.constraint(equalTo: trailingAnchor, constant: -12),
            stack.centerYAnchor.constraint(equalTo: centerYAnchor)
        ])
    }

    private func makeButton(_ title: String, action: Selector?) -> NSButton {
        let button = NSButton(title: title, target: action == nil ? nil : self, action: action)
        button.bezelStyle = .rounded
        button.controlSize = .regular
        button.font = .systemFont(ofSize: 11, weight: .medium)
        return button
    }

    func configure(title: String, subtitle: String, detail: String) {
        titleLabel.stringValue = title
        titleLabel.toolTip = detail
        subtitleLabel.stringValue = subtitle
        subtitleLabel.toolTip = detail
    }

    /// Whether the "Show All Files" toggle is offered. It stays hidden while the
    /// tree is already showing everything, so it is never a dead control.
    func setShowAllAvailable(_ available: Bool) {
        showAllButton?.isHidden = !available
        needsLayout = true
    }

    /// Width below which the subtitle is dropped rather than truncated to
    /// nothing. Below it the pull request title and the actions are what the
    /// user needs, and two clipped fragments are worse than one legible line.
    private static let subtitleMinimumWidth: CGFloat = 900

    override func layout() {
        super.layout()
        let roomForSubtitle = bounds.width >= PRBannerView.subtitleMinimumWidth
        if subtitleLabel.isHidden == roomForSubtitle {
            subtitleLabel.isHidden = !roomForSubtitle
        }
    }

    @objc private func reviewTapped() { onReview?() }
    @objc private func reportTapped() { onShowReport?() }
    @objc private func showAllTapped() { onShowAll?() }
    @objc private func changesTapped() { onShowChanges?() }
    @objc private func closeTapped() { onClose?() }
}
// by cipher.org.uk
import AppKit

/// Settings window, opened from the app menu. Currently hosts the MCP service
/// controls: start/stop, the endpoint to copy into a client, and the AI switch.
final class MCPSettingsWindowController: NSWindowController {
    private let service = MCPService.shared

    private let statusDot = NSView()
    private let statusLabel = NSTextField(labelWithString: "")
    private let urlField = NSTextField(labelWithString: "")
    private let statsLabel = NSTextField(labelWithString: "")
    private let errorLabel = NSTextField(labelWithString: "")
    private let startStopButton = NSButton(title: "Start Service", target: nil, action: nil)
    private let configView = NSTextView()
    private let allowAICheck = NSButton(checkboxWithTitle:
        "Allow AI scans over MCP (uses the selected provider and may cost money)",
        target: nil, action: nil)
    private let autoStartCheck = NSButton(checkboxWithTitle:
        "Start the service when Karma Pro launches", target: nil, action: nil)

    convenience init() {
        let window = EscClosableWindow(
            contentRect: NSRect(x: 0, y: 0, width: 680, height: 660),
            styleMask: [.titled, .closable, .miniaturizable, .resizable],
            backing: .buffered,
            defer: false)
        window.title = "Settings"
        window.minSize = NSSize(width: 620, height: 560)
        window.center()
        self.init(window: window)
        buildUI()
        service.onChange = { [weak self] in self?.refresh() }
        refresh()
    }

    override func showWindow(_ sender: Any?) {
        refresh()
        super.showWindow(sender)
        NSApp.activate(ignoringOtherApps: true)
    }

    // MARK: - UI

    private func buildUI() {
        guard let content = window?.contentView else { return }

        let title = NSTextField(labelWithString: "MCP Service")
        title.font = .systemFont(ofSize: 15, weight: .semibold)

        let intro = Self.wrappingLabel(
            "Connects Karma Pro's scanner to an MCP client, which can request a vulnerability "
            + "scan of a directory and read the results as SARIF 2.1.0. The service listens on "
            + "this Mac only and runs while Karma Pro is open.")
        intro.textColor = .secondaryLabelColor

        statusDot.wantsLayer = true
        statusDot.layer?.cornerRadius = 4
        statusDot.translatesAutoresizingMaskIntoConstraints = false
        statusDot.widthAnchor.constraint(equalToConstant: 8).isActive = true
        statusDot.heightAnchor.constraint(equalToConstant: 8).isActive = true

        statusLabel.font = .systemFont(ofSize: 12, weight: .medium)
        let statusRow = NSStackView(views: [statusDot, statusLabel])
        statusRow.orientation = .horizontal
        statusRow.alignment = .centerY
        statusRow.spacing = 8

        urlField.font = NSFont.monospacedSystemFont(ofSize: 11, weight: .regular)
        urlField.lineBreakMode = .byTruncatingMiddle
        urlField.isSelectable = true
        urlField.maximumNumberOfLines = 1

        startStopButton.target = self
        startStopButton.action = #selector(toggleService)
        startStopButton.bezelStyle = .rounded
        startStopButton.keyEquivalent = "\r"

        let copyURL = NSButton(title: "Copy URL", target: self, action: #selector(copyURL))
        let copyConfig = NSButton(title: "Copy Client Config",
                                  target: self, action: #selector(copyConfig))
        let rotate = NSButton(title: "New Token", target: self, action: #selector(rotateToken))
        for button in [copyURL, copyConfig, rotate] { button.bezelStyle = .rounded }

        let buttons = NSStackView(views: [startStopButton, copyURL, copyConfig, rotate])
        buttons.orientation = .horizontal
        buttons.spacing = 8

        allowAICheck.target = self
        allowAICheck.action = #selector(toggleAI)
        allowAICheck.state = service.allowAI ? .on : .off

        autoStartCheck.target = self
        autoStartCheck.action = #selector(toggleAutoStart)
        autoStartCheck.state = service.autoStart ? .on : .off

        let configTitle = NSTextField(labelWithString: "Client configuration")
        configTitle.font = .systemFont(ofSize: 12, weight: .semibold)

        let configHint = Self.wrappingLabel(
            "Paste this into the MCP server settings of your client, then restart it. "
            + "The token is part of the URL, so treat it like a password.")
        configHint.textColor = .secondaryLabelColor
        configHint.font = .systemFont(ofSize: 11)

        let configScroll = NSScrollView()
        configScroll.translatesAutoresizingMaskIntoConstraints = false
        configScroll.hasVerticalScroller = true
        configScroll.borderType = .bezelBorder
        configScroll.documentView = configView
        configScroll.heightAnchor.constraint(equalToConstant: 118).isActive = true

        configView.isEditable = false
        configView.isSelectable = true
        configView.drawsBackground = true
        configView.font = NSFont.monospacedSystemFont(ofSize: 11, weight: .regular)
        configView.textContainerInset = NSSize(width: 8, height: 8)
        configView.minSize = NSSize(width: 0, height: 0)
        configView.maxSize = NSSize(width: CGFloat.greatestFiniteMagnitude,
                                    height: CGFloat.greatestFiniteMagnitude)
        configView.isVerticallyResizable = true
        configView.isHorizontallyResizable = false
        configView.autoresizingMask = [.width]
        configView.textContainer?.widthTracksTextView = true

        statsLabel.font = .systemFont(ofSize: 11)
        statsLabel.textColor = .secondaryLabelColor

        errorLabel.font = .systemFont(ofSize: 11)
        errorLabel.textColor = .systemRed
        errorLabel.isHidden = true
        errorLabel.maximumNumberOfLines = 2

        let footer = Self.wrappingLabel(
            "Scans run one at a time so the AI worker pool (1 for a local server, 3 for a hosted "
            + "provider) is never doubled. Quitting Karma Pro stops the service and cancels "
            + "running scans.")
        footer.textColor = .tertiaryLabelColor
        footer.font = .systemFont(ofSize: 11)

        let stack = NSStackView(views: [
            title, intro, statusRow, urlField, buttons,
            Self.separator(), allowAICheck, autoStartCheck,
            configTitle, configHint, configScroll,
            Self.separator(), statsLabel, errorLabel, footer
        ])
        stack.orientation = .vertical
        stack.alignment = .leading
        stack.spacing = 10
        stack.setCustomSpacing(4, after: title)
        stack.setCustomSpacing(14, after: buttons)
        stack.setCustomSpacing(6, after: configTitle)
        stack.setCustomSpacing(6, after: configHint)
        stack.translatesAutoresizingMaskIntoConstraints = false
        content.addSubview(stack)

        // A separator has no intrinsic width, so it must follow the stack.
        for box in stack.arrangedSubviews.compactMap({ $0 as? NSBox }) {
            box.widthAnchor.constraint(equalTo: stack.widthAnchor).isActive = true
        }

        NSLayoutConstraint.activate([
            stack.topAnchor.constraint(equalTo: content.topAnchor, constant: 20),
            stack.leadingAnchor.constraint(equalTo: content.leadingAnchor, constant: 20),
            stack.trailingAnchor.constraint(equalTo: content.trailingAnchor, constant: -20),
            stack.bottomAnchor.constraint(lessThanOrEqualTo: content.bottomAnchor, constant: -20),
            urlField.widthAnchor.constraint(equalTo: stack.widthAnchor),
            configScroll.widthAnchor.constraint(equalTo: stack.widthAnchor),
            intro.widthAnchor.constraint(equalTo: stack.widthAnchor),
            configHint.widthAnchor.constraint(equalTo: stack.widthAnchor),
            footer.widthAnchor.constraint(equalTo: stack.widthAnchor),
            statsLabel.widthAnchor.constraint(equalTo: stack.widthAnchor),
            errorLabel.widthAnchor.constraint(equalTo: stack.widthAnchor)
        ])
    }

    private static func wrappingLabel(_ text: String) -> NSTextField {
        let label = NSTextField(wrappingLabelWithString: text)
        label.font = .systemFont(ofSize: 12)
        label.isSelectable = false
        return label
    }

    private static func separator() -> NSBox {
        let box = NSBox()
        box.boxType = .separator
        box.translatesAutoresizingMaskIntoConstraints = false
        box.heightAnchor.constraint(equalToConstant: 1).isActive = true
        return box
    }

    // MARK: - State

    private func refresh() {
        let running = service.isRunning
        statusLabel.stringValue = running
            ? "Running on 127.0.0.1:\(service.port)"
            : "Stopped"
        statusDot.wantsLayer = true
        statusDot.layer?.backgroundColor = running
            ? NSColor.systemGreen.cgColor
            : NSColor.tertiaryLabelColor.cgColor
        startStopButton.title = running ? "Stop Service" : "Start Service"
        urlField.stringValue = service.url
        configView.string = service.clientConfig
        allowAICheck.state = service.allowAI ? .on : .off
        autoStartCheck.state = service.autoStart ? .on : .off

        var stats = "\(service.scanCount) scan\(service.scanCount == 1 ? "" : "s") served this session"
        if let started = service.startedAt {
            let minutes = Int(Date().timeIntervalSince(started) / 60)
            stats += " · up \(minutes) min"
        }
        statsLabel.stringValue = stats
        errorLabel.stringValue = service.lastError ?? ""
        errorLabel.isHidden = (service.lastError ?? "").isEmpty
    }

    // MARK: - Actions

    @objc private func toggleService() {
        service.toggle()
        refresh()
    }

    @objc private func toggleAI() {
        service.allowAI = allowAICheck.state == .on
        refresh()
    }

    @objc private func toggleAutoStart() {
        service.autoStart = autoStartCheck.state == .on
        refresh()
    }

    @objc private func copyURL() {
        Self.copyToPasteboard(service.url)
    }

    @objc private func copyConfig() {
        Self.copyToPasteboard(service.clientConfig)
    }

    @objc private func rotateToken() {
        let alert = NSAlert()
        alert.messageText = "Generate a new token?"
        alert.informativeText = "The current URL stops working and every client must be updated."
        alert.addButton(withTitle: "New Token")
        alert.addButton(withTitle: "Cancel")
        guard let window else { return }
        alert.beginSheetModal(for: window) { [weak self] response in
            guard response == .alertFirstButtonReturn else { return }
            self?.service.rotateToken()
            self?.refresh()
        }
    }

    private static func copyToPasteboard(_ text: String) {
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(text, forType: .string)
    }
}

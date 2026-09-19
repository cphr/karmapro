// by cipher.org.uk
import AppKit
import UniformTypeIdentifiers

/// The AI Assistant window: connects to an OpenAI-compatible provider chosen
/// from a dropdown — the OpenRouter cloud API with a user-provided API key,
/// or a local Ollama server via an editable, remembered server field (no key
/// needed) — lets the user pick a model, and sends prompts about the project
/// currently open in Karma Pro. Prompts share one conversation for the session,
/// so follow-ups and the Continue button (used after Stop or a network
/// failure) keep the full context; "New Chat" starts over. A dropdown offers
/// reusable prompt templates (shipped + user-defined); selecting one pastes
/// its text into the prompt editor. Templates can be added, edited, and
/// removed from this window.
final class AIWindowController: NSWindowController {
    private let promptPopup = NSPopUpButton(frame: .zero, pullsDown: false)
    private let promptScrollView = NSScrollView()
    private let promptTextView = NSTextView()
    private let responseScrollView = NSScrollView()
    private let responseTextView = NSTextView()
    private let modelPopup = NSPopUpButton(frame: .zero, pullsDown: false)
    private let refreshModelsButton = NSButton(title: "Refresh", target: nil, action: nil)
    private let apiKeyField = NSSecureTextField()
    private let providerPopup = NSPopUpButton()
    private let serverField = NSTextField()
    private let connectButton = NSButton(title: "Connect", target: nil, action: nil)
    private var keyLabel: NSTextField!
    private var connectLabel: NSTextField!
    /// Bottom-bar constraints for the currently shown provider; the other
    /// provider's set is deactivated while this one is active.
    private var providerBarConstraints: [NSLayoutConstraint] = []
    private let sendButton = NSButton(title: "Send to AI", target: nil, action: nil)
    private let continueButton = NSButton(title: "Continue", target: nil, action: nil)
    private let newChatButton = NSButton(title: "New Chat", target: nil, action: nil)
    private let spinner = NSProgressIndicator()
    /// Thinking indicator overlaid on the response pane while the model is
    /// reasoning: a rotating spinner next to a "Thinking…" label (the actual
    /// reasoning text is deliberately not shown).
    private let thinkingSpinner = NSProgressIndicator()
    private let thinkingLabel = NSTextField(wrappingLabelWithString: "Thinking…")
    private let addPromptButton = NSButton(title: "Add…", target: nil, action: nil)
    private let editPromptButton = NSButton(title: "Edit…", target: nil, action: nil)
    private let removePromptButton = NSButton(title: "Remove", target: nil, action: nil)
    private let exportPromptsButton = NSButton(title: "Export…", target: nil, action: nil)
    private let importPromptsButton = NSButton(title: "Import…", target: nil, action: nil)
    private let privacyNoticeButton = NSButton(title: "", target: nil, action: nil)
    private let statusLabel = NSTextField(wrappingLabelWithString: "")

    /// The project currently open in the main window; its path is included as
    /// context with every request.
    var projectRootURL: URL?

    private var selectedPromptID: String?
    private var requestInFlight = false
    /// Set when the user cancels via Stop, so the completion message can say
    /// the response was truncated on purpose.
    private var cancelRequested = false
    /// True after the non-streaming fallback has been attempted once.
    private var usedFallback = false
    /// Assembled streaming response text while tokens arrive.
    private var streamAccumulated = ""
    /// True while the model emits reasoning deltas before its answer; the
    /// reasoning text itself is discarded and only a thinking indicator is shown.
    private var modelIsThinking = false
    /// Coalesced re-render of the streaming pane. Tokens can arrive faster than
    /// the screen can repaint; rendering on every single token rebuilds the
    /// entire attributed string and re-scrolls, which makes the terminal look
    /// jerky once the text overflows the pane. Batching into a ~30 fps tick
    /// keeps the display updating in smooth, even steps.
    private var streamRenderDirty = false
    private var streamRenderTick: DispatchWorkItem?
    /// Agent state: conversation history for tool-calling rounds. Persists
    /// across prompts in this session — follow-up prompts and Continue keep
    /// the full context; "New Chat" clears it.
    private var conversation: [[String: Any]] = []
    private var toolRound = 0

    /// One chronological item of the response transcript shown in the pane.
    private enum TranscriptEntry {
        case turnMarker(String)
        case tool(name: String, args: String, output: String)
        case answer(String)
    }
    private var transcript: [TranscriptEntry] = []
    /// True when the last task ended interrupted (Stop or a network failure)
    /// with its context still in `conversation`, so Continue can resume it.
    private var lastTaskInterrupted = false

    // Terminal look for the response pane (Terminal.app-like).
    private let terminalBackground = NSColor(red: 0.07, green: 0.08, blue: 0.09, alpha: 1)
    private let terminalForeground = NSColor(red: 0.80, green: 0.86, blue: 0.77, alpha: 1)
    private let terminalDim = NSColor(red: 0.45, green: 0.48, blue: 0.45, alpha: 1)
    private let terminalCodeBackground = NSColor(red: 0.13, green: 0.15, blue: 0.14, alpha: 1)
    private let terminalAccent = NSColor(red: 0.45, green: 0.85, blue: 0.55, alpha: 1)

    convenience init() {
        let window = EscClosableWindow(
            contentRect: NSRect(x: 0, y: 0, width: 880, height: 680),
            styleMask: [.titled, .closable, .resizable, .miniaturizable],
            backing: .buffered,
            defer: false
        )
        window.title = "AI Assistant"
        window.isRestorable = false
        window.minSize = NSSize(width: 720, height: 520)
        self.init(window: window)
        buildContent()
        reloadPromptPopup()
        loadSettings()
        refreshModelList()
    }

    override func showWindow(_ sender: Any?) {
        window?.center()
        window?.delegate = self
        super.showWindow(sender)
    }

    // MARK: - UI construction

    private func buildContent() {
        guard let content = window?.contentView else { return }

        let templatesLabel = NSTextField(labelWithString: "Prompt Templates:")
        templatesLabel.font = NSFont.systemFont(ofSize: 12)
        templatesLabel.translatesAutoresizingMaskIntoConstraints = false
        content.addSubview(templatesLabel)

        promptPopup.target = self
        promptPopup.action = #selector(promptSelected(_:))
        promptPopup.toolTip = "Pick a saved prompt template — its text is pasted into the prompt editor"
        promptPopup.translatesAutoresizingMaskIntoConstraints = false
        promptPopup.setContentCompressionResistancePriority(.defaultLow, for: .horizontal)
        content.addSubview(promptPopup)

        for (button, tip, selector) in [
            (addPromptButton, "Create a new prompt template", #selector(addPromptClicked(_:))),
            (editPromptButton, "Edit the selected prompt template", #selector(editPromptClicked(_:))),
            (removePromptButton, "Delete the selected prompt template", #selector(removePromptClicked(_:))),
            (exportPromptsButton, "Save all prompt templates to a JSON file", #selector(exportPromptsClicked(_:))),
            (importPromptsButton, "Add prompts from a JSON file (duplicates are skipped)", #selector(importPromptsClicked(_:)))
        ] as [(NSButton, String, Selector)] {
            button.bezelStyle = .rounded
            button.controlSize = .small
            button.toolTip = tip
            button.target = self
            button.action = selector
            button.translatesAutoresizingMaskIntoConstraints = false
            content.addSubview(button)
        }

        privacyNoticeButton.bezelStyle = .rounded
        privacyNoticeButton.controlSize = .small
        privacyNoticeButton.image = Self.tintedImage(
            NSImage(systemSymbolName: "exclamationmark.circle",
                    accessibilityDescription: "Privacy notice"),
            with: .systemRed)
        privacyNoticeButton.imagePosition = .imageOnly
        privacyNoticeButton.toolTip = "About scanning code with a remote AI model"
        privacyNoticeButton.target = self
        privacyNoticeButton.action = #selector(privacyNoticeClicked(_:))
        privacyNoticeButton.translatesAutoresizingMaskIntoConstraints = false
        content.addSubview(privacyNoticeButton)

        // --- Claude-style composer card: prompt + model row + Send inside one
        // rounded, subtly bordered container; the response flows below without
        // any chrome. ---
        let composer = NSView()
        composer.wantsLayer = true
        composer.layer?.cornerRadius = 16
        composer.layer?.borderWidth = 1
        composer.layer?.borderColor = NSColor.separatorColor.cgColor
        composer.layer?.backgroundColor = NSColor.controlBackgroundColor.cgColor
        composer.translatesAutoresizingMaskIntoConstraints = false
        content.addSubview(composer)

        configureTextScrollView(promptScrollView, textView: promptTextView, editable: true, bordered: false)
        composer.addSubview(promptScrollView)

        configureTextScrollView(responseScrollView, textView: responseTextView, editable: false, bordered: false)
        // The response renders AI markdown (bold, lists, code fences), so the
        // text view must accept styled attributed content. Its base font is one
        // size smaller than the prompt editor for a denser reading experience.
        responseTextView.isRichText = true
        responseTextView.font = NSFont.userFixedPitchFont(ofSize: 12)
        // Terminal styling: near-black panel, rounded, monospaced green-tinted text.
        responseTextView.drawsBackground = true
        responseTextView.backgroundColor = terminalBackground
        responseTextView.insertionPointColor = terminalAccent
        responseTextView.selectedTextAttributes = [.backgroundColor: NSColor.selectedTextBackgroundColor]
        responseScrollView.drawsBackground = true
        responseScrollView.backgroundColor = terminalBackground
        responseScrollView.wantsLayer = true
        responseScrollView.layer?.cornerRadius = 10
        responseScrollView.layer?.borderWidth = 1
        responseScrollView.layer?.borderColor = NSColor.separatorColor.cgColor
        responseScrollView.layer?.masksToBounds = true

        thinkingSpinner.controlSize = .small
        thinkingSpinner.style = .spinning
        thinkingSpinner.isDisplayedWhenStopped = false
        thinkingSpinner.translatesAutoresizingMaskIntoConstraints = false
        thinkingLabel.font = NSFont.systemFont(ofSize: 12)
        thinkingLabel.textColor = terminalDim
        thinkingLabel.translatesAutoresizingMaskIntoConstraints = false
        content.addSubview(thinkingSpinner)
        content.addSubview(thinkingLabel)
        refreshThinkingIndicator()

        spinner.controlSize = .small
        spinner.style = .spinning
        spinner.isDisplayedWhenStopped = false
        spinner.toolTip = "Waiting for the model's response…"
        spinner.translatesAutoresizingMaskIntoConstraints = false
        composer.addSubview(spinner)

        let modelLabel = NSTextField(labelWithString: "Model:")
        modelLabel.font = NSFont.systemFont(ofSize: 12)
        modelLabel.textColor = .secondaryLabelColor
        modelLabel.translatesAutoresizingMaskIntoConstraints = false
        content.addSubview(modelLabel)

        modelPopup.target = self
        modelPopup.action = #selector(modelSelected(_:))
        modelPopup.toolTip = "The model used for requests; your choice is remembered"
        modelPopup.translatesAutoresizingMaskIntoConstraints = false
        modelPopup.setContentCompressionResistancePriority(.defaultLow, for: .horizontal)
        content.addSubview(modelPopup)

        refreshModelsButton.bezelStyle = .rounded
        refreshModelsButton.controlSize = .small
        refreshModelsButton.toolTip = "Re-fetch the model list from the endpoint"
        refreshModelsButton.target = self
        refreshModelsButton.action = #selector(refreshModelsClicked(_:))
        refreshModelsButton.translatesAutoresizingMaskIntoConstraints = false
        content.addSubview(refreshModelsButton)

        let keyLabel = NSTextField(labelWithString: "API Key:")
        keyLabel.font = NSFont.systemFont(ofSize: 12)
        keyLabel.textColor = .secondaryLabelColor
        keyLabel.translatesAutoresizingMaskIntoConstraints = false
        content.addSubview(keyLabel)
        self.keyLabel = keyLabel

        let connectLabel = NSTextField(labelWithString: "Connect:")
        connectLabel.font = NSFont.systemFont(ofSize: 12)
        connectLabel.textColor = .secondaryLabelColor
        connectLabel.translatesAutoresizingMaskIntoConstraints = false
        content.addSubview(connectLabel)
        self.connectLabel = connectLabel

        providerPopup.addItems(withTitles: ["OpenRouter", "Ollama"])
        providerPopup.controlSize = .small
        providerPopup.toolTip = "Which AI service to use: the OpenRouter cloud API, or a local Ollama server"
        providerPopup.target = self
        providerPopup.action = #selector(providerSelected(_:))
        providerPopup.translatesAutoresizingMaskIntoConstraints = false
        content.addSubview(providerPopup)

        serverField.placeholderString = OpenRouterClient.ollamaBaseURLString
        serverField.font = NSFont.systemFont(ofSize: 12)
        serverField.toolTip = "Ollama server URL, e.g. http://localhost:11434/v1 — edits are remembered"
        serverField.target = self
        serverField.action = #selector(serverFieldAction(_:))
        serverField.translatesAutoresizingMaskIntoConstraints = false
        content.addSubview(serverField)

        apiKeyField.placeholderString = "sk-or-…"
        apiKeyField.font = NSFont.systemFont(ofSize: 12)
        apiKeyField.translatesAutoresizingMaskIntoConstraints = false
        content.addSubview(apiKeyField)

        connectButton.bezelStyle = .rounded
        connectButton.controlSize = .small
        connectButton.toolTip = "Verify the connection (and, for OpenRouter, the key) and refresh the model list"
        connectButton.target = self
        connectButton.action = #selector(connectClicked(_:))
        connectButton.translatesAutoresizingMaskIntoConstraints = false
        content.addSubview(connectButton)

        applySendTitle("Send to AI")
        sendButton.bezelStyle = .rounded
        sendButton.keyEquivalent = "\r"
        sendButton.controlSize = .regular
        sendButton.bezelColor = NSColor(red: 0.85, green: 0.47, blue: 0.34, alpha: 1)
        sendButton.toolTip = "Send the prompt to the selected model"
        sendButton.target = self
        sendButton.action = #selector(sendClicked(_:))
        sendButton.translatesAutoresizingMaskIntoConstraints = false
        composer.addSubview(sendButton)

        continueButton.bezelStyle = .rounded
        continueButton.controlSize = .regular
        continueButton.toolTip = "Resume the interrupted response — the model keeps the full conversation and continues where it stopped"
        continueButton.target = self
        continueButton.action = #selector(continueClicked(_:))
        continueButton.translatesAutoresizingMaskIntoConstraints = false
        composer.addSubview(continueButton)

        newChatButton.bezelStyle = .rounded
        newChatButton.controlSize = .regular
        newChatButton.toolTip = "Clear the conversation and start a new one"
        newChatButton.target = self
        newChatButton.action = #selector(newChatClicked(_:))
        newChatButton.translatesAutoresizingMaskIntoConstraints = false
        composer.addSubview(newChatButton)

        statusLabel.font = NSFont.systemFont(ofSize: 11)
        statusLabel.textColor = .secondaryLabelColor
        statusLabel.lineBreakMode = .byTruncatingTail
        statusLabel.cell?.truncatesLastVisibleLine = true
        statusLabel.maximumNumberOfLines = 1
        statusLabel.setContentCompressionResistancePriority(.defaultLow, for: .horizontal)
        statusLabel.setContentHuggingPriority(.defaultLow, for: .horizontal)
        statusLabel.translatesAutoresizingMaskIntoConstraints = false
        content.addSubview(statusLabel)

        NSLayoutConstraint.activate([
            // Row 1 — template templates bar
            templatesLabel.leadingAnchor.constraint(equalTo: content.leadingAnchor, constant: 20),
            templatesLabel.centerYAnchor.constraint(equalTo: promptPopup.centerYAnchor),

            promptPopup.leadingAnchor.constraint(equalTo: templatesLabel.trailingAnchor, constant: 8),
            promptPopup.topAnchor.constraint(equalTo: content.topAnchor, constant: 14),
            addPromptButton.leadingAnchor.constraint(equalTo: promptPopup.trailingAnchor, constant: 8),
            addPromptButton.centerYAnchor.constraint(equalTo: promptPopup.centerYAnchor),
            editPromptButton.leadingAnchor.constraint(equalTo: addPromptButton.trailingAnchor, constant: 6),
            editPromptButton.centerYAnchor.constraint(equalTo: promptPopup.centerYAnchor),
            removePromptButton.leadingAnchor.constraint(equalTo: editPromptButton.trailingAnchor, constant: 6),
            removePromptButton.centerYAnchor.constraint(equalTo: promptPopup.centerYAnchor),
            exportPromptsButton.leadingAnchor.constraint(equalTo: removePromptButton.trailingAnchor, constant: 6),
            exportPromptsButton.centerYAnchor.constraint(equalTo: promptPopup.centerYAnchor),
            importPromptsButton.leadingAnchor.constraint(equalTo: exportPromptsButton.trailingAnchor, constant: 6),
            importPromptsButton.centerYAnchor.constraint(equalTo: promptPopup.centerYAnchor),
            privacyNoticeButton.leadingAnchor.constraint(equalTo: importPromptsButton.trailingAnchor, constant: 10),
            privacyNoticeButton.centerYAnchor.constraint(equalTo: promptPopup.centerYAnchor),

            // Composer card: prompt editor + spinner + Send only
            composer.topAnchor.constraint(equalTo: promptPopup.bottomAnchor, constant: 10),
            composer.leadingAnchor.constraint(equalTo: content.leadingAnchor, constant: 20),
            composer.trailingAnchor.constraint(equalTo: content.trailingAnchor, constant: -20),

            // Prompt editor inside the card
            promptScrollView.topAnchor.constraint(equalTo: composer.topAnchor, constant: 12),
            promptScrollView.leadingAnchor.constraint(equalTo: composer.leadingAnchor, constant: 14),
            promptScrollView.trailingAnchor.constraint(equalTo: composer.trailingAnchor, constant: -14),
            promptScrollView.heightAnchor.constraint(equalToConstant: 84),

            // Send stays on the card's bottom row, with Continue and New Chat
            // to its left.
            sendButton.trailingAnchor.constraint(equalTo: composer.trailingAnchor, constant: -14),
            sendButton.topAnchor.constraint(equalTo: promptScrollView.bottomAnchor, constant: 8),
            sendButton.bottomAnchor.constraint(equalTo: composer.bottomAnchor, constant: -12),
            spinner.trailingAnchor.constraint(equalTo: sendButton.leadingAnchor, constant: -10),
            spinner.centerYAnchor.constraint(equalTo: sendButton.centerYAnchor),
            continueButton.trailingAnchor.constraint(equalTo: spinner.leadingAnchor, constant: -10),
            continueButton.centerYAnchor.constraint(equalTo: sendButton.centerYAnchor),
            newChatButton.trailingAnchor.constraint(equalTo: continueButton.leadingAnchor, constant: -8),
            newChatButton.centerYAnchor.constraint(equalTo: sendButton.centerYAnchor),

            // Response fills the space between the card and the status line
            responseScrollView.topAnchor.constraint(equalTo: composer.bottomAnchor, constant: 10),
            responseScrollView.leadingAnchor.constraint(equalTo: content.leadingAnchor, constant: 20),
            responseScrollView.trailingAnchor.constraint(equalTo: content.trailingAnchor, constant: -20),
            responseScrollView.bottomAnchor.constraint(equalTo: statusLabel.topAnchor, constant: -8),
            // The thinking indicator floats at the bottom-right inside the response
            // pane, above the streamed text.
            thinkingSpinner.trailingAnchor.constraint(equalTo: responseScrollView.trailingAnchor, constant: -14),
            thinkingSpinner.bottomAnchor.constraint(equalTo: responseScrollView.bottomAnchor, constant: -10),
            thinkingLabel.trailingAnchor.constraint(equalTo: thinkingSpinner.leadingAnchor, constant: -6),
            thinkingLabel.centerYAnchor.constraint(equalTo: thinkingSpinner.centerYAnchor),

            // Status on its own full-width line (always visible, never squeezed)
            statusLabel.leadingAnchor.constraint(equalTo: content.leadingAnchor, constant: 20),
            statusLabel.trailingAnchor.constraint(equalTo: content.trailingAnchor, constant: -20),
            statusLabel.bottomAnchor.constraint(equalTo: modelPopup.topAnchor, constant: -8),

            // Bottom bar: model picker, provider dropdown, then the provider-
            // specific controls (see updateProviderUI)
            modelLabel.leadingAnchor.constraint(equalTo: content.leadingAnchor, constant: 20),
            modelLabel.centerYAnchor.constraint(equalTo: modelPopup.centerYAnchor),
            modelPopup.leadingAnchor.constraint(equalTo: modelLabel.trailingAnchor, constant: 6),
            modelPopup.widthAnchor.constraint(lessThanOrEqualToConstant: 200),
            modelPopup.bottomAnchor.constraint(equalTo: content.bottomAnchor, constant: -14),
            refreshModelsButton.leadingAnchor.constraint(equalTo: modelPopup.trailingAnchor, constant: 8),
            refreshModelsButton.centerYAnchor.constraint(equalTo: modelPopup.centerYAnchor),
            providerPopup.leadingAnchor.constraint(equalTo: refreshModelsButton.trailingAnchor, constant: 14),
            providerPopup.centerYAnchor.constraint(equalTo: modelPopup.centerYAnchor),
            connectButton.centerYAnchor.constraint(equalTo: modelPopup.centerYAnchor)
        ])
        updateProviderUI()
        updateControlButtons()
    }

    /// Shows the controls for the selected provider: OpenRouter displays the
    /// API key field, Ollama displays the editable "Connect" server field.
    /// The inactive provider's constraints are deactivated so both layouts
    /// can share the same bar without conflicts.
    private func updateProviderUI() {
        let client = OpenRouterClient.shared
        NSLayoutConstraint.deactivate(providerBarConstraints)
        providerBarConstraints.removeAll()

        if client.provider == .openRouter {
            keyLabel.isHidden = false
            apiKeyField.isHidden = false
            connectLabel.isHidden = true
            serverField.isHidden = true
            providerBarConstraints = [
                keyLabel.leadingAnchor.constraint(equalTo: providerPopup.trailingAnchor, constant: 14),
                keyLabel.centerYAnchor.constraint(equalTo: modelPopup.centerYAnchor),
                apiKeyField.leadingAnchor.constraint(equalTo: keyLabel.trailingAnchor, constant: 6),
                apiKeyField.centerYAnchor.constraint(equalTo: modelPopup.centerYAnchor),
                apiKeyField.widthAnchor.constraint(equalToConstant: 140),
                connectButton.leadingAnchor.constraint(equalTo: apiKeyField.trailingAnchor, constant: 6)
            ]
        } else {
            keyLabel.isHidden = true
            apiKeyField.isHidden = true
            connectLabel.isHidden = false
            serverField.isHidden = false
            providerBarConstraints = [
                connectLabel.leadingAnchor.constraint(equalTo: providerPopup.trailingAnchor, constant: 14),
                connectLabel.centerYAnchor.constraint(equalTo: modelPopup.centerYAnchor),
                serverField.leadingAnchor.constraint(equalTo: connectLabel.trailingAnchor, constant: 6),
                serverField.centerYAnchor.constraint(equalTo: modelPopup.centerYAnchor),
                serverField.widthAnchor.constraint(equalToConstant: 210),
                connectButton.leadingAnchor.constraint(equalTo: serverField.trailingAnchor, constant: 6)
            ]
        }
        NSLayoutConstraint.activate(providerBarConstraints)
    }

    private func configureTextScrollView(_ scroll: NSScrollView, textView: NSTextView, editable: Bool, bordered: Bool = true) {
        scroll.hasVerticalScroller = true
        scroll.autohidesScrollers = true
        scroll.borderType = bordered ? .bezelBorder : .noBorder
        scroll.drawsBackground = bordered
        scroll.translatesAutoresizingMaskIntoConstraints = false

        textView.isEditable = editable
        textView.isSelectable = true
        textView.isRichText = false
        textView.drawsBackground = bordered
        textView.font = NSFont.systemFont(ofSize: 13)
        textView.autoresizingMask = [.width]
        textView.isVerticallyResizable = true
        textView.textContainer?.widthTracksTextView = true
        textView.textContainerInset = NSSize(width: 4, height: 6)
        scroll.documentView = textView
        window?.contentView?.addSubview(scroll)
    }

    // MARK: - Prompt templates

    private func reloadPromptPopup() {
        promptPopup.removeAllItems()
        let all = PromptStore.shared.prompts
        if all.isEmpty {
            promptPopup.addItem(withTitle: "(no saved prompts)")
            promptPopup.isEnabled = false
            editPromptButton.isEnabled = false
            removePromptButton.isEnabled = false
            return
        }
        promptPopup.isEnabled = true
        editPromptButton.isEnabled = true
        removePromptButton.isEnabled = true
        for p in all {
            let item = NSMenuItem(title: p.title, action: nil, keyEquivalent: "")
            item.representedObject = p.id
            promptPopup.menu?.addItem(item)
        }
        if let id = selectedPromptID,
           let idx = all.firstIndex(where: { $0.id == id }) {
            promptPopup.selectItem(at: idx)
        }
    }

    /// Pastes the selected template's text into the prompt editor at the
    /// current insertion point (or over the current selection).
    @objc private func promptSelected(_ sender: NSPopUpButton) {
        guard let id = sender.selectedItem?.representedObject as? String,
              let template = PromptStore.shared.prompt(id: id) else { return }
        selectedPromptID = id

        let current = promptTextView.string
        let text = template.promptText
        let insertRange = promptTextView.selectedRange()
        let atEnd = insertRange.location == NSNotFound || insertRange.location >= (current as NSString).length
        if current.isEmpty {
            promptTextView.string = text
        } else if atEnd {
            promptTextView.string = current + "\n\n" + text
        } else {
            promptTextView.insertText(text, replacementRange: insertRange)
        }
        promptTextView.scrollToEndOfDocument(nil)
    }

    // MARK: - Template add / edit / remove

    @objc private func addPromptClicked(_ sender: Any?) {
        showPromptEditor(existing: nil)
    }

    @objc private func editPromptClicked(_ sender: Any?) {
        guard let id = promptPopup.selectedItem?.representedObject as? String,
              let template = PromptStore.shared.prompt(id: id) else { return }
        showPromptEditor(existing: template)
    }

    @objc private func removePromptClicked(_ sender: Any?) {
        guard let id = promptPopup.selectedItem?.representedObject as? String,
              let template = PromptStore.shared.prompt(id: id) else { return }
        let alert = NSAlert()
        alert.messageText = "Remove Prompt"
        alert.informativeText = "Remove \"\(template.title)\" from the saved prompts?"
        alert.addButton(withTitle: "Remove")
        alert.addButton(withTitle: "Cancel")
        NSApp.activate(ignoringOtherApps: true)
        if alert.runModal() == .alertFirstButtonReturn {
            if selectedPromptID == id { selectedPromptID = nil }
            PromptStore.shared.remove(id: id)
            reloadPromptPopup()
        }
    }

    /// Saves every stored prompt template to a user-chosen JSON file.
    @objc private func exportPromptsClicked(_ sender: Any?) {
        guard let win = window else { return }
        let panel = NSSavePanel()
        panel.allowedContentTypes = [.json]
        panel.nameFieldStringValue = "KarmaPro-Prompts.json"
        panel.message = "Export all prompt templates"
        panel.beginSheetModal(for: win) { [weak self] response in
            guard let self = self, response == .OK, let url = panel.url else { return }
            let data = PromptStore.shared.exportData()
            do {
                try data.write(to: url, options: .atomic)
                self.setStatus("Exported \(PromptStore.shared.prompts.count) prompt templates.",
                               color: .systemGreen)
            } catch {
                self.setStatus("Export failed: \(error.localizedDescription)", color: .systemRed)
            }
        }
    }

    /// Adds prompts from a JSON file, skipping entries already stored
    /// (same title or same text).
    @objc private func importPromptsClicked(_ sender: Any?) {
        guard let win = window else { return }
        let panel = NSOpenPanel()
        panel.allowedContentTypes = [.json]
        panel.allowsMultipleSelection = false
        panel.canChooseDirectories = false
        panel.message = "Choose a Karma Pro prompts export file"
        panel.beginSheetModal(for: win) { [weak self] response in
            guard let self = self, response == .OK, let url = panel.url else { return }
            guard let data = try? Data(contentsOf: url) else {
                self.setStatus("Could not read the selected file.", color: .systemRed)
                return
            }
            let result = PromptStore.shared.importData(data)
            self.reloadPromptPopup()
            if let error = result.error {
                self.setStatus(error, color: .systemRed)
            } else {
                self.setStatus("Imported \(result.added) prompt(s), skipped \(result.skipped) duplicate(s).",
                               color: result.added > 0 ? .systemGreen : .secondaryLabelColor)
            }
        }
    }

    /// Renders a template image in the given color (symbol tinting via
    /// `NSImage.SymbolConfiguration(paletteColors:)` needs a newer SDK than
    /// this project builds with).
    private static func tintedImage(_ image: NSImage?, with tint: NSColor) -> NSImage? {
        guard let image = image else { return nil }
        let size = image.size
        let result = NSImage(size: size)
        result.lockFocus()
        let rect = NSRect(origin: .zero, size: size)
        image.draw(in: rect, from: .zero, operation: .sourceOver, fraction: 1.0)
        tint.setFill()
        rect.fill(using: .sourceAtop)
        result.unlockFocus()
        return result
    }

    /// Explains the privacy and reliability caveats of scanning source code
    /// with a remote AI model.
    @objc private func privacyNoticeClicked(_ sender: Any?) {
        let alert = NSAlert()
        alert.messageText = "Privacy & Reliability Notice"
        alert.informativeText = """
            When scanning source code with a remote AI model, your source code will be read by a third party, make sure that you do not have any privacy concerns. Also note that even though AI models identify in many cases real vulnerabilities, they don't always identify the same issues i.e. if a model reads your code many times it may identify different vulnerabilities, for the same source code, and not necessarily the same as with a previous review.

            Note, if you want you can use a local model and it may be safer for proprietary source code, so if privacy is a concern use Ollama instead of OpenRouter and point Karma Pro to a local running model.
            """
        alert.addButton(withTitle: "OK")
        NSApp.activate(ignoringOtherApps: true)
        alert.runModal()
    }

    /// Sheet with a title field + body text editor for creating or editing a
    /// prompt template.
    private func showPromptEditor(existing: PromptTemplate?) {
        let accessory = NSView(frame: NSRect(x: 0, y: 0, width: 440, height: 300))

        let titleLabel = NSTextField(labelWithString: "Title:")
        titleLabel.frame = NSRect(x: 0, y: 278, width: 440, height: 16)
        accessory.addSubview(titleLabel)

        let titleField = NSTextField(frame: NSRect(x: 0, y: 252, width: 440, height: 22))
        titleField.placeholderString = "Menu title, e.g. \"Audit Auth Code\""
        titleField.stringValue = existing?.title ?? ""
        accessory.addSubview(titleField)

        let bodyLabel = NSTextField(labelWithString: "Prompt text:")
        bodyLabel.frame = NSRect(x: 0, y: 228, width: 440, height: 16)
        accessory.addSubview(bodyLabel)

        let bodyScroll = NSScrollView(frame: NSRect(x: 0, y: 0, width: 440, height: 220))
        bodyScroll.hasVerticalScroller = true
        bodyScroll.borderType = .bezelBorder
        let bodyView = NSTextView(frame: bodyScroll.bounds)
        bodyView.isRichText = false
        bodyView.font = NSFont.systemFont(ofSize: 13)
        bodyView.isVerticallyResizable = true
        bodyView.autoresizingMask = [.width]
        bodyView.textContainer?.widthTracksTextView = true
        bodyView.string = existing?.promptText ?? ""
        bodyScroll.documentView = bodyView
        accessory.addSubview(bodyScroll)

        let alert = NSAlert()
        alert.messageText = existing == nil ? "New Prompt" : "Edit Prompt"
        alert.informativeText = "The title appears in the dropdown; selecting it pastes the prompt text into the editor."
        alert.accessoryView = accessory
        alert.addButton(withTitle: "Save")
        alert.addButton(withTitle: "Cancel")
        alert.window.initialFirstResponder = titleField
        NSApp.activate(ignoringOtherApps: true)
        let response = alert.runModal()

        let title = titleField.stringValue.trimmingCharacters(in: .whitespacesAndNewlines)
        let text = bodyView.string.trimmingCharacters(in: .whitespacesAndNewlines)
        guard response == .alertFirstButtonReturn, !title.isEmpty else { return }

        if let existing = existing {
            PromptStore.shared.update(id: existing.id, title: title, promptText: text)
        } else {
            let added = PromptStore.shared.add(title: title, promptText: text)
            selectedPromptID = added.id
        }
        reloadPromptPopup()
    }

    // MARK: - Model / API key

    private func loadSettings() {
        let client = OpenRouterClient.shared
        providerPopup.selectItem(withTitle: client.provider.rawValue)
        serverField.stringValue = client.ollamaServerURLString
        apiKeyField.stringValue = client.apiKey
        updateProviderUI()
        if !client.selectedModel.isEmpty {
            modelPopup.addItem(withTitle: client.selectedModel)
            modelPopup.selectItem(withTitle: client.selectedModel)
        }
    }

    /// Switches provider (remembered across relaunches), swaps the visible
    /// controls, and refreshes the model list for the new provider.
    @objc private func providerSelected(_ sender: NSPopUpButton) {
        let client = OpenRouterClient.shared
        guard let name = sender.titleOfSelectedItem,
              let newProvider = AIProvider(rawValue: name),
              newProvider != client.provider else { return }
        client.provider = newProvider
        updateProviderUI()
        setStatus(newProvider == .ollama
                  ? "Using Ollama at \(client.ollamaServerURLString)"
                  : "Using OpenRouter",
                  color: .secondaryLabelColor)
        refreshModelList()
    }

    /// Persists the server field into the client (normalised). Called before
    /// every Ollama request and on Enter so edits take effect immediately.
    @discardableResult
    private func syncServer() -> Bool {
        guard OpenRouterClient.shared.provider == .ollama else { return true }
        let raw = serverField.stringValue
        guard let normalized = OpenRouterClient.normalizeBaseURLString(raw) else {
            setStatus("Invalid server URL — e.g. http://localhost:11434/v1", color: .systemRed)
            return false
        }
        serverField.stringValue = normalized
        if normalized != OpenRouterClient.shared.ollamaServerURLString {
            OpenRouterClient.shared.ollamaServerURLString = normalized
        }
        return true
    }

    /// Return in the server field commits the edit (it is remembered).
    @objc private func serverFieldAction(_ sender: NSTextField) {
        guard syncServer() else { return }
        setStatus("Ollama server set to \(OpenRouterClient.shared.ollamaServerURLString)", color: .secondaryLabelColor)
        refreshModelList()
    }

    /// Populates the model dropdown immediately with the fallback list, then
    /// replaces it with the live catalog when the fetch completes
    /// (asynchronously — never blocks the UI). Ollama has no useful fallback
    /// list, so it shows just the saved model until the live fetch answers.
    private func refreshModelList() {
        syncServer()
        let client = OpenRouterClient.shared
        let saved = client.selectedModel
        if client.isOllama {
            applyModelItems([saved], keeping: saved)
        } else {
            applyModelItems(OpenRouterClient.fallbackModels, keeping: saved)
        }
        if client.requiresAPIKey && client.apiKey.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty { return }
        client.fetchModels { [weak self] live in
            guard let self = self, !live.isEmpty else { return }
            DispatchQueue.main.async {
                self.applyModelItems(live.map { $0.id }.sorted(),
                                     keeping: OpenRouterClient.shared.selectedModel)
            }
        }
    }

    private func applyModelItems(_ items: [String], keeping selected: String) {
        modelPopup.removeAllItems()
        for m in items { modelPopup.addItem(withTitle: m) }
        if let idx = items.firstIndex(of: selected) {
            modelPopup.selectItem(at: idx)
        } else {
            modelPopup.insertItem(withTitle: selected, at: 0)
            modelPopup.selectItem(withTitle: selected)
        }
    }

    @objc private func modelSelected(_ sender: NSPopUpButton) {
        if let model = sender.titleOfSelectedItem {
            OpenRouterClient.shared.selectedModel = model
        }
    }

    @objc private func refreshModelsClicked(_ sender: Any?) {
        refreshModelList()
        setStatus("Model list refreshed.", color: .secondaryLabelColor)
    }

    @objc private func connectClicked(_ sender: Any?) {
        let client = OpenRouterClient.shared
        guard syncServer() else { return }
        let key = apiKeyField.stringValue.trimmingCharacters(in: .whitespacesAndNewlines)
        if client.requiresAPIKey && key.isEmpty {
            setStatus("Enter your OpenRouter API key first.", color: .systemRed)
            return
        }
        client.apiKey = key

        if client.isOllama {
            // Local server: verify by listing models.
            let host = client.baseURL.host ?? client.ollamaServerURLString
            setStatus("Connecting to Ollama at \(host)…", color: .secondaryLabelColor)
            client.fetchModels { [weak self] models in
                DispatchQueue.main.async {
                    guard let self = self else { return }
                    if models.isEmpty {
                        self.setStatus("Could not reach Ollama at \(host) — is the server running? " +
                                       "Launch the Ollama app or run `ollama serve`.", color: .systemRed)
                        return
                    }
                    self.setStatus("Connected to Ollama — \(models.count) model(s) available.", color: .systemGreen)
                    self.refreshModelList()
                }
            }
            return
        }

        setStatus("Connecting to OpenRouter…", color: .secondaryLabelColor)

        var request = URLRequest(url: client.baseURL.appendingPathComponent("key"))
        request.httpMethod = "GET"
        request.timeoutInterval = 20
        request.setValue("Bearer \(key)", forHTTPHeaderField: "Authorization")
        URLSession.shared.dataTask(with: request) { [weak self] data, response, error in
            DispatchQueue.main.async {
                guard let self = self else { return }
                if let http = response as? HTTPURLResponse, http.statusCode == 401 {
                    self.setStatus("OpenRouter rejected this API key.", color: .systemRed)
                    return
                }
                guard error == nil, data != nil else {
                    self.setStatus("Could not reach openrouter.ai — key saved anyway.", color: .systemOrange)
                    return
                }
                self.setStatus("Connected to OpenRouter.", color: .systemGreen)
                self.refreshModelList()
            }
        }.resume()
    }

    // MARK: - Sending

    @objc private func sendClicked(_ sender: Any?) {
        // While a request is streaming the button acts as Stop.
        if requestInFlight {
            stopRequested()
            return
        }

        let prompt = promptTextView.string.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !prompt.isEmpty else {
            setStatus("Type or paste a prompt first.", color: .systemRed)
            return
        }
        guard syncServer() else { return }
        if OpenRouterClient.shared.requiresAPIKey
            && OpenRouterClient.shared.apiKey.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
            setStatus("Enter your OpenRouter API key and click Connect.", color: .systemRed)
            return
        }

        let model = OpenRouterClient.shared.selectedModel
        runUserTurn(content: prompt, marker: prompt, model: model, isNewConversation: conversation.isEmpty)
        promptTextView.string = ""
    }

    /// Fills the prompt editor with a "How to fix it" request for the given
    /// file + line and immediately triggers the same send flow as the Send
    /// button (requiring the app to be connected to a model as usual).
    func askHowToFix(fileURL: URL, line: Int, lineText: String) {
        let prompt = "How to fix the vulnerability at: \(fileURL.path):\(line)\n\n\(lineText)"
        promptTextView.string = prompt
        sendClicked(nil)
    }

    /// Resumes the interrupted task: the whole conversation — including the
    /// model's partial answer and any tool results — is sent back with an
    /// instruction to continue exactly where it stopped.
    @objc private func continueClicked(_ sender: Any?) {
        guard !requestInFlight, lastTaskInterrupted, !conversation.isEmpty else { return }
        guard syncServer() else { return }
        if OpenRouterClient.shared.requiresAPIKey
            && OpenRouterClient.shared.apiKey.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
            setStatus("Enter your OpenRouter API key and click Connect.", color: .systemRed)
            return
        }
        runUserTurn(content: "Your previous response was interrupted. Continue exactly where you stopped — do not repeat text you already produced, and complete the remaining work.",
                    marker: "continue interrupted response",
                    model: OpenRouterClient.shared.selectedModel,
                    isNewConversation: false)
    }

    /// Clears the conversation and the transcript so the next prompt starts
    /// fresh.
    @objc private func newChatClicked(_ sender: Any?) {
        guard !requestInFlight else { return }
        conversation = []
        transcript = []
        streamAccumulated = ""
        modelIsThinking = false
        toolRound = 0
        lastTaskInterrupted = false
        cancelRequested = false
        usedFallback = false
        responseTextView.textStorage?.setAttributedString(NSAttributedString(string: ""))
        refreshThinkingIndicator()
        updateControlButtons()
        setStatus("New conversation — the previous context was cleared.", color: .secondaryLabelColor)
    }

    /// Appends a user turn (refreshing the system message so the currently
    /// open project is described) and starts the streaming agent loop. The
    /// first prompt of a session starts a new conversation; later prompts
    /// append to it so the model keeps the full context.
    private func runUserTurn(content: String, marker: String, model: String, isNewConversation: Bool) {
        if isNewConversation {
            conversation = [["role": "system", "content": Self.systemPrompt(projectRoot: projectRootURL)],
                            ["role": "user", "content": content]]
            transcript = [.turnMarker(marker)]
            responseTextView.textStorage?.setAttributedString(NSAttributedString(string: ""))
        } else {
            if let first = conversation.first, first["role"] as? String == "system" {
                conversation[0]["content"] = Self.systemPrompt(projectRoot: projectRootURL)
            }
            conversation.append(["role": "user", "content": content])
            transcript.append(.turnMarker(marker))
        }
        streamAccumulated = ""
        modelIsThinking = false
        cancelRequested = false
        usedFallback = false
        toolRound = 0
        lastTaskInterrupted = false
        updateControlButtons()
        setStreamingUI(true)
        spinner.startAnimation(nil)
        renderStreamingResponse()
        setStatus("Waiting for \(model)…", color: .secondaryLabelColor)
        runStreamingRound(model: model)
    }

    /// One streaming round of the agent loop. When the model asks for tools,
    /// they are executed (sandboxed to the project directory), the results
    /// are appended to the conversation, and the next round is started.
    private func runStreamingRound(model: String) {
        // Stop pressed between rounds (e.g. during tool execution): no new
        // request is started and the UI is reset (no completion will fire).
        guard !cancelRequested else {
            setStreamingUI(false)
            spinner.stopAnimation(nil)
            return
        }
        let started = OpenRouterClient.shared.sendStreamingMessages(
            messages: conversation,
            tools: AIToolExecutor.toolDefinitions,
            model: model,
            onPart: { [weak self] part in
                DispatchQueue.main.async {
                    guard let self = self, self.requestInFlight else { return }
                    switch part {
                    case .reasoning:
                        if !self.modelIsThinking {
                            self.modelIsThinking = true
                            self.setStatus("Model is thinking…", color: .secondaryLabelColor)
                            self.refreshThinkingIndicator()
                        }
                    case .content(let text):
                        if self.streamAccumulated.isEmpty {
                            self.setStatus("Receiving response…", color: .secondaryLabelColor)
                        }
                        self.modelIsThinking = false
                        self.streamAccumulated += text
                    }
                    self.scheduleStreamingRender()
                }
            },
            completion: { [weak self] result in
                DispatchQueue.main.async {
                    guard let self = self else { return }
                    switch result {
                    case .failure(let error):
                        self.finishStreamingRound(error: error, model: model)
                    case .success(let sr):
                        if sr.toolCalls.isEmpty || self.toolRound >= 5 {
                            self.finishStreamingRound(success: sr, model: model)
                        } else {
                            self.executeToolCalls(sr: sr, model: model)
                        }
                    }
                }
            })
        if !started {
            setStreamingUI(false)
            spinner.stopAnimation(nil)
        }
    }

    private func finishStreamingRound(success: OpenRouterStreamResult? = nil, error: Error? = nil, model: String = "") {
        setStreamingUI(false)
        spinner.stopAnimation(nil)
        if let sr = success {
            finalizeAssistantTurn(content: sr.content, interrupted: cancelRequested)
            if cancelRequested {
                lastTaskInterrupted = true
                setStatus("Stopped — press Continue to resume with context, or type a new prompt.", color: .secondaryLabelColor)
            } else {
                lastTaskInterrupted = false
                setStatus("Done.", color: .secondaryLabelColor)
            }
        } else if let error = error {
            if (error as NSError).code == NSURLErrorCancelled {
                finalizeAssistantTurn(content: streamAccumulated, interrupted: true)
                lastTaskInterrupted = true
                setStatus("Cancelled — press Continue to resume with context.", color: .secondaryLabelColor)
            } else if !usedFallback && toolRound == 0 {
                // Streaming failed (timeout/connection): retry once via the
                // non-streaming request so an answer still arrives.
                sendFallback(model: model)
            } else {
                finalizeAssistantTurn(content: streamAccumulated, interrupted: !streamAccumulated.isEmpty)
                lastTaskInterrupted = true
                setStatus("Failed: \(error.localizedDescription) — press Continue to retry with context.", color: .systemRed)
            }
        }
        updateControlButtons()
    }

    /// Moves the finished round's text into the transcript and appends the
    /// assistant message to the conversation, so later prompts and Continue
    /// see everything the model produced so far. Interrupted answers are
    /// stored with a marker telling the model where it stopped.
    private func finalizeAssistantTurn(content: String, interrupted: Bool) {
        if !content.isEmpty {
            transcript.append(.answer(content))
            let stored = interrupted
                ? content + "\n\n_[response interrupted here — continue from this point]_"
                : content
            conversation.append(["role": "assistant", "content": stored])
        }
        streamAccumulated = ""
        modelIsThinking = false
        refreshThinkingIndicator()
        renderStreamingResponse()
    }

    /// Executes the model's requested tools (concurrently, on background
    /// queues), appends results to the conversation, and starts the next
    /// streaming round.
    private func executeToolCalls(sr: OpenRouterStreamResult, model: String) {
        toolRound += 1
        // Assistant turn that requested the tools.
        var assistantMsg: [String: Any] = ["role": "assistant"]
        assistantMsg["content"] = sr.content.isEmpty ? NSNull() : sr.content
        assistantMsg["tool_calls"] = sr.toolCalls.map { tc in
            ["id": tc.id, "type": "function",
             "function": ["name": tc.name, "arguments": tc.arguments]]
        }
        conversation.append(assistantMsg)

        guard let root = projectRootURL ?? window?.representedURL else {
            setStreamingUI(false)
            spinner.stopAnimation(nil)
            setStatus("No project open — tools need a project.", color: .systemRed)
            return
        }
        let executor = AIToolExecutor(projectRoot: root)
        setStatus("Running tools (round \(toolRound))…", color: .secondaryLabelColor)

        var results: [Int: String] = [:]
        // Multiple tools execute concurrently; Dictionary mutation is NOT
        // thread-safe — unsynchronised writes here caused SIGSEGV crashes
        // (Dictionary._Variant.setValue in the executeToolCalls closure).
        let resultsLock = NSLock()
        let group = DispatchGroup()
        for (index, tc) in sr.toolCalls.enumerated() {
            group.enter()
            DispatchQueue.global().async { [weak self] in
                let output = executor.execute(name: tc.name, argumentsJSON: tc.arguments)
                resultsLock.lock()
                results[index] = output
                resultsLock.unlock()
                DispatchQueue.main.async { [weak self] in
                    guard let self = self else { return }
                    self.transcript.append(.tool(name: tc.name, args: tc.arguments, output: String(output.prefix(4000))))
                    self.renderStreamingResponse()
                }
                group.leave()
            }
        }
        group.notify(queue: .main) { [weak self] in
            guard let self = self else { return }
            // Stop pressed while tools ran: no next round will start and no
            // completion will fire. Answer the requested tool calls with a
            // placeholder (the API requires every tool_call to be followed by
            // a tool message before the conversation may continue), keep the
            // partial answer, and offer Continue.
            guard !self.cancelRequested else {
                for tc in sr.toolCalls {
                    self.conversation.append(["role": "tool",
                                              "tool_call_id": tc.id,
                                              "content": "{\"ok\":false,\"error\":\"stopped by user before execution\"}"])
                }
                self.lastTaskInterrupted = true
                self.finalizeAssistantTurn(content: self.streamAccumulated, interrupted: true)
                self.setStreamingUI(false)
                self.spinner.stopAnimation(nil)
                self.setStatus("Stopped — press Continue to resume with context.", color: .secondaryLabelColor)
                return
            }
            for (index, tc) in sr.toolCalls.enumerated() {
                self.conversation.append(["role": "tool",
                                          "tool_call_id": tc.id,
                                          "content": results[index] ?? "{\"ok\":false,\"error\":\"no result\"}"])
            }
            self.streamAccumulated = ""   // next round's answer replaces this round's text
            self.runStreamingRound(model: model)
        }
    }

    /// One-shot retry through the non-streaming endpoint (used when the
    /// streaming request fails). The full conversation is sent so the retry
    /// keeps the same context.
    private func sendFallback(model: String) {
        usedFallback = true
        setStatus("Streaming unavailable — retrying without streaming…", color: .secondaryLabelColor)
        spinner.startAnimation(nil)
        setStreamingUI(true)
        requestInFlight = true
        OpenRouterClient.shared.sendChatMessages(messages: conversation, model: model) { [weak self] result in
            DispatchQueue.main.async {
                guard let self = self else { return }
                self.requestInFlight = false
                self.setStreamingUI(false)
                self.spinner.stopAnimation(nil)
                switch result {
                case .success(let content):
                    self.finalizeAssistantTurn(content: content, interrupted: false)
                    self.lastTaskInterrupted = false
                    self.setStatus("Done (non-streaming).", color: .secondaryLabelColor)
                case .failure(let error):
                    if (error as NSError).code == NSURLErrorCancelled {
                        self.finalizeAssistantTurn(content: self.streamAccumulated, interrupted: true)
                        self.lastTaskInterrupted = true
                        self.setStatus("Cancelled — press Continue to resume with context.", color: .secondaryLabelColor)
                    } else {
                        self.finalizeAssistantTurn(content: self.streamAccumulated, interrupted: !self.streamAccumulated.isEmpty)
                        self.lastTaskInterrupted = true
                        self.setStatus("Failed: \(error.localizedDescription) — press Continue to retry with context.", color: .systemRed)
                    }
                }
                self.updateControlButtons()
            }
        }
    }

    /// User pressed Stop: cancel the in-flight request; the partial response
    /// streamed so far is kept in the response pane.
    private func stopRequested() {
        cancelRequested = true
        setStatus("Cancelling…", color: .secondaryLabelColor)
        OpenRouterClient.shared.cancelActiveStream()
        // Between streaming rounds (tool execution) there is no network
        // request to cancel and no completion will fire — reset the UI here,
        // otherwise the spinner and the Stop button would stay stuck.
        guard OpenRouterClient.shared.hasActiveRequest else {
            if !streamAccumulated.isEmpty || modelIsThinking {
                finishStreamingRound(success: OpenRouterStreamResult(reasoning: "",
                                                                     content: streamAccumulated,
                                                                     toolCalls: []))
            } else {
                finishStreamingRound(error: NSError(domain: NSURLErrorDomain,
                                                    code: NSURLErrorCancelled,
                                                    userInfo: [NSLocalizedDescriptionKey: "Request cancelled."]))
            }
            return
        }
    }

    /// Flips the Send button into a Stop button while a request is in flight.
    /// (The button stays enabled so the user can cancel slow responses.)
    func setStreamingUI(_ streaming: Bool) {
        requestInFlight = streaming
        applySendTitle(streaming ? "Stop" : "Send to AI")
        sendButton.toolTip = streaming
            ? "Cancel the in-flight request (partial response is kept)"
            : "Send the prompt to the selected model"
        updateControlButtons()
    }

    /// Continue is enabled only when an interrupted task can be resumed; New
    /// Chat only when there is a conversation to clear.
    private func updateControlButtons() {
        continueButton.isEnabled = !requestInFlight && lastTaskInterrupted && !conversation.isEmpty
        newChatButton.isEnabled = !requestInFlight && !conversation.isEmpty
    }

    /// White semibold label so it stays readable on the accent bezel.
    private func applySendTitle(_ text: String) {
        sendButton.attributedTitle = NSAttributedString(string: text, attributes: [
            .foregroundColor: NSColor.white,
            .font: NSFont.systemFont(ofSize: 13, weight: .semibold)
        ])
    }

    /// Schedules a coalesced render of the streaming pane. The high-frequency
    /// token callback calls this; the actual `renderStreamingResponse()` runs
    /// at most once per tick (~30 fps) so a burst of tokens becomes a smooth
    /// stream of updates instead of a per-token full re-layout + re-scroll.
    private func scheduleStreamingRender() {
        streamRenderDirty = true
        guard streamRenderTick == nil else { return }
        streamRenderTick = DispatchWorkItem { [weak self] in
            self?.streamRenderTick = nil
            guard let self = self, self.streamRenderDirty else { return }
            self.streamRenderDirty = false
            self.renderStreamingResponse()
        }
        let interval: TimeInterval = 1.0 / 30.0
        DispatchQueue.main.asyncAfter(deadline: .now() + interval, execute: streamRenderTick!)
    }

    /// Live view while streaming: the transcript renders finished turns (dim
    /// prompt markers, tool activity, thinking, markdown answers) and the
    /// in-flight reasoning + partial answer stream below them.
    func renderStreamingResponse() {
        let combined = NSMutableAttributedString()
        let mono = Self.terminalBaseFont(size: 11)
        for entry in transcript {
            switch entry {
            case .turnMarker(let text):
                let oneLine = text.replacingOccurrences(of: "\n", with: " ")
                let label = oneLine.count > 100 ? String(oneLine.prefix(100)) + "…" : oneLine
                combined.append(NSAttributedString(string: "> \(label)\n", attributes: [
                    .font: mono, .foregroundColor: terminalDim
                ]))
            case .tool(let name, let args, let output):
                combined.append(NSAttributedString(string: Self.toolDisplayLabel(name: name, args: args) + "\n", attributes: [
                    .font: mono, .foregroundColor: terminalAccent
                ]))
                let out = Self.toolDisplayOutput(output)
                combined.append(NSAttributedString(string: "  \(out)\n\n", attributes: [
                    .font: mono, .foregroundColor: terminalDim
                ]))
            case .answer(let text):
                combined.append(attributedMarkdownResponse(text))
                combined.append(NSAttributedString(string: "\n", attributes: [
                    .font: mono, .foregroundColor: terminalForeground
                ]))
            }
        }
        if !streamAccumulated.isEmpty {
            combined.append(attributedMarkdownResponse(streamAccumulated))
        }
        // Blinking-cursor style block while the model is still writing.
        if requestInFlight {
            combined.append(NSAttributedString(string: "▍", attributes: [
                .font: mono,
                .foregroundColor: terminalAccent
            ]))
        }
        responseTextView.textStorage?.setAttributedString(combined)
        responseTextView.scrollToEndOfDocument(nil)
        refreshThinkingIndicator()
    }

    /// Shows the rotating "Thinking…" indicator overlaid on the response pane
    /// while the model is reasoning; hides it once the answer streams in.
    private func refreshThinkingIndicator() {
        let show = modelIsThinking && requestInFlight
        thinkingSpinner.isHidden = !show
        thinkingLabel.isHidden = !show
        if show {
            thinkingSpinner.startAnimation(nil)
        } else {
            thinkingSpinner.stopAnimation(nil)
        }
    }

    /// Terminal-friendly tool label: "$ name (key: value, …)" instead of raw
    /// JSON arguments.
    static func toolDisplayLabel(name: String, args: String) -> String {
        if let data = args.data(using: .utf8),
           let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
           !obj.isEmpty {
            let pairs = obj.sorted { $0.key < $1.key }
                .map { "\($0.key): \($0.value)" }
                .joined(separator: ", ")
            return "$ \(name)(\(pairs))"
        }
        return "$ \(name)"
    }

    /// Terminal-friendly tool result: human-readable summary instead of the
    /// raw JSON envelope.
    static func toolDisplayOutput(_ raw: String) -> String {
        guard let data = raw.data(using: .utf8),
              let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            return String(raw.prefix(300))
        }
        if let error = obj["error"] as? String { return "error: \(error)" }
        if let output = obj["output"] as? String {           // run_command output
            let trimmed = output.trimmingCharacters(in: .whitespacesAndNewlines)
            let single = trimmed.replacingOccurrences(of: "\n", with: " ⏎ ")
            return single.isEmpty ? "(no output)" : String(single.prefix(300))
        }
        if let entries = obj["entries"] as? [String] {        // list_files
            let head = entries.prefix(12).joined(separator: ", ")
            return entries.isEmpty ? "(empty)" :
                "\(entries.count) entries: \(head)\(entries.count > 12 ? ", …" : "")"
        }
        if let matches = obj["matches"] as? [String] {        // search_files
            return matches.isEmpty ? "no matches" : "\(matches.count) matches"
        }
        if let content = obj["content"] as? String {          // read_file
            return "read \(content.count) chars"
        }
        if (obj["ok"] as? Bool) == true { return "ok" }
        return String(raw.prefix(300))
    }

    /// Renders an AI markdown reply as styled attributed text: headings become
    /// bold larger text, `**bold**` and `*italic*` are styled, `inline code`
    /// and fenced ``` code blocks render in monospace on a tinted background
    /// (with the fence's language tag line removed). Implemented by hand so it
    /// works with any macOS SDK (no Foundation Markdown API dependency).
    func attributedMarkdownResponse(_ markdown: String) -> NSAttributedString {
        let baseFont = NSFont.userFixedPitchFont(ofSize: 12)
            ?? NSFont.monospacedSystemFont(ofSize: 12, weight: .regular)
        let boldFont = NSFontManager.shared.convert(baseFont, toHaveTrait: .boldFontMask)
        let codeFont = baseFont
        let codeBackground = terminalCodeBackground
        let result = NSMutableAttributedString()

        func baseAttrs(_ font: NSFont) -> [NSAttributedString.Key: Any] {
            [.font: font, .foregroundColor: terminalForeground]
        }

        /// Appends `text` styling `**bold**` and `*italic*` runs on top of `font`.
        func appendEmphasis(_ text: String, font: NSFont) {
            var boldSegments = text.components(separatedBy: "**")
            if boldSegments.count % 2 == 0 { boldSegments = [text] } // unbalanced: render literally
            for (bi, boldSeg) in boldSegments.enumerated() {
                let segFont = bi % 2 == 1 ? Self.terminalBoldFont(size: 12) : font
                // Italic via single * or _ delimiters hugging non-space characters
                // (so `a * b` in code snippets stays literal).
                var marker: Character?
                var idx = boldSeg.startIndex
                var plainStart = idx
                while idx < boldSeg.endIndex {
                    let c = boldSeg[idx]
                    if (c == "*" || c == "_"), marker == nil,
                       idx > boldSeg.startIndex,
                       let next = boldSeg.index(idx, offsetBy: 1, limitedBy: boldSeg.endIndex),
                       next != boldSeg.endIndex,
                       !boldSeg[boldSeg.index(before: idx)].isWhitespace,
                       !boldSeg[next].isWhitespace {
                        marker = c
                        if plainStart < idx {
                            result.append(NSAttributedString(string: String(boldSeg[plainStart..<idx]),
                                                             attributes: baseAttrs(segFont)))
                        }
                        if let close = boldSeg[idx...].dropFirst().firstIndex(of: c) {
                            let inner = String(boldSeg[boldSeg.index(after: idx)..<close])
                            let italicFont = Self.terminalItalicFont(size: 12)
                            result.append(NSAttributedString(string: inner, attributes: baseAttrs(italicFont)))
                            idx = boldSeg.index(after: close)
                            plainStart = idx
                            marker = nil
                            continue
                        } else {
                            marker = nil
                        }
                    }
                    idx = boldSeg.index(after: idx)
                }
                if plainStart < boldSeg.endIndex {
                    result.append(NSAttributedString(string: String(boldSeg[plainStart...]),
                                                     attributes: baseAttrs(segFont)))
                }
            }
        }

        /// Appends one prose line, handling ATX headings and inline styles.
        func appendProseLine(_ line: String) {
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            if trimmed.hasPrefix("#") {
                let headingFont = boldFont
                let text = trimmed.drop(while: { $0 == "#" }).trimmingCharacters(in: .whitespaces)
                result.append(NSAttributedString(string: text, attributes: baseAttrs(headingFont)))
                result.append(NSAttributedString(string: "\n", attributes: baseAttrs(baseFont)))
                return
            }
            // Inline `code` first so emphasis markers inside code stay literal.
            let codeParts = line.components(separatedBy: "`")
            for (ci, part) in codeParts.enumerated() {
                if ci % 2 == 1 {
                    result.append(NSAttributedString(string: part, attributes: [
                        .font: codeFont,
                        .foregroundColor: terminalAccent,
                        .backgroundColor: codeBackground
                    ]))
                } else if !part.isEmpty {
                    appendEmphasis(part, font: baseFont)
                }
            }
            result.append(NSAttributedString(string: "\n", attributes: baseAttrs(baseFont)))
        }

        // Alternate between prose (even) and fenced code (odd) segments.
        let parts = markdown.components(separatedBy: "```")
        for (index, part) in parts.enumerated() {
            if index % 2 == 1 {
                var code = part
                // Drop the optional language tag on the first fence line.
                if let firstNewline = code.firstIndex(of: "\n") {
                    let firstLine = String(code[..<firstNewline]).trimmingCharacters(in: .whitespaces)
                    if !firstLine.isEmpty && !firstLine.contains(" ") {
                        code = String(code[firstNewline...])
                    }
                }
                code = code.trimmingCharacters(in: .whitespacesAndNewlines)
                result.append(NSAttributedString(string: code + "\n", attributes: [
                    .font: codeFont,
                    .foregroundColor: NSColor(white: 0.92, alpha: 1),
                    .backgroundColor: codeBackground
                ]))
            } else {
                for line in part.components(separatedBy: "\n") {
                    appendProseLine(line)
                }
            }
        }
        return result
    }

    /// Terminal fonts: named Menlo faces are deterministic; trait conversion
    /// via NSFontManager produced a CoreText TRunGlue crash on draw once, so
    /// it is only used as a last-resort fallback.
    static func terminalBaseFont(size: CGFloat) -> NSFont {
        NSFont(name: "Menlo-Regular", size: size)
            ?? NSFont.userFixedPitchFont(ofSize: size)
            ?? NSFont.monospacedSystemFont(ofSize: size, weight: .regular)
    }

    static func terminalBoldFont(size: CGFloat) -> NSFont {
        NSFont(name: "Menlo-Bold", size: size)
            ?? NSFontManager.shared.convert(terminalBaseFont(size: size), toHaveTrait: .boldFontMask)
    }

    static func terminalItalicFont(size: CGFloat) -> NSFont {
        NSFont(name: "Menlo-Italic", size: size)
            ?? NSFontManager.shared.convert(terminalBaseFont(size: size), toHaveTrait: .italicFontMask)
    }

    /// Replaces any font attribute that CoreText could choke on (zero/NaN
    /// size or nil) with a known-good font.
    static func sanitizeFonts(_ attr: NSAttributedString, fallback: NSFont) -> NSAttributedString {
        let fixed = NSMutableAttributedString(attributedString: attr)
        let full = NSRange(location: 0, length: fixed.length)
        fixed.enumerateAttribute(.font, in: full, options: []) { value, range, _ in
            guard let font = value as? NSFont else { return }
            if font.pointSize.isFinite == false || font.pointSize <= 0 {
                fixed.addAttribute(.font, value: fallback, range: range)
            }
        }
        return fixed
    }

    /// Test hook: exposes the system prompt for smoke tests.
    static func systemPromptForTest() -> String { systemPrompt(projectRoot: URL(fileURLWithPath: "/tmp")) }

    /// Test hook: exposes the resume state without touching private members.
    func resumeStateForTest() -> (canContinue: Bool, turns: Int, canNewChat: Bool) {
        (lastTaskInterrupted && !requestInFlight, conversation.count, newChatButton.isEnabled)
    }

    /// The system message sent with every request; anchors the model to the
    /// project currently open in Karma Pro and explains the sandboxed tools.
    private static func systemPrompt(projectRoot: URL?) -> String {
        var parts = ["You are a senior software analysis assistant embedded in Karma Pro, a static-analysis IDE."]
        if let root = projectRoot {
            parts.append("The user's project directory is: \(root.path)")
            parts.append("File paths in the conversation are relative to that directory.")
        }
        parts.append("You have tools to inspect the project: list_files, read_file, search_files, and run_command (read-only commands executed inside the project directory). Use them to analyse the actual source code before answering instead of guessing. All tools are strictly confined to the project directory: never read, list, search, or run anything outside it, and never attempt to modify or delete files. Prefer search_files/read_file over shell commands. Cite concrete file paths and line numbers in your answers.")
        return parts.joined(separator: " ")
    }

    private func setStatus(_ text: String, color: NSColor) {
        statusLabel.stringValue = text
        statusLabel.textColor = color
    }
}

extension AIWindowController: NSWindowDelegate {
    func windowWillClose(_ notification: Notification) {
        // Stop the in-flight stream so background work ends with the window.
        OpenRouterClient.shared.cancelActiveStream()
    }
}

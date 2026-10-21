// by cipher.org.uk
import AppKit

/// Sheet for managing OpenAI-compatible endpoints: lists the shipped presets
/// (read-only) plus the user's own, with add, edit, remove and test.
///
/// The editor is deliberately a separate sheet rather than inline cell editing:
/// a provider is a name, a base URL and whether it needs a key, and inline
/// editing of three fields across a table row invites half-saved states.
final class ProviderManagerController: NSWindowController {

    /// Fired after any change, so the AI window can rebuild its dropdown.
    var onChange: (() -> Void)?

    private let tableView = NSTableView()
    private let addButton = NSButton(title: "Add…", target: nil, action: nil)
    private let editButton = NSButton(title: "Edit…", target: nil, action: nil)
    private let removeButton = NSButton(title: "Remove", target: nil, action: nil)
    private let testButton = NSButton(title: "Test", target: nil, action: nil)
    private let closeButton = NSButton(title: "Done", target: nil, action: nil)
    private let statusLabel = NSTextField(wrappingLabelWithString: "")
    private let spinner = NSProgressIndicator()

    private var providers: [AIProviderConfig] = []

    convenience init() {
        let window = NSWindow(
            contentRect: NSRect(x: 0, y: 0, width: 620, height: 380),
            styleMask: [.titled, .closable, .miniaturizable],
            backing: .buffered,
            defer: false)
        window.title = "AI Providers"
        window.center()
        self.init(window: window)
        buildUI()
        reload()
    }

    private func buildUI() {
        guard let content = window?.contentView else { return }

        let header = NSTextField(wrappingLabelWithString:
            "Karma Pro ships with OpenRouter and Ollama. Add any OpenAI-compatible endpoint "
            + ", including a local server such as LM Studio, vLLM or llama.cpp.")
        header.font = NSFont.systemFont(ofSize: 12)
        header.textColor = .secondaryLabelColor
        header.translatesAutoresizingMaskIntoConstraints = false
        content.addSubview(header)

        tableView.usesAlternatingRowBackgroundColors = true
        tableView.allowsMultipleSelection = false
        tableView.rowHeight = 22
        tableView.dataSource = self
        tableView.delegate = self
        tableView.doubleAction = #selector(editClicked(_:))
        tableView.target = self

        let nameColumn = NSTableColumn(identifier: NSUserInterfaceItemIdentifier("name"))
        nameColumn.title = "Name"
        nameColumn.width = 190
        let urlColumn = NSTableColumn(identifier: NSUserInterfaceItemIdentifier("url"))
        urlColumn.title = "Base URL"
        urlColumn.width = 300
        let keyColumn = NSTableColumn(identifier: NSUserInterfaceItemIdentifier("key"))
        keyColumn.title = "Key"
        keyColumn.width = 70
        tableView.addTableColumn(nameColumn)
        tableView.addTableColumn(urlColumn)
        tableView.addTableColumn(keyColumn)

        let scroll = NSScrollView()
        scroll.documentView = tableView
        scroll.hasVerticalScroller = true
        scroll.borderType = .bezelBorder
        scroll.translatesAutoresizingMaskIntoConstraints = false
        content.addSubview(scroll)

        for (button, tip, selector) in [
            (addButton, "Add an OpenAI-compatible endpoint", #selector(addClicked(_:))),
            (editButton, "Edit the selected endpoint's name, URL or key", #selector(editClicked(_:))),
            (removeButton, "Remove the selected endpoint and its saved key", #selector(removeClicked(_:))),
            (testButton, "Check the endpoint answers and the model can be used", #selector(testClicked(_:))),
            (closeButton, "Close this window", #selector(closeClicked(_:)))
        ] as [(NSButton, String, Selector)] {
            button.bezelStyle = .rounded
            button.controlSize = .regular
            button.toolTip = tip
            button.target = self
            button.action = selector
            button.translatesAutoresizingMaskIntoConstraints = false
            content.addSubview(button)
        }
        closeButton.keyEquivalent = "\r"

        spinner.controlSize = .small
        spinner.style = .spinning
        spinner.isDisplayedWhenStopped = false
        spinner.translatesAutoresizingMaskIntoConstraints = false
        content.addSubview(spinner)

        statusLabel.font = NSFont.systemFont(ofSize: 11)
        statusLabel.textColor = .secondaryLabelColor
        statusLabel.translatesAutoresizingMaskIntoConstraints = false
        content.addSubview(statusLabel)

        NSLayoutConstraint.activate([
            header.topAnchor.constraint(equalTo: content.topAnchor, constant: 16),
            header.leadingAnchor.constraint(equalTo: content.leadingAnchor, constant: 20),
            header.trailingAnchor.constraint(equalTo: content.trailingAnchor, constant: -20),

            scroll.topAnchor.constraint(equalTo: header.bottomAnchor, constant: 12),
            scroll.leadingAnchor.constraint(equalTo: content.leadingAnchor, constant: 20),
            scroll.trailingAnchor.constraint(equalTo: content.trailingAnchor, constant: -20),
            scroll.bottomAnchor.constraint(equalTo: addButton.topAnchor, constant: -14),

            addButton.leadingAnchor.constraint(equalTo: content.leadingAnchor, constant: 20),
            editButton.leadingAnchor.constraint(equalTo: addButton.trailingAnchor, constant: 8),
            removeButton.leadingAnchor.constraint(equalTo: editButton.trailingAnchor, constant: 8),
            testButton.leadingAnchor.constraint(equalTo: removeButton.trailingAnchor, constant: 8),
            closeButton.trailingAnchor.constraint(equalTo: content.trailingAnchor, constant: -20),

            spinner.leadingAnchor.constraint(equalTo: testButton.trailingAnchor, constant: 12),
            spinner.centerYAnchor.constraint(equalTo: addButton.centerYAnchor),

            statusLabel.topAnchor.constraint(equalTo: addButton.bottomAnchor, constant: 10),
            statusLabel.leadingAnchor.constraint(equalTo: content.leadingAnchor, constant: 20),
            statusLabel.trailingAnchor.constraint(equalTo: content.trailingAnchor, constant: -20),
            statusLabel.bottomAnchor.constraint(equalTo: content.bottomAnchor, constant: -16),

            editButton.centerYAnchor.constraint(equalTo: addButton.centerYAnchor),
            removeButton.centerYAnchor.constraint(equalTo: addButton.centerYAnchor),
            testButton.centerYAnchor.constraint(equalTo: addButton.centerYAnchor),
            closeButton.centerYAnchor.constraint(equalTo: addButton.centerYAnchor)
        ])
    }

    private func reload() {
        providers = ProviderStore.shared.providers
        tableView.reloadData()
        updateButtons()
    }

    private func updateButtons() {
        let selected = selectedProvider()
        // Shipped presets are not editable or removable.
        let editable = selected != nil && selected?.isBuiltin == false
        editButton.isEnabled = editable
        removeButton.isEnabled = editable
        testButton.isEnabled = selected != nil
    }

    private func selectedProvider() -> AIProviderConfig? {
        let row = tableView.selectedRow
        guard row >= 0, row < providers.count else { return nil }
        return providers[row]
    }

    private func setStatus(_ text: String, color: NSColor = .secondaryLabelColor) {
        statusLabel.stringValue = text
        statusLabel.textColor = color
    }

    // MARK: - Actions

    @objc private func addClicked(_ sender: Any?) {
        showEditor(existing: nil)
    }

    @objc private func editClicked(_ sender: Any?) {
        guard let provider = selectedProvider(), !provider.isBuiltin else { return }
        showEditor(existing: provider)
    }

    @objc private func removeClicked(_ sender: Any?) {
        guard let provider = selectedProvider(), !provider.isBuiltin else { return }
        let alert = NSAlert()
        alert.messageText = "Remove Provider"
        alert.informativeText = "Remove \"\(provider.name)\" and its saved API key?"
        alert.addButton(withTitle: "Remove")
        alert.addButton(withTitle: "Cancel")
        guard alert.runModal() == .alertFirstButtonReturn else { return }
        ProviderStore.shared.remove(id: provider.id)
        // Drop the key/model so a removed endpoint leaves no secret behind.
        UserDefaults.standard.removeObject(forKey: "AI.\(provider.id).apiKey")
        UserDefaults.standard.removeObject(forKey: "AI.\(provider.id).model")
        // If the AI window was using it, fall back to the shipped default.
        if OpenRouterClient.shared.providerID == provider.id {
            OpenRouterClient.shared.provider = .openRouter
        }
        reload()
        onChange?()
        setStatus("Removed \(provider.name).", color: .systemGreen)
    }

    @objc private func testClicked(_ sender: Any?) {
        guard let provider = selectedProvider() else { return }
        let key = UserDefaults.standard.string(forKey: "AI.\(provider.id).apiKey") ?? ""
        let model = UserDefaults.standard.string(forKey: "AI.\(provider.id).model") ?? ""
        let urlString = provider.isOllama ? OpenRouterClient.shared.ollamaServerURLString : provider.baseURL
        guard let url = URL(string: urlString) else {
            setStatus("Invalid base URL.", color: .systemRed)
            return
        }
        spinner.startAnimation(nil)
        setStatus("Testing \(provider.name)…")
        OpenRouterClient.shared.testConnection(
            name: provider.name, baseURL: url, apiKey: key,
            model: model.isEmpty ? nil : model,
            requiresAPIKey: provider.requiresAPIKey) { [weak self] result in
                DispatchQueue.main.async {
                    guard let self = self else { return }
                    self.spinner.stopAnimation(nil)
                    switch result {
                    case .success(let count):
                        self.setStatus("\(provider.name) OK — \(count) model(s) available.", color: .systemGreen)
                    case .failure(let error):
                        self.setStatus("\(provider.name): \(error.localizedDescription)", color: .systemRed)
                    }
                }
            }
    }

    @objc private func closeClicked(_ sender: Any?) {
        window?.sheetParent?.endSheet(window!)
        window?.close()
    }

    // MARK: - Editor sheet

    /// Presents the add/edit form, validating before it writes anything.
    private func showEditor(existing: AIProviderConfig?) {
        let editor = ProviderEditorController(provider: existing) { [weak self] saved in
            guard let self = self else { return }
            if existing == nil {
                ProviderStore.shared.add(saved)
            } else {
                ProviderStore.shared.update(saved)
            }
            self.reload()
            self.onChange?()
            self.setStatus("Saved \(saved.name).", color: .systemGreen)
        }
        guard let window = window else { return }
        window.beginSheet(editor.window!) { _ in }
    }
}

// MARK: - Table data

extension ProviderManagerController: NSTableViewDataSource, NSTableViewDelegate {
    func numberOfRows(in tableView: NSTableView) -> Int { providers.count }

    func tableView(_ tableView: NSTableView, viewFor tableColumn: NSTableColumn?, row: Int) -> NSView? {
        guard row < providers.count, let column = tableColumn else { return nil }
        let provider = providers[row]
        let identifier = column.identifier

        let cell: NSTextField
        if let reused = tableView.makeView(withIdentifier: identifier, owner: self) as? NSTextField {
            cell = reused
        } else {
            cell = NSTextField(labelWithString: "")
            cell.identifier = identifier
            cell.font = NSFont.systemFont(ofSize: 12)
            cell.lineBreakMode = .byTruncatingMiddle
            cell.usesSingleLineMode = true
            cell.maximumNumberOfLines = 1
        }

        switch identifier.rawValue {
        case "name":
            cell.stringValue = provider.isBuiltin ? provider.name + "  (built-in)" : provider.name
            cell.textColor = provider.isBuiltin ? .secondaryLabelColor : .labelColor
        case "url":
            cell.stringValue = provider.isOllama ? OpenRouterClient.shared.ollamaServerURLString : provider.baseURL
            cell.textColor = .secondaryLabelColor
        default:
            cell.stringValue = provider.requiresAPIKey ? "required" : "none"
            cell.textColor = .secondaryLabelColor
        }
        return cell
    }

    func tableViewSelectionDidChange(_ notification: Notification) {
        updateButtons()
    }
}

/// Add/edit form for one endpoint. Validates name uniqueness and the base URL,
/// and keeps the key in a separate secure field; the key is written to storage
/// only when the form is saved.
final class ProviderEditorController: NSWindowController {

    private let nameField = NSTextField()
    private let urlField = NSTextField()
    private let keyField = NSSecureTextField()
    private let requiresKeyCheckbox = NSButton(checkboxWithTitle: "This endpoint requires an API key",
                                               target: nil, action: nil)
    private let keyLabel = NSTextField(labelWithString: "API Key:")

    private let existing: AIProviderConfig?
    private let onSave: (AIProviderConfig) -> Void

    init(provider: AIProviderConfig?, onSave: @escaping (AIProviderConfig) -> Void) {
        self.existing = provider
        self.onSave = onSave
        let window = NSWindow(
            contentRect: NSRect(x: 0, y: 0, width: 460, height: 240),
            styleMask: [.titled],
            backing: .buffered,
            defer: false)
        window.title = provider == nil ? "Add Provider" : "Edit Provider"
        super.init(window: window)
        buildUI()
    }

    required init?(coder: NSCoder) { fatalError("init(coder:) has not been implemented") }

    private func buildUI() {
        guard let content = window?.contentView else { return }

        let nameLabel = NSTextField(labelWithString: "Name:")
        let urlLabel = NSTextField(labelWithString: "Base URL:")
        let hint = NSTextField(wrappingLabelWithString:
            "The OpenAI-compatible root, e.g. https://api.example.com/v1 — a trailing "
            + "/chat/completions is stripped automatically.")
        hint.font = NSFont.systemFont(ofSize: 11)
        hint.textColor = .secondaryLabelColor

        for label in [nameLabel, urlLabel, keyLabel] {
            label.font = NSFont.systemFont(ofSize: 12)
            label.textColor = .secondaryLabelColor
            label.translatesAutoresizingMaskIntoConstraints = false
            content.addSubview(label)
        }
        nameLabel.alignment = .right
        urlLabel.alignment = .right
        keyLabel.alignment = .right

        nameField.placeholderString = "My Provider"
        urlField.placeholderString = "https://api.example.com/v1"
        keyField.placeholderString = "sk-…"
        for field in [nameField, urlField, keyField] {
            field.font = NSFont.systemFont(ofSize: 12)
            field.translatesAutoresizingMaskIntoConstraints = false
            content.addSubview(field)
        }

        // Keyed endpoints get the attribution-free bearer path; keyless ones
        // are typically local servers.
        requiresKeyCheckbox.state = (existing?.requiresAPIKey ?? true) ? .on : .off
        requiresKeyCheckbox.target = self
        requiresKeyCheckbox.action = #selector(requiresKeyToggled(_:))
        requiresKeyCheckbox.translatesAutoresizingMaskIntoConstraints = false
        content.addSubview(requiresKeyCheckbox)

        hint.translatesAutoresizingMaskIntoConstraints = false
        content.addSubview(hint)

        let cancel = NSButton(title: "Cancel", target: self, action: #selector(cancelClicked(_:)))
        let save = NSButton(title: existing == nil ? "Add" : "Save", target: self, action: #selector(saveClicked(_:)))
        save.keyEquivalent = "\r"
        for button in [cancel, save] {
            button.bezelStyle = .rounded
            button.translatesAutoresizingMaskIntoConstraints = false
            content.addSubview(button)
        }

        NSLayoutConstraint.activate([
            nameLabel.topAnchor.constraint(equalTo: content.topAnchor, constant: 22),
            nameLabel.leadingAnchor.constraint(equalTo: content.leadingAnchor, constant: 20),
            nameLabel.widthAnchor.constraint(equalToConstant: 80),
            nameField.leadingAnchor.constraint(equalTo: nameLabel.trailingAnchor, constant: 8),
            nameField.trailingAnchor.constraint(equalTo: content.trailingAnchor, constant: -20),
            nameField.centerYAnchor.constraint(equalTo: nameLabel.centerYAnchor),

            urlLabel.topAnchor.constraint(equalTo: nameField.bottomAnchor, constant: 14),
            urlLabel.leadingAnchor.constraint(equalTo: content.leadingAnchor, constant: 20),
            urlLabel.widthAnchor.constraint(equalToConstant: 80),
            urlField.leadingAnchor.constraint(equalTo: urlLabel.trailingAnchor, constant: 8),
            urlField.trailingAnchor.constraint(equalTo: content.trailingAnchor, constant: -20),
            urlField.centerYAnchor.constraint(equalTo: urlLabel.centerYAnchor),

            hint.topAnchor.constraint(equalTo: urlField.bottomAnchor, constant: 4),
            hint.leadingAnchor.constraint(equalTo: urlField.leadingAnchor),
            hint.trailingAnchor.constraint(equalTo: urlField.trailingAnchor),

            requiresKeyCheckbox.topAnchor.constraint(equalTo: hint.bottomAnchor, constant: 12),
            requiresKeyCheckbox.leadingAnchor.constraint(equalTo: urlField.leadingAnchor),

            keyLabel.topAnchor.constraint(equalTo: requiresKeyCheckbox.bottomAnchor, constant: 12),
            keyLabel.leadingAnchor.constraint(equalTo: content.leadingAnchor, constant: 20),
            keyLabel.widthAnchor.constraint(equalToConstant: 80),
            keyField.leadingAnchor.constraint(equalTo: keyLabel.trailingAnchor, constant: 8),
            keyField.trailingAnchor.constraint(equalTo: content.trailingAnchor, constant: -20),
            keyField.centerYAnchor.constraint(equalTo: keyLabel.centerYAnchor),

            save.bottomAnchor.constraint(equalTo: content.bottomAnchor, constant: -16),
            save.trailingAnchor.constraint(equalTo: content.trailingAnchor, constant: -20),
            cancel.trailingAnchor.constraint(equalTo: save.leadingAnchor, constant: -8),
            cancel.centerYAnchor.constraint(equalTo: save.centerYAnchor),
            cancel.topAnchor.constraint(greaterThanOrEqualTo: keyField.bottomAnchor, constant: 14)
        ])

        // Prefill when editing; the key is read back from storage.
        if let existing = existing {
            nameField.stringValue = existing.name
            urlField.stringValue = existing.baseURL
            keyField.stringValue = UserDefaults.standard.string(forKey: "AI.\(existing.id).apiKey") ?? ""
        }
        toggledKeyField()
    }

    @objc private func requiresKeyToggled(_ sender: Any?) { toggledKeyField() }

    private func toggledKeyField() {
        let needs = requiresKeyCheckbox.state == .on
        keyField.isEnabled = needs
        keyLabel.textColor = needs ? .secondaryLabelColor : .tertiaryLabelColor
    }

    @objc private func cancelClicked(_ sender: Any?) {
        window?.sheetParent?.endSheet(window!)
    }

    @objc private func saveClicked(_ sender: Any?) {
        let name = nameField.stringValue.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !name.isEmpty else { alert("Enter a name for this provider."); return }
        guard !ProviderStore.shared.nameExists(name, excluding: existing?.id) else {
            alert("Another provider already uses the name \"\(name)\"."); return
        }
        guard let normalized = ProviderStore.normalizeBaseURL(urlField.stringValue) else {
            alert("Enter a valid base URL, e.g. https://api.example.com/v1"); return
        }
        let requiresKey = requiresKeyCheckbox.state == .on
        let key = keyField.stringValue.trimmingCharacters(in: .whitespacesAndNewlines)
        if requiresKey && key.isEmpty {
            alert("This endpoint requires an API key."); return
        }

        let id = existing?.id ?? "custom.\(UUID().uuidString)"
        let provider = AIProviderConfig(id: id, name: name, baseURL: normalized,
                                        requiresAPIKey: requiresKey, isBuiltin: false)
        // Store the key under the stable id, so editing the name keeps it.
        UserDefaults.standard.set(key, forKey: "AI.\(id).apiKey")
        onSave(provider)
        window?.sheetParent?.endSheet(window!)
    }

    private func alert(_ message: String) {
        let alert = NSAlert()
        alert.messageText = "Cannot Save Provider"
        alert.informativeText = message
        alert.alertStyle = .warning
        alert.addButton(withTitle: "OK")
        alert.runModal()
    }
}

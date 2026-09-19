// by cipher.org.uk
import AppKit
import UniformTypeIdentifiers

/// Lets the user point the app at a directory of software patches, name the
/// training model, and train a Bayesian classifier over the "+" (good) and
/// "-" (bad) lines of every patch/diff file.
final class MLTrainingWindowController: NSWindowController {

    private let folderField = NSTextField(wrappingLabelWithString: "No patch folder chosen.")
    private let chooseButton = NSButton(title: "Choose Patch Folder…", target: nil, action: nil)
    private let nameField = NSTextField(string: "")
    private let languagePopup = NSPopUpButton(frame: .zero, pullsDown: false)
    private let progressBar = NSProgressIndicator()
    private let trainButton = NSButton(title: "Train Model", target: nil, action: nil)
    private let exportButton = NSButton(title: "Export Model…", target: nil, action: nil)
    private let importButton = NSButton(title: "Import Model…", target: nil, action: nil)
    private let importURLButton = NSButton(title: "Import from URL…", target: nil, action: nil)
    private let statusLabel = NSTextField(wrappingLabelWithString: "")
    private let trainedModelsLabel = NSTextField(wrappingLabelWithString: "")

    private var patchRoot: URL?

    convenience init() {
        let window = EscClosableWindow(
            contentRect: NSRect(x: 0, y: 0, width: 620, height: 400),
            styleMask: [.titled, .closable, .miniaturizable, .resizable],
            backing: .buffered,
            defer: false
        )
        window.title = "Train Bayesian Classifier"
        window.minSize = NSSize(width: 560, height: 360)
        window.center()
        self.init(window: window)
        buildContent()
    }

    /// Re-center the window each time it is shown.
    override func showWindow(_ sender: Any?) {
        super.showWindow(sender)
        window?.center()
    }

    private func buildContent() {
        guard let content = window?.contentView else { return }

        let intro = NSTextField(wrappingLabelWithString: "Point at a folder of software patches (.patch/.diff). Lines starting with “+” are treated as good code; “-” lines as bad (vulnerable) code.")
        intro.font = NSFont.systemFont(ofSize: 12)
        intro.textColor = .secondaryLabelColor

        let chooseRow = NSStackView(views: [chooseButton, folderField])
        chooseRow.orientation = .horizontal
        chooseRow.alignment = .centerY
        chooseRow.spacing = 10

        let nameLabel = NSTextField(labelWithString: "Model name:")
        nameField.placeholderString = "e.g. CVE-2024-patches"
        nameField.font = NSFont.systemFont(ofSize: 12)

        let nameRow = NSStackView(views: [nameLabel, nameField])
        nameRow.orientation = .horizontal
        nameRow.alignment = .centerY
        nameRow.spacing = 10

        let langLabel = NSTextField(labelWithString: "Language:")
        languagePopup.addItems(withTitles: Language.supported.filter { $0.name != "All Languages" }.map { $0.name })
        languagePopup.selectItem(at: 0)
        languagePopup.target = self
        languagePopup.action = #selector(languageChanged)
        let trainRow = NSStackView(views: [langLabel, languagePopup, trainButton])
        trainRow.orientation = .horizontal
        trainRow.alignment = .centerY
        trainRow.spacing = 10

        progressBar.style = .bar
        progressBar.minValue = 0
        progressBar.maxValue = 1
        progressBar.isIndeterminate = false
        progressBar.isHidden = true

        statusLabel.font = NSFont.systemFont(ofSize: 12)
        statusLabel.textColor = .secondaryLabelColor

        trainButton.bezelStyle = .rounded
        trainButton.keyEquivalent = "\r"
        trainButton.target = self
        trainButton.action = #selector(trainClicked)

        chooseButton.target = self
        chooseButton.action = #selector(chooseClicked)

        let transferRow = NSStackView(views: [exportButton, importButton, importURLButton])
        transferRow.orientation = .horizontal
        transferRow.alignment = .centerY
        transferRow.spacing = 10
        exportButton.target = self
        exportButton.action = #selector(exportClicked)
        importButton.target = self
        importButton.action = #selector(importClicked)
        importURLButton.target = self
        importURLButton.action = #selector(importURLClicked)

        let contentStack = NSStackView(views: [intro, chooseRow, nameRow, progressBar, trainRow, transferRow, statusLabel, trainedModelsLabel])
        contentStack.orientation = .vertical
        contentStack.alignment = .width
        contentStack.spacing = 12
        contentStack.translatesAutoresizingMaskIntoConstraints = false

        intro.setContentCompressionResistancePriority(.defaultLow, for: .horizontal)
        folderField.setContentCompressionResistancePriority(.defaultLow, for: .horizontal)
        nameField.setContentCompressionResistancePriority(.defaultLow, for: .horizontal)
        [chooseButton, nameLabel, langLabel, exportButton, importButton, importURLButton, statusLabel, trainedModelsLabel].forEach { $0.setContentHuggingPriority(.required, for: .horizontal) }
        statusLabel.maximumNumberOfLines = 0
        trainedModelsLabel.maximumNumberOfLines = 0

        nameField.widthAnchor.constraint(greaterThanOrEqualToConstant: 260).isActive = true

        content.addSubview(contentStack)
        NSLayoutConstraint.activate([
            contentStack.topAnchor.constraint(equalTo: content.topAnchor, constant: 20),
            contentStack.leadingAnchor.constraint(equalTo: content.leadingAnchor, constant: 20),
            contentStack.trailingAnchor.constraint(equalTo: content.trailingAnchor, constant: -20),
            contentStack.bottomAnchor.constraint(lessThanOrEqualTo: content.bottomAnchor, constant: -20)
        ])

        refreshModelsLabel()
    }

    private func refreshModelsLabel() {
        let names = ModelStore.shared.listModels()
        if names.isEmpty {
            trainedModelsLabel.stringValue = "No trained models yet."
        } else {
            trainedModelsLabel.stringValue = "Saved models: " + names.joined(separator: ", ")
        }
    }

    @objc private func chooseClicked() {
        let panel = NSOpenPanel()
        panel.canChooseFiles = false
        panel.canChooseDirectories = true
        panel.allowsMultipleSelection = false
        panel.message = "Choose a folder of software patches (.patch / .diff)"
        if panel.runModal() == .OK, let url = panel.url {
            patchRoot = url
            folderField.stringValue = url.path
        }
    }

    @objc private func languageChanged(_ sender: NSPopUpButton) {}

    @objc private func trainClicked() {
        guard let root = patchRoot else {
            presentAlert("No patch folder chosen", "Use “Choose Patch Folder…” to select a directory of patches first.")
            return
        }
        let name = nameField.stringValue.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !name.isEmpty else {
            presentAlert("No model name", "Enter a name for the training model.")
            return
        }

        let model = BayesianClassifier(name: name)
        trainButton.isEnabled = false
        progressBar.isHidden = false
        progressBar.doubleValue = 0
        statusLabel.stringValue = "Reading patches…"

        let selectedLang = Language.supported.first { $0.name == languagePopup.titleOfSelectedItem ?? "" }
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            let (patches, lines) = PatchTrainer.train(model: model, in: root, language: selectedLang) { done, total in
                DispatchQueue.main.async {
                    self?.progressBar.doubleValue = Double(done) / Double(total)
                }
            }
            let saved = ModelStore.shared.save(model)
            DispatchQueue.main.async {
                guard let self = self else { return }
                self.trainButton.isEnabled = true
                self.progressBar.isHidden = true
                if saved {
                    self.statusLabel.stringValue = "Trained on \(patches) patch(es), \(lines) lines. Model “\(name)” saved."
                } else {
                    self.statusLabel.stringValue = "Training finished but failed to save the model."
                }
                self.refreshModelsLabel()
            }
        }
    }

    @objc private func exportClicked() {
        let names = ModelStore.shared.listModels()
        guard !names.isEmpty else {
            presentAlert("No Models", "There are no trained models to export yet.")
            return
        }

        let alert = NSAlert()
        alert.messageText = "Export Model"
        alert.informativeText = "Choose a trained model to export:"
        alert.addButton(withTitle: "Export")
        alert.addButton(withTitle: "Cancel")
        let popup = NSPopUpButton(frame: NSRect(x: 0, y: 0, width: 280, height: 26), pullsDown: false)
        popup.addItems(withTitles: names)
        alert.accessoryView = popup
        guard alert.runModal() == .alertFirstButtonReturn else { return }
        let name = popup.titleOfSelectedItem ?? ""
        guard let model = ModelStore.shared.load(named: name) else { return }

        let panel = NSSavePanel()
        panel.title = "Export Model"
        panel.nameFieldStringValue = "\(name).karmamodel"
        panel.allowedContentTypes = [UTType(filenameExtension: "karmamodel") ?? .data]
        panel.canCreateDirectories = true
        guard panel.runModal() == .OK, let url = panel.url else { return }

        if ModelStore.shared.export(model, to: url) {
            presentAlert("Exported", "Model “\(name)” exported to \(url.path)")
        } else {
            presentAlert("Export Failed", "Could not write the model file.")
        }
    }

    @objc private func importClicked() {
        let panel = NSOpenPanel()
        panel.title = "Import Model"
        panel.canChooseFiles = true
        panel.canChooseDirectories = false
        panel.allowsMultipleSelection = false
        panel.allowedContentTypes = [UTType(filenameExtension: "karmamodel") ?? .data, UTType(filenameExtension: "json") ?? .json]
        panel.message = "Choose a Karma Pro model file (.karmamodel or .json)"
        guard panel.runModal() == .OK, let url = panel.url else { return }

        let result = ModelStore.shared.importModel(from: url)
        if let model = result.model {
            presentAlert("Imported", "Imported model “\(model.name)”.")
            refreshModelsLabel()
        } else {
            presentAlert("Import Failed", result.error)
        }
    }

    @objc private func importURLClicked() {
        let alert = NSAlert()
        alert.messageText = "Import Model from URL"
        alert.informativeText = "Enter the web address of a raw Karma Pro model file (.karmamodel or .json):"
        alert.addButton(withTitle: "Import")
        alert.addButton(withTitle: "Cancel")
        let field = NSTextField(frame: NSRect(x: 0, y: 0, width: 380, height: 24))
        field.placeholderString = "https://example.com/model.json"
        field.font = NSFont.systemFont(ofSize: 13)
        alert.accessoryView = field
        guard alert.runModal() == .alertFirstButtonReturn else { return }
        let raw = field.stringValue.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !raw.isEmpty, let url = URL(string: raw) else {
            presentAlert("Invalid URL", "Enter a valid web address.")
            return
        }

        importURLButton.isEnabled = false
        statusLabel.stringValue = "Downloading model…"

        let task = URLSession.shared.dataTask(with: url) { [weak self] data, response, error in
            DispatchQueue.main.async {
                guard let self = self else { return }
                self.importURLButton.isEnabled = true
                if let error = error {
                    self.statusLabel.stringValue = "Import failed: \(error.localizedDescription)"
                    return
                }
                if let http = response as? HTTPURLResponse, !(200...299).contains(http.statusCode) {
                    self.statusLabel.stringValue = "Import failed: server returned HTTP \(http.statusCode)."
                    return
                }
                guard let data = data, !data.isEmpty else {
                    self.statusLabel.stringValue = "Import failed: no data received."
                    return
                }
                let result = ModelStore.shared.importModel(fromData: data)
                if let model = result.model {
                    self.statusLabel.stringValue = "Imported model “\(model.name)” from URL."
                    self.refreshModelsLabel()
                } else {
                    self.statusLabel.stringValue = "Import failed: \(result.error)"
                }
            }
        }
        task.resume()
    }

    private func presentAlert(_ title: String, _ message: String) {
        let alert = NSAlert()
        alert.messageText = title
        alert.informativeText = message
        alert.addButton(withTitle: "OK")
        alert.runModal()
    }
}

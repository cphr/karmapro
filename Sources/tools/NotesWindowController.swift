// by cipher.org.uk
import AppKit
import UniformTypeIdentifiers

/// Displays all notes recorded for the opened project in a table (file, line,
/// text). Clicking a row asks the main window to load that file and jump to the
/// line where the note was added.
final class NotesWindowController: NSWindowController {
    private let tableView = NSTableView()
    private let scrollView = NSScrollView()
    private let statusLabel = NSTextField(wrappingLabelWithString: "No notes yet.")
    private let exportButton = NSButton(title: "Export Notes…", target: nil, action: nil)
    private let importButton = NSButton(title: "Import Notes…", target: nil, action: nil)
    private let importURLButton = NSButton(title: "Import from URL…", target: nil, action: nil)

    private var notes: [NoteStore.StoredNote] = []

    /// The project folder the notes belong to. Used to store exported note keys
    /// relative to the project root so they are portable across machines/users.
    var projectRootURL: URL?

    /// Invoked when the user opens a note; passes the file path and 1-based line.
    var onOpenNote: ((String, Int) -> Void)?

    convenience init() {
        let window = EscClosableWindow(
            contentRect: NSRect(x: 0, y: 0, width: 760, height: 520),
            styleMask: [.titled, .closable, .resizable],
            backing: .buffered,
            defer: false
        )
        window.title = "Notes"
        window.minSize = NSSize(width: 480, height: 300)
        self.init(window: window)
        buildContent()
        // Center the window on the screen
        centerWindowOnScreen()
    }

    private func buildContent() {
        guard let content = window?.contentView else { return }

        statusLabel.font = NSFont.systemFont(ofSize: 12)
        statusLabel.textColor = .secondaryLabelColor
        statusLabel.setContentHuggingPriority(.defaultLow, for: .horizontal)
        statusLabel.translatesAutoresizingMaskIntoConstraints = false

        exportButton.bezelStyle = .rounded
        exportButton.target = self
        exportButton.action = #selector(exportClicked)
        importButton.bezelStyle = .rounded
        importButton.target = self
        importButton.action = #selector(importClicked)
        importURLButton.bezelStyle = .rounded
        importURLButton.target = self
        importURLButton.action = #selector(importURLClicked)

        let headerRow = NSStackView(views: [statusLabel, exportButton, importButton, importURLButton])
        headerRow.orientation = .horizontal
        headerRow.alignment = .centerY
        headerRow.spacing = 10
        headerRow.setHuggingPriority(.required, for: .horizontal)
        headerRow.translatesAutoresizingMaskIntoConstraints = false
        content.addSubview(headerRow)

        let fileColumn = NSTableColumn(identifier: NSUserInterfaceItemIdentifier("file"))
        fileColumn.title = "File"
        fileColumn.width = 240

        let lineColumn = NSTableColumn(identifier: NSUserInterfaceItemIdentifier("line"))
        lineColumn.title = "Line"
        lineColumn.width = 50

        let textColumn = NSTableColumn(identifier: NSUserInterfaceItemIdentifier("text"))
        textColumn.title = "Note"
        textColumn.width = 420
        textColumn.resizingMask = .autoresizingMask

        tableView.addTableColumn(fileColumn)
        tableView.addTableColumn(lineColumn)
        tableView.addTableColumn(textColumn)

        tableView.usesAlternatingRowBackgroundColors = true
        tableView.usesAutomaticRowHeights = true
        tableView.columnAutoresizingStyle = .lastColumnOnlyAutoresizingStyle
        tableView.dataSource = self
        tableView.delegate = self
        tableView.target = self
        tableView.action = #selector(rowClicked(_:))
        tableView.doubleAction = #selector(rowDoubleClicked(_:))

        scrollView.documentView = tableView
        scrollView.hasVerticalScroller = true
        scrollView.autohidesScrollers = true
        scrollView.translatesAutoresizingMaskIntoConstraints = false
        content.addSubview(scrollView)

        NSLayoutConstraint.activate([
            headerRow.topAnchor.constraint(equalTo: content.topAnchor, constant: 12),
            headerRow.leadingAnchor.constraint(equalTo: content.leadingAnchor, constant: 16),
            headerRow.trailingAnchor.constraint(equalTo: content.trailingAnchor, constant: -16),
            scrollView.topAnchor.constraint(equalTo: headerRow.bottomAnchor, constant: 8),
            scrollView.bottomAnchor.constraint(equalTo: content.bottomAnchor),
            scrollView.leadingAnchor.constraint(equalTo: content.leadingAnchor),
            scrollView.trailingAnchor.constraint(equalTo: content.trailingAnchor)
        ])

        // Center the window on the screen
        centerWindowOnScreen()

        reloadNotes()
    }

    // MARK: - Window positioning

    private func centerWindowOnScreen() {
        guard let window = window,
              let screen = window.screen else { return }
        let screenFrame = screen.visibleFrame
        let windowSize = window.frame.size
        let x = screenFrame.midX - windowSize.width / 2
        let y = screenFrame.midY - windowSize.height / 2
        window.setFrameOrigin(NSPoint(x: x, y: y))
    }

    /// Reloads notes from the store and refreshes the table. When a project root is
    /// set, only notes belonging to that project are shown (never other projects).
    func reloadNotes() {
        if let root = projectRootURL {
            notes = NoteStore.shared.notes(forProject: root)
        } else {
            notes = NoteStore.shared.allNotes()
        }
        tableView.reloadData()
        if notes.isEmpty {
            statusLabel.stringValue = "No notes yet."
        } else {
            statusLabel.stringValue = "\(notes.count) note\(notes.count == 1 ? "" : "s")"
        }
    }

    private func selectedNote() -> NoteStore.StoredNote? {
        let row = tableView.selectedRow
        guard row >= 0, row < notes.count else { return nil }
        return notes[row]
    }

    @objc private func rowClicked(_ sender: Any?) {
        openSelected()
    }

    @objc private func rowDoubleClicked(_ sender: Any?) {
        openSelected()
    }

    private func openSelected() {
        guard let n = selectedNote() else { return }
        onOpenNote?(n.path, n.line)
    }

    @objc private func exportClicked() {
        let panel = NSSavePanel()
        panel.title = "Export Notes"
        let projectName = projectRootURL?.lastPathComponent ?? "UnknownProject"
        panel.nameFieldStringValue = "\(projectName)-notes.codenotes"
        panel.allowedContentTypes = [UTType(filenameExtension: "codenotes") ?? .data]
        panel.canCreateDirectories = true
        guard panel.runModal() == .OK, let url = panel.url else { return }
        if NoteStore.shared.export(to: url, projectRoot: projectRootURL) {
            presentAlert("Exported", "Notes exported to \(url.lastPathComponent).")
        } else {
            presentAlert("Export Failed", "Could not write the notes file.")
        }
    }

    @objc private func importClicked() {
        let panel = NSOpenPanel()
        panel.title = "Import Notes"
        panel.canChooseFiles = true
        panel.canChooseDirectories = false
        panel.allowsMultipleSelection = false
        panel.allowedContentTypes = [UTType(filenameExtension: "codenotes") ?? .data, UTType(filenameExtension: "json") ?? .json]
        panel.message = "Choose a Karma Pro notes file (.codenotes or .json)"
        guard panel.runModal() == .OK, let url = panel.url else { return }
        let result = NoteStore.shared.importFrom(url: url, projectRoot: projectRootURL)
        if result.count > 0 {
            presentAlert("Imported", "Merged \(result.count) note\(result.count == 1 ? "" : "s").")
        } else if result.error.isEmpty {
            presentAlert("Imported", "No new notes to add.")
        } else {
            presentAlert("Import Failed", result.error)
        }
        reloadNotes()
    }

    @objc private func importURLClicked() {
        let alert = NSAlert()
        alert.messageText = "Import Notes from URL"
        alert.informativeText = "Enter the web address of a raw Karma Pro notes file (.codenotes or .json):"
        alert.addButton(withTitle: "Import")
        alert.addButton(withTitle: "Cancel")
        let field = NSTextField(frame: NSRect(x: 0, y: 0, width: 380, height: 24))
        field.placeholderString = "https://example.com/notes.json"
        field.font = NSFont.systemFont(ofSize: 13)
        alert.accessoryView = field
        guard alert.runModal() == .alertFirstButtonReturn else { return }
        let raw = field.stringValue.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !raw.isEmpty, let url = URL(string: raw) else {
            presentAlert("Invalid URL", "Enter a valid web address.")
            return
        }

        importURLButton.isEnabled = false
        let task = URLSession.shared.dataTask(with: url) { [weak self] data, response, error in
            DispatchQueue.main.async {
                guard let self = self else { return }
                self.importURLButton.isEnabled = true
                if let error = error {
                    self.presentAlert("Import Failed", error.localizedDescription)
                    return
                }
                if let http = response as? HTTPURLResponse, !(200...299).contains(http.statusCode) {
                    self.presentAlert("Import Failed", "Server returned HTTP \(http.statusCode).")
                    return
                }
                guard let data = data, !data.isEmpty else {
                    self.presentAlert("Import Failed", "No data received.")
                    return
                }
                let result = NoteStore.shared.importFrom(data: data, projectRoot: self.projectRootURL)
                if result.count > 0 {
                    self.presentAlert("Imported", "Merged \(result.count) note\(result.count == 1 ? "" : "s").")
                } else if result.error.isEmpty {
                    self.presentAlert("Imported", "No new notes to add.")
                } else {
                    self.presentAlert("Import Failed", result.error)
                }
                self.reloadNotes()
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

extension NotesWindowController: NSTableViewDataSource, NSTableViewDelegate {
    func numberOfRows(in tableView: NSTableView) -> Int {
        notes.count
    }

    func tableView(_ tableView: NSTableView, viewFor tableColumn: NSTableColumn?, row: Int) -> NSView? {
        guard row < notes.count else { return nil }
        let n = notes[row]
        let columnID = tableColumn?.identifier.rawValue ?? ""
        let ident = NSUserInterfaceItemIdentifier("cell_\(columnID)")

        let cellView: NSTableCellView
        if let reused = tableView.makeView(withIdentifier: ident, owner: nil) as? NSTableCellView {
            cellView = reused
        } else {
            cellView = NSTableCellView()
            cellView.identifier = ident
            let field = NSTextField(wrappingLabelWithString: "")
            field.font = NSFont.systemFont(ofSize: 12)
            field.translatesAutoresizingMaskIntoConstraints = false
            cellView.addSubview(field)
            cellView.textField = field

            if columnID == "text" {
                field.maximumNumberOfLines = 0
                field.lineBreakMode = .byWordWrapping
                NSLayoutConstraint.activate([
                    field.leadingAnchor.constraint(equalTo: cellView.leadingAnchor, constant: 6),
                    field.trailingAnchor.constraint(equalTo: cellView.trailingAnchor, constant: -6),
                    field.topAnchor.constraint(equalTo: cellView.topAnchor, constant: 4),
                    field.bottomAnchor.constraint(equalTo: cellView.bottomAnchor, constant: -4)
                ])
            } else {
                field.lineBreakMode = .byTruncatingTail
                NSLayoutConstraint.activate([
                    field.leadingAnchor.constraint(equalTo: cellView.leadingAnchor, constant: 6),
                    field.trailingAnchor.constraint(equalTo: cellView.trailingAnchor, constant: -6),
                    field.centerYAnchor.constraint(equalTo: cellView.centerYAnchor)
                ])
            }
        }

        cellView.textField?.textColor = .labelColor

        switch columnID {
        case "file":
            cellView.textField?.stringValue = (n.path as NSString).lastPathComponent
            cellView.textField?.toolTip = n.path
        case "line":
            cellView.textField?.stringValue = "\(n.line)"
            cellView.textField?.alignment = .right
        case "text":
            cellView.textField?.stringValue = n.text
            cellView.textField?.toolTip = n.text
        default:
            cellView.textField?.stringValue = ""
        }
        return cellView
    }

    func tableView(_ tableView: NSTableView, heightOfRow row: Int) -> CGFloat {
        guard row < notes.count else { return 28 }
        let n = notes[row]
        let width = (tableView.tableColumn(withIdentifier: NSUserInterfaceItemIdentifier("text"))?.width ?? 420) - 12
        let field = NSTextField(wrappingLabelWithString: n.text)
        field.font = NSFont.systemFont(ofSize: 12)
        field.maximumNumberOfLines = 0
        field.lineBreakMode = .byWordWrapping
        field.preferredMaxLayoutWidth = width
        return max(28, field.fittingSize.height + 8)
    }
}

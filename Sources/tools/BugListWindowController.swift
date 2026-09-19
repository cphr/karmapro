// by cipher.org.uk
import AppKit
import UniformTypeIdentifiers

/// The main bug tracking window. Lists all bug reports in a table, lets the user
/// search them, select one to view its full detail, create new reports, and edit
/// or delete existing ones.
final class BugListWindowController: NSWindowController, NSSearchFieldDelegate {
    private let tableView = NSTableView()
    private let scrollView = NSScrollView()
    private let searchField = NSSearchField()
    private let newButton = NSButton(title: "New Bug", target: nil, action: nil)
    private let backupButton = NSButton(title: "Backup…", target: nil, action: nil)
    private let importButton = NSButton(title: "Import…", target: nil, action: nil)
    private let statusLabel = NSTextField(wrappingLabelWithString: "")

    private let detailBox = NSBox()
    private let detailTitle = NSTextField(wrappingLabelWithString: "")
    private let detailMeta = NSTextField(wrappingLabelWithString: "")
    private let detailBody = NSTextField(wrappingLabelWithString: "")
    private let editButton = NSButton(title: "Edit…", target: nil, action: nil)
    private let deleteButton = NSButton(title: "Delete", target: nil, action: nil)

    private var bugs: [Bug] = []
    private var query = ""

    private static let dateFormatter: DateFormatter = {
        let f = DateFormatter()
        f.dateFormat = "MMM d, yyyy HH:mm"
        return f
    }()

    /// A custom UTI identifying Karma Pro backup files (extension ".karmapro").
    private static let karmaType = UTType(exportedAs: "com.karmapro.sourcebrowser.backup", conformingTo: .data)

    convenience init() {
        let window = EscClosableWindow(
            contentRect: NSRect(x: 0, y: 0, width: 920, height: 640),
            styleMask: [.titled, .closable, .resizable, .miniaturizable],
            backing: .buffered,
            defer: false
        )
        window.title = "Security bugs tracker"
        window.minSize = NSSize(width: 720, height: 440)
        if let screen = NSScreen.main {
            window.maxSize = screen.visibleFrame.size
        }
        self.init(window: window)
        buildContent()
        reload()
    }

    override func showWindow(_ sender: Any?) {
        window?.center()
        super.showWindow(sender)
        DispatchQueue.main.async { [weak self] in
            self?.window?.makeFirstResponder(self?.searchField)
        }
    }

    private func buildContent() {
        guard let content = window?.contentView else { return }

        searchField.placeholderString = "Search bugs by title, description, severity…"
        searchField.delegate = self
        searchField.sendsSearchStringImmediately = true
        searchField.translatesAutoresizingMaskIntoConstraints = false
        searchField.setContentHuggingPriority(NSLayoutConstraint.Priority(1), for: .horizontal)
        searchField.setContentCompressionResistancePriority(NSLayoutConstraint.Priority(760), for: .horizontal)
        searchField.widthAnchor.constraint(greaterThanOrEqualToConstant: 280).isActive = true

        newButton.bezelStyle = .rounded
        newButton.target = self
        newButton.action = #selector(newClicked)

        backupButton.bezelStyle = .rounded
        backupButton.target = self
        backupButton.action = #selector(backupClicked)
        backupButton.toolTip = "Export all bug reports to a JSON file"

        importButton.bezelStyle = .rounded
        importButton.target = self
        importButton.action = #selector(importClicked)
        importButton.toolTip = "Import bug reports from a JSON backup file"

        statusLabel.font = NSFont.systemFont(ofSize: 12)
        statusLabel.textColor = .secondaryLabelColor
        statusLabel.setContentHuggingPriority(.defaultLow, for: .horizontal)

        let topRow = NSStackView(views: [searchField, statusLabel, NSView(), backupButton, importButton, newButton])
        topRow.orientation = .horizontal
        topRow.alignment = .centerY
        topRow.spacing = 10
        topRow.translatesAutoresizingMaskIntoConstraints = false

        let idColumn = NSTableColumn(identifier: NSUserInterfaceItemIdentifier("id"))
        idColumn.title = "ID"
        idColumn.width = 150
        let titleColumn = NSTableColumn(identifier: NSUserInterfaceItemIdentifier("title"))
        titleColumn.title = "Title"
        titleColumn.width = 260
        titleColumn.resizingMask = .autoresizingMask
        let sevColumn = NSTableColumn(identifier: NSUserInterfaceItemIdentifier("severity"))
        sevColumn.title = "Severity"
        sevColumn.width = 90
        let expColumn = NSTableColumn(identifier: NSUserInterfaceItemIdentifier("exploitability"))
        expColumn.title = "Exploitability"
        expColumn.width = 105
        let pkgColumn = NSTableColumn(identifier: NSUserInterfaceItemIdentifier("package"))
        pkgColumn.title = "Package"
        pkgColumn.width = 150
        let statusColumn = NSTableColumn(identifier: NSUserInterfaceItemIdentifier("status"))
        statusColumn.title = "Status"
        statusColumn.width = 90
        let createdColumn = NSTableColumn(identifier: NSUserInterfaceItemIdentifier("created"))
        createdColumn.title = "Created"
        createdColumn.width = 140

        for c in [idColumn, titleColumn, sevColumn, expColumn, pkgColumn, statusColumn, createdColumn] {
            tableView.addTableColumn(c)
        }
        tableView.usesAlternatingRowBackgroundColors = true
        tableView.usesAutomaticRowHeights = true
        tableView.columnAutoresizingStyle = .lastColumnOnlyAutoresizingStyle
        tableView.dataSource = self
        tableView.delegate = self
        tableView.target = self
        tableView.action = #selector(rowSelected(_:))
        tableView.doubleAction = #selector(rowDoubleClicked(_:))

        scrollView.documentView = tableView
        scrollView.hasVerticalScroller = true
        scrollView.autohidesScrollers = true
        scrollView.translatesAutoresizingMaskIntoConstraints = false

        // Detail panel.
        detailBox.title = "Bug Detail"
        detailBox.translatesAutoresizingMaskIntoConstraints = false

        detailTitle.font = NSFont.systemFont(ofSize: 15, weight: .bold)
        detailMeta.font = NSFont.systemFont(ofSize: 12)
        detailMeta.textColor = .secondaryLabelColor
        detailBody.font = NSFont.systemFont(ofSize: 13)
        detailBody.maximumNumberOfLines = 0
        detailBody.lineBreakMode = .byWordWrapping
        detailBody.setContentCompressionResistancePriority(.defaultLow, for: .vertical)
        detailBody.heightAnchor.constraint(lessThanOrEqualToConstant: 120).isActive = true

        editButton.bezelStyle = .rounded
        editButton.target = self
        editButton.action = #selector(editClicked(_:))
        deleteButton.bezelStyle = .rounded
        deleteButton.target = self
        deleteButton.action = #selector(deleteClicked(_:))

        let detailButtons = NSStackView(views: [NSView(), editButton, deleteButton])
        detailButtons.orientation = .horizontal
        detailButtons.alignment = .centerY
        detailButtons.spacing = 8

        let detailStack = NSStackView(views: [detailTitle, detailMeta, detailBody, detailButtons])
        detailStack.orientation = .vertical
        detailStack.alignment = .leading
        detailStack.spacing = 8
        detailStack.translatesAutoresizingMaskIntoConstraints = false
        detailBox.contentView?.addSubview(detailStack)

        content.addSubview(topRow)
        content.addSubview(scrollView)
        content.addSubview(detailBox)

        NSLayoutConstraint.activate([
            topRow.topAnchor.constraint(equalTo: content.topAnchor, constant: 12),
            topRow.leadingAnchor.constraint(equalTo: content.leadingAnchor, constant: 16),
            topRow.trailingAnchor.constraint(equalTo: content.trailingAnchor, constant: -16),

            scrollView.topAnchor.constraint(equalTo: topRow.bottomAnchor, constant: 8),
            scrollView.leadingAnchor.constraint(equalTo: content.leadingAnchor),
            scrollView.trailingAnchor.constraint(equalTo: content.trailingAnchor),
            scrollView.bottomAnchor.constraint(equalTo: detailBox.topAnchor, constant: -10),

            detailBox.topAnchor.constraint(equalTo: scrollView.bottomAnchor, constant: 10),
            detailBox.leadingAnchor.constraint(equalTo: content.leadingAnchor, constant: 16),
            detailBox.trailingAnchor.constraint(equalTo: content.trailingAnchor, constant: -16),
            detailBox.bottomAnchor.constraint(equalTo: content.bottomAnchor, constant: -16),

            detailStack.topAnchor.constraint(equalTo: detailBox.contentView!.topAnchor, constant: 12),
            detailStack.leadingAnchor.constraint(equalTo: detailBox.contentView!.leadingAnchor, constant: 12),
            detailStack.trailingAnchor.constraint(equalTo: detailBox.contentView!.trailingAnchor, constant: -12),
            detailStack.bottomAnchor.constraint(lessThanOrEqualTo: detailBox.contentView!.bottomAnchor, constant: -12),
            detailBody.widthAnchor.constraint(equalTo: detailStack.widthAnchor, constant: -8)
        ])

        reload()
    }

    func reload() {
        bugs = BugStore.shared.search(query)
        tableView.reloadData()
        statusLabel.stringValue = "\(bugs.count) bug\(bugs.count == 1 ? "" : "s")"
        showDetail(for: selectedBug())
    }

    private func selectedBug() -> Bug? {
        let row = tableView.selectedRow
        guard row >= 0, row < bugs.count else { return nil }
        return bugs[row]
    }

    private func showDetail(for bug: Bug?) {
        detailBody.stringValue = ""
        editButton.isEnabled = bug != nil
        deleteButton.isEnabled = bug != nil
        guard let bug = bug else {
            detailTitle.stringValue = "No bug selected"
            detailMeta.stringValue = "Select a bug report to see its full details."
            return
        }
        detailTitle.stringValue = bug.title
        let sevColor = severityColor(bug.severity)
        var meta = "Severity: \(bug.severity)   ·   Exploitability: \(bug.exploitability)   ·   Status: \(bug.status)"
        meta += "\nCreated: \(Self.dateFormatter.string(from: bug.createdAt))"
        if !bug.packageName.isEmpty {
            meta += "\nPackage: \(bug.packageName)"
            if !bug.version.isEmpty { meta += "   v\(bug.version)" }
        }
        detailMeta.stringValue = meta
        detailMeta.textColor = sevColor
        detailBody.stringValue = bug.detail.isEmpty ? "(no description)" : bug.detail
    }

    private func severityColor(_ level: String) -> NSColor {
        switch level {
        case "critical": return .systemRed
        case "high": return .systemOrange
        case "medium": return .systemYellow
        case "low": return .systemGreen
        default: return .secondaryLabelColor
        }
    }

    // MARK: - Actions

    @objc private func newClicked() {
        presentEditor(bug: nil)
    }

    @objc private func backupClicked() {
        let savePanel = NSSavePanel()
        savePanel.title = "Backup Bug Reports"
        savePanel.nameFieldStringValue = "KarmaProBugBackup.karmapro"
        savePanel.allowedContentTypes = [Self.karmaType]
        guard savePanel.runModal() == .OK, let url = savePanel.url else { return }
        do {
            let jsonData = try JSONEncoder().encode(BugStore.shared.allBugs())
            var data = jsonData

            let protectAlert = NSAlert()
            protectAlert.messageText = "Password Protect Backup?"
            protectAlert.informativeText = "Encrypt the exported backup with a password. You will need this password to import it later."
            protectAlert.addButton(withTitle: "Encrypt")
            protectAlert.addButton(withTitle: "Don't Encrypt")
            if protectAlert.runModal() == .alertFirstButtonReturn {
                guard let password = promptForNewPassword(prompt: "Choose a password to protect this backup."),
                      let confirmed = promptForNewPassword(prompt: "Confirm the backup password."),
                      password == confirmed else {
                    let alert = NSAlert()
                    alert.messageText = "Backup Cancelled"
                    alert.informativeText = "The passwords did not match or were blank. No backup was saved."
                    alert.addButton(withTitle: "OK")
                    alert.runModal()
                    return
                }
                data = try BackupCrypto.seal(jsonData, password: password)
            }

            try data.write(to: url, options: .atomic)
            let protected = BackupCrypto.isEncrypted(data)
            let alert = NSAlert()
            alert.messageText = "Backup Saved"
            alert.informativeText = "Exported \(BugStore.shared.allBugs().count) bug reports to \(url.lastPathComponent)."
                + (protected ? "\nThis backup is password protected." : "")
            alert.addButton(withTitle: "OK")
            alert.runModal()
        } catch {
            let alert = NSAlert()
            alert.messageText = "Backup Failed"
            alert.informativeText = error.localizedDescription
            alert.addButton(withTitle: "OK")
            alert.runModal()
        }
    }

    @objc private func importClicked() {
        let openPanel = NSOpenPanel()
        openPanel.title = "Import Bug Reports"
        openPanel.allowedContentTypes = [Self.karmaType, .json]
        openPanel.allowsMultipleSelection = false
        guard openPanel.runModal() == .OK, let url = openPanel.url else { return }
        do {
            let data = try Data(contentsOf: url)
            var plain: Data
            if BackupCrypto.isEncrypted(data) {
                guard let password = promptForExistingPassword(prompt: "This backup is encrypted. Enter its password to import it.") else { return }
                plain = try BackupCrypto.open(data, password: password)
            } else {
                plain = data
            }
            let imported = try JSONDecoder().decode([Bug].self, from: plain)
            guard !imported.isEmpty else {
                let alert = NSAlert()
                alert.messageText = "Nothing to Import"
                alert.informativeText = "The selected file contains no bug reports."
                alert.addButton(withTitle: "OK")
                alert.runModal()
                return
            }
            let added = BugStore.shared.merge(imported)
            reload()
            let alert = NSAlert()
            alert.messageText = "Import Complete"
            alert.informativeText = "Imported \(added) new bug report(s) from \(url.lastPathComponent)."
            alert.addButton(withTitle: "OK")
            alert.runModal()
        } catch let error as BackupError {
            let alert = NSAlert()
            alert.messageText = "Import Failed"
            alert.informativeText = error.localizedDescription
            alert.addButton(withTitle: "OK")
            alert.runModal()
        } catch {
            let alert = NSAlert()
            alert.messageText = "Import Failed"
            alert.informativeText = "Could not read the backup file: \(error.localizedDescription)"
            alert.addButton(withTitle: "OK")
            alert.runModal()
        }
    }

    /// Shows an alert with a secure text field and returns the entered value, or nil
    /// if the user cancelled or left it blank.
    private func promptForExistingPassword(prompt: String) -> String? {
        let alert = NSAlert()
        alert.messageText = "Enter Backup Password"
        alert.informativeText = prompt
        alert.addButton(withTitle: "OK")
        alert.addButton(withTitle: "Cancel")
        let field = NSSecureTextField(frame: NSRect(x: 0, y: 0, width: 260, height: 24))
        field.placeholderString = "Backup password"
        alert.accessoryView = field
        NSApp.activate(ignoringOtherApps: true)
        alert.window.initialFirstResponder = field
        guard alert.runModal() == .alertFirstButtonReturn else { return nil }
        let value = field.stringValue
        return value.isEmpty ? nil : value
    }

    /// Shows an alert with a secure text field for choosing a new password.
    private func promptForNewPassword(prompt: String) -> String? {
        let alert = NSAlert()
        alert.messageText = "Set Backup Password"
        alert.informativeText = prompt
        alert.addButton(withTitle: "OK")
        alert.addButton(withTitle: "Cancel")
        let field = NSSecureTextField(frame: NSRect(x: 0, y: 0, width: 260, height: 24))
        field.placeholderString = "Password"
        alert.accessoryView = field
        NSApp.activate(ignoringOtherApps: true)
        alert.window.initialFirstResponder = field
        guard alert.runModal() == .alertFirstButtonReturn else { return nil }
        let value = field.stringValue
        return value.isEmpty ? nil : value
    }

    @objc private func editClicked(_ sender: Any?) {
        guard let bug = selectedBug() else { return }
        presentEditor(bug: bug)
    }

    @objc private func deleteClicked(_ sender: Any?) {
        guard let bug = selectedBug() else { return }
        let alert = NSAlert()
        alert.messageText = "Delete Bug Report?"
        alert.informativeText = "This will permanently remove \"\(bug.title)\"."
        alert.addButton(withTitle: "Delete")
        alert.addButton(withTitle: "Cancel")
        if alert.runModal() == .alertFirstButtonReturn {
            BugStore.shared.delete(id: bug.id)
            reload()
        }
    }

    @objc private func rowSelected(_ sender: Any?) {
        showDetail(for: selectedBug())
    }

    @objc private func rowDoubleClicked(_ sender: Any?) {
        guard selectedBug() != nil else { return }
        presentEditor(bug: selectedBug())
    }

    private func presentEditor(bug: Bug?) {
        guard let parent = window else { return }
        let controller = BugEditorWindowController(bug: bug)
        controller.onSaved = { [weak self] savedBug in
            self?.reload()
            let row = self?.bugs.firstIndex(where: { $0.id == savedBug.id }) ?? 0
            self?.tableView.selectRowIndexes(IndexSet(integer: row), byExtendingSelection: false)
            self?.showDetail(for: savedBug)
        }
        if let sheet = controller.window {
            parent.beginSheet(sheet)
        }
    }

    // MARK: - Search

    func controlTextDidChange(_ obj: Notification) {
        if let field = obj.object as? NSSearchField {
            query = field.stringValue
            reload()
        }
    }
}

extension BugListWindowController: NSTableViewDataSource, NSTableViewDelegate {
    func numberOfRows(in tableView: NSTableView) -> Int {
        bugs.count
    }

    func tableView(_ tableView: NSTableView, viewFor tableColumn: NSTableColumn?, row: Int) -> NSView? {
        guard row < bugs.count else { return nil }
        let bug = bugs[row]
        let columnID = tableColumn?.identifier.rawValue ?? ""
        let ident = NSUserInterfaceItemIdentifier("bugcell_\(columnID)")

        let cellView: NSTableCellView
        if let reused = tableView.makeView(withIdentifier: ident, owner: nil) as? NSTableCellView {
            cellView = reused
        } else {
            cellView = NSTableCellView()
            cellView.identifier = ident
            let field = NSTextField(wrappingLabelWithString: "")
            field.font = NSFont.systemFont(ofSize: 12)
            field.lineBreakMode = .byTruncatingTail
            field.translatesAutoresizingMaskIntoConstraints = false
            cellView.addSubview(field)
            cellView.textField = field
            NSLayoutConstraint.activate([
                field.leadingAnchor.constraint(equalTo: cellView.leadingAnchor, constant: 6),
                field.trailingAnchor.constraint(equalTo: cellView.trailingAnchor, constant: -6),
                field.centerYAnchor.constraint(equalTo: cellView.centerYAnchor)
            ])
        }

        cellView.textField?.textColor = .labelColor
        switch columnID {
        case "id":
            cellView.textField?.stringValue = String(bug.id.prefix(8))
        case "title":
            cellView.textField?.stringValue = bug.title
            cellView.textField?.toolTip = bug.title
        case "severity":
            cellView.textField?.stringValue = bug.severity
            cellView.textField?.textColor = severityColor(bug.severity)
        case "exploitability":
            cellView.textField?.stringValue = bug.exploitability
            cellView.textField?.textColor = severityColor(bug.exploitability)
        case "package":
            let pkg = bug.packageName.isEmpty ? "—" : bug.packageName
            let ver = bug.version.isEmpty ? "" : " v\(bug.version)"
            cellView.textField?.stringValue = pkg + ver
        case "status":
            cellView.textField?.stringValue = bug.status
        case "created":
            cellView.textField?.stringValue = Self.dateFormatter.string(from: bug.createdAt)
        default:
            cellView.textField?.stringValue = ""
        }
        return cellView
    }
}

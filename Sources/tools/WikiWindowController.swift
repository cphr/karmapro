// by cipher.org.uk
import AppKit
import UniformTypeIdentifiers

/// The private wiki's page list: search box, all pages (title + updated date),
/// and the actions for creating, opening, renaming, deleting and backing up
/// pages. Double-clicking a row (or the Open button) opens the rich-text
/// editor; navigating a link in the editor opens the target page, creating it
/// if it does not exist yet.
final class WikiWindowController: NSWindowController, NSTableViewDataSource, NSTableViewDelegate, NSSearchFieldDelegate {
    private static let karmaWikiType = UTType(filenameExtension: "karmawiki") ?? .data
    private static let dateFormatter: DateFormatter = {
        let formatter = DateFormatter()
        formatter.dateStyle = .medium
        formatter.timeStyle = .short
        return formatter
    }()

    private let store = WikiStore.shared
    private let tableView = NSTableView()
    private let scrollView = NSScrollView()
    private let searchField = NSSearchField()
    private let statusLabel = NSTextField(wrappingLabelWithString: "")
    private let newButton = NSButton(title: "New Page", target: nil, action: nil)
    private let openButton = NSButton(title: "Open", target: nil, action: nil)
    private let renameButton = NSButton(title: "Rename…", target: nil, action: nil)
    private let deleteButton = NSButton(title: "Delete…", target: nil, action: nil)
    private let backupButton = NSButton(title: "Backup…", target: nil, action: nil)
    private let importButton = NSButton(title: "Import…", target: nil, action: nil)

    private var pages: [WikiStore.PageInfo] = []
    private var editors: [String: WikiEditorWindowController] = [:]
    private var isImporting = false

    convenience init() {
        let window = EscClosableWindow(
            contentRect: NSRect(x: 0, y: 0, width: 700, height: 520),
            styleMask: [.titled, .closable, .resizable],
            backing: .buffered,
            defer: false
        )
        window.title = "Wiki"
        window.minSize = NSSize(width: 480, height: 300)
        self.init(window: window)
        buildContent()
        centerWindowOnScreen()
        registerForTerminationSave()
    }

    deinit {
        NotificationCenter.default.removeObserver(self)
    }

    /// Saves any dirty open editor when the app quits, so a pending edit in a
    /// page window is never lost even if the app terminates without closing it.
    private func registerForTerminationSave() {
        NotificationCenter.default.addObserver(self,
                                               selector: #selector(appWillTerminate),
                                               name: NSApplication.willTerminateNotification,
                                               object: nil)
    }

    @objc private func appWillTerminate() {
        for editor in editors.values {
            editor.saveNow()
        }
    }

    private func buildContent() {
        guard let content = window?.contentView else { return }

        searchField.placeholderString = "Search pages (title or body)"
        searchField.delegate = self
        searchField.translatesAutoresizingMaskIntoConstraints = false

        let actions = [newButton, openButton, renameButton, deleteButton, backupButton, importButton]
        newButton.bezelStyle = .rounded
        openButton.bezelStyle = .rounded
        renameButton.bezelStyle = .rounded
        deleteButton.bezelStyle = .rounded
        backupButton.bezelStyle = .rounded
        importButton.bezelStyle = .rounded
        newButton.target = self
        openButton.target = self
        renameButton.target = self
        deleteButton.target = self
        backupButton.target = self
        importButton.target = self
        newButton.action = #selector(newPageClicked)
        openButton.action = #selector(openClicked)
        renameButton.action = #selector(renameClicked)
        deleteButton.action = #selector(deleteClicked)
        backupButton.action = #selector(backupClicked)
        importButton.action = #selector(importClicked)

        let buttonRow = NSStackView(views: actions)
        buttonRow.orientation = .horizontal
        buttonRow.alignment = .centerY
        buttonRow.spacing = 10
        buttonRow.translatesAutoresizingMaskIntoConstraints = false

        statusLabel.font = NSFont.systemFont(ofSize: 12)
        statusLabel.textColor = .secondaryLabelColor
        statusLabel.translatesAutoresizingMaskIntoConstraints = false

        let headerRow = NSStackView(views: [searchField, buttonRow])
        headerRow.orientation = .vertical
        headerRow.alignment = .leading
        headerRow.spacing = 10
        headerRow.translatesAutoresizingMaskIntoConstraints = false
        content.addSubview(headerRow)

        let titleColumn = NSTableColumn(identifier: NSUserInterfaceItemIdentifier("title"))
        titleColumn.title = "Page"
        titleColumn.width = 340
        titleColumn.resizingMask = .autoresizingMask

        let createdColumn = NSTableColumn(identifier: NSUserInterfaceItemIdentifier("created"))
        createdColumn.title = "Created"
        createdColumn.width = 140

        let updatedColumn = NSTableColumn(identifier: NSUserInterfaceItemIdentifier("updated"))
        updatedColumn.title = "Updated"
        updatedColumn.width = 140

        tableView.addTableColumn(titleColumn)
        tableView.addTableColumn(createdColumn)
        tableView.addTableColumn(updatedColumn)
        tableView.usesAlternatingRowBackgroundColors = true
        tableView.columnAutoresizingStyle = .lastColumnOnlyAutoresizingStyle
        tableView.dataSource = self
        tableView.delegate = self
        tableView.target = self
        tableView.action = #selector(singleClick(_:))
        tableView.doubleAction = #selector(openClicked)

        scrollView.documentView = tableView
        scrollView.hasVerticalScroller = true
        scrollView.autohidesScrollers = true
        scrollView.translatesAutoresizingMaskIntoConstraints = false
        content.addSubview(scrollView)

        content.addSubview(statusLabel)

        NSLayoutConstraint.activate([
            headerRow.topAnchor.constraint(equalTo: content.topAnchor, constant: 12),
            headerRow.leadingAnchor.constraint(equalTo: content.leadingAnchor, constant: 16),
            headerRow.trailingAnchor.constraint(equalTo: content.trailingAnchor, constant: -16),

            statusLabel.topAnchor.constraint(equalTo: headerRow.bottomAnchor, constant: 4),
            statusLabel.leadingAnchor.constraint(equalTo: content.leadingAnchor, constant: 16),

            scrollView.topAnchor.constraint(equalTo: statusLabel.bottomAnchor, constant: 4),
            scrollView.leadingAnchor.constraint(equalTo: content.leadingAnchor),
            scrollView.trailingAnchor.constraint(equalTo: content.trailingAnchor),
            scrollView.bottomAnchor.constraint(equalTo: content.bottomAnchor)
        ])

        reload()
    }

    private func centerWindowOnScreen() {
        guard let window = window, let screen = window.screen else { return }
        let frame = screen.visibleFrame
        let origin = NSPoint(x: frame.midX - window.frame.width / 2,
                             y: frame.midY - window.frame.height / 2)
        window.setFrameOrigin(origin)
    }

    func reload() {
        let query = searchField.stringValue
        pages = store.search(query)
        tableView.reloadData()
        let count = pages.count
        statusLabel.stringValue = query.isEmpty
            ? (count == 1 ? "1 page" : "\(count) pages")
            : "\(count) page\(count == 1 ? "" : "s") matching \"\(query)\""
    }

    private func selectedPage() -> WikiStore.PageInfo? {
        let row = tableView.selectedRow
        guard row >= 0, row < pages.count else { return nil }
        return pages[row]
    }

    // MARK: - Search

    func controlTextDidChange(_ obj: Notification) {
        reload()
    }

    // MARK: - Actions

    @objc private func singleClick(_ sender: Any?) {
        _ = selectedPage()
    }

    @objc private func newPageClicked() {
        let title = promptForText(title: "New Page", prompt: "Name of the new page:")
        let body = NSAttributedString(string: "")
        let slug = store.createPage(title: title ?? "Untitled", body: body)
        reload()
        openEditor(slug: slug)
    }

    @objc private func openClicked() {
        guard let page = selectedPage() else { return }
        openEditor(slug: page.slug)
    }

    @objc private func renameClicked() {
        guard let page = selectedPage() else { return }
        guard let newTitle = promptForText(title: "Rename Page", prompt: "New title:", initial: page.title),
              !newTitle.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty,
              newTitle != page.title else { return }
        if let editor = editors[page.slug] {
            editor.close()
            editors.removeValue(forKey: page.slug)
        }
        guard let newSlug = store.renamePage(slug: page.slug, newTitle: newTitle) else { return }
        if let row = pages.firstIndex(where: { $0.slug == page.slug }) {
            var renamed = pages[row]
            renamed.slug = newSlug
            renamed.title = newTitle
            pages[row] = renamed
        }
        reload()
    }

    @objc private func deleteClicked() {
        guard let page = selectedPage() else { return }
        let alert = NSAlert()
        alert.messageText = "Delete Page"
        alert.informativeText = "Delete \"\(page.title)\" permanently? This cannot be undone."
        alert.addButton(withTitle: "Delete")
        alert.addButton(withTitle: "Cancel")
        guard alert.runModal() == .alertFirstButtonReturn else { return }
        editors[page.slug]?.close()
        editors.removeValue(forKey: page.slug)
        store.deletePage(slug: page.slug)
        reload()
    }

    /// Opens a page in the rich-text editor. If `slug` does not exist yet it is
    /// created first (from the page name), so clicking a dead link grows a page.
    private func openEditor(slug: String) {
        if let editor = editors[slug] {
            editor.showWindow(nil)
            editor.window?.makeKeyAndOrderFront(nil)
            NSApp.activate(ignoringOtherApps: true)
            return
        }
        guard store.pageInfo(slug: slug) != nil else {
            let body = NSAttributedString(string: "")
            let created = store.createPage(title: titleFromSlug(slug), body: body, slug: slug)
            return openEditor(slug: created)
        }
        let editor = WikiEditorWindowController(slug: slug)
        editor.onNavigate = { [weak self, weak editor] target in
            guard let self = self else { return }
            let slug = self.store.resolve(target) ?? self.store.createPage(title: target, body: NSAttributedString(string: ""))
            editor?.close()
            self.reload()
            self.openEditor(slug: slug)
        }
        editor.onClose = { [weak self, weak editor] in
            if let e = editor {
                self?.editors.removeValue(forKey: e.pageSlug)
            }
            self?.reload()
        }
        editors[slug] = editor
        editor.showWindow(nil)
        editor.window?.makeKeyAndOrderFront(nil)
        NSApp.activate(ignoringOtherApps: true)
    }

    private func titleFromSlug(_ slug: String) -> String {
        slug.split(separator: "-").map { $0.capitalized }.joined(separator: " ")
    }

    private func promptForText(title: String, prompt: String, initial: String = "") -> String? {
        let alert = NSAlert()
        alert.messageText = title
        alert.informativeText = prompt
        alert.addButton(withTitle: "OK")
        alert.addButton(withTitle: "Cancel")
        let field = NSTextField(frame: NSRect(x: 0, y: 0, width: 300, height: 24))
        field.stringValue = initial
        alert.accessoryView = field
        NSApp.activate(ignoringOtherApps: true)
        alert.window.initialFirstResponder = field
        guard alert.runModal() == .alertFirstButtonReturn else { return nil }
        let value = field.stringValue.trimmingCharacters(in: .whitespacesAndNewlines)
        return value.isEmpty ? nil : value
    }

    // MARK: - Backup / import

    @objc private func backupClicked() {
        let panel = NSSavePanel()
        panel.title = "Backup Wiki"
        panel.nameFieldStringValue = "KarmaProWiki.karmawiki"
        panel.allowedContentTypes = [Self.karmaWikiType]
        guard panel.runModal() == .OK, let url = panel.url else { return }
        do {
            var password: String?
            let protectAlert = NSAlert()
            protectAlert.messageText = "Password Protect Backup?"
            protectAlert.informativeText = "Encrypt the backup with a password? You will need it to import this backup later."
            protectAlert.addButton(withTitle: "Encrypt")
            protectAlert.addButton(withTitle: "Don't Encrypt")
            if protectAlert.runModal() == .alertFirstButtonReturn {
                guard let first = promptForNewPassword(prompt: "Choose a password to protect this backup."),
                      let second = promptForNewPassword(prompt: "Confirm the backup password."),
                      first == second else {
                    presentAlert("Backup Cancelled", "The passwords did not match or were blank. No backup was saved.")
                    return
                }
                password = first
            }
            let count = try store.backup(to: url, password: password)
            let protected = password != nil
            presentAlert("Backup Saved", "Exported \(count) page\(count == 1 ? "" : "s") to \(url.lastPathComponent)."
                + (protected ? "\nThis backup is password protected." : ""))
        } catch {
            presentAlert("Backup Failed", error.localizedDescription)
        }
    }

    @objc private func importClicked() {
        guard !isImporting else { return }
        isImporting = true
        defer { isImporting = false }

        let panel = NSOpenPanel()
        panel.title = "Import Wiki"
        panel.message = "Choose a .karmawiki backup, or a folder containing wiki pages (.rtf)."
        panel.allowedContentTypes = [Self.karmaWikiType, .data]
        panel.allowsMultipleSelection = false
        panel.canChooseFiles = true
        panel.canChooseDirectories = true
        guard panel.runModal() == .OK, let url = panel.url else { return }

        do {
            let data = try? (url.hasDirectoryPath ? nil : Data(contentsOf: url))
            var password: String?
            if let data = data, BackupCrypto.isEncrypted(data) {
                guard let pw = promptForExistingPassword(prompt: "This backup is encrypted. Enter its password to import it.") else { return }
                password = pw
            }

            let result = try store.import(from: url, password: password) { slug in
                self.askConflict(for: slug)
            }
            reload()
            let parts: [String] = [
                result.imported > 0 ? "\(result.imported) new" : nil,
                result.overwritten > 0 ? "\(result.overwritten) overwritten" : nil,
                result.renamed > 0 ? "\(result.renamed) renamed" : nil,
                result.skipped > 0 ? "\(result.skipped) skipped" : nil
            ].compactMap { $0 }
            presentAlert("Import Complete", parts.isEmpty ? "Nothing was imported." : "Imported: " + parts.joined(separator: ", ") + ".")
        } catch let error as BackupError {
            presentAlert("Import Failed", error.localizedDescription)
        } catch let error as WikiStore.WikiError {
            presentAlert("Import Failed", error.localizedDescription)
        } catch {
            presentAlert("Import Failed", error.localizedDescription)
        }
    }

    /// Asks how to handle a page that already exists when importing. Esc or the
    /// window close aborts the whole import via `skip-all`.
    private func askConflict(for slug: String) -> WikiStore.Conflict {
        let info = store.pageInfo(slug: slug)
        let title = info?.title ?? slug
        let alert = NSAlert()
        alert.messageText = "Page Already Exists"
        alert.informativeText = "\"\(title)\" already exists in your wiki. What should happen to the imported copy?"
        alert.addButton(withTitle: "Overwrite")
        alert.addButton(withTitle: "Rename Imported")
        alert.addButton(withTitle: "Skip")
        alert.addButton(withTitle: "Cancel Import")
        switch alert.runModal() {
        case .alertFirstButtonReturn: return .overwrite
        case .alertSecondButtonReturn: return .rename
        case .alertThirdButtonReturn: return .skip
        default: return .skip
        }
    }

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

    private func presentAlert(_ title: String, _ message: String) {
        let alert = NSAlert()
        alert.messageText = title
        alert.informativeText = message
        alert.addButton(withTitle: "OK")
        alert.runModal()
    }
}

// MARK: - Table view

extension WikiWindowController {
    func numberOfRows(in tableView: NSTableView) -> Int {
        pages.count
    }

    func tableView(_ tableView: NSTableView, viewFor tableColumn: NSTableColumn?, row: Int) -> NSView? {
        guard row < pages.count else { return nil }
        let page = pages[row]
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
        case "title":
            cellView.textField?.stringValue = page.title
            cellView.textField?.toolTip = page.slug
        case "created":
            cellView.textField?.stringValue = Self.dateFormatter.string(from: Date(timeIntervalSince1970: page.created))
        case "updated":
            cellView.textField?.stringValue = Self.dateFormatter.string(from: Date(timeIntervalSince1970: page.updated))
        default:
            cellView.textField?.stringValue = ""
        }
        return cellView
    }
}
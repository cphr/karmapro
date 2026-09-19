// by cipher.org.uk
import AppKit

/// A window that searches for a string across every file in an opened folder.
/// Results (file, line, snippet) are shown in a table; opening a row asks the
/// main window to load that file and jump to the matching line.
final class FileSearchWindowController: NSWindowController, NSOpenSavePanelDelegate, NSSearchFieldDelegate {
    private let searchField = NSSearchField()
    private let statusLabel = NSTextField(wrappingLabelWithString: "Type a query to search all files in the folder.")
    private let tableView = NSTableView()
    private let scrollView = NSScrollView()

    private struct Result {
        let url: URL
        let line: Int
        let snippet: String
        let column: Int
    }

    private var results: [Result] = []
    private var openFolderURL: URL?
    private var language: Language?

    /// Invoked when the user opens a result; passes the file URL and 1-based line.
    var onOpenResult: ((URL, Int) -> Void)?

    convenience init(folderURL: URL?, language: Language? = nil) {
        let window = EscClosableWindow(
            contentRect: NSRect(x: 0, y: 0, width: 760, height: 520),
            styleMask: [.titled, .closable, .resizable],
            backing: .buffered,
            defer: false
        )
        window.title = language == nil ? "Search in Files" : "Search in Files (\(language!.name))"
        window.minSize = NSSize(width: 480, height: 300)
        self.init(window: window)
        openFolderURL = folderURL
        self.language = language
        buildContent()
    }

    private func buildContent() {
        guard let content = window?.contentView else { return }

        searchField.placeholderString = "Search across all files…"
        searchField.delegate = self
        searchField.translatesAutoresizingMaskIntoConstraints = false
        content.addSubview(searchField)

        statusLabel.font = NSFont.systemFont(ofSize: 12)
        statusLabel.textColor = .secondaryLabelColor
        statusLabel.translatesAutoresizingMaskIntoConstraints = false
        content.addSubview(statusLabel)

        // Table
        let column = NSTableColumn(identifier: NSUserInterfaceItemIdentifier("snippet"))
        column.title = "Match"
        column.width = 600
        column.resizingMask = .autoresizingMask
        tableView.addTableColumn(column)
        tableView.headerView = nil
        tableView.rowHeight = 20
        tableView.usesAlternatingRowBackgroundColors = true
        tableView.dataSource = self
        tableView.delegate = self
        tableView.target = self
        tableView.action = #selector(rowClicked(_:))
        tableView.doubleAction = #selector(rowDoubleClicked(_:))

        // Attributed snippet cell with file:line as the leading bold part.
        let cell = NSTextFieldCell()
        cell.isEditable = false
        cell.lineBreakMode = .byTruncatingTail
        column.dataCell = cell

        scrollView.documentView = tableView
        scrollView.hasVerticalScroller = true
        scrollView.autohidesScrollers = true
        scrollView.translatesAutoresizingMaskIntoConstraints = false
        content.addSubview(scrollView)

        NSLayoutConstraint.activate([
            searchField.topAnchor.constraint(equalTo: content.topAnchor, constant: 12),
            searchField.leadingAnchor.constraint(equalTo: content.leadingAnchor, constant: 16),
            searchField.trailingAnchor.constraint(equalTo: content.trailingAnchor, constant: -16),
            statusLabel.topAnchor.constraint(equalTo: searchField.bottomAnchor, constant: 8),
            statusLabel.leadingAnchor.constraint(equalTo: content.leadingAnchor, constant: 16),
            statusLabel.trailingAnchor.constraint(lessThanOrEqualTo: content.trailingAnchor, constant: -16),
            scrollView.topAnchor.constraint(equalTo: statusLabel.bottomAnchor, constant: 8),
            scrollView.bottomAnchor.constraint(equalTo: content.bottomAnchor),
            scrollView.leadingAnchor.constraint(equalTo: content.leadingAnchor),
            scrollView.trailingAnchor.constraint(equalTo: content.trailingAnchor)
        ])

        window?.makeFirstResponder(searchField)
    }

    func controlTextDidChange(_ obj: Notification) {
        guard (obj.object as? NSSearchField) === searchField else { return }
        performSearch(term: searchField.stringValue)
    }

    private func performSearch(term: String) {
        guard let folder = openFolderURL else {
            statusLabel.stringValue = "No folder is open."
            results = []
            tableView.reloadData()
            return
        }

        statusLabel.stringValue = "Searching…"
        let trimmed = term
        let search = trimmed.isEmpty ? nil : trimmed

        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            guard let self = self else { return }
            var found: [Result] = []

            if let search = search {
                let fm = FileManager.default
                if let enumerator = fm.enumerator(at: folder,
                                                  includingPropertiesForKeys: [.isRegularFileKey],
                                                  options: [.skipsHiddenFiles]) {
                    for case let url as URL in enumerator {
                        if self.shouldSkip(url) { continue }
                        guard let contents = try? String(contentsOf: url, encoding: .utf8) else { continue }
                        let ns = contents as NSString
                        let lines = ns.components(separatedBy: "\n")
                        var lineNumber = 0
                        for line in lines {
                            lineNumber += 1
                            let range = (line as NSString).range(of: search, options: [.caseInsensitive])
                            if range.location != NSNotFound {
                                found.append(Result(url: url, line: lineNumber,
                                                    snippet: line, column: range.location))
                            }
                        }
                    }
                }
            }

            DispatchQueue.main.async { [weak self] in
                guard let self = self else { return }
                self.results = found
                self.tableView.reloadData()
                self.statusLabel.stringValue = found.isEmpty
                    ? "No matches"
                    : "\(found.count) match\(found.count == 1 ? "" : "es")"
            }
        }
    }

    private func shouldSkip(_ url: URL) -> Bool {
        let ext = url.pathExtension.lowercased()
        if ext == "png" || ext == "jpg" || ext == "jpeg" || ext == "gif" ||
           ext == "pdf" || ext == "zip" || ext == "app" || ext == "framework" { return true }
        // When a specific language is selected, only search files of that language.
        if let lang = language, !lang.contains(url) { return true }
        return false
    }

    @objc private func rowClicked(_ sender: Any?) {
        openSelected()
    }

    @objc private func rowDoubleClicked(_ sender: Any?) {
        openSelected()
    }

    private func openSelected() {
        guard tableView.selectedRow >= 0, tableView.selectedRow < results.count else { return }
        let r = results[tableView.selectedRow]
        onOpenResult?(r.url, r.line)
    }
}

extension FileSearchWindowController: NSTableViewDataSource, NSTableViewDelegate {
    func numberOfRows(in tableView: NSTableView) -> Int {
        results.count
    }

    func tableView(_ tableView: NSTableView, viewFor tableColumn: NSTableColumn?, row: Int) -> NSView? {
        guard row < results.count else { return nil }
        let r = results[row]
        let ident = NSUserInterfaceItemIdentifier("cell")
        let cellView: NSTableCellView
        if let reused = tableView.makeView(withIdentifier: ident, owner: nil) as? NSTableCellView {
            cellView = reused
        } else {
            cellView = NSTableCellView()
            cellView.identifier = ident
            let field = NSTextField(labelWithString: "")
            field.font = NSFont.monospacedSystemFont(ofSize: 12, weight: .regular)
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
        let value = "\(r.url.lastPathComponent):\(r.line)\t\(r.snippet)"
        let attributed = NSMutableAttributedString(string: value)
        let headerRange = NSRange(location: 0, length: "\(r.url.lastPathComponent):\(r.line)".count)
        attributed.addAttribute(.font, value: NSFont.monospacedSystemFont(ofSize: 12, weight: .bold), range: headerRange)
        attributed.addAttribute(.foregroundColor, value: NSColor.controlAccentColor, range: headerRange)
        cellView.textField?.attributedStringValue = attributed
        cellView.textField?.toolTip = r.url.path
        return cellView
    }
}

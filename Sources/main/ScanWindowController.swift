// by cipher.org.uk
import AppKit

/// Displays the results of a project vulnerability scan in a table. Each row
/// is a finding (file, line, function, category, severity); single/double
/// clicking a row asks the main window to load that file and jump to the line.
final class ScanWindowController: NSWindowController {
    /// Cached scan results so reopening the window doesn't re-scan the same folder.
    private static var cachedFolder: URL?
    private static var cachedFindings: [ScanFinding] = []

    private let tableView = NSTableView()
    private let scrollView = NSScrollView()
    private let statusLabel = NSTextField(wrappingLabelWithString: "No scan has been run yet.")
    private let progressBar = NSProgressIndicator()
    private let rescanButton = NSButton(title: "Rescan", target: nil, action: nil)
    private let ignoreButton = NSButton(title: "Ignore issue", target: nil, action: nil)

    private var findings: [ScanFinding] = []
    private var scannedFolder: URL?
    /// The project-wide source cache to reuse for walking and reading during a
    /// scan, when the app already loaded it for the same folder. Kept weak-like
    /// by the caller (already retained by the main controller for its lifetime).
    var sourceIndex: ProjectSourceIndex?
    /// Set to true when a scan is running; cleared when it completes or is
    /// cancelled. When the user closes the window mid-scan, this is flipped so the
    /// background scan stops and never touches a deallocated view.
    private var scanCancelled = false

    /// Line numbers the user has chosen to ignore (persisted in UserDefaults), keyed
    /// by the file path so the same finding stays hidden across relaunches.
    private var ignoredLines: Set<String> {
        get {
            Set(UserDefaults.standard.stringArray(forKey: "ScanWindowController.ignoredLines") ?? [])
        }
        set {
            UserDefaults.standard.set(Array(newValue), forKey: "ScanWindowController.ignoredLines")
        }
    }

    private var sortDescriptors: [NSSortDescriptor] = []

    /// Invoked when the user opens a finding; passes the file URL and 1-based line.
    var onOpenResult: ((URL, Int) -> Void)?

    convenience init() {
        let window = EscClosableWindow(
            contentRect: NSRect(x: 0, y: 0, width: 1100, height: 560),
            styleMask: [.titled, .closable, .resizable],
            backing: .buffered,
            defer: false
        )
        window.title = "Security Scan"
        window.minSize = NSSize(width: 1000, height: 560)
        self.init(window: window)
        buildContent()
    }

    override func showWindow(_ sender: Any?) {
        window?.center()
        window?.delegate = self
        super.showWindow(sender)
    }

    private func buildContent() {
        guard let content = window?.contentView else { return }

        statusLabel.font = NSFont.systemFont(ofSize: 12)
        statusLabel.textColor = .secondaryLabelColor
        statusLabel.translatesAutoresizingMaskIntoConstraints = false
        content.addSubview(statusLabel)

        rescanButton.bezelStyle = .rounded
        rescanButton.controlSize = .small
        rescanButton.target = self
        rescanButton.action = #selector(rescanClicked(_:))
        rescanButton.toolTip = "Re-run the scan for the current project"
        rescanButton.translatesAutoresizingMaskIntoConstraints = false
        content.addSubview(rescanButton)

        ignoreButton.bezelStyle = .rounded
        ignoreButton.controlSize = .small
        ignoreButton.isEnabled = false
        ignoreButton.target = self
        ignoreButton.action = #selector(ignoreClicked(_:))
        ignoreButton.toolTip = "Hide this finding (persisted across sessions)"
        ignoreButton.translatesAutoresizingMaskIntoConstraints = false
        content.addSubview(ignoreButton)

        progressBar.style = .bar
        progressBar.isIndeterminate = false
        progressBar.minValue = 0
        progressBar.maxValue = 1
        progressBar.doubleValue = 0
        progressBar.isHidden = true
        progressBar.translatesAutoresizingMaskIntoConstraints = false
        content.addSubview(progressBar)

        // Columns: Exploitability, Severity, Category, Function, File, Line, Engine, Cross-file, Finding
        let expColumn = NSTableColumn(identifier: NSUserInterfaceItemIdentifier("exp"))
        expColumn.title = "Exploitability"
        expColumn.width = 92
        expColumn.sortDescriptorPrototype = NSSortDescriptor(key: "exploitability", ascending: false)

        let sevColumn = NSTableColumn(identifier: NSUserInterfaceItemIdentifier("sev"))
        sevColumn.title = "Severity"
        sevColumn.width = 80
        sevColumn.sortDescriptorPrototype = NSSortDescriptor(key: "severity", ascending: false)

        let catColumn = NSTableColumn(identifier: NSUserInterfaceItemIdentifier("cat"))
        catColumn.title = "Category"
        catColumn.width = 180
        catColumn.sortDescriptorPrototype = NSSortDescriptor(key: "category", ascending: true)

        let fnColumn = NSTableColumn(identifier: NSUserInterfaceItemIdentifier("fn"))
        fnColumn.title = "Function"
        fnColumn.width = 150
        fnColumn.sortDescriptorPrototype = NSSortDescriptor(key: "function", ascending: true)

        let fileColumn = NSTableColumn(identifier: NSUserInterfaceItemIdentifier("file"))
        fileColumn.title = "File"
        fileColumn.width = 160
        fileColumn.sortDescriptorPrototype = NSSortDescriptor(key: "fileURL", ascending: true)

        let lineColumn = NSTableColumn(identifier: NSUserInterfaceItemIdentifier("line"))
        lineColumn.title = "Line"
        lineColumn.width = 50
        lineColumn.sortDescriptorPrototype = NSSortDescriptor(key: "line", ascending: true)

        let srcColumn = NSTableColumn(identifier: NSUserInterfaceItemIdentifier("src"))
        srcColumn.title = "Engine"
        srcColumn.width = 90
        srcColumn.sortDescriptorPrototype = NSSortDescriptor(key: "scanningSource", ascending: true)

        let cfColumn = NSTableColumn(identifier: NSUserInterfaceItemIdentifier("crossfile"))
        cfColumn.title = "Cross-file"
        cfColumn.width = 80
        cfColumn.sortDescriptorPrototype = NSSortDescriptor(key: "crossFile", ascending: false)

        let msgColumn = NSTableColumn(identifier: NSUserInterfaceItemIdentifier("msg"))
        msgColumn.title = "Finding"
        msgColumn.width = 300
        msgColumn.resizingMask = .autoresizingMask

        tableView.addTableColumn(expColumn)
        tableView.addTableColumn(sevColumn)
        tableView.addTableColumn(catColumn)
        tableView.addTableColumn(fnColumn)
        tableView.addTableColumn(fileColumn)
        tableView.addTableColumn(lineColumn)
        tableView.addTableColumn(srcColumn)
        tableView.addTableColumn(cfColumn)
        tableView.addTableColumn(msgColumn)

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
            statusLabel.topAnchor.constraint(equalTo: content.topAnchor, constant: 12),
            statusLabel.leadingAnchor.constraint(equalTo: content.leadingAnchor, constant: 16),
            statusLabel.trailingAnchor.constraint(lessThanOrEqualTo: ignoreButton.leadingAnchor, constant: -8),

            ignoreButton.topAnchor.constraint(equalTo: content.topAnchor, constant: 10),
            ignoreButton.trailingAnchor.constraint(equalTo: rescanButton.leadingAnchor, constant: -8),

            rescanButton.topAnchor.constraint(equalTo: content.topAnchor, constant: 10),
            rescanButton.trailingAnchor.constraint(equalTo: content.trailingAnchor, constant: -16),

            progressBar.topAnchor.constraint(equalTo: statusLabel.bottomAnchor, constant: 8),
            progressBar.leadingAnchor.constraint(equalTo: content.leadingAnchor, constant: 16),
            progressBar.trailingAnchor.constraint(equalTo: content.trailingAnchor, constant: -16),

            scrollView.topAnchor.constraint(equalTo: progressBar.bottomAnchor, constant: 8),
            scrollView.bottomAnchor.constraint(equalTo: content.bottomAnchor),
            scrollView.leadingAnchor.constraint(equalTo: content.leadingAnchor),
            scrollView.trailingAnchor.constraint(equalTo: content.trailingAnchor)
        ])
    }

    /// Loads results for `folder`, showing the cached scan if this folder was
    /// already scanned; otherwise performs a fresh scan.
    func load(folder: URL) {
        scannedFolder = folder
        rescanButton.isEnabled = true

        if let cached = ScanWindowController.cachedFolder, cached.standardizedFileURL == folder.standardizedFileURL {
            let cachedFindings = ScanWindowController.cachedFindings
            findings = applyIgnoredFilter(cachedFindings)
            applySorting()
            tableView.reloadData()
            if cachedFindings.isEmpty {
                statusLabel.stringValue = "Cached scan (no issues found) — Rescan to refresh."
            } else {
                statusLabel.stringValue = "Showing cached scan: \(cachedFindings.count) potential issue\(cachedFindings.count == 1 ? "" : "s") — Rescan to refresh."
            }
        } else {
            performScan(folder: folder)
        }
    }

    /// Removes findings the user has ignored, based on persisted (file, line) keys.
    private func applyIgnoredFilter(_ input: [ScanFinding]) -> [ScanFinding] {
        let ignored = ignoredLines
        guard !ignored.isEmpty else { return input }
        return input.filter { !ignored.contains(ignoredKey(for: $0)) }
    }

    /// Builds a stable key identifying a single finding across scans.
    private func ignoredKey(for f: ScanFinding) -> String {
        "\(f.fileURL.path)#\(f.line)"
    }

    private func applySorting() {
        guard !sortDescriptors.isEmpty else { return }
        let current = sortDescriptors
        findings.sort { a, b in
            for d in current {
                let result = compareFinding(a, b, descriptor: d)
                if result != .orderedSame {
                    // Reverse NSComparisonResult into a Bool for the ascending predicate.
                    return (result == .orderedAscending) == d.ascending
                }
            }
            return false
        }
    }

    /// Compares two findings according to one sort descriptor WITHOUT Key-Value
    /// Coding, because `ScanFinding` is a Swift struct (KVC would crash). The
    /// descriptor's `key` selects an explicit field comparator, and `comparator`
    /// (used by the File column) is honored when present.
    private func compareFinding(_ a: ScanFinding, _ b: ScanFinding, descriptor d: NSSortDescriptor) -> ComparisonResult {
        let key = d.key ?? ""
        switch key {
        case "line":
            return compareValues(a.line, b.line)
        case "severity":
            return compareValues(a.severity.rawValue, b.severity.rawValue)
        case "exploitability":
            return compareValues(a.exploitability.rawValue, b.exploitability.rawValue)
        case "scanningSource":
            return compareValues(a.scanningSource, b.scanningSource)
        case "crossFile":
            return compareValues(a.crossFile ? 1 : 0, b.crossFile ? 1 : 0)
        case "fileURL":
            return compareValues(a.fileURL.lastPathComponent, b.fileURL.lastPathComponent)
        default:
            // Fall back to a string comparison on whatever text is in that column.
            return compareValues(displayText(for: key, finding: a), displayText(for: key, finding: b))
        }
    }

    private func displayText(for key: String, finding f: ScanFinding) -> String {
        switch key {
        case "category": return f.category
        case "function": return f.function
        case "fileURL": return f.fileURL.lastPathComponent
        case "crossFile": return f.crossFile ? "Yes" : "No"
        default: return ""
        }
    }

    private func compareValues<T: Comparable>(_ a: T, _ b: T) -> ComparisonResult {
        if a < b { return .orderedAscending }
        if a > b { return .orderedDescending }
        return .orderedSame
    }

    @objc private func ignoreClicked(_ sender: Any?) {
        guard let f = selectedFinding() else { return }
        var key = ignoredKey(for: f)
        var set = ignoredLines
        set.insert(key)
        ignoredLines = set
        // Update the in-memory flag so a later re-sort / reselect stays consistent.
        if let idx = findings.firstIndex(where: { ignoredKey(for: $0) == key }) {
            findings[idx].ignored = true
            key = ignoredKey(for: findings[idx])
            _ = key
        }
        findings = applyIgnoredFilter(findings)
        tableView.reloadData()
        ignoreButton.isEnabled = selectedFinding() != nil
    }

    @objc private func rescanClicked(_ sender: Any?) {
        guard let folder = scannedFolder else { return }
        performScan(folder: folder)
    }

    /// Runs a scan of `folder` on a background queue, stores the result in the
    /// shared cache, and shows results on the main thread. If the window is
    /// closed while the scan is running, the scan is cancelled and the results
    /// are discarded.
    private func performScan(folder: URL) {
        statusLabel.stringValue = "Scanning \(folder.lastPathComponent)…"
        progressBar.doubleValue = 0
        progressBar.isIndeterminate = true
        progressBar.isHidden = false
        progressBar.startAnimation(nil)
        scanCancelled = false

        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            let result = VulnerabilityScanner.scan(projectRoot: folder,
                                                   progress: { done, total in
                DispatchQueue.main.async {
                    guard let self = self, !self.scanCancelled else { return }
                    let fraction = total > 0 ? Double(done) / Double(total) : 0
                    if self.progressBar.isIndeterminate {
                        self.progressBar.isIndeterminate = false
                        self.progressBar.stopAnimation(nil)
                    }
                    self.progressBar.doubleValue = fraction
                }
            }, isCancelled: { [weak self] in
                self?.scanCancelled == true
            }, sourceIndex: self?.sourceIndex)
            DispatchQueue.main.async {
                guard let self = self, !self.scanCancelled else { return }
                ScanWindowController.cachedFolder = folder
                ScanWindowController.cachedFindings = result
                self.progressBar.doubleValue = 1
                self.progressBar.isHidden = true
                self.progressBar.stopAnimation(nil)
                self.findings = self.applyIgnoredFilter(result)
                self.applySorting()
                self.tableView.reloadData()
                if result.isEmpty {
                    self.statusLabel.stringValue = "Scan complete: no issues found."
                } else {
                    self.statusLabel.stringValue = "Scan complete: \(result.count) potential issue\(result.count == 1 ? "" : "s") found."
                }
            }
        }
    }

    private func selectedFinding() -> ScanFinding? {
        let row = tableView.selectedRow
        guard row >= 0, row < findings.count else { return nil }
        return findings[row]
    }

    @objc private func rowClicked(_ sender: Any?) {
        ignoreButton.isEnabled = selectedFinding() != nil
        openSelected()
    }

    @objc private func rowDoubleClicked(_ sender: Any?) {
        openSelected()
    }

    private func openSelected() {
        guard let f = selectedFinding() else { return }
        onOpenResult?(f.fileURL, f.line)
    }
}

extension ScanWindowController: NSWindowDelegate {
    func windowWillClose(_ notification: Notification) {
        // Cancel any in-progress scan so the background work stops immediately
        // rather than continuing to churn CPU on a closed window.
        scanCancelled = true
    }
}

extension ScanWindowController: NSTableViewDataSource, NSTableViewDelegate {
    func numberOfRows(in tableView: NSTableView) -> Int {
        findings.count
    }

    func tableView(_ tableView: NSTableView, sortDescriptorsDidChange oldDescriptors: [NSSortDescriptor]) {
        sortDescriptors = tableView.sortDescriptors
        applySorting()
        tableView.reloadData()
    }

    func tableView(_ tableView: NSTableView, viewFor tableColumn: NSTableColumn?, row: Int) -> NSView? {
        guard row < findings.count else { return nil }
        let f = findings[row]
        let columnID = tableColumn?.identifier.rawValue ?? ""
        let isMsg = columnID == "msg"
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

            if isMsg {
                // Multi-line wrapping for the Finding column so the full text is readable.
                field.maximumNumberOfLines = 0
                field.lineBreakMode = .byWordWrapping
                field.setContentHuggingPriority(.fittingSizeCompression, for: .vertical)
                field.setContentCompressionResistancePriority(.defaultLow, for: .vertical)
                field.preferredMaxLayoutWidth = columnWidth(for: "msg")
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

        // Keep the preferred width in sync for correct wrapping when resizing.
        if isMsg {
            cellView.textField?.preferredMaxLayoutWidth = columnWidth(for: "msg")
        }

        cellView.textField?.textColor = .labelColor
        cellView.textField?.font = NSFont.systemFont(ofSize: 12)
        cellView.textField?.alignment = .left
        cellView.textField?.toolTip = nil

        switch columnID {
        case "exp":
            cellView.textField?.stringValue = f.exploitability.label
            cellView.textField?.font = NSFont.systemFont(ofSize: 12, weight: .bold)
            cellView.textField?.textColor = f.exploitability.color
        case "sev":
            cellView.textField?.stringValue = f.severity.label
            cellView.textField?.font = NSFont.systemFont(ofSize: 12, weight: .semibold)
            cellView.textField?.textColor = f.severity.color
        case "cat":
            cellView.textField?.stringValue = f.category
        case "fn":
            var fnText = f.function
            if !f.reachable { fnText += "  ⇢" }
            cellView.textField?.stringValue = fnText
            cellView.textField?.toolTip = f.reachable ? "Function is reachable from an entry point." : "Function is NOT reachable from an entry point in this file."
        case "file":
            cellView.textField?.stringValue = f.fileURL.lastPathComponent
            cellView.textField?.toolTip = f.fileURL.path
        case "line":
            cellView.textField?.stringValue = "\(f.line)"
            cellView.textField?.alignment = .right
        case "src":
            cellView.textField?.stringValue = f.scanningSource
            cellView.textField?.alignment = .center
            if f.scanningSource == "AST" {
                cellView.textField?.font = NSFont.systemFont(ofSize: 12, weight: .bold)
                cellView.textField?.textColor = .systemGreen
            } else {
                cellView.textField?.font = NSFont.systemFont(ofSize: 12, weight: .semibold)
                cellView.textField?.textColor = .systemBlue
            }
        case "crossfile":
            cellView.textField?.stringValue = f.crossFile ? "Yes" : "No"
            cellView.textField?.alignment = .center
            if f.crossFile {
                cellView.textField?.font = NSFont.systemFont(ofSize: 12, weight: .semibold)
                cellView.textField?.textColor = .systemOrange
                cellView.textField?.toolTip = "Taint originates from a source defined in another file."
            } else {
                cellView.textField?.toolTip = "Taint is local to this file or from a built-in source."
            }
        case "msg":
            var parts: [String] = []
            if let path = f.taintPath, !path.isEmpty { parts.append("flow: \(path)") }
            parts.append(f.message)
            if !f.reachable { parts.append("(function not reachable from entry point)") }
            let base = parts.joined(separator: "\n")
            cellView.textField?.stringValue = base
            cellView.textField?.toolTip = base
        default:
            cellView.textField?.stringValue = ""
        }
        return cellView
    }

    private func columnWidth(for id: String) -> CGFloat {
        if let col = tableView.tableColumn(withIdentifier: NSUserInterfaceItemIdentifier(id)) {
            return col.width - 12
        }
        return 280
    }

    func tableView(_ tableView: NSTableView, heightOfRow row: Int) -> CGFloat {
        guard row < findings.count else { return 30 }
        let f = findings[row]
        let width = columnWidth(for: "msg")
        var text = f.message
        if let path = f.taintPath, !path.isEmpty { text = "flow: \(path)\n" + text }
        if !f.reachable { text += "\n(function not reachable)" }

        let field = NSTextField(wrappingLabelWithString: text)
        field.font = NSFont.systemFont(ofSize: 12)
        field.maximumNumberOfLines = 0
        field.lineBreakMode = .byWordWrapping
        field.preferredMaxLayoutWidth = width
        let size = field.fittingSize
        return max(28, size.height + 8)
    }
}

// by cipher.org.uk
import AppKit
import UniformTypeIdentifiers

final class PackageScanWindowController: NSWindowController {
    private let descriptionLabel = NSTextField(wrappingLabelWithString:
        "Scans this project's dependency manifests and lockfiles for known vulnerabilities by checking every resolved package version against the API source below. Lockfiles are preferred over manifests, and only exact versions are queried.")
    private let apiCaption = NSTextField(labelWithString: "API source:")
    private let apiPopup = NSPopUpButton(frame: .zero, pullsDown: false)
    private let filesCaption = NSTextField(labelWithString: "Package files detected:")
    private let filesScrollView = NSScrollView()
    private let filesTextView = NSTextView()
    private let privacyLabel = NSTextField(wrappingLabelWithString: "")
    private let statusLabel = NSTextField(wrappingLabelWithString: "Detecting package files…")
    private let spinner = NSProgressIndicator()
    private let progressBar = NSProgressIndicator()
    private let scanButton = NSButton(title: "Scan", target: nil, action: nil)
    private let ignoreButton = NSButton(title: "Ignore issue", target: nil, action: nil)
    private let exportButton = NSButton(title: "Export Scan", target: nil, action: nil)
    private let tableView = FindingsTableView()
    private let tableScrollView = NSScrollView()

    private var findings: [ScanFinding] = [] {
        didSet { exportButton.isEnabled = !findings.isEmpty }
    }
    private var detectedFiles: [PackageDetection.DetectedFile] = []
    private var projectRoot: URL?
    private var busy = false
    private var cancelled = false
    private var sortDescriptors: [NSSortDescriptor] = []

    var onOpenResult: ((URL, Int) -> Void)?
    var onAskAI: ((String) -> Void)?

    private var ignoredLines: Set<String> {
        get {
            Set(UserDefaults.standard.stringArray(forKey: "PackageScanWindowController.ignoredLines") ?? [])
        }
        set {
            UserDefaults.standard.set(Array(newValue), forKey: "PackageScanWindowController.ignoredLines")
        }
    }

    convenience init(projectRoot: URL) {
        let window = EscClosableWindow(
            contentRect: NSRect(x: 0, y: 0, width: 1120, height: 660),
            styleMask: [.titled, .closable, .resizable, .miniaturizable],
            backing: .buffered,
            defer: false
        )
        window.title = "Scan Project's Packages"
        window.minSize = NSSize(width: 940, height: 560)
        self.init(window: window)
        self.projectRoot = projectRoot
        buildContent()
        startDetection()
    }

    override func showWindow(_ sender: Any?) {
        window?.center()
        window?.delegate = self
        super.showWindow(sender)
    }

    private func buildContent() {
        guard let content = window?.contentView else { return }

        descriptionLabel.font = NSFont.systemFont(ofSize: 12)
        descriptionLabel.textColor = .secondaryLabelColor
        descriptionLabel.translatesAutoresizingMaskIntoConstraints = false
        content.addSubview(descriptionLabel)

        apiCaption.font = NSFont.systemFont(ofSize: 12)
        apiCaption.translatesAutoresizingMaskIntoConstraints = false
        content.addSubview(apiCaption)

        apiPopup.addItems(withTitles: ["api.osv.dev"])
        apiPopup.lastItem?.representedObject = OSVClient.defaultEndpoint
        apiPopup.target = self
        apiPopup.action = #selector(apiSourceChanged(_:))
        apiPopup.translatesAutoresizingMaskIntoConstraints = false
        content.addSubview(apiPopup)
        updatePrivacyLabel()

        filesCaption.font = NSFont.systemFont(ofSize: 12)
        filesCaption.translatesAutoresizingMaskIntoConstraints = false
        content.addSubview(filesCaption)

        filesTextView.isEditable = false
        filesTextView.isSelectable = true
        filesTextView.font = NSFont.monospacedSystemFont(ofSize: 11, weight: .regular)
        filesTextView.backgroundColor = .textBackgroundColor
        filesTextView.textContainerInset = NSSize(width: 6, height: 6)
        filesTextView.autoresizingMask = [.width]
        filesTextView.isVerticallyResizable = true
        filesTextView.isHorizontallyResizable = false
        filesTextView.textContainer?.widthTracksTextView = true
        filesTextView.textContainer?.containerSize = NSSize(width: 0, height: CGFloat.greatestFiniteMagnitude)
        filesScrollView.documentView = filesTextView
        filesScrollView.hasVerticalScroller = true
        filesScrollView.borderType = .bezelBorder
        filesScrollView.translatesAutoresizingMaskIntoConstraints = false
        content.addSubview(filesScrollView)

        privacyLabel.font = NSFont.systemFont(ofSize: 11)
        privacyLabel.textColor = .systemOrange
        privacyLabel.translatesAutoresizingMaskIntoConstraints = false
        content.addSubview(privacyLabel)

        statusLabel.font = NSFont.systemFont(ofSize: 12)
        statusLabel.textColor = .secondaryLabelColor
        statusLabel.translatesAutoresizingMaskIntoConstraints = false
        content.addSubview(statusLabel)

        spinner.style = .spinning
        spinner.controlSize = .small
        spinner.isDisplayedWhenStopped = false
        spinner.translatesAutoresizingMaskIntoConstraints = false
        content.addSubview(spinner)

        ignoreButton.bezelStyle = .rounded
        ignoreButton.controlSize = .small
        ignoreButton.isEnabled = false
        ignoreButton.target = self
        ignoreButton.action = #selector(ignoreClicked(_:))
        ignoreButton.toolTip = "Hide this finding (persisted across sessions)"
        ignoreButton.translatesAutoresizingMaskIntoConstraints = false
        content.addSubview(ignoreButton)

        exportButton.bezelStyle = .rounded
        exportButton.controlSize = .small
        exportButton.isEnabled = false
        exportButton.bezelColor = .systemOrange
        exportButton.contentTintColor = .labelColor
        exportButton.target = self
        exportButton.action = #selector(exportClicked(_:))
        exportButton.toolTip = "Save the rows shown in the table as a SARIF file"
        exportButton.translatesAutoresizingMaskIntoConstraints = false
        content.addSubview(exportButton)

        scanButton.bezelStyle = .rounded
        scanButton.controlSize = .small
        scanButton.target = self
        scanButton.action = #selector(scanClicked(_:))
        scanButton.toolTip = "Re-detect package files and query the selected source"
        scanButton.translatesAutoresizingMaskIntoConstraints = false
        content.addSubview(scanButton)

        progressBar.style = .bar
        progressBar.isIndeterminate = false
        progressBar.minValue = 0
        progressBar.maxValue = 1
        progressBar.isHidden = true
        progressBar.translatesAutoresizingMaskIntoConstraints = false
        content.addSubview(progressBar)

        let severityColumn = NSTableColumn(identifier: NSUserInterfaceItemIdentifier("sev"))
        severityColumn.title = "Severity"
        severityColumn.width = 84
        severityColumn.sortDescriptorPrototype = NSSortDescriptor(key: "severity", ascending: false)

        let packageColumn = NSTableColumn(identifier: NSUserInterfaceItemIdentifier("pkg"))
        packageColumn.title = "Package"
        packageColumn.width = 200
        packageColumn.sortDescriptorPrototype = NSSortDescriptor(key: "package", ascending: true)

        let fileColumn = NSTableColumn(identifier: NSUserInterfaceItemIdentifier("file"))
        fileColumn.title = "File"
        fileColumn.width = 160
        fileColumn.sortDescriptorPrototype = NSSortDescriptor(key: "fileURL", ascending: true)

        let lineColumn = NSTableColumn(identifier: NSUserInterfaceItemIdentifier("line"))
        lineColumn.title = "Line"
        lineColumn.width = 50
        lineColumn.sortDescriptorPrototype = NSSortDescriptor(key: "line", ascending: true)

        let messageColumn = NSTableColumn(identifier: NSUserInterfaceItemIdentifier("msg"))
        messageColumn.title = "Finding"
        messageColumn.width = 320
        messageColumn.resizingMask = .autoresizingMask

        tableView.addTableColumn(severityColumn)
        tableView.addTableColumn(packageColumn)
        tableView.addTableColumn(fileColumn)
        tableView.addTableColumn(lineColumn)
        tableView.addTableColumn(messageColumn)
        tableView.usesAlternatingRowBackgroundColors = true
        tableView.usesAutomaticRowHeights = true
        tableView.columnAutoresizingStyle = .lastColumnOnlyAutoresizingStyle
        tableView.dataSource = self
        tableView.delegate = self
        tableView.target = self
        tableView.action = #selector(rowClicked(_:))
        tableView.doubleAction = #selector(rowDoubleClicked(_:))
        tableView.contextMenuProvider = { [weak self] row in
            self?.contextMenu(row: row)
        }

        tableScrollView.documentView = tableView
        tableScrollView.hasVerticalScroller = true
        tableScrollView.autohidesScrollers = true
        tableScrollView.translatesAutoresizingMaskIntoConstraints = false
        content.addSubview(tableScrollView)

        NSLayoutConstraint.activate([
            descriptionLabel.topAnchor.constraint(equalTo: content.topAnchor, constant: 14),
            descriptionLabel.leadingAnchor.constraint(equalTo: content.leadingAnchor, constant: 16),
            descriptionLabel.trailingAnchor.constraint(equalTo: content.trailingAnchor, constant: -16),

            apiCaption.topAnchor.constraint(equalTo: descriptionLabel.bottomAnchor, constant: 10),
            apiCaption.leadingAnchor.constraint(equalTo: content.leadingAnchor, constant: 16),
            apiPopup.centerYAnchor.constraint(equalTo: apiCaption.centerYAnchor),
            apiPopup.leadingAnchor.constraint(equalTo: apiCaption.trailingAnchor, constant: 6),

            filesCaption.topAnchor.constraint(equalTo: apiCaption.bottomAnchor, constant: 12),
            filesCaption.leadingAnchor.constraint(equalTo: content.leadingAnchor, constant: 16),

            filesScrollView.topAnchor.constraint(equalTo: filesCaption.bottomAnchor, constant: 4),
            filesScrollView.leadingAnchor.constraint(equalTo: content.leadingAnchor, constant: 16),
            filesScrollView.trailingAnchor.constraint(equalTo: content.trailingAnchor, constant: -16),
            filesScrollView.heightAnchor.constraint(equalToConstant: 96),

            privacyLabel.topAnchor.constraint(equalTo: filesScrollView.bottomAnchor, constant: 8),
            privacyLabel.leadingAnchor.constraint(equalTo: content.leadingAnchor, constant: 16),
            privacyLabel.trailingAnchor.constraint(equalTo: content.trailingAnchor, constant: -16),

            statusLabel.topAnchor.constraint(equalTo: privacyLabel.bottomAnchor, constant: 10),
            statusLabel.leadingAnchor.constraint(equalTo: content.leadingAnchor, constant: 16),
            statusLabel.trailingAnchor.constraint(lessThanOrEqualTo: spinner.leadingAnchor, constant: -8),

            spinner.centerYAnchor.constraint(equalTo: statusLabel.centerYAnchor),
            spinner.trailingAnchor.constraint(equalTo: ignoreButton.leadingAnchor, constant: -8),

            ignoreButton.centerYAnchor.constraint(equalTo: statusLabel.centerYAnchor),
            ignoreButton.trailingAnchor.constraint(equalTo: exportButton.leadingAnchor, constant: -8),

            exportButton.centerYAnchor.constraint(equalTo: statusLabel.centerYAnchor),
            exportButton.trailingAnchor.constraint(equalTo: scanButton.leadingAnchor, constant: -8),

            scanButton.centerYAnchor.constraint(equalTo: statusLabel.centerYAnchor),
            scanButton.trailingAnchor.constraint(equalTo: content.trailingAnchor, constant: -16),

            progressBar.topAnchor.constraint(equalTo: statusLabel.bottomAnchor, constant: 8),
            progressBar.leadingAnchor.constraint(equalTo: content.leadingAnchor, constant: 16),
            progressBar.trailingAnchor.constraint(equalTo: content.trailingAnchor, constant: -16),

            tableScrollView.topAnchor.constraint(equalTo: progressBar.bottomAnchor, constant: 6),
            tableScrollView.bottomAnchor.constraint(equalTo: content.bottomAnchor),
            tableScrollView.leadingAnchor.constraint(equalTo: content.leadingAnchor),
            tableScrollView.trailingAnchor.constraint(equalTo: content.trailingAnchor),
        ])
    }

    private func updatePrivacyLabel() {
        let host = (apiPopup.selectedItem?.representedObject as? URL)?.host ?? "the selected service"
        privacyLabel.stringValue = "Privacy: package names and versions are sent to \(host) when you scan. Source code, file contents, and file paths are never sent."
    }

    @objc private func apiSourceChanged(_ sender: Any?) {
        updatePrivacyLabel()
    }

    private func updateFilesList(_ detection: PackageDetection) {
        detectedFiles = detection.files
        filesTextView.string = detection.files.map { file in
            let kind = file.isLockfile ? "lockfile" : "manifest"
            return "\(file.relativePath) — \(file.language)/\(file.ecosystem) (\(kind))"
        }.joined(separator: "\n")
    }

    private func startDetection() {
        guard let root = projectRoot else { return }
        busy = true
        scanButton.isEnabled = false
        spinner.startAnimation(nil)
        statusLabel.stringValue = "Detecting package files…"
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            let detection = PackageDetector.detect(root: root)
            DispatchQueue.main.async { [weak self] in
                guard let self = self else { return }
                self.busy = false
                self.spinner.stopAnimation(nil)
                self.applyDetection(detection)
            }
        }
    }

    private func applyDetection(_ detection: PackageDetection) {
        updateFilesList(detection)
        guard !detection.files.isEmpty else {
            filesTextView.string = "(no supported dependency manifests or lockfiles found)"
            statusLabel.stringValue = "The current project is not supported for package scanning"
            statusLabel.textColor = .systemOrange
            scanButton.isEnabled = false
            return
        }
        let entries = detection.dependencies.count
        let files = detection.files.count
        statusLabel.stringValue = "\(entries) package entr\(entries == 1 ? "y" : "ies") in \(files) file\(files == 1 ? "" : "s"). Click Scan to query."
        statusLabel.textColor = .secondaryLabelColor
        scanButton.isEnabled = true
    }

    @objc private func scanClicked(_ sender: Any?) {
        guard !busy,
              let root = projectRoot,
              let endpoint = apiPopup.selectedItem?.representedObject as? URL else { return }
        busy = true
        cancelled = false
        scanButton.isEnabled = false
        ignoreButton.isEnabled = false
        spinner.startAnimation(nil)
        progressBar.isHidden = false
        progressBar.isIndeterminate = true
        progressBar.startAnimation(nil)
        statusLabel.textColor = .secondaryLabelColor
        statusLabel.stringValue = "Detecting package files…"
        let host = endpoint.host ?? "the selected service"

        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            guard let self = self else { return }
            let detection = PackageDetector.detect(root: root)
            var result: Result<(detection: PackageDetection, findings: [ScanFinding]), Error>
            if detection.dependencies.isEmpty {
                result = .success((detection, []))
            } else {
                do {
                    let vulnerabilities = try OSVClient.vulnerabilities(
                        for: detection.dependencies,
                        endpoint: endpoint
                    ) { stage in
                        DispatchQueue.main.async { [weak self] in
                            guard let self = self, !self.cancelled else { return }
                            self.progressBar.isIndeterminate = false
                            self.progressBar.stopAnimation(nil)
                            switch stage {
                            case .querying(let done, let total):
                                if total > 0 {
                                    self.progressBar.doubleValue = 0.7 * Double(done) / Double(total)
                                }
                                self.statusLabel.stringValue = "Querying \(host)… \(done)/\(total) packages"
                            case .fetchingDetails(let done, let total):
                                if total > 0 {
                                    self.progressBar.doubleValue = 0.7 + 0.3 * Double(done) / Double(total)
                                }
                                self.statusLabel.stringValue = "Fetching vulnerability details… \(done)/\(total)"
                            }
                        }
                    }
                    result = .success((detection, self.makeFindings(
                        dependencies: detection.dependencies,
                        vulnerabilities: vulnerabilities)))
                } catch {
                    result = .failure(error)
                }
            }
            DispatchQueue.main.async { [weak self] in
                self?.finishScan(result)
            }
        }
    }

    private func finishScan(_ result: Result<(detection: PackageDetection, findings: [ScanFinding]), Error>) {
        spinner.stopAnimation(nil)
        progressBar.stopAnimation(nil)
        progressBar.isHidden = true
        busy = false
        guard !cancelled else { return }
        switch result {
        case .failure(let error):
            statusLabel.textColor = .systemRed
            statusLabel.stringValue = "Scan failed: \(error.localizedDescription)"
            scanButton.isEnabled = !detectedFiles.isEmpty
        case .success(let payload):
            updateFilesList(payload.detection)
            guard !payload.detection.files.isEmpty else {
                applyDetection(payload.detection)
                findings = []
                return
            }
            findings = applyIgnoredFilter(payload.findings)
            applySorting()
            tableView.reloadData()
            scanButton.isEnabled = true
            statusLabel.textColor = .secondaryLabelColor
            guard !payload.findings.isEmpty else {
                statusLabel.stringValue = "Scan complete: no known vulnerabilities found."
                return
            }
            let total = payload.findings.count
            var text = "Scan complete: \(total) known vulnerabilit\(total == 1 ? "y" : "ies") found."
            let hidden = total - findings.count
            if hidden > 0 {
                text += " (\(hidden) ignored row\(hidden == 1 ? "" : "s") hidden)"
            }
            statusLabel.stringValue = text
        }
    }

    private func makeFindings(dependencies: [PackageDependency],
                              vulnerabilities: [String: [OSVVulnerability]]) -> [ScanFinding] {
        var out: [ScanFinding] = []
        for dependency in dependencies {
            let key = OSVClient.queryKey(ecosystem: dependency.ecosystem,
                                         name: dependency.name,
                                         version: dependency.version)
            guard let matches = vulnerabilities[key], !matches.isEmpty else { continue }
            for vulnerability in matches {
                let severity: ScanFinding.Severity
                switch OSVClient.severity(of: vulnerability) {
                case .critical: severity = .critical
                case .high: severity = .high
                case .medium: severity = .medium
                case .low: severity = .low
                }
                let summary = vulnerability.summary.flatMap { $0.isEmpty ? nil : $0 }
                    ?? vulnerability.details?.components(separatedBy: "\n").first
                    ?? vulnerability.id
                let displayID = vulnerability.aliases?.first(where: { $0.hasPrefix("CVE-") })
                    ?? vulnerability.id
                out.append(ScanFinding(fileURL: dependency.fileURL,
                                       line: dependency.line,
                                       function: dependency.ecosystem,
                                       category: vulnerability.id,
                                       message: "\(displayID): \(summary)",
                                       taint: nil,
                                       severity: severity,
                                       exploitability: severity,
                                       reachable: true,
                                       taintPath: nil,
                                       ignored: false,
                                       scanningSource: "OSV",
                                       crossFile: false,
                                       packageName: "\(dependency.name)@\(dependency.version)"))
            }
        }
        out.sort { a, b in
            if a.severity != b.severity { return a.severity > b.severity }
            let lhs = a.packageName ?? ""
            let rhs = b.packageName ?? ""
            if lhs != rhs { return lhs < rhs }
            return a.category < b.category
        }
        return out
    }

    private func applyIgnoredFilter(_ input: [ScanFinding]) -> [ScanFinding] {
        let ignored = ignoredLines
        guard !ignored.isEmpty else { return input }
        return input.filter { !ignored.contains(ignoredKey(for: $0)) }
    }

    private func ignoredKey(for finding: ScanFinding) -> String {
        "\(finding.fileURL.path)#\(finding.line)#\(finding.packageName ?? "")"
    }

    private func applySorting() {
        guard !sortDescriptors.isEmpty else { return }
        let current = sortDescriptors
        findings.sort { a, b in
            for descriptor in current {
                let result = compareFinding(a, b, descriptor: descriptor)
                if result != .orderedSame {
                    return (result == .orderedAscending) == descriptor.ascending
                }
            }
            return false
        }
    }

    private func compareFinding(_ a: ScanFinding, _ b: ScanFinding,
                                descriptor: NSSortDescriptor) -> ComparisonResult {
        switch descriptor.key ?? "" {
        case "severity":
            return compareValues(a.severity.rawValue, b.severity.rawValue)
        case "package":
            return compareValues(a.packageName ?? "", b.packageName ?? "")
        case "fileURL":
            return compareValues(a.fileURL.lastPathComponent, b.fileURL.lastPathComponent)
        case "line":
            return compareValues(a.line, b.line)
        default:
            return compareValues(a.message, b.message)
        }
    }

    private func compareValues<T: Comparable>(_ a: T, _ b: T) -> ComparisonResult {
        if a < b { return .orderedAscending }
        if a > b { return .orderedDescending }
        return .orderedSame
    }

    private func selectedFinding() -> ScanFinding? {
        let row = tableView.selectedRow
        guard row >= 0, row < findings.count else { return nil }
        return findings[row]
    }

    @objc private func ignoreClicked(_ sender: Any?) {
        guard let finding = selectedFinding() else { return }
        var set = ignoredLines
        set.insert(ignoredKey(for: finding))
        ignoredLines = set
        findings = applyIgnoredFilter(findings)
        tableView.reloadData()
        ignoreButton.isEnabled = selectedFinding() != nil
    }

    @objc private func exportClicked(_ sender: Any?) {
        guard !findings.isEmpty else { return }
        let panel = NSSavePanel()
        panel.title = "Export Scan"
        panel.nameFieldStringValue = "KarmaPro-packages.sarif.json"
        panel.allowedContentTypes = [.json]
        panel.canCreateDirectories = true
        panel.message = "Exports the \(findings.count) finding\(findings.count == 1 ? "" : "s") "
            + "shown in the table, with absolute file paths."
        guard panel.runModal() == .OK, let url = panel.url else { return }
        do {
            try SARIFExport.data(from: findings).write(to: url, options: .atomic)
        } catch {
            let alert = NSAlert()
            alert.messageText = "Export Failed"
            alert.informativeText = error.localizedDescription
            alert.alertStyle = .warning
            alert.addButton(withTitle: "OK")
            alert.runModal()
        }
    }

    @objc private func rowClicked(_ sender: Any?) {
        ignoreButton.isEnabled = selectedFinding() != nil
        openSelected()
    }

    @objc private func rowDoubleClicked(_ sender: Any?) {
        openSelected()
    }

    private func openSelected() {
        guard let finding = selectedFinding() else { return }
        onOpenResult?(finding.fileURL, finding.line)
    }

    private func contextMenu(row: Int) -> NSMenu? {
        guard row >= 0, row < findings.count else { return nil }
        ignoreButton.isEnabled = selectedFinding() != nil
        let menu = NSMenu(title: "")
        let item = NSMenuItem(title: "(AI) Is it vulnerable?",
                              action: #selector(askIfVulnerable(_:)),
                              keyEquivalent: "")
        item.target = self
        item.representedObject = row
        menu.addItem(item)
        return menu
    }

    @objc private func askIfVulnerable(_ sender: NSMenuItem) {
        guard let row = sender.representedObject as? Int,
              row >= 0, row < findings.count else { return }
        let finding = findings[row]
        onAskAI?("Is the currently open project vulnerable to: \(finding.message)")
    }
}

extension PackageScanWindowController: NSWindowDelegate {
    func windowWillClose(_ notification: Notification) {
        cancelled = true
    }
}

extension PackageScanWindowController: NSTableViewDataSource, NSTableViewDelegate {
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
        let finding = findings[row]
        let columnID = tableColumn?.identifier.rawValue ?? ""
        let isMessage = columnID == "msg"
        let identifier = NSUserInterfaceItemIdentifier("cell_\(columnID)")

        let cellView: NSTableCellView
        if let reused = tableView.makeView(withIdentifier: identifier, owner: nil) as? NSTableCellView {
            cellView = reused
        } else {
            cellView = NSTableCellView()
            cellView.identifier = identifier
            let field = NSTextField(wrappingLabelWithString: "")
            field.font = NSFont.systemFont(ofSize: 12)
            field.translatesAutoresizingMaskIntoConstraints = false
            cellView.addSubview(field)
            cellView.textField = field

            if isMessage {
                field.maximumNumberOfLines = 0
                field.lineBreakMode = .byWordWrapping
                field.setContentHuggingPriority(.fittingSizeCompression, for: .vertical)
                field.setContentCompressionResistancePriority(.defaultLow, for: .vertical)
                field.preferredMaxLayoutWidth = columnWidth(for: "msg")
                NSLayoutConstraint.activate([
                    field.leadingAnchor.constraint(equalTo: cellView.leadingAnchor, constant: 6),
                    field.trailingAnchor.constraint(equalTo: cellView.trailingAnchor, constant: -6),
                    field.topAnchor.constraint(equalTo: cellView.topAnchor, constant: 4),
                    field.bottomAnchor.constraint(equalTo: cellView.bottomAnchor, constant: -4),
                ])
            } else {
                field.lineBreakMode = .byTruncatingTail
                NSLayoutConstraint.activate([
                    field.leadingAnchor.constraint(equalTo: cellView.leadingAnchor, constant: 6),
                    field.trailingAnchor.constraint(equalTo: cellView.trailingAnchor, constant: -6),
                    field.centerYAnchor.constraint(equalTo: cellView.centerYAnchor),
                ])
            }
        }

        if isMessage {
            cellView.textField?.preferredMaxLayoutWidth = columnWidth(for: "msg")
        }
        cellView.textField?.textColor = .labelColor
        cellView.textField?.font = NSFont.systemFont(ofSize: 12)
        cellView.textField?.alignment = .left
        cellView.textField?.toolTip = nil

        switch columnID {
        case "sev":
            cellView.textField?.stringValue = finding.severity.label
            cellView.textField?.font = NSFont.systemFont(ofSize: 12, weight: .semibold)
            cellView.textField?.textColor = finding.severity.color
        case "pkg":
            cellView.textField?.stringValue = finding.packageName ?? ""
            cellView.textField?.toolTip = finding.packageName
        case "file":
            cellView.textField?.stringValue = finding.fileURL.lastPathComponent
            cellView.textField?.toolTip = finding.fileURL.path
        case "line":
            cellView.textField?.stringValue = "\(finding.line)"
            cellView.textField?.alignment = .right
        case "msg":
            cellView.textField?.stringValue = finding.message
            cellView.textField?.toolTip = finding.message
        default:
            cellView.textField?.stringValue = ""
        }
        return cellView
    }

    private func columnWidth(for id: String) -> CGFloat {
        if let column = tableView.tableColumn(withIdentifier: NSUserInterfaceItemIdentifier(id)) {
            return column.width - 12
        }
        return 300
    }

    func tableView(_ tableView: NSTableView, heightOfRow row: Int) -> CGFloat {
        guard row < findings.count else { return 30 }
        let width = columnWidth(for: "msg")
        let field = NSTextField(wrappingLabelWithString: findings[row].message)
        field.font = NSFont.systemFont(ofSize: 12)
        field.maximumNumberOfLines = 0
        field.lineBreakMode = .byWordWrapping
        field.preferredMaxLayoutWidth = width
        return max(28, field.fittingSize.height + 8)
    }
}

private final class FindingsTableView: NSTableView {
    var contextMenuProvider: ((Int) -> NSMenu?)?

    override func menu(for event: NSEvent) -> NSMenu? {
        let point = convert(event.locationInWindow, from: nil)
        let row = row(at: point)
        guard row >= 0 else { return nil }
        if row != selectedRow {
            selectRowIndexes(IndexSet(integer: row), byExtendingSelection: false)
        }
        return contextMenuProvider?(row)
    }
}

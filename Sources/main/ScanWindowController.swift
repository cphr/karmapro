// by cipher.org.uk
import AppKit
import UniformTypeIdentifiers

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
    private let aiThinkingLabel = NSTextField(labelWithString: "(thinking)")
    private let aiThinkingSpinner = NSProgressIndicator()
    private let progressBar = NSProgressIndicator()
    private let rescanButton = NSButton(title: "Rescan", target: nil, action: nil)
    private let ignoreButton = NSButton(title: "Ignore issue", target: nil, action: nil)
    private let autoTriageButton = NSButton(title: "Triage (AI)", target: nil, action: nil)
    private let exportButton = NSButton(title: "Export Scan", target: nil, action: nil)

    // MARK: - Triage state

    /// Verdict per finding key (path#line): true = valid, false = invalid.
    private var triageVerdicts: [String: Bool] = [:]
    private var triageRows: [ScanFinding] = []
    private var triageIndex = 0
    private var triageFailed = 0
    private var triageRunning = false
    private var triageCancelled = false
    private var triageColumn: NSTableColumn?

    private var findings: [ScanFinding] = [] {
        // Export is available exactly when the table has rows to export, so
        // every assignment that changes what is shown updates it here rather
        // than at each of the handful of assignment sites.
        didSet {
            exportButton.isEnabled = !findings.isEmpty
            refreshAutoTriageButton()
        }
    }
    private var scannedFolder: URL?

    // MARK: - Pull request review mode

    /// Set while the window is reviewing a pull request. Nil for an ordinary
    /// project scan, which keeps every existing code path unchanged.
    var prSession: PRReviewSession?
    /// Classification for the current results, keyed the same way as the
    /// "ignore" set so both survive the same row assembly.
    private var prAwareness: [String: DiffAwareness] = [:]
    private var prReviewColumn: NSTableColumn?
    private var prBanner: PRBannerView?
    /// The project-wide source cache to reuse for walking and reading during a
    /// scan, when the app already loaded it for the same folder. Kept weak-like
    /// by the caller (already retained by the main controller for its lifetime).
    var sourceIndex: ProjectSourceIndex?
    /// Set to true when a scan is running; cleared when it completes or is
    /// cancelled. When the user closes the window mid-scan, this is flipped so the
    /// background scan stops and never touches a deallocated view.
    private var scanCancelled = false

    /// True while the AI discovery pass may still emit stream deltas. Cleared
    /// the instant the pass finishes so a late (thinking)/(answering) delta can
    /// never re-show the indicator after the scan has completed.
    private var aiPhaseActive = false

    /// Whether the AI scan was requested by the user at the Security Scanner
    /// button; kept so the Rescan action repeats the same choice.
    private var wantsAI = false
    private var wantsAIBase = false

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
        // The AI Assistant may have been configured since this window opened.
        refreshAutoTriageButton()
        super.showWindow(sender)
    }

    private func buildContent() {
        guard let content = window?.contentView else { return }

        statusLabel.font = NSFont.systemFont(ofSize: 12)
        statusLabel.textColor = .secondaryLabelColor
        statusLabel.setContentCompressionResistancePriority(.defaultLow, for: .horizontal)
        statusLabel.translatesAutoresizingMaskIntoConstraints = false
        content.addSubview(statusLabel)

        aiThinkingLabel.font = NSFont.systemFont(ofSize: 11, weight: .semibold)
        aiThinkingLabel.textColor = .systemPurple
        aiThinkingLabel.isHidden = true
        aiThinkingLabel.translatesAutoresizingMaskIntoConstraints = false
        content.addSubview(aiThinkingLabel)

        aiThinkingSpinner.style = .spinning
        aiThinkingSpinner.controlSize = .small
        aiThinkingSpinner.isHidden = true
        aiThinkingSpinner.translatesAutoresizingMaskIntoConstraints = false
        content.addSubview(aiThinkingSpinner)

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

        // contentTintColor does not tint a small .rounded button, so the purple
        // fill is drawn by the button's layer instead.
        autoTriageButton.bezelStyle = .rounded
        autoTriageButton.controlSize = .small
        autoTriageButton.isBordered = false
        autoTriageButton.wantsLayer = true
        autoTriageButton.layer?.cornerRadius = 5
        autoTriageButton.layer?.backgroundColor = NSColor.systemPurple.cgColor
        // A borderless button shrinks to the title's line box, so its size is
        // pinned to Ignore's and padded with spaces to match the bezel.
        autoTriageButton.attributedTitle = NSAttributedString(string: "  Triage (AI)  ", attributes: [
            .foregroundColor: NSColor.black,
            .font: NSFont.systemFont(ofSize: NSFont.smallSystemFontSize)
        ])
        autoTriageButton.target = self
        autoTriageButton.action = #selector(autoTriageClicked(_:))
        autoTriageButton.toolTip = "Ask the AI model to check every finding for validity"
        autoTriageButton.translatesAutoresizingMaskIntoConstraints = false
        content.addSubview(autoTriageButton)

        exportButton.bezelStyle = .rounded
        exportButton.controlSize = .small
        exportButton.isEnabled = false
        // Orange bezel with the normal dark title, so the button reads as a
        // call to action without the label losing contrast on the fill.
        exportButton.bezelColor = .systemOrange
        exportButton.contentTintColor = .labelColor
        exportButton.target = self
        exportButton.action = #selector(exportClicked(_:))
        exportButton.toolTip = "Save the results shown in the table as a SARIF file"
        exportButton.translatesAutoresizingMaskIntoConstraints = false
        content.addSubview(exportButton)

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

        // Added only while a pull request review is open, so a normal project
        // scan keeps exactly the columns it has always had.
        let prColumn = NSTableColumn(identifier: NSUserInterfaceItemIdentifier("inpr"))
        prColumn.title = "In PR?"
        prColumn.width = 90
        prColumn.sortDescriptorPrototype = NSSortDescriptor(key: "inpr", ascending: true)

        // Revealed by Triage (AI); hidden until a triage pass runs.
        let triColumn = NSTableColumn(identifier: NSUserInterfaceItemIdentifier("triage"))
        triColumn.title = "Triage"
        triColumn.width = 70
        triColumn.isHidden = true

        tableView.addTableColumn(expColumn)
        tableView.addTableColumn(sevColumn)
        tableView.addTableColumn(catColumn)
        tableView.addTableColumn(fnColumn)
        tableView.addTableColumn(fileColumn)
        tableView.addTableColumn(lineColumn)
        tableView.addTableColumn(srcColumn)
        tableView.addTableColumn(cfColumn)
        // Added in its final position and toggled with `isHidden`: NSTableView
        // exposes no insert/reorder API, and hiding preserves both the column's
        // place and its width between PR reviews.
        prColumn.isHidden = true
        prReviewColumn = prColumn
        tableView.addTableColumn(prColumn)
        triColumn.isHidden = true
        triageColumn = triColumn
        tableView.addTableColumn(triColumn)
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
            statusLabel.topAnchor.constraint(equalTo: content.topAnchor, constant: 14),
            statusLabel.leadingAnchor.constraint(equalTo: content.leadingAnchor, constant: 16),
            statusLabel.trailingAnchor.constraint(lessThanOrEqualTo: aiThinkingLabel.leadingAnchor, constant: -8),

            aiThinkingLabel.centerYAnchor.constraint(equalTo: statusLabel.centerYAnchor),
            aiThinkingLabel.trailingAnchor.constraint(equalTo: aiThinkingSpinner.leadingAnchor, constant: -4),

            aiThinkingSpinner.centerYAnchor.constraint(equalTo: statusLabel.centerYAnchor),
            aiThinkingSpinner.trailingAnchor.constraint(lessThanOrEqualTo: autoTriageButton.leadingAnchor, constant: -10),

            autoTriageButton.topAnchor.constraint(equalTo: content.topAnchor, constant: 10),
            autoTriageButton.heightAnchor.constraint(equalTo: ignoreButton.heightAnchor),
            autoTriageButton.trailingAnchor.constraint(equalTo: ignoreButton.leadingAnchor, constant: -8),

            ignoreButton.topAnchor.constraint(equalTo: content.topAnchor, constant: 10),
            ignoreButton.trailingAnchor.constraint(equalTo: exportButton.leadingAnchor, constant: -8),

            exportButton.topAnchor.constraint(equalTo: content.topAnchor, constant: 10),
            exportButton.trailingAnchor.constraint(equalTo: rescanButton.leadingAnchor, constant: -8),

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
    /// already scanned (and no AI scan was requested); otherwise performs a
    /// fresh scan. `wantsAI` comes from the prompt shown when the Security
    /// Scanner button is pressed.
    func load(folder: URL, wantsAI: Bool) {
        // Scanning a plain folder ends any pull-request review (the "In PR?"
        // column describes a different question) and any triage of old rows.
        if prSession != nil { clearPullRequestReview() }
        cancelAutoTriage()
        self.wantsAI = wantsAI
        scannedFolder = folder
        rescanButton.isEnabled = false

        if !wantsAI, let cached = ScanWindowController.cachedFolder, cached.standardizedFileURL == folder.standardizedFileURL {
            aiPhaseActive = false
            setAIThinking(false)
            let cachedFindings = enforceNoScannerDuplicates(ScanWindowController.cachedFindings)
            findings = applyIgnoredFilter(cachedFindings)
            applySorting()
            resetTriage()
            tableView.reloadData()
            rescanButton.isEnabled = true
            if cachedFindings.isEmpty {
                statusLabel.stringValue = "Cached scan (no issues found) — Rescan to refresh."
            } else {
                statusLabel.stringValue = "Showing cached scan: \(cachedFindings.count) potential issue\(cachedFindings.count == 1 ? "" : "s") — Rescan to refresh."
            }
        } else {
            performScan(folder: folder)
        }
    }

    // MARK: - Pull request review mode

    /// Reviews a pull request instead of a plain folder: scans both the PR and its
    /// base, then shows every finding with an "In PR?" column so the user can
    /// see at a glance which problems this change is responsible for.
    func loadPullRequestReview(_ session: PRReviewSession, wantsAI: Bool, wantsAIBase: Bool = false) {
        cancelAutoTriage()
        prSession = session
        self.wantsAI = wantsAI
        self.wantsAIBase = wantsAIBase
        showPRColumn(true)
        window?.title = "Karma Pro \u{2014} \(session.title)"
        // The static folder cache must not be reused: a normal scan of the same
        // workspace would overwrite the classified results with plain ones.
        scannedFolder = nil
        rescanButton.isEnabled = false

        statusLabel.stringValue = "Reviewing \(session.context.pr.number)\u{2026}"
        progressBar.isIndeterminate = true
        progressBar.isHidden = false
        progressBar.startAnimation(nil)

        session.scan(wantsAI: wantsAI, wantsAIBase: wantsAIBase, progress: { [weak self] message in
            DispatchQueue.main.async {
                guard let self = self else { return }
                self.statusLabel.stringValue = message
            }
        }, completion: { [weak self] completed in
            guard let self = self else { return }
            self.progressBar.stopAnimation(nil)
            self.progressBar.isHidden = true
            self.rescanButton.isEnabled = completed
            guard completed else {
                self.statusLabel.stringValue = "Review cancelled."
                return
            }
            // Same post-processing a project scan gets, so the two tables are
            // presented identically: the same duplicate guard, the same sort,
            // and rows coloured by the same per-column rules. The "In PR?"
            // column is the only difference a pull-request scan adds.
            let merged = self.enforceNoScannerDuplicates(session.findings.map(\.finding))
            self.findings = self.applyIgnoredFilter(merged)
            self.applySorting()
            self.rebuildAwareness()
            self.resetTriage()
            self.tableView.reloadData()
            self.updatePRStatus()
        })
    }

    private func rescanPullRequest(session: PRReviewSession) {
        session.cancelScan()
        loadPullRequestReview(session, wantsAI: wantsAI)
    }

    private func showPRColumn(_ visible: Bool) {
        prReviewColumn?.isHidden = !visible
    }

    private func rebuildAwareness() {
        guard let session = prSession else {
            prAwareness.removeAll()
            return
        }
        prAwareness = Dictionary(session.findings.map {
            ($0.finding.fileURL.path + "#" + String($0.finding.line), $0.awareness)
        }, uniquingKeysWith: { first, _ in first })
    }

    private func awareness(for finding: ScanFinding) -> DiffAwareness? {
        prAwareness[finding.fileURL.path + "#" + String(finding.line)]
    }

    private func updatePRStatus() {
        guard let session = prSession else { return }
        let all = session.findings
        let introduced = DiffAwareClassifier.introduced(all).count
        let contextual = DiffAwareClassifier.contextual(all).count
        let preExisting = DiffAwareClassifier.preExisting(all).count
        let fixed = DiffAwareClassifier.fixed(all).count
        statusLabel.stringValue = "PR #\(session.context.pr.number): \(introduced) new \u{00B7} \(contextual) touched \u{00B7} "
            + "\(preExisting) pre-existing \u{00B7} \(fixed) fixed"
    }

    /// Removes pull-request mode and returns to an ordinary project scan.
    func clearPullRequestReview() {
        prSession?.cancelScan()
        prSession = nil
        prAwareness.removeAll()
        showPRColumn(false)
    }

    /// Removes findings the user has ignored, based on persisted (file, line) keys.
    private func applyIgnoredFilter(_ input: [ScanFinding]) -> [ScanFinding] {
        let ignored = ignoredLines
        guard !ignored.isEmpty else { return input }
        return input.filter { !ignored.contains(ignoredKey(for: $0)) }
    }

    /// Hard guarantee for the results table: an AI finding is shown only if the
    /// built-in scanner (AST/Heuristic) did NOT already report the same file on
    /// the same line. Applied every time rows are assembled, including cached
    /// scans, so duplicates can never reappear.
    private func enforceNoScannerDuplicates(_ input: [ScanFinding]) -> [ScanFinding] {
        let scannerOccupied = Set(input
            .filter { $0.scanningSource != "AI" }
            .map { AISecurityScanner.locationKey($0) })
        return input.filter { finding in
            if finding.scanningSource == "AI" {
                return !scannerOccupied.contains(AISecurityScanner.locationKey(finding))
            }
            return true
        }
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

    /// Saves the rows currently shown in the table as a SARIF 2.1.0 file.
    @objc private func exportClicked(_ sender: Any?) {
        guard !findings.isEmpty else { return }
        let panel = NSSavePanel()
        panel.title = "Export Scan"
        panel.nameFieldStringValue = "KarmaPro-scan.sarif.json"
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

    @objc private func rescanClicked(_ sender: Any?) {
        // A pull-request review re-runs the paired head+base scan; a project
        // scan re-runs the single pass. Keeping them distinct means Rescan
        // always means "answer the same question again".
        if let session = prSession {
            rescanPullRequest(session: session)
            return
        }
        guard let folder = scannedFolder else { return }
        performScan(folder: folder)
    }

    // MARK: - Triage (AI)

    private func refreshAutoTriageButton() {
        let enabled = OpenRouterClient.shared.isConfigured
            && !findings.isEmpty && !triageRunning
        autoTriageButton.isEnabled = enabled
        autoTriageButton.layer?.backgroundColor =
            (enabled ? NSColor.systemPurple : NSColor.systemGray).cgColor
        autoTriageButton.alphaValue = enabled ? 1.0 : 0.6
    }

    @objc private func autoTriageClicked(_ sender: Any?) {
        // rescanButton is disabled exactly while a scan / AI phase is running.
        guard !triageRunning, !findings.isEmpty, rescanButton.isEnabled else { return }
        guard OpenRouterClient.shared.isConfigured else { return }
        let client = OpenRouterClient.shared
        let ask = NSAlert()
        ask.messageText = "Triage with AI"
        ask.informativeText = "Triage is 60-80% accurate depending on the model used, so it is recommended to also verify the results.\n\nEvery finding in the table will be checked with \(client.selectedModel) (\(client.provider.rawValue)). This sends the finding details to the AI model and consumes tokens / credits from your AI account (unless you use Ollama and a local model)."
        ask.alertStyle = .informational
        ask.addButton(withTitle: "Triage")
        ask.addButton(withTitle: "Cancel")
        guard ask.runModal() == .alertFirstButtonReturn else { return }
        startAutoTriage()
    }

    private func startAutoTriage() {
        triageRows = findings
        guard !triageRows.isEmpty else { return }
        triageRunning = true
        triageCancelled = false
        triageIndex = 0
        triageFailed = 0
        triageVerdicts.removeAll()
        refreshAutoTriageButton()
        rescanButton.isEnabled = false
        triageColumn?.isHidden = false
        tableView.reloadData()
        progressBar.isHidden = false
        progressBar.isIndeterminate = false
        progressBar.doubleValue = 0
        statusLabel.stringValue = "Triage: 0/\(triageRows.count) checked…"
        triageNext()
    }

    private func triageNext() {
        guard triageRunning, !triageCancelled else { return }
        guard triageIndex < triageRows.count else {
            finishAutoTriage()
            return
        }
        let f = triageRows[triageIndex]
        let model = OpenRouterClient.shared.selectedModel
        OpenRouterClient.shared.sendChat(
            systemPrompt: Self.triageSystemPrompt,
            userPrompt: Self.triagePrompt(for: f),
            model: model) { [weak self] result in
            DispatchQueue.main.async {
                guard let self = self, self.triageRunning else { return }
                switch result {
                case .success(let text):
                    if let verdict = Self.parseTriageVerdict(text) {
                        self.triageVerdicts[self.ignoredKey(for: f)] = verdict
                    } else {
                        self.triageFailed += 1
                    }
                case .failure:
                    self.triageFailed += 1
                }
                self.triageIndex += 1
                self.progressBar.doubleValue = Double(self.triageIndex) / Double(self.triageRows.count)
                self.statusLabel.stringValue = "Triage: \(self.triageIndex)/\(self.triageRows.count) checked…"
                self.tableView.reloadData()
                self.triageNext()
            }
        }
    }

    private func finishAutoTriage() {
        let wasCancelled = triageCancelled
        let total = triageRows.count
        let checked = triageIndex
        triageRunning = false
        triageCancelled = false
        refreshAutoTriageButton()
        rescanButton.isEnabled = true
        progressBar.doubleValue = 1
        progressBar.isHidden = true
        ignoreButton.isEnabled = selectedFinding() != nil
        if wasCancelled {
            statusLabel.stringValue = "Triage cancelled — \(checked)/\(total) checked."
        } else if triageFailed > 0 {
            statusLabel.stringValue = "Triage complete: \(checked)/\(total) checked (\(triageFailed) failed)."
        } else {
            statusLabel.stringValue = "Triage complete: \(checked)/\(total) checked."
        }
    }

    /// Stops an in-flight triage (window close, new scan, PR switch).
    private func cancelAutoTriage() {
        guard triageRunning else { return }
        triageCancelled = true
        finishAutoTriage()
    }

    /// Clears verdicts and hides the column when a new set of rows arrives.
    private func resetTriage() {
        guard !triageRunning else { return }
        triageVerdicts.removeAll()
        triageColumn?.isHidden = true
    }

    private static let triageSystemPrompt = """
    You are a security triage researcher. You are shown a finding reported by a static analysis scanner, including the code around the reported line. Decide whether it is a genuine, exploitable security issue or a false positive / non-issue / purely informational. Answer with exactly one word: VALID or INVALID.
    """

    private static func triagePrompt(for f: ScanFinding) -> String {
        var parts: [String] = []
        parts.append("Category: \(f.category)")
        parts.append("Severity: \(f.severity.label)")
        parts.append("Message: \(f.message)")
        if let p = f.taintPath, !p.isEmpty { parts.append("Data flow: \(p)") }
        parts.append("Function: \(f.function)")
        parts.append("File: \(f.fileURL.path)")
        parts.append("Line: \(f.line)")
        if let snippet = codeSnippet(for: f) {
            parts.append("Code around the line:\n\(snippet)")
        }
        parts.append("Answer with VALID or INVALID only.")
        return parts.joined(separator: "\n")
    }

    /// Lines around the finding, capped, so the model judges real code.
    private static func codeSnippet(for f: ScanFinding) -> String? {
        let fm = FileManager.default
        guard let attrs = try? fm.attributesOfItem(atPath: f.fileURL.path),
              let size = attrs[.size] as? Int, size < 1_000_000 else { return nil }
        guard let text = try? String(contentsOf: f.fileURL, encoding: .utf8) else { return nil }
        let lines = text.components(separatedBy: "\n")
        let start = max(0, f.line - 21)
        let end = min(lines.count, f.line + 25)
        guard start < end else { return nil }
        return (start..<end).map { i in
            let marker = (i + 1) == f.line ? ">>>" : "   "
            return "\(marker) \(i + 1)| \(lines[i])"
        }.joined(separator: "\n")
    }

    private static func parseTriageVerdict(_ raw: String) -> Bool? {
        let t = raw.uppercased()
        if t.contains("INVALID") { return false }
        if t.contains("VALID") { return true }
        return nil
    }

    /// Runs a scan of `folder` on a background queue, stores the result in the
    /// shared cache, and shows results on the main thread. If the window is
    /// closed while the scan is running, the scan is cancelled and the results
    /// are discarded.
    private func performScan(folder: URL) {
        // A fresh scan supersedes any triage pass over the previous rows.
        cancelAutoTriage()
        resetTriage()
        statusLabel.stringValue = "Scanning \(folder.lastPathComponent)…"
        progressBar.doubleValue = 0
        progressBar.isIndeterminate = true
        progressBar.isHidden = false
        progressBar.startAnimation(nil)
        scanCancelled = false
        aiPhaseActive = false
        rescanButton.isEnabled = false

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
                    // The heuristic phase fills the whole bar when AI was not
                    // requested, or the first 40% when an AI pass will follow.
                    self.progressBar.doubleValue = fraction * (self.wantsAI ? 0.4 : 1.0)
                }
            }, isCancelled: { [weak self] in
                self?.scanCancelled == true
            }, sourceIndex: self?.sourceIndex)
            DispatchQueue.main.async {
                guard let self = self, !self.scanCancelled else { return }
                ScanWindowController.cachedFolder = folder
                ScanWindowController.cachedFindings = result
                self.progressBar.doubleValue = self.wantsAI ? 0.4 : 1.0
                self.progressBar.isHidden = !self.wantsAI
                self.progressBar.stopAnimation(nil)
                self.findings = self.applyIgnoredFilter(result)
                self.applySorting()
                self.tableView.reloadData()
                self.updateStatus(heuristicCount: result.count, aiCount: 0)
                guard self.wantsAI, !self.scanCancelled else {
                    self.rescanButton.isEnabled = true
                    return
                }
                self.runAIPhase(folder: folder, heuristic: result)
            }
        }
    }

    /// Runs the AI discovery pass on a background queue, scaling its progress
    /// over the remaining 60% of the bar and merging any additional findings.
    /// The user already authorised token consumption at the Security Scanner
    /// button; the API-key check below is the only gate.
    private func runAIPhase(folder: URL, heuristic: [ScanFinding]) {
        let client = OpenRouterClient.shared
        let providerName = client.provider.rawValue

        guard !client.requiresAPIKey
            || !client.apiKey.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
            let missing = NSAlert()
            missing.messageText = "AI scan unavailable"
            missing.informativeText = "AI scan needs a model connected. Open the AI Assistant window, choose \(providerName), add your API key, and connect, then re-run the scan."
            missing.alertStyle = .warning
            missing.addButton(withTitle: "OK")
            missing.runModal()
            updateStatus(heuristicCount: heuristic.count, aiCount: 0, aiSkipped: true)
            rescanButton.isEnabled = true
            return
        }

        setStatusAIPhase()
        progressBar.doubleValue = 0.4
        progressBar.isHidden = false
        progressBar.isIndeterminate = false
        progressBar.stopAnimation(nil)
        aiPhaseActive = true

        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            AISecurityScanner.runAI(projectRoot: folder,
                                    existingFindings: heuristic,
                                    progress: { fraction in
                DispatchQueue.main.async {
                    guard let self = self, !self.scanCancelled else { return }
                    // The app shows "AI phase: reviewing the code…" while the
                    // model works; the bar fills the remaining 0.4 → 1.0.
                    self.progressBar.doubleValue = 0.4 + 0.6 * min(fraction, 1)
                }
            },
            isCancelled: { [weak self] in
                self?.scanCancelled == true
            },
            completion: { result in
                DispatchQueue.main.async {
                    guard let self = self else { return }
                    self.aiPhaseActive = false
                    self.setAIThinking(false)
                    guard !self.scanCancelled else { return }
                    // Safety net: never let an AI row appear where the built-in
                    // scanner already reported the same file and line.
                    let aiFindings = AISecurityScanner.dedupe(result.findings, against: heuristic)
                    let merged = self.enforceNoScannerDuplicates(heuristic + aiFindings)
                    ScanWindowController.cachedFindings = merged
                    self.findings = self.applyIgnoredFilter(merged)
                    self.applySorting()
                    self.resetTriage()
                    self.tableView.reloadData()
                    self.progressBar.doubleValue = 1
                    self.progressBar.isHidden = true
                    self.progressBar.stopAnimation(nil)
                    self.updateStatus(heuristicCount: heuristic.count, aiCount: aiFindings.count,
                                      aiCancelled: result.cancelled,
                                      aiIssues: result.errors)
                    self.rescanButton.isEnabled = true
                }
            },
            onPhase: { phase in
                DispatchQueue.main.async {
                    guard let self = self, self.aiPhaseActive, !self.scanCancelled else { return }
                    self.setAIThinking(phase == .thinking)
                }
            })
        }
    }

    /// Shows "AI phase: reviewing the code…" with "AI phase" in the purple
    /// used by the Engine column and "reviewing the code…" in green (the user
    /// authorised this step).
    private func setStatusAIPhase() {
        let purple = NSColor.systemPurple
        let green = NSColor.systemGreen
        let attributed = NSMutableAttributedString(
            string: "AI phase: ",
            attributes: [.foregroundColor: purple, .font: NSFont.boldSystemFont(ofSize: 12)])
        attributed.append(NSAttributedString(
            string: "reviewing the code…",
            attributes: [.foregroundColor: green, .font: NSFont.systemFont(ofSize: 12)]))
        statusLabel.textColor = .secondaryLabelColor
        statusLabel.attributedStringValue = attributed
    }

    /// Shows/hides the "(thinking)" indicator + spinner that tell the user the
    /// model is still working (reasoning) as opposed to streaming an answer.
    private func setAIThinking(_ thinking: Bool) {
        if thinking {
            aiThinkingLabel.isHidden = false
            aiThinkingSpinner.isHidden = false
            aiThinkingSpinner.startAnimation(nil)
        } else {
            aiThinkingLabel.isHidden = true
            aiThinkingSpinner.isHidden = true
            aiThinkingSpinner.stopAnimation(nil)
        }
    }

    private func updateStatus(heuristicCount: Int,
                              aiCount: Int,
                              aiSkipped: Bool = false,
                              aiCancelled: Bool = false,
                              aiIssues: [String] = []) {
        let plural = { (n: Int) in n == 1 ? "" : "s" }
        if heuristicCount == 0 && aiCount == 0 {
            if aiSkipped {
                statusLabel.stringValue = "Scan complete: no issues found. (AI analysis skipped — no source files were reported.)"
            } else {
                statusLabel.stringValue = "Scan complete: no issues found."
            }
            return
        }
        var text = "Scan complete: \(heuristicCount + aiCount) potential issue\(plural(heuristicCount + aiCount)) found"
        if aiCount > 0 {
            text += " (\(aiCount) via AI)"
        }
        if aiSkipped {
            text += " — AI analysis skipped"
        } else if aiCancelled {
            text += " — AI analysis cancelled"
        }
        if !aiIssues.isEmpty {
            text += " (\(aiIssues.count) AI chunk\(plural(aiIssues.count)) skipped: \(aiIssues.prefix(3).joined(separator: "; ")))"
        }
        statusLabel.stringValue = text + "."
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
        cancelAutoTriage()
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
            // A "Fixed" row is a finding from the base scan, so its line number
            // is a base-revision coordinate and will not land on the same code in
            // the file on disk. Marking it stops a reader from jumping to line N
            // of the checked-out head file and concluding the function name is
            // wrong when the two revisions simply number differently.
            if awareness(for: f) == .fixed {
                cellView.textField?.stringValue = "\(f.line) (base)"
                cellView.textField?.toolTip = "Line \(f.line) of the base revision, not of the current file."
                cellView.textField?.textColor = .secondaryLabelColor
            } else {
                cellView.textField?.stringValue = "\(f.line)"
                cellView.textField?.toolTip = nil
                cellView.textField?.textColor = .labelColor
            }
            cellView.textField?.alignment = .right
        case "src":
            cellView.textField?.stringValue = f.scanningSource
            cellView.textField?.alignment = .center
            if f.scanningSource == "AST" {
                cellView.textField?.font = NSFont.systemFont(ofSize: 12, weight: .bold)
                cellView.textField?.textColor = .systemGreen
            } else if f.scanningSource == "AI" {
                cellView.textField?.font = NSFont.systemFont(ofSize: 12, weight: .bold)
                cellView.textField?.textColor = .systemPurple
                cellView.textField?.toolTip = "Found by the AI assistant model during the AI deep scan phase."
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
        case "inpr":
            // Only rendered while a PR review is open; the column is not
            // installed for a normal project scan.
            switch awareness(for: f) {
            case .some(.introduced):
                cellView.textField?.stringValue = "New"
                cellView.textField?.font = NSFont.systemFont(ofSize: 12, weight: .bold)
                cellView.textField?.textColor = .systemRed
                cellView.textField?.toolTip = "Introduced by this pull request."
            case .some(.contextual):
                cellView.textField?.stringValue = "Touched"
                cellView.textField?.font = NSFont.systemFont(ofSize: 12, weight: .semibold)
                cellView.textField?.textColor = .systemOrange
                cellView.textField?.toolTip = "In a file this PR modifies, but not on changed lines and not present at base."
            case .some(.preExisting):
                cellView.textField?.stringValue = "Pre-existing"
                cellView.textField?.textColor = .secondaryLabelColor
                cellView.textField?.toolTip = "Already present before this pull request."
            case .some(.fixed):
                cellView.textField?.stringValue = "Fixed"
                cellView.textField?.textColor = .systemGreen
                cellView.textField?.toolTip = "Present at the base commit and gone from this pull request. The line number shown is the base revision's."
            case .none:
                cellView.textField?.stringValue = ""
            }
            cellView.textField?.alignment = .center
        case "triage":
            cellView.textField?.alignment = .center
            if let valid = triageVerdicts[ignoredKey(for: f)] {
                cellView.textField?.stringValue = valid ? "✓" : "✗"
                cellView.textField?.font = NSFont.systemFont(ofSize: 14, weight: .bold)
                cellView.textField?.textColor = valid ? .systemRed : .secondaryLabelColor
                cellView.textField?.toolTip = valid
                    ? "AI triage: the model judges this a valid issue."
                    : "AI triage: the model judges this not a valid issue."
            } else {
                cellView.textField?.stringValue = ""
            }
        case "msg":
            var parts: [String] = []
            if let path = f.taintPath, !path.isEmpty { parts.append("flow: \(path)") }
            var message = f.message
            if f.scanningSource == "AI" { message = "flow: \(message)" }
            parts.append(message)
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
        if f.scanningSource == "AI" { text = "flow: " + text }
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

// by cipher.org.uk
import AppKit

/// Scans every source file of the opened project (for C or C++) line by
/// line through a trained Bayesian classifier, and stores which lines reach a
/// user-selectable bad-probability threshold so the source viewer highlights them.
final class MLScanWindowController: NSWindowController {

    private let modelPopup = NSPopUpButton(frame: .zero, pullsDown: false)
    private let languagePopup = NSPopUpButton(frame: .zero, pullsDown: false)
    private let progressBar = NSProgressIndicator()
    private let statusLabel = NSTextField(wrappingLabelWithString: "No scan run yet.")
    private let scanButton = NSButton(title: "Scan Project", target: nil, action: nil)
    private let unavailableLabel = NSTextField(wrappingLabelWithString: "Open a source folder before scanning.")

    private let thresholdSlider = NSSlider(value: 70, minValue: 1, maxValue: 100,
                                           target: nil, action: nil)
    private let thresholdValueLabel = NSTextField(labelWithString: "70%")

    /// User-set threshold: probability (percent) above which a line is flagged.
    private(set) var thresholdPercent: Double = 70

    private var projectRoot: URL?

    private var heatmapController: HeatmapWindowController?

    /// Called when a scan finishes, so the main window can refresh highlights.
    var onScanFinished: (() -> Void)?

    /// Called when the user clicks a heatmap cell; passes the file's URL so the
    /// main window can open it.
    var onOpenFile: ((URL) -> Void)?

    convenience init(projectRoot: URL?) {
        let window = EscClosableWindow(
            contentRect: NSRect(x: 0, y: 0, width: 560, height: 320),
            styleMask: [.titled, .closable, .miniaturizable, .resizable],
            backing: .buffered,
            defer: false
        )
        window.title = "ML Project Scan"
        window.isRestorable = false
        window.setFrameAutosaveName("")
        window.minSize = NSSize(width: 480, height: 300)
        self.init(window: window)
        self.projectRoot = projectRoot
        buildContent()
        window.setContentSize(NSSize(width: 560, height: 320))
        window.center()
    }

    private func buildContent() {
        guard let content = window?.contentView else { return }

        let modelLabel = NSTextField(labelWithString: "Trained model:")
        modelPopup.target = self
        modelPopup.action = #selector(modelChanged)
        let modelRow = NSStackView(views: [modelLabel, modelPopup])
        modelRow.orientation = .horizontal
        modelRow.alignment = .centerY
        modelRow.spacing = 10

        let langLabel = NSTextField(labelWithString: "Language:")
        languagePopup.addItems(withTitles: Language.supported.map { $0.name })
        languagePopup.selectItem(at: 0)
        let langRow = NSStackView(views: [langLabel, languagePopup])
        langRow.orientation = .horizontal
        langRow.alignment = .centerY
        langRow.spacing = 10

        let threshLabel = NSTextField(labelWithString: "Flag threshold:")
        thresholdSlider.isContinuous = true
        thresholdSlider.target = self
        thresholdSlider.action = #selector(thresholdChanged)
        thresholdValueLabel.font = NSFont.monospacedDigitSystemFont(ofSize: 12, weight: .medium)
        thresholdValueLabel.textColor = .secondaryLabelColor
        let thresholdRow = NSStackView(views: [threshLabel, thresholdSlider, thresholdValueLabel])
        thresholdRow.orientation = .horizontal
        thresholdRow.alignment = .centerY
        thresholdRow.spacing = 10

        progressBar.style = .bar
        progressBar.minValue = 0
        progressBar.maxValue = 1
        progressBar.isIndeterminate = false
        progressBar.isHidden = true

        statusLabel.font = NSFont.systemFont(ofSize: 12)
        statusLabel.textColor = .secondaryLabelColor

        scanButton.bezelStyle = .rounded
        scanButton.keyEquivalent = "\r"
        scanButton.target = self
        scanButton.action = #selector(scanClicked)

        let stack = NSStackView(views: [modelRow, langRow, thresholdRow, progressBar, scanButton, statusLabel, unavailableLabel])
        stack.orientation = .vertical
        stack.alignment = .width
        stack.spacing = 14
        stack.translatesAutoresizingMaskIntoConstraints = false

        content.addSubview(stack)
        stack.topAnchor.constraint(equalTo: content.topAnchor, constant: 20).isActive = true
        stack.leadingAnchor.constraint(equalTo: content.leadingAnchor, constant: 20).isActive = true
        stack.widthAnchor.constraint(lessThanOrEqualTo: content.widthAnchor, constant: -40).isActive = true
        stack.bottomAnchor.constraint(lessThanOrEqualTo: content.bottomAnchor, constant: -20).isActive = true

        [modelLabel, langLabel, threshLabel, thresholdValueLabel].forEach {
            $0.setContentHuggingPriority(.required, for: .horizontal)
            $0.setContentCompressionResistancePriority(.required, for: .horizontal)
        }
        [modelPopup, languagePopup].forEach {
            $0.setContentHuggingPriority(.defaultLow, for: .horizontal)
            $0.setContentCompressionResistancePriority(.defaultLow, for: .horizontal)
            $0.widthAnchor.constraint(greaterThanOrEqualToConstant: 220).isActive = true
        }
        thresholdSlider.translatesAutoresizingMaskIntoConstraints = false
        // Let the slider stretch with the window instead of locking a fixed width.
        thresholdSlider.setContentCompressionResistancePriority(.defaultLow, for: .horizontal)
        thresholdSlider.setContentHuggingPriority(.defaultLow, for: .horizontal)
        [progressBar, scanButton, statusLabel, unavailableLabel].forEach {
            $0.translatesAutoresizingMaskIntoConstraints = false
            $0.widthAnchor.constraint(equalTo: stack.widthAnchor).isActive = true
        }

        refreshAvailableState()
    }

    @objc private func thresholdChanged(_ sender: Any?) {
        let percent = Int(thresholdSlider.doubleValue.rounded())
        thresholdPercent = Double(percent)
        thresholdValueLabel.stringValue = "\(percent)%"
    }

    override func showWindow(_ sender: Any?) {
        super.showWindow(sender)
        if let window = window {
            let screenFrame = window.screen?.visibleFrame ?? NSScreen.main?.visibleFrame
            var f = NSRect(x: 0, y: 0, width: 560, height: 320)
            if let sf = screenFrame {
                f.origin.x = sf.midX - f.width / 2
                f.origin.y = sf.midY - f.height / 2
            } else {
                f.origin = NSPoint(x: 120, y: 120)
            }
            window.setFrame(f, display: true)
        }
        refreshAvailableState()
        refreshModels()
    }

    private func refreshModels() {
        let names = ModelStore.shared.listModels()
        let current = modelPopup.titleOfSelectedItem
        modelPopup.removeAllItems()
        if names.isEmpty {
            modelPopup.addItem(withTitle: "-- no models --")
        } else {
            modelPopup.addItems(withTitles: names)
            if let c = current { modelPopup.selectItem(withTitle: c) }
        }
    }

    private func refreshAvailableState() {
        let hasFolder = projectRoot != nil
        let hasModels = !ModelStore.shared.listModels().isEmpty
        let canScan = hasFolder && hasModels
        scanButton.isEnabled = canScan
        if !hasFolder {
            unavailableLabel.isHidden = false
            unavailableLabel.stringValue = "Open a source folder before scanning."
        } else if !hasModels {
            unavailableLabel.isHidden = false
            unavailableLabel.stringValue = "Train a model first (Train Bayesian Classifier)."
        } else {
            unavailableLabel.isHidden = true
        }
        refreshModels()
    }

    @objc private func modelChanged(_ sender: Any?) {}

    private func selectedLanguageExts() -> Set<String> {
        let name = languagePopup.titleOfSelectedItem ?? "All Languages"
        guard let lang = Language.supported.first(where: { $0.name == name }) else { return [] }
        return lang.extensions
    }

    @objc private func scanClicked() {
        guard let root = projectRoot else {
            showAlert("No Folder Open", "Open a source folder first.")
            return
        }
        let modelName = modelPopup.titleOfSelectedItem ?? ""
        guard modelName != "-- no models --", let model = ModelStore.shared.load(named: modelName) else {
            showAlert("No Model", "Choose a trained model.")
            return
        }
        let exts = selectedLanguageExts()
        let threshold = max(0.01, thresholdPercent / 100.0)

        scanButton.isEnabled = false
        progressBar.isHidden = false
        progressBar.doubleValue = 0
        statusLabel.stringValue = "Scanning with model “\(modelName)”…"

        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            let outcome = Self.scanProject(root: root,
                                           model: model,
                                           extensions: exts,
                                           threshold: threshold) { done, total in
                DispatchQueue.main.async { self?.progressBar.doubleValue = Double(done) / Double(total) }
            }
            DispatchQueue.main.async {
                guard let self = self else { return }
                MLScanResultStore.shared.setResults(outcome.results, modelName: modelName, threshold: threshold)
                let flagged = outcome.results.values.reduce(0) { $0 + $1.count }
                let pct = Int(threshold * 100)
                self.statusLabel.stringValue = "Scanned \(outcome.totalFiles) file(s), \(outcome.totalLines) line(s) with model “\(modelName)”. \(flagged) line(s) >=\(pct)% flagged."
                self.scanButton.isEnabled = true
                self.progressBar.isHidden = true
                self.presentHeatmap()
                self.onScanFinished?()
            }
        }
    }

    /// Opens (or refreshes) the heatmap window showing files colored by how many
    /// lines were flagged — hottest files glow red, coldest blue.
    private func presentHeatmap() {
        let controller: HeatmapWindowController
        if let existing = heatmapController {
            controller = existing
        } else {
            controller = HeatmapWindowController()
            heatmapController = controller
        }
        controller.projectRoot = projectRoot
        controller.onOpenFile = onOpenFile
        controller.reload()
        controller.showWindow(nil)
        controller.window?.makeKeyAndOrderFront(nil)
        NSApp.activate(ignoringOtherApps: true)
    }

    /// Result of a project scan: per-file line findings plus summary totals.
    struct ScanOutcome {
        let results: [String: [Int: Double]]
        let totalFiles: Int
        let totalLines: Int
    }

    /// Scans every matching file in the project tree, classifying each line.
    static func scanProject(root: URL, model: BayesianClassifier, extensions: Set<String>, threshold: Double = 0.80, progress: ((Int, Int) -> Void)?) -> ScanOutcome {
        let files = Self.enumerateSourceFiles(in: root, extensions: extensions)
        let total = max(files.count, 1)
        var results: [String: [Int: Double]] = [:]
        var totalLines = 0
        for (i, url) in files.enumerated() {
            if let text = try? String(contentsOf: url, encoding: .utf8) {
                var lineMap: [Int: Double] = [:]
                let lines = text.components(separatedBy: "\n")
                totalLines += lines.count
                var inBlockComment = false
                for (idx, line) in lines.enumerated() {
                    let (isComment, newInBlockComment) = Self.isCommentLine(line, inBlockComment: inBlockComment)
                    inBlockComment = newInBlockComment
                    if isComment { continue }
                    let prob = model.probabilityBad(line: line)
                    if prob >= threshold {
                        lineMap[idx + 1] = prob
                    }
                }
                if !lineMap.isEmpty {
                    results[url.path] = lineMap
                }
            }
            progress?(i + 1, total)
        }
        return ScanOutcome(results: results, totalFiles: files.count, totalLines: totalLines)
    }

    /// Returns (isComment, newInBlockCommentState). Handles // line comments and /* */ block comments.
    /// The inBlockComment parameter tracks multi-line block comment state across lines.
    private static func isCommentLine(_ line: String, inBlockComment: Bool) -> (Bool, Bool) {
        var i = line.startIndex
        var inBlock = inBlockComment

        func advance(_ n: Int = 1) {
            for _ in 0..<n {
                if i < line.endIndex { i = line.index(after: i) }
            }
        }

        while i < line.endIndex {
            let c = line[i]
            if inBlock {
                if c == "*" {
                    advance()
                    if i < line.endIndex && line[i] == "/" {
                        advance()
                        inBlock = false
                    }
                } else {
                    advance()
                }
            } else {
                if c == "/" {
                    advance()
                    if i < line.endIndex {
                        let next = line[i]
                        if next == "/" {
                            return (true, inBlock) // rest of line is comment
                        } else if next == "*" {
                            advance()
                            inBlock = true
                        }
                    }
                } else if c == " " || c == "\t" {
                    advance()
                } else {
                    // Non-whitespace code encountered
                    break
                }
            }
        }

        // Line is a comment if we're still in a block comment (and didn't exit) OR
        // if we only saw comment tokens and whitespace.
        let onlyComment = inBlock || (i >= line.endIndex)
        return (onlyComment, inBlock)
    }

    private static func enumerateSourceFiles(in root: URL, extensions: Set<String>) -> [URL] {
        if extensions.isEmpty { return SourceTree.enumerateAll(in: root) }
        return SourceTree.enumerate(extensions: extensions, in: root)
    }

    private func showAlert(_ title: String, _ message: String) {
        let alert = NSAlert()
        alert.messageText = title
        alert.informativeText = message
        alert.addButton(withTitle: "OK")
        alert.runModal()
    }
}

// by cipher.org.uk

import AppKit

final class SimDebugWindowController: NSWindowController, NSTableViewDataSource, NSTableViewDelegate, NSTextViewDelegate, NSTextFieldDelegate {

    // MARK: - Public

    /// Requests the main editor to open/reveal the file at the given 1-based line.
    var onOpenFile: ((URL, Int) -> Void)?
    /// Called when the debug session finishes (function returned or step limit reached).
    var onFinished: (() -> Void)?

    private var engine: SimDebugEngine
    private var sourceText: String
    private var fileExtension: String
    private var functionName: String
    /// The file whose source is currently shown in the source pane (changes as
    /// the simulation steps into functions defined in other project files).
    private var displayedFileURL: URL?
    /// When the user has not edited the seed table, edits are to these.
    private var currentSeeds: [SimParameterSeed]

    // MARK: - UI

    private let sourceTextView = NSTextView()
    private let watchTable = NSTableView()
    private let stackTable = NSTableView()
    private let seedsTable = NSTableView()
    private let statusLabel = NSTextField(labelWithString: "")
    private let functionBadgeLabel = NSTextField(labelWithString: "")
    private let stepOverButton = NSButton(title: "Step Over", target: nil, action: nil)
    private let stepIntoButton = NSButton(title: "Step Into", target: nil, action: nil)
    private let stepBackButton = NSButton(title: "Step Back", target: nil, action: nil)
    private let resetButton = NSButton(title: "Reset", target: nil, action: nil)
    private let playButton = NSButton(title: "Play", target: nil, action: nil)

    // MARK: - State

    private var stepHistory: [SimDebugStep] = []
    private var currentStep: SimDebugStep?
    private var selectedFrameIndex = 0
    private var playTimer: Timer?
    private var isPlaying = false

    private let monospaced = NSFont.monospacedSystemFont(ofSize: 12, weight: .regular)

    /// Pill-shaped container holding the current function-name badge.
    private lazy var functionBadge: NSView = {
        let pill = NSView()
        pill.wantsLayer = true
        pill.layer?.backgroundColor = NSColor.controlAccentColor.withAlphaComponent(0.18).cgColor
        pill.layer?.cornerRadius = 6
        functionBadgeLabel.translatesAutoresizingMaskIntoConstraints = false
        pill.addSubview(functionBadgeLabel)
        NSLayoutConstraint.activate([
            functionBadgeLabel.topAnchor.constraint(equalTo: pill.topAnchor, constant: 3),
            functionBadgeLabel.bottomAnchor.constraint(equalTo: pill.bottomAnchor, constant: -3),
            functionBadgeLabel.leadingAnchor.constraint(equalTo: pill.leadingAnchor, constant: 8),
            functionBadgeLabel.trailingAnchor.constraint(equalTo: pill.trailingAnchor, constant: -8)
        ])
        return pill
    }()

    // MARK: - Init

    init(sourceIndex: ProjectSourceIndex?, fileURL: URL, functionName: String) {
        self.functionName = functionName
        self.engine = SimDebugEngine(sourceIndex: sourceIndex, fileURL: fileURL, functionName: functionName)
        self.sourceText = (try? String(contentsOf: fileURL, encoding: .utf8)) ?? ""
        self.fileExtension = fileURL.pathExtension.lowercased()
        self.displayedFileURL = fileURL
        self.currentSeeds = engine.parameters
        let window = EscClosableWindow(
            contentRect: NSRect(x: 0, y: 0, width: 960, height: 640),
            styleMask: [.titled, .closable, .miniaturizable, .resizable],
            backing: .buffered,
            defer: false
        )
        window.title = "\(functionName) — Debugger (Experimental)"
        window.minSize = NSSize(width: 760, height: 480)
        super.init(window: window)
        window.contentView = buildContentView()
    }

    @available(*, unavailable)
    required init?(coder: NSCoder) {
        fatalError("init(coder:) is not supported")
    }

    // MARK: - Lifecycle

    func begin() {
        let initial = stepHistory.last ?? engine.initialStep()
        apply(initial)
    }

    /// Overridden so the window is centered over its parent on first display.
    /// Note: `windowDidLoad` is NOT called for programmatic windows (those created
    /// with `init(window:)`), so the first-step initialization runs here instead.
    override func showWindow(_ sender: Any?) {
        super.showWindow(sender)
        if currentStep == nil {
            begin()
        }
        window?.center()
    }

    /// Switches the debugger to a different function/file without re-opening the
    /// window so "Simulate" on another function reuses the same panel.
    func reload(fileURL: URL, functionName: String) {
        self.functionName = functionName
        self.sourceText = (try? String(contentsOf: fileURL, encoding: .utf8)) ?? ""
        self.fileExtension = fileURL.pathExtension.lowercased()
        self.engine = SimDebugEngine(
            sourceIndex: engine.sourceIndex,
            fileURL: fileURL,
            functionName: functionName
        )
        self.currentSeeds = engine.parameters
        self.stepHistory = []
        self.currentStep = nil
        self.selectedFrameIndex = 0
        self.displayedFileURL = fileURL
        playTimer?.invalidate()
        playTimer = nil
        isPlaying = false
        playButton.title = "Play"
        self.window?.title = "\(functionName) — Debugger (Experimental)"
        functionBadgeLabel.stringValue = "\(functionName)()"
        sourceTextView.string = sourceText
        if let highlighted = SyntaxHighlighter().highlight(sourceText, for: fileExtension) {
            sourceTextView.textStorage?.setAttributedString(highlighted)
        }
        begin()
    }

    override func windowDidLoad() {
        super.windowDidLoad()
        begin()
    }

    func windowWillClose(_ notification: Notification) {
        playTimer?.invalidate()
        playTimer = nil
    }

    // MARK: - Layout

    private func buildContentView() -> NSView {
        let container = NSView(frame: .zero)
        functionBadgeLabel.stringValue = "\(functionName)()"
        functionBadgeLabel.font = monospaced
        functionBadgeLabel.textColor = .labelColor
        functionBadgeLabel.isSelectable = true

        sourceTextView.isEditable = false
        sourceTextView.isRichText = true
        sourceTextView.isSelectable = true
        sourceTextView.font = monospaced
        sourceTextView.textContainerInset = NSSize(width: 8, height: 8)
        sourceTextView.autoresizingMask = [.width]
        sourceTextView.delegate = self
        if let highlighted = SyntaxHighlighter().highlight(sourceText, for: fileExtension) {
            sourceTextView.textStorage?.setAttributedString(highlighted)
        } else {
            sourceTextView.string = sourceText
        }
        let sourceScroll = NSScrollView(frame: .zero)
        sourceScroll.documentView = sourceTextView
        sourceScroll.hasVerticalScroller = true
        sourceScroll.hasHorizontalScroller = true
        sourceScroll.autohidesScrollers = true

        let watchLabel = sectionLabel("Variables")
        watchTable.addTableColumn(column("Name", width: 150, id: "name"))
        watchTable.addTableColumn(column("Value", width: 260, id: "value"))
        watchTable.rowHeight = 20
        watchTable.usesAlternatingRowBackgroundColors = true
        watchTable.dataSource = self
        watchTable.delegate = self

        let paramsLabel = sectionLabel("Parameters (editable)")
        seedsTable.addTableColumn(column("Parameter", width: 160, id: "pname"))
        seedsTable.addTableColumn(column("Value", width: 180, id: "pvalue"))
        seedsTable.rowHeight = 20
        seedsTable.usesAlternatingRowBackgroundColors = true
        seedsTable.dataSource = self
        seedsTable.delegate = self
        seedsTable.heightAnchor.constraint(equalToConstant: 110).isActive = true

        let stackLabel = sectionLabel("Call Stack")
        stackTable.addTableColumn(column("Frame", width: 340, id: "frame"))
        stackTable.rowHeight = 20
        stackTable.usesAlternatingRowBackgroundColors = true
        stackTable.dataSource = self
        stackTable.delegate = self
        stackTable.target = self
        stackTable.doubleAction = #selector(stackDoubleClicked(_:))
        stackTable.heightAnchor.constraint(equalToConstant: 180).isActive = true
        watchLabel.setContentHuggingPriority(.required, for: .vertical)
        stackLabel.setContentHuggingPriority(.required, for: .vertical)
        paramsLabel.setContentHuggingPriority(.required, for: .vertical)

        let sideStack = NSStackView(views: [paramsLabel, seedsTable, watchLabel, watchTable, stackLabel, stackTable])
        sideStack.orientation = .vertical
        sideStack.alignment = .leading
        sideStack.distribution = .fill
        sideStack.spacing = 5
        for v in [paramsLabel, seedsTable, watchLabel, watchTable, stackLabel, stackTable] {
            if v is NSTableView {
                v.widthAnchor.constraint(equalToConstant: 420).isActive = true
            }
        }

        let split = NSSplitView(frame: .zero)
        split.isVertical = true
        split.dividerStyle = .thin
        split.addArrangedSubview(sourceScroll)
        split.addArrangedSubview(sideStack)
        sourceScroll.translatesAutoresizingMaskIntoConstraints = false
        sideStack.translatesAutoresizingMaskIntoConstraints = false
        split.setHoldingPriority(NSLayoutConstraint.Priority(260), forSubviewAt: 1)
        split.setHoldingPriority(NSLayoutConstraint.Priority(255), forSubviewAt: 0)

        stepOverButton.target = self
        stepOverButton.action = #selector(stepOverClicked(_:))
        stepIntoButton.target = self
        stepIntoButton.action = #selector(stepIntoClicked(_:))
        stepBackButton.target = self
        stepBackButton.action = #selector(stepBackClicked(_:))
        resetButton.target = self
        resetButton.action = #selector(resetClicked(_:))
        playButton.target = self
        playButton.action = #selector(playClicked(_:))

        let toolRow = NSStackView(views: [functionBadge, stepOverButton, stepIntoButton, stepBackButton, resetButton, playButton, statusLabel])
        toolRow.orientation = .horizontal
        toolRow.alignment = .centerY
        toolRow.spacing = 8
        toolRow.setContentHuggingPriority(.required, for: .vertical)
        statusLabel.lineBreakMode = .byTruncatingTail
        statusLabel.textColor = .secondaryLabelColor
        statusLabel.font = NSFont.systemFont(ofSize: 11)
        statusLabel.setContentHuggingPriority(.defaultLow, for: .horizontal)
        statusLabel.setContentCompressionResistancePriority(.defaultLow, for: .horizontal)
        container.addSubview(toolRow)
        container.addSubview(split)
        toolRow.translatesAutoresizingMaskIntoConstraints = false
        split.translatesAutoresizingMaskIntoConstraints = false
        NSLayoutConstraint.activate([
            toolRow.topAnchor.constraint(equalTo: container.topAnchor, constant: 8),
            toolRow.leadingAnchor.constraint(equalTo: container.leadingAnchor, constant: 12),
            toolRow.trailingAnchor.constraint(equalTo: container.trailingAnchor, constant: -12),
            toolRow.heightAnchor.constraint(equalToConstant: 38),
            split.topAnchor.constraint(equalTo: toolRow.bottomAnchor, constant: 8),
            split.leadingAnchor.constraint(equalTo: container.leadingAnchor),
            split.trailingAnchor.constraint(equalTo: container.trailingAnchor),
            split.bottomAnchor.constraint(equalTo: container.bottomAnchor)
        ])
        for subview in [sourceScroll, sideStack] {
            subview.heightAnchor.constraint(greaterThanOrEqualToConstant: 200).isActive = true
        }
        return container
    }

    private func sectionLabel(_ text: String) -> NSTextField {
        let label = NSTextField(labelWithString: text)
        label.font = NSFont.boldSystemFont(ofSize: 11)
        label.textColor = .secondaryLabelColor
        return label
    }

    private func column(_ title: String, width: CGFloat, id: String) -> NSTableColumn {
        let col = NSTableColumn(identifier: NSUserInterfaceItemIdentifier(id))
        col.title = title
        col.width = width
        return col
    }

    // MARK: - Actions

    @objc private func stepOverClicked(_ sender: Any?) {
        isPlaying = false
        playTimer?.invalidate()
        step(mode: .over)
    }

    @objc private func stepIntoClicked(_ sender: Any?) {
        isPlaying = false
        playTimer?.invalidate()
        step(mode: .into)
    }

    @objc private func stepBackClicked(_ sender: Any?) {
        isPlaying = false
        playTimer?.invalidate()
        guard let stepped = engine.stepBack() else { return }
        stepHistory.append(stepped)
        apply(stepped)
    }

    @objc private func resetClicked(_ sender: Any?) {
        isPlaying = false
        playTimer?.invalidate()
        engine.reset(withSeeds: currentSeeds)
        stepHistory = []
        apply(engine.initialStep())
    }

    @objc private func playClicked(_ sender: Any?) {
        isPlaying.toggle()
        playButton.title = isPlaying ? "Pause" : "Play"
        if isPlaying {
            playTimer = Timer.scheduledTimer(withTimeInterval: 0.12, repeats: true) { [weak self] _ in
                guard let self = self else { return }
                if !self.autoStep() {
                    self.isPlaying = false
                    self.playButton.title = "Play"
                    self.playTimer?.invalidate()
                    self.playTimer = nil
                }
            }
        } else {
            playTimer?.invalidate()
            playTimer = nil
        }
    }

    @objc private func stackDoubleClicked(_ sender: Any?) {
        let row = stackTable.clickedRow
        guard row >= 0, row < stackFrames().count else { return }
        let frame = stackFrames()[row]
        onOpenFile?(frame.fileURL, frame.line)
    }

    private func step(mode: SimStepMode) {
        guard let stepped = engine.stepForward(mode: mode) else {
            statusLabel.stringValue = "Finished."
            onFinished?()
            return
        }
        stepHistory.append(stepped)
        apply(stepped)
    }

    private func autoStep() -> Bool {
        guard let stepped = engine.stepForward(mode: .over) else {
            statusLabel.stringValue = "Finished."
            playButton.title = "Play"
            onFinished?()
            return false
        }
        stepHistory.append(stepped)
        apply(stepped)
        return true
    }

    // MARK: - Display

    private func apply(_ step: SimDebugStep?) {
        currentStep = step
        guard let step = step else {
            statusLabel.stringValue = "Finished."
            enableButtons(running: false)
            return
        }
        enableButtons(running: !engine.hasRunCompleted)
        displayStep(step)
        if let warning = step.warning, !warning.isEmptyOrWhitespace {
            statusLabel.stringValue = "[\(warning)] \(step.effects.joined(separator: ", "))"
        } else {
            statusLabel.stringValue = step.effects.joined(separator: "  |  ")
        }
        selectedFrameIndex = step.activeFrameIndex
        watchTable.reloadData()
        stackTable.reloadData()
        if stackTable.numberOfRows > 0 {
            stackTable.selectRowIndexes(IndexSet(integer: 0), byExtendingSelection: false)
        }
        seedsTable.reloadData()
        revealCurrentLine()
    }

    private func displayStep(_ step: SimDebugStep) {
        let activeFrame = step.activeFrameIndex >= 0 && step.activeFrameIndex < step.frames.count
            ? step.frames[step.activeFrameIndex]
            : nil
        if let activeFrame = activeFrame {
            functionBadgeLabel.stringValue = "\(activeFrame.functionName)()"
        }
        let activeFile = activeFrame?.fileURL ?? step.fileURL
        if displayedFileURL?.standardizedFileURL != activeFile.standardizedFileURL {
            displayedFileURL = activeFile
            let fileExtension = activeFile.pathExtension.lowercased()
            self.fileExtension = fileExtension
            self.sourceText = (try? String(contentsOf: activeFile, encoding: .utf8)) ?? ""
            sourceTextView.string = sourceText
            sourceTextView.textStorage?.setAttributedString(NSAttributedString())
            if let highlighted = SyntaxHighlighter().highlight(sourceText, for: fileExtension) {
                sourceTextView.textStorage?.setAttributedString(highlighted)
            }
        }
        markCurrentLine(step.line)
        scopeToFunction()
    }

    private func markCurrentLine(_ line: Int) {
        let storage = sourceTextView.textStorage!
        storage.removeAttribute(.backgroundColor, range: NSRange(location: 0, length: storage.length))
        let lineRange = sourceLineRange(line)
        guard lineRange.location != NSNotFound, lineRange.length > 0 else {
            sourceTextView.setSelectedRange(NSRange(location: 0, length: 0))
            return
        }
        storage.addAttribute(.backgroundColor, value: NSColor.systemYellow.withAlphaComponent(0.28), range: lineRange)
        sourceTextView.setSelectedRange(NSRange(location: 0, length: 0))
    }

    private func sourceLineRange(_ line: Int) -> NSRange {
        if line <= 1 { return NSRange(location: 0, length: 0) }
        var count = 0
        var idx = sourceText.startIndex
        while idx < sourceText.endIndex, count < line - 1 {
            if sourceText[idx] == "\n" { count += 1 }
            idx = sourceText.index(after: idx)
        }
        let start = sourceText.utf16.distance(from: sourceText.startIndex, to: idx)
        var end = start
        var jdx = idx
        while jdx < sourceText.endIndex {
            let c = sourceText[jdx]
            if c == "\n" {
                end = sourceText.utf16.distance(from: sourceText.startIndex, to: jdx)
                break
            }
            end += 1
            jdx = sourceText.index(after: jdx)
        }
        return NSRange(location: start, length: max(0, end - start))
    }

    private func revealCurrentLine() {
        let line = max(1, currentStep?.line ?? 1)
        let range = sourceLineRange(line)
        guard range.location != NSNotFound, range.length > 0 else {
            sourceTextView.scrollRangeToVisible(range)
            return
        }

        guard let layoutManager = sourceTextView.layoutManager,
              let textContainer = sourceTextView.textContainer else {
            sourceTextView.scrollRangeToVisible(range)
            return
        }

        let glyphRange = layoutManager.glyphRange(forCharacterRange: range, actualCharacterRange: nil)
        guard glyphRange.location != NSNotFound, glyphRange.length > 0 else {
            sourceTextView.scrollRangeToVisible(range)
            return
        }

        let lineRect = layoutManager.boundingRect(forGlyphRange: glyphRange, in: textContainer)
        let origin = sourceTextView.textContainerOrigin
        let viewRect = lineRect.offsetBy(dx: origin.x, dy: origin.y)

        let visible = sourceTextView.visibleRect
        let target = NSRect(
            x: visible.minX,
            y: viewRect.midY - visible.height / 2,
            width: visible.width,
            height: visible.height
        ).integral
        sourceTextView.scrollToVisible(target)
    }

    /// Dims every source line that lies outside the simulated function's own
    /// body so the debugger shows *just the function* rather than the entire
    /// file. Runs in a single pass over the text (O(n)) so it never blocks the
    /// main thread, even for large files.
    private func scopeToFunction() {
        guard let body = engine.functionBodyLineRange else { return }
        guard let storage = sourceTextView.textStorage else { return }
        guard displayedFileURL?.standardizedFileURL == engine.entryFileURL else { return }

        let ns = sourceText as NSString
        let nslen = ns.length
        guard nslen > 0 else { return }

        storage.beginEditing()
        defer { storage.endEditing() }

        var line = 1
        var location = 0
        var inBody = body.contains(1)
        while location < nslen {
            let r = ns.lineRange(for: NSRange(location: location, length: 0))
            if !inBody {
                storage.addAttribute(.backgroundColor,
                                     value: NSColor.quaternaryLabelColor.withAlphaComponent(0.3),
                                     range: r)
            }
            let next = r.location + r.length
            line += 1
            inBody = body.contains(line)
            if next >= nslen { break }
            location = next
        }
    }

    private var sourceLineCount: Int {
        sourceText.split(separator: "\n", omittingEmptySubsequences: false).count
    }

    private func enableButtons(running: Bool) {
        stepOverButton.isEnabled = running
        stepIntoButton.isEnabled = running
        playButton.isEnabled = running
        stepBackButton.isEnabled = true
        resetButton.isEnabled = true
    }

    // MARK: - Data Access

    private func watchRows() -> [SimVariableRow] {
        guard let step = currentStep else { return [] }
        let frames = step.frames
        let active = selectedFrameIndex
        if active >= 0 && active < frames.count {
            return frames[active].variables
        }
        return frames.first?.variables ?? []
    }

    private func stackFrames() -> [SimCallFrameView] {
        return currentStep?.frames ?? []
    }

    private func glowColor(for index: Int) -> NSColor {
        stackFrames()[index].isActive ? .systemBlue : .secondaryLabelColor
    }

    // MARK: - NSTableViewDataSource / Delegate

    func numberOfRows(in tableView: NSTableView) -> Int {
        if tableView === watchTable { return watchRows().count }
        if tableView === stackTable { return stackFrames().count }
        if tableView === seedsTable { return currentSeeds.count }
        return 0
    }

    func tableView(_ tableView: NSTableView, viewFor tableColumn: NSTableColumn?, row: Int) -> NSView? {
        guard let tableColumn = tableColumn else { return nil }
        let id = tableColumn.identifier.rawValue
        var label = (tableView.makeView(withIdentifier: tableColumn.identifier, owner: self) as? NSTextField)
        if label == nil {
            label = NSTextField(labelWithString: "")
            label!.identifier = tableColumn.identifier
            label!.font = NSFont.systemFont(ofSize: 11)
            label!.lineBreakMode = .byTruncatingTail
            label!.isSelectable = true
        }
        if tableView === watchTable {
            if id == "name" {
                label!.stringValue = watchRows()[row].name
                label!.textColor = watchRows()[row].changed ? .systemOrange : .labelColor
            } else {
                label!.stringValue = watchRows()[row].value.display
                label!.textColor = .labelColor
            }
        } else if tableView === stackTable {
            let frame = stackFrames()[row]
            if id == "frame" {
                label!.stringValue = "\(frame.functionName) — \(frame.fileName):\(frame.line)"
                label!.textColor = glowColor(for: row)
            }
        } else if tableView === seedsTable {
            let seed = currentSeeds[row]
            if id == "pvalue" {
                let field = NSTextField(string: seed.value.display)
                field.identifier = tableColumn.identifier
                field.font = NSFont.systemFont(ofSize: 11)
                field.delegate = self
                field.isBordered = false
                field.isBezeled = false
                field.drawsBackground = false
                field.isEditable = true
                return field
            }
            label!.stringValue = seed.summary
            label!.textColor = .secondaryLabelColor
        }
        return label
    }

    func tableViewSelectionDidChange(_ notification: Notification) {
        guard let tableView = notification.object as? NSTableView else { return }
        if tableView === stackTable {
            let row = stackTable.selectedRow
            if row >= 0 {
                selectedFrameIndex = row
                watchTable.reloadData()
            }
        }
    }

    // MARK: - Seed editing

    func tableView(_ tableView: NSTableView, shouldEdit tableColumn: NSTableColumn?, row: Int) -> Bool {
        return tableView === seedsTable
    }

    func controlTextDidEndEditing(_ obj: Notification) {
        guard let textField = obj.object as? NSTextField else { return }
        let index = seedsTable.row(for: textField)
        guard index >= 0, index < currentSeeds.count else { return }
        let edited = textField.stringValue
        let seed = currentSeeds[index]
        var newSeeds = currentSeeds
        newSeeds[index] = SimParameterSeed(
            name: seed.name,
            typeHint: seed.typeHint,
            value: self.parseValue(edited, for: seed),
            isBuffer: seed.isBuffer,
            capacity: seed.capacity
        )
        currentSeeds = newSeeds
        engine.parameters = newSeeds
        seedsTable.reloadData()
    }

    private func parseValue(_ text: String, for seed: SimParameterSeed) -> SimDebugValue {
        let trimmed = text.trimmingCharacters(in: .whitespaces)
        if seed.isBuffer {
            var value = trimmed
            if value.hasPrefix("\""), value.hasSuffix("\"") {
                value = String(value.dropFirst().dropLast())
            }
            return .buffer(value, capacity: seed.capacity)
        }
        if let b = Bool(trimmed) { return .bool(b) }
        if trimmed == "true" { return .bool(true) }
        if trimmed == "false" { return .bool(false) }
        if let i = Int(trimmed) { return .int(i) }
        if trimmed.contains("."), let d = Double(trimmed) { return .double(d) }
        if trimmed.hasPrefix("\""), trimmed.hasSuffix("\""), trimmed.count >= 2 {
            return .string(String(trimmed.dropFirst().dropLast()))
        }
        return .string(trimmed)
    }

    func control(_ control: NSControl, textView: NSTextView, doCommandBy commandSelector: Selector) -> Bool {
        if commandSelector == #selector(NSResponder.insertNewline(_:)) {
            window?.makeFirstResponder(nil)
            return true
        }
        return false
    }
}

extension String {
    var isEmptyOrWhitespace: Bool {
        trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
    }
}
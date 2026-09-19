// by cipher.org.uk
import AppKit

/// Protocol to unify CCFunctionParser.FunctionDef and JSFunctionParser.FunctionDef
private protocol FunctionDefProtocol {
    var name: String { get }
    var bodyRange: NSRange { get }
    var signatureRange: NSRange { get }
    var nameRange: NSRange { get }
}

private struct FunctionDefWrapper: FunctionDefProtocol {
    let name: String
    let bodyRange: NSRange
    let signatureRange: NSRange
    let nameRange: NSRange

    init(_ def: CCFunctionParser.FunctionDef) {
        self.name = def.name
        self.bodyRange = def.bodyRange
        self.signatureRange = def.signatureRange
        self.nameRange = def.nameRange
    }

    init(_ def: JSFunctionParser.FunctionDef) {
        self.name = def.name
        self.bodyRange = def.bodyRange
        self.signatureRange = def.signatureRange
        self.nameRange = def.nameRange
    }
}

/// Displays the content of a selected source file with syntax highlighting
/// and a line-number gutter on the left.
final class SourceViewer: NSViewController, NSTextViewDelegate, NSSearchFieldDelegate {
    private let scrollView = NSScrollView()
    private let textView = ClickableTextView()
    private let emptyLabel = NSTextField(labelWithString: "Choose a folder, then select a file to view its source.")
    private let highlighter = SyntaxHighlighter()
    private var lineNumberRuler: LineNumberRulerView?
    private var notePopover: NSPopover?

    // Find-in-file
    private let searchBar = NSSearchField()
    private let matchCountLabel = NSTextField(labelWithString: "")
    private var matchRanges: [NSRange] = []
    private var currentMatchIndex: Int = -1
    private let searchIndicatorColor = NSColor(calibratedRed: 1.0, green: 0.9, blue: 0.3, alpha: 0.6)

    // Bottom pane: dataflow diagram of the clicked function (same-file only).
    private let dataflowTitle = NSTextField(labelWithString: "Function dataflow (within file)")
    private let dataflowView = DataFlowDiagramView()
    private var dataflowPane: NSView?

    /// The language currently selected in the dropdown. C/C++ makes function names clickable.
    var language: Language?
    private var currentFileURL: URL?
    private var currentSource: String?
    private var scrollSettleTimer: Timer?

    /// Project-wide definition index (name → source locations). When non-nil,
    /// call sites of project-defined functions become clickable and open a
    /// definition popup. Set by the owning controller when a project is opened.
    var definitionIndex: DefinitionIndex? {
        didSet { reapplyIfDisplaying() }
    }
    /// Color for a call site (a *call* of a project-defined function). Uses a
    /// teal/green so call sites read apart from the accent-blue definition names.
    private let callSiteHighlightColor = NSColor(calibratedRed: 0.0, green: 0.55, blue: 0.5, alpha: 1)

    /// Line numbers (1-based) flagged as >=80% likely vulnerable by the ML scan,
    /// mapped to their probability (0.8...1.0). Applied as a background highlight.
    private var highRiskLines: [Int: Double] = [:]

    /// Compact clickable table at the top of the viewer listing the highlighted
    /// lines for the current file. Clicking a row scrolls the source to that line.
    private lazy var resultsViewController: HighlightedLinesViewController = {
        let vc = HighlightedLinesViewController()
        vc.onSelectLine = { [weak self] line in
            self?.scrollToLine(line)
        }
        return vc
    }()

    /// Top constraint of the source scroll view. Toggled between the top of the
    /// pane (search bar hidden) and just below the search bar (search bar visible),
    /// so there is no gap above the source code when Find-in-File is inactive.
    private var scrollTopConstraint: NSLayoutConstraint?

    /// Container holding the search bar and the source scroll view.
    private let topContainer = NSView()

    /// C/C++ function name ranges (location + length) mapped to their names, used for
    /// left-click highlighting and right-click context-menu lookup.
    private var functionRanges: [(name: String, range: NSRange)] = []
    /// Java class/interface/enum/record name ranges mapped to their names.
    private var classRanges: [(name: String, range: NSRange)] = []
    /// Distinct colour for highlighted Java class names (purple, so they read apart
    /// from the accent-blue function names).
    private let classHighlightColor = NSColor.systemPurple

    /// Called when a clickable function name is clicked. Passes the file and function name.
    var onDiagramRequest: ((URL, String) -> Void)?
    /// Called when a function name is clicked — passes the file, function name, full source, and file extension,
    /// enabling downstream panels to compute complexity/flowcharts.
    var onFunctionSelected: ((URL, String, String, String) -> Void)?
    /// Called when a Java class name is clicked. Passes the class name.
    var onClassRequest: ((String) -> Void)?
    /// Called when the user picks "Backtrace Analyser" from the context menu.
    var onBacktraceRequest: (() -> Void)?
    /// Called when the user picks "Follow the variable" from the context menu.
    /// Passes the file, the UTF-16 char index of the highlighted variable, and its name.
    var onVariableFlowRequest: ((URL, Int, String) -> Void)?
    /// Called when the user picks "(AI) How to fix it" from the context menu.
    /// Passes the file, the 1-based line number, and the text of that line.
    var onHowToFix: ((URL, Int, String) -> Void)?
    /// The charIndex of the right-click that built the current context menu, so
    /// menu actions can resolve which line was clicked.
    private var lastMenuCharIndex = 0

    override func loadView() {
        let container = NSView()

        // Vertical split: source on top, dataflow diagram of a clicked function below.
        let split = NSSplitView()
        split.isVertical = false
        split.dividerStyle = .thin

        // --- Top: highlighted-lines table + search bar + source scroll view ---
        // The results table is its own pane of the outer vertical split so it is
        // draggable/resizable, and collapses when empty so the source fills the viewer.
        topContainer.translatesAutoresizingMaskIntoConstraints = false

        searchBar.placeholderString = "Find in file…"
        searchBar.delegate = self
        searchBar.isHidden = true
        searchBar.translatesAutoresizingMaskIntoConstraints = false
        topContainer.addSubview(searchBar)

        matchCountLabel.font = NSFont.systemFont(ofSize: 11)
        matchCountLabel.textColor = .secondaryLabelColor
        matchCountLabel.isHidden = true
        matchCountLabel.translatesAutoresizingMaskIntoConstraints = false
        topContainer.addSubview(matchCountLabel)

        scrollView.hasVerticalScroller = true
        scrollView.hasHorizontalScroller = true
        scrollView.autohidesScrollers = true
        scrollView.borderType = .noBorder
        scrollView.translatesAutoresizingMaskIntoConstraints = false

        // Configure the source text view
        textView.isEditable = false
        textView.isSelectable = true
        textView.isRichText = false
        textView.delegate = self
        textView.font = NSFont.monospacedSystemFont(ofSize: 13, weight: .regular)
        textView.textColor = .labelColor
        textView.backgroundColor = .textBackgroundColor
        textView.isVerticallyResizable = true
        textView.isHorizontallyResizable = false
        textView.autoresizingMask = [.width]
        textView.textContainerInset = NSSize(width: 8, height: 4)

        let textContainer = textView.textContainer!
        textContainer.widthTracksTextView = true
        textContainer.containerSize = NSSize(width: CGFloat.greatestFiniteMagnitude, height: CGFloat.greatestFiniteMagnitude)

        scrollView.documentView = textView

        // Line-number gutter: a vertical ruler, reliably rendered and clickable.
        scrollView.hasVerticalRuler = true
        scrollView.hasHorizontalRuler = false
        let ruler = LineNumberRulerView(scrollView: scrollView, orientation: .verticalRuler)
        ruler.clientView = textView
        ruler.reservedThicknessForMarkers = 0
        ruler.gaugeWidth = 36
        scrollView.verticalRulerView = ruler
        lineNumberRuler = ruler
        scrollView.rulersVisible = true
        topContainer.addSubview(scrollView)

        // Clicking a line number lets the user attach a persistent note.
        ruler.onLineClick = { [weak self] line in
            self?.showNotePopover(line: line)
        }

        // Keep the line-number gutter in sync with scrolling: redraw the ruler
        // whenever the clip view moves (live scroll, page/word scroll, etc.).
        scrollView.contentView.postsBoundsChangedNotifications = true
        NotificationCenter.default.addObserver(
            self,
            selector: #selector(documentScrolled(_:)),
            name: NSView.boundsDidChangeNotification,
            object: scrollView.contentView
        )

        NSLayoutConstraint.activate([
            searchBar.topAnchor.constraint(equalTo: topContainer.topAnchor, constant: 6),
            searchBar.leadingAnchor.constraint(equalTo: topContainer.leadingAnchor, constant: 12),
            matchCountLabel.centerYAnchor.constraint(equalTo: searchBar.centerYAnchor),
            matchCountLabel.leadingAnchor.constraint(equalTo: searchBar.trailingAnchor, constant: 10),
            matchCountLabel.trailingAnchor.constraint(lessThanOrEqualTo: topContainer.trailingAnchor, constant: -12),
            scrollView.bottomAnchor.constraint(equalTo: topContainer.bottomAnchor),
            scrollView.leadingAnchor.constraint(equalTo: topContainer.leadingAnchor),
            scrollView.trailingAnchor.constraint(equalTo: topContainer.trailingAnchor)
        ])
        // Pin the source to the very top of the pane (search bar hidden by default).
        let top = scrollView.topAnchor.constraint(equalTo: topContainer.topAnchor)
        top.isActive = true
        scrollTopConstraint = top

        // --- Bottom: dataflow pane ---
        let bottom = NSView()
        bottom.wantsLayer = true
        bottom.layer?.backgroundColor = NSColor.controlBackgroundColor.cgColor
        bottom.translatesAutoresizingMaskIntoConstraints = false
        dataflowPane = bottom

        dataflowTitle.font = NSFont.systemFont(ofSize: 12, weight: .semibold)
        dataflowTitle.textColor = .secondaryLabelColor
        dataflowTitle.translatesAutoresizingMaskIntoConstraints = false
        bottom.addSubview(dataflowTitle)

        dataflowView.translatesAutoresizingMaskIntoConstraints = false
        bottom.addSubview(dataflowView)

        NSLayoutConstraint.activate([
            dataflowTitle.topAnchor.constraint(equalTo: bottom.topAnchor, constant: 8),
            dataflowTitle.leadingAnchor.constraint(equalTo: bottom.leadingAnchor, constant: 12),
            dataflowTitle.trailingAnchor.constraint(lessThanOrEqualTo: bottom.trailingAnchor, constant: -12),
            dataflowView.topAnchor.constraint(equalTo: dataflowTitle.bottomAnchor, constant: 6),
            dataflowView.bottomAnchor.constraint(equalTo: bottom.bottomAnchor),
            dataflowView.leadingAnchor.constraint(equalTo: bottom.leadingAnchor),
            dataflowView.trailingAnchor.constraint(equalTo: bottom.trailingAnchor),
            bottom.heightAnchor.constraint(greaterThanOrEqualToConstant: 150)
        ])

        // --- Assemble split ---
        let resultsView = resultsViewController.view
        resultsView.translatesAutoresizingMaskIntoConstraints = false
        resultsView.isHidden = true
        topContainer.translatesAutoresizingMaskIntoConstraints = false
        split.addArrangedSubview(resultsView)
        split.addArrangedSubview(topContainer)
        split.addArrangedSubview(bottom)
        split.setHoldingPriority(NSLayoutConstraint.Priority(250), forSubviewAt: 0)
        split.setHoldingPriority(NSLayoutConstraint.Priority(240), forSubviewAt: 1)
        split.setHoldingPriority(NSLayoutConstraint.Priority(261), forSubviewAt: 2)
        bottom.isHidden = true

        split.translatesAutoresizingMaskIntoConstraints = false
        container.addSubview(split)

        emptyLabel.font = NSFont.systemFont(ofSize: 15)
        emptyLabel.textColor = .secondaryLabelColor
        emptyLabel.translatesAutoresizingMaskIntoConstraints = false
        container.addSubview(emptyLabel)

        NSLayoutConstraint.activate([
            split.topAnchor.constraint(equalTo: container.topAnchor),
            split.bottomAnchor.constraint(equalTo: container.bottomAnchor),
            split.leadingAnchor.constraint(equalTo: container.leadingAnchor),
            split.trailingAnchor.constraint(equalTo: container.trailingAnchor),
            emptyLabel.centerXAnchor.constraint(equalTo: container.centerXAnchor),
            emptyLabel.centerYAnchor.constraint(equalTo: container.centerYAnchor)
        ])

        scrollView.isHidden = true
        self.view = container
    }

    func clear() {
        currentFileURL = nil
        currentSource = nil
        dataflowPane?.isHidden = true
        textView.hideTypeTooltip()
        textView.typeResolver = nil
        textView.typeLanguageName = nil
        highRiskLines = [:]
        resultsViewController.configure(lines: [:], source: "")
        textView.string = ""
        textView.textStorage?.setAttributedString(NSAttributedString(string: ""))
        lineNumberRuler?.markedLines = []
        lineNumberRuler?.highRiskLines = [:]
        lineNumberRuler?.cachedLineCount = 1
        lineNumberRuler?.needsDisplay = true
        emptyLabel.isHidden = false
        scrollView.isHidden = true
    }

    func display(fileAt url: URL) {
        scrollView.isHidden = false
        emptyLabel.isHidden = true
        currentFileURL = url
        dataflowPane?.isHidden = true

        defer { textView.needsDisplay = true }

        do {
            let text = try String(contentsOf: url, encoding: .utf8)
            currentSource = text

            // Hover type tooltip: enable resolution only for C/C++/Java files.
            configureTypeTooltip(forExtension: url.pathExtension.lowercased())

            // Load ML scan results for this file if a scan has been run.
            highRiskLines = MLScanResultStore.shared.highRiskLines(forFile: url.path)
            resultsViewController.configure(lines: highRiskLines, source: text)

            lineNumberRuler?.gaugeWidth = gutterWidth(for: text)
            lineNumberRuler?.markedLines = NoteStore.shared.lineNumbers(for: url)
            lineNumberRuler?.highRiskLines = highRiskLines
            lineNumberRuler?.cachedLineCount = text.components(separatedBy: "\n").count
            lineNumberRuler?.needsDisplay = true

            let attributed = highlighter.highlight(text, for: url.pathExtension)
            let result = applyClickableLinks(to: attributed ?? NSAttributedString(string: text), forExtension: url.pathExtension)

            textView.textStorage?.beginEditing()
            textView.textStorage?.setAttributedString(result)
            applyVulnerabilityHighlights()
            textView.textStorage?.endEditing()

            textView.scrollToBeginningOfDocument(nil)
        } catch {
            presentError(url: url)
        }
    }

    /// Enables or disables the hover type tooltip based on the file's language.
    /// For C/C++/Java we hand the text view a resolver backed by `TypeResolver`.
    private func configureTypeTooltip(forExtension ext: String) {
        textView.hideTypeTooltip()

        let langName: String?
        switch ext {
        case "c", "h": langName = "C"
        case "cpp", "cc", "cxx", "hpp", "hxx", "hh": langName = "C++"
        case "java": langName = "Java"
        case "cs", "csx": langName = "C#"
        default: langName = nil
        }

        guard langName != nil, currentSource != nil else {
            textView.typeResolver = nil
            textView.typeLanguageName = nil
            textView.hideTypeTooltip()
            return
        }
        let language = Language(name: langName!, extensions: [])
        textView.typeLanguageName = langName
        textView.typeResolver = { [weak self] charIndex in
            guard let src = self?.currentSource else { return nil }
            return TypeResolver.type(at: charIndex, in: src, language: language)
        }
    }

    /// Applies a probability-scaled background highlight to every line flagged as
    /// >=80% likely vulnerable. Intensity/color scales from yellow (80%) to red (100%).
    private func applyVulnerabilityHighlights() {
        guard !highRiskLines.isEmpty,
              let storage = textView.textStorage,
              let source = currentSource else { return }
        let ns = source as NSString
        var lineStart = 0
        var line = 1
        let lineEnds = source.components(separatedBy: "\n").count
        for _ in 0..<lineEnds {
            var length = lineStart
            var end = lineStart
            while end < ns.length && ns.character(at: end) != 0x0A { end += 1 }
            length = end - lineStart
            let range = NSRange(location: lineStart, length: length)
            if let prob = highRiskLines[line] {
                storage.addAttribute(.backgroundColor, value: highlightColor(for: prob), range: range)
            }
            lineStart = end + 1
            line += 1
        }
    }
    private func highlightColor(for probability: Double) -> NSColor {
        let t = min(max((probability - 0.8) / 0.2, 0.0), 1.0)
        // Resolve dynamic/system colors to a concrete sRGB color first, because
        // reading `.redComponent` directly on a dynamic color throws an exception.
        let yellow = NSColor.systemYellow.usingColorSpace(.sRGB)
        let red = NSColor.systemRed.usingColorSpace(.sRGB)
        if let y = yellow, let r = red {
            let rr = y.redComponent + (r.redComponent - y.redComponent) * CGFloat(t)
            let g = y.greenComponent + (r.greenComponent - y.greenComponent) * CGFloat(t)
            let b = y.blueComponent + (r.blueComponent - y.blueComponent) * CGFloat(t)
            return NSColor(calibratedRed: rr, green: g, blue: b, alpha: 0.45)
        }
        // Fallback.
        return NSColor.systemRed.withAlphaComponent(0.45)
    }

    /// Re-reads the ML scan results for the currently open file and reapplies the
    /// line highlights. Called after a project scan finishes while a file is open.
    func refreshVulnerabilityHighlights() {
        guard let url = currentFileURL else { return }
        highRiskLines = MLScanResultStore.shared.highRiskLines(forFile: url.path)
        resultsViewController.configure(lines: highRiskLines, source: currentSource)
        lineNumberRuler?.highRiskLines = highRiskLines
        // Clear any existing background highlight in the whole document, then reapply.
        textView.textStorage?.beginEditing()
        let all = NSRange(location: 0, length: textView.textStorage?.length ?? 0)
        if all.length > 0 {
            textView.textStorage?.removeAttribute(.backgroundColor, range: all)
        }
        applyVulnerabilityHighlights()
        textView.textStorage?.endEditing()
        lineNumberRuler?.needsDisplay = true
        textView.needsDisplay = true
    }

    /// If the file is a supported analysis language, makes the function-name
    /// ranges link attributes so they're clickable (C/C++/ObjC/Java/C#/Go/Kotlin/
    /// Python/Ruby/Rust).
    private func applyClickableLinks(to attributed: NSAttributedString, forExtension ext: String) -> NSAttributedString {
        guard DiagramLanguage.from(ext: ext) != nil else { return attributed }

        let mutable = NSMutableAttributedString(attributedString: attributed)
        let source = attributed.string
        let lowerExt = ext.lowercased()

        // Select parser based on language
        let defs: [FunctionDefProtocol]
        let classNames: [(name: String, range: NSRange)]
        defs = diagramDefinitions(source: source, ext: ext).map { def in
            FunctionDefWrapper(def)
        }
        classNames = CCFunctionParser(source: source).parseClassNames()

        functionRanges.removeAll()
        for def in defs {
            guard def.nameRange.location != NSNotFound, def.nameRange.length > 0 else { continue }
            mutable.addAttribute(ClickableTextView.functionNameKey, value: def.name as NSString, range: def.nameRange)
            mutable.addAttribute(.underlineStyle, value: NSUnderlineStyle.single.rawValue, range: def.nameRange)
            mutable.addAttribute(.foregroundColor, value: NSColor.controlAccentColor, range: def.nameRange)
            functionRanges.append((name: def.name, range: def.nameRange))
        }
        textView.functionRanges = functionRanges
        textView.onFunctionClick = { [weak self] name in
            self?.handleFunctionClick(name)
        }

        classRanges.removeAll()
        if lowerExt == "java" || lowerExt == "cs" || lowerExt == "csx" {
            for cls in classNames {
                let r = cls.range
                guard r.location != NSNotFound, r.length > 0 else { continue }
                mutable.addAttribute(ClickableTextView.classNameKey, value: cls.name as NSString, range: r)
                mutable.addAttribute(.underlineStyle, value: NSUnderlineStyle.single.rawValue, range: r)
                mutable.addAttribute(.foregroundColor, value: classHighlightColor, range: r)
                classRanges.append((name: cls.name, range: r))
            }
        }
        textView.classRanges = classRanges
        textView.onClassClick = { [weak self] name in
            self?.onClassRequest?(name)
        }

        applyCallSiteLinks(mutable, source: source, forExtension: ext)

        return mutable
    }

    /// Tags every *call site* of a project-defined function/method in the source
    /// as clickable. The name itself is underlined in a teal hue so it reads
    /// apart from definitions (accent blue). Definition name ranges are exempt:
    /// clicking a definition keeps the existing dataflow behaviour instead of
    /// opening the definition popup.
    private func applyCallSiteLinks(_ mutable: NSMutableAttributedString,
                                    source: String,
                                    forExtension ext: String) {
        textView.callSiteRanges.removeAll()
        textView.onCallSiteClick = { [weak self] name in
            self?.handleCallSiteClick(name)
        }
        guard let index = definitionIndex else { return }

        // Character ranges that must NOT become call sites: the function/class
        // definition sites in this file.
        var excluded = Set<Int>()
        for entry in functionRanges + classRanges {
            let range = entry.range
            for i in range.location..<(range.location + range.length) {
                excluded.insert(i)
            }
        }

        let ns = source as NSString
        let len = ns.length
        var callSites: [(name: String, range: NSRange)] = []

        var i = 0
        while i < len {
            let c = ns.character(at: i)
            guard isCallIdentStart(c) else { i += 1; continue }
            let start = i
            i += 1
            while i < len && isCallIdentChar(ns.character(at: i)) { i += 1 }
            let ident = ns.substring(with: NSRange(location: start, length: i - start))

            // Skip control-flow / declaration keywords entirely.
            if isCallKeyword(ident) || ident.isEmpty { continue }

            // The token is a candidate call site only if a `(` (possibly after
            // whitespace) follows, we're not inside a definition name, the name
            // is defined somewhere in the project, and it is not the current
            // file's own definition name range.
            var j = i
            while j < len && isCallWs(ns.character(at: j)) { j += 1 }
            guard j < len, ns.character(at: j) == 0x28 else { continue }

            let nameOffset = start
            var isInsideDefinition = false
            for k in nameOffset..<i where excluded.contains(k) { isInsideDefinition = true; break }
            guard isInsideDefinition == false else { continue }

            // Only make names clickable when they resolve to a definition in the
            // currently open project.
            guard index.contains(name: ident) else { continue }

            let range = NSRange(location: start, length: i - start)
            mutable.addAttribute(ClickableTextView.callSiteKey, value: ident as NSString, range: range)
            mutable.addAttribute(.underlineStyle, value: NSUnderlineStyle.single.rawValue, range: range)
            mutable.addAttribute(.foregroundColor, value: callSiteHighlightColor, range: range)
            callSites.append((name: ident, range: range))

            i = j + 1
        }
        textView.callSiteRanges = callSites
    }

    /// Called when the user clicks a call site. Resolves the called symbol to
    /// its definition in the project and opens the definition popup.
    private func handleCallSiteClick(_ name: String) {
        guard let index = definitionIndex,
              let fileURL = currentFileURL,
              let loc = index.lookUp(name: name, preferredFileURL: fileURL) else { return }
        let controller = DefinitionWindowController(location: loc)
        controller.showWindow(nil)
        NSApp.activate(ignoringOtherApps: true)
    }

    /// Re-renders the current file when the definition index arrives, so that
    /// call sites become clickable without the user having to reopen the file.
    private func reapplyIfDisplaying() {
        guard let url = currentFileURL, definitionIndex != nil else { return }
        let ext = url.pathExtension
        guard let source = currentSource else { return }
        let attributed = highlighter.highlight(source, for: ext)
        let result = applyClickableLinks(to: attributed ?? NSAttributedString(string: source), forExtension: ext)
        textView.textStorage?.beginEditing()
        textView.textStorage?.setAttributedString(result)
        applyVulnerabilityHighlights()
        textView.textStorage?.endEditing()
    }

    // MARK: - Call-site scanning helpers

    private func isCallIdentStart(_ scalar: unichar) -> Bool {
        return (scalar >= 0x41 && scalar <= 0x5A) || scalar == 0x5F || (scalar >= 0x61 && scalar <= 0x7A)
    }

    private func isCallIdentChar(_ scalar: unichar) -> Bool {
        return isCallIdentStart(scalar) || (scalar >= 0x30 && scalar <= 0x39)
    }

    private func isCallWs(_ scalar: unichar) -> Bool {
        return scalar == 0x20 || scalar == 0x09 || scalar == 0x0A || scalar == 0x0D
    }

    /// Control-flow / declaration keywords and punctuation-like names that
    /// should never be treated as call sites even when immediately followed by
    /// `(`.
    private func isCallKeyword(_ ident: String) -> Bool {
        switch ident {
        case "if", "for", "while", "switch", "catch", "return", "throw", "new",
             "import", "export", "from", "use", "as", "in", "of", "sizeof",
             "guard", "do", "else", "case", "default", "try", "finally",
             "instanceof", "typeof", "yield", "await", "assert", "defer",
             "struct", "union", "enum", "class", "interface", "protocol",
             "extension", "func", "function", "def", "let", "var", "const",
             "public", "private", "internal", "protected", "static", "final",
             "override", "typealias", "typedef", "template", "namespace",
             "using", "require", "include", "define", "supers", "match",
             "when", "where", "impl", "trait", "self", "super", "this",
             "init", "int", "float", "double", "long", "short", "char",
             "void", "bool", "boolean", "byte", "string", "String", "size_t":
            return true
        default:
            return false
        }
    }

    private func handleFunctionClick(_ functionName: String) {
        guard let fileURL = currentFileURL else { return }
        showFunctionDataflow(functionName: functionName)
        if let source = currentSource {
            let ext = fileURL.pathExtension
            onFunctionSelected?(fileURL, functionName, source, ext)
        }
    }

    // MARK: - Bottom dataflow pane

    /// Builds and shows a dataflow graph for `functionName`, limited to functions
    /// defined within the currently opened file (the clicked function plus its
    /// transitive same-file callees). Language-aware: resolves definitions and
    /// call/data edges per the file's extension.
    private func showFunctionDataflow(functionName: String) {
        guard let source = currentSource, let pane = dataflowPane, let url = currentFileURL else { return }

        let (calls, data, definedNames): ([(String, String)], [(String, String)], Set<String>) = {
            let defs = diagramDefinitions(source: source, ext: url.pathExtension)
            let (c, d) = diagramCallGraph(source: source, definitions: defs)
            return (c, d, Set(defs.map { $0.name }))
        }()

        // Transitive same-file callees reachable from the clicked function.
        var reachable: Set<String> = [functionName]
        var frontier = [functionName]
        while let f = frontier.popLast() {
            for (from, to) in calls where from == f && definedNames.contains(to) && !reachable.contains(to) {
                reachable.insert(to)
                frontier.append(to)
            }
        }

        let graph = CallGraph()
        for (from, to) in calls where reachable.contains(from) && reachable.contains(to) {
            graph.addCall(from: from, to: to)
        }
        for (from, to) in data where reachable.contains(from) && reachable.contains(to) {
            graph.addDataFlow(from: from, to: to)
        }

        if graph.nodes.isEmpty {
            dataflowPane?.isHidden = true
            return
        }

        pane.isHidden = false
        dataflowTitle.stringValue = "Dataflow within file — \(functionName)"
        dataflowView.display(
            graph: graph,
            callEdges: calls.filter { graph.hasNode($0.0) && graph.hasNode($0.1) },
            dataEdges: data.filter { graph.hasNode($0.0) && graph.hasNode($0.1) },
            highlight: functionName
        )
    }

    // MARK: - NSTextViewDelegate

    /// Builds the right-click context menu. When the click is on a C/C++ function name,
    /// offers a "Show Flow Diagram" action (the diagram is opened from the menu, not on click).
    private var magnifyingGlass: CodeMagnifyingGlassView?
    private var isMagnifyingEnabled = false
    private var mouseTrackingMonitor: Any?

    func textView(_ view: NSTextView, menu: NSMenu, for event: NSEvent, at charIndex: Int) -> NSMenu? {
        let menu = NSMenu(title: "Source")
        lastMenuCharIndex = charIndex

        let copyItem = NSMenuItem(title: "Copy", action: #selector(NSText.copy(_:)), keyEquivalent: "c")
        copyItem.isEnabled = view.selectedRange.length > 0 || !view.string.isEmpty
        menu.addItem(copyItem)
        menu.addItem(NSMenuItem.separator())
        
        let lensTitle = isMagnifyingEnabled ? "Disable Magnifying Glass Lens" : "Enable Magnifying Glass Lens"
        let lensItem = NSMenuItem(title: lensTitle, action: #selector(toggleMagnifyingGlass(_:)), keyEquivalent: "")
        lensItem.target = self
        menu.addItem(lensItem)

        if let functionName = functionName(at: charIndex) {
            menu.addItem(NSMenuItem.separator())
            let item = NSMenuItem(
                title: "Show Flow Diagram for \(functionName)",
                action: #selector(showFlowDiagram(_:)),
                keyEquivalent: ""
            )
            item.target = self
            item.representedObject = functionName
            menu.addItem(item)
        }

        if let variableName = variableWord(at: charIndex) {
            menu.addItem(NSMenuItem.separator())
            let item = NSMenuItem(
                title: "Follow the variable '\(variableName)'",
                action: #selector(followVariable(_:)),
                keyEquivalent: ""
            )
            item.target = self
            item.representedObject = variableName
            menu.addItem(item)
        }

        menu.addItem(NSMenuItem.separator())
        let backtraceItem = NSMenuItem(
            title: "Backtrace Analyser…",
            action: #selector(showBacktraceAnalyser(_:)),
            keyEquivalent: ""
        )
        backtraceItem.target = self
        menu.addItem(backtraceItem)

        menu.addItem(NSMenuItem.separator())
        let howToFixItem = NSMenuItem(
            title: "(AI) How to fix it",
            action: #selector(howToFixIt(_:)),
            keyEquivalent: ""
        )
        howToFixItem.target = self
        menu.addItem(howToFixItem)

        return menu
    }

    @objc private func toggleMagnifyingGlass(_ sender: NSMenuItem) {
        isMagnifyingEnabled.toggle()
        if isMagnifyingEnabled {
            if magnifyingGlass == nil {
                let glass = CodeMagnifyingGlassView(targetTextView: textView)
                scrollView.contentView.addSubview(glass)
                magnifyingGlass = glass
            }
            magnifyingGlass?.isHidden = false
            
            // Monitor mouse moves over the scrollview/textview
            mouseTrackingMonitor = NSEvent.addLocalMonitorForEvents(matching: [.mouseMoved]) { [weak self] event in
                self?.handleMouseMoved(event)
                return event
            }
        } else {
            magnifyingGlass?.isHidden = true
            if let monitor = mouseTrackingMonitor {
                NSEvent.removeMonitor(monitor)
                mouseTrackingMonitor = nil
            }
        }
    }

    private func handleMouseMoved(_ event: NSEvent) {
        guard isMagnifyingEnabled, let glass = magnifyingGlass else { return }
        glass.updatePosition(withEvent: event)
    }

    @objc private func showFlowDiagram(_ sender: NSMenuItem) {
        guard let functionName = sender.representedObject as? String,
              let fileURL = currentFileURL else { return }
        onDiagramRequest?(fileURL, functionName)
    }

    @objc private func followVariable(_ sender: NSMenuItem) {
        guard let variableName = sender.representedObject as? String,
              let fileURL = currentFileURL else { return }
        // Anchor the trace at the exact click position. Only when the right-click
        // lands inside a non-empty selection do we prefer the selection's start
        // (the click can be mid-word; the selection start is more predictable).
        // Never fall back to the text view's insertion point: with no active
        // selection that is the caret, which may be far from where the user
        // clicked (often offset 0), so the tracer would miss the enclosing
        // function entirely.
        let selection = textView.selectedRange
        let charIndex: Int
        if selection.length > 0, NSLocationInRange(lastMenuCharIndex, selection) {
            charIndex = selection.location
        } else {
            charIndex = lastMenuCharIndex
        }
        onVariableFlowRequest?(fileURL, charIndex, variableName)
    }

    @objc private func showBacktraceAnalyser(_ sender: NSMenuItem) {
        onBacktraceRequest?()
    }

    @objc private func howToFixIt(_ sender: NSMenuItem) {
        guard let fileURL = currentFileURL else { return }
        let ns = textView.string as NSString
        guard ns.length > 0 else { return }
        let charIndex = min(max(lastMenuCharIndex, 0), ns.length)
        let lineRange = ns.lineRange(for: NSRange(location: charIndex, length: 0))
        let lineText = ns.substring(with: lineRange).trimmingCharacters(in: .newlines)
        let lineNumber = ns.substring(with: NSRange(location: 0, length: lineRange.location))
            .reduce(0) { $1 == "\n" ? $0 + 1 : $0 } + 1
        onHowToFix?(fileURL, lineNumber, lineText)
    }

    private func extractSnippet(for functionName: String, in source: String) -> String {
        for entry in functionRanges where entry.name == functionName {
            let ns = source as NSString
            if entry.range.location != NSNotFound, entry.range.location + entry.range.length <= ns.length {
                return ns.substring(with: entry.range)
            }
        }
        return source
    }

    private func functionName(at charIndex: Int) -> String? {
        guard charIndex >= 0 else { return nil }
        for entry in functionRanges where NSLocationInRange(charIndex, entry.range) {
            return entry.name
        }
        return nil
    }

    /// The identifier word under/around `charIndex` (also straddling an active
    /// selection), or nil when it is empty or a language keyword — used to offer
    /// the "Follow the variable" context-menu action.
    private func variableWord(at charIndex: Int) -> String? {
        guard let source = currentSource else { return nil }
        let ns = source as NSString
        guard ns.length > 0 else { return nil }

        // Prefer a currently-highlighted selection of a single word.
        let selection = textView.selectedRange
        if selection.location != NSNotFound, selection.length > 0, selection.length <= 80,
           let selected = ns.substring(with: selection) as String? {
            let trimmed = selected.trimmingCharacters(in: .whitespacesAndNewlines)
            if trimmed.allSatisfy({ isVariableWordChar($0) }), !trimmed.isEmpty {
                return isVariableKeyword(trimmed) ? nil : trimmed
            }
        }

        let idx = min(max(charIndex, 0), ns.length)
        var start = idx
        var end = idx
        while start > 0 && ns.character(at: start - 1) != 0x0A {
            let c = ns.character(at: start - 1)
            if isVariableWordScalar(c) { start -= 1 } else { break }
        }
        while end < ns.length {
            let c = ns.character(at: end)
            if isVariableWordScalar(c) { end += 1 } else { break }
        }
        guard end > start else { return nil }
        let word = ns.substring(with: NSRange(location: start, length: end - start))
        guard !word.isEmpty, !isVariableKeyword(word) else { return nil }
        return word
    }

    private func isVariableWordChar(_ c: Character) -> Bool {
        if c.isASCII, let v = c.asciiValue {
            return isVariableWordScalar(UInt16(v))
        }
        return c.isLetter || c == "_"
    }

    private func isVariableWordScalar(_ c: unichar) -> Bool {
        (c >= 0x41 && c <= 0x5A) || (c >= 0x61 && c <= 0x7A) || (c >= 0x30 && c <= 0x39) || c == 0x5F
    }

    private func isVariableKeyword(_ ident: String) -> Bool {
        switch ident {
        case "if", "for", "while", "switch", "catch", "return", "throw", "new",
             "import", "export", "from", "use", "as", "in", "of", "sizeof",
             "guard", "do", "else", "case", "default", "try", "finally",
             "instanceof", "typeof", "yield", "await", "assert", "defer",
             "struct", "union", "enum", "class", "interface", "protocol",
             "extension", "func", "function", "def", "let", "var", "const",
             "public", "private", "internal", "protected", "static", "final",
             "override", "typealias", "typedef", "template", "namespace",
             "using", "require", "include", "define", "match", "when", "where",
             "impl", "trait", "self", "super", "this", "init",
             "int", "float", "double", "long", "short", "char", "void", "bool",
             "boolean", "byte", "string", "String", "size_t", "null", "nil",
             "None", "true", "false", "NULL", "nullptr", "undefined", "NaN":
            return true
        default:
            return false
        }
    }

    private func gutterWidth(for text: String) -> CGFloat {
        let lineCount = text.components(separatedBy: "\n").count
        let digits = max(1, String(lineCount).count)
        // Room for digits + a marker dot + padding.
        return CGFloat(digits * 9 + 26)
    }

    private func presentError(url: URL) {
        textView.textStorage?.setAttributedString(NSAttributedString(
            string: "Could not read file:\n\(url.path)",
            attributes: [.foregroundColor: NSColor.systemRed]
        ))
    }

    // MARK: - Find in file

    /// Invoked externally to show the find-in-file search bar (e.g. via ⌘F).
    func activateFind() {
        searchBar.isHidden = false
        matchCountLabel.isHidden = false
        updateScrollTop(isSearchShown: true)
        view.window?.makeFirstResponder(searchBar)
    }

    /// Repins the source scroll view: to the very top of the pane when the search
    /// bar is hidden, or just below the search bar when it is visible.
    private func updateScrollTop(isSearchShown: Bool) {
        scrollTopConstraint?.isActive = false
        let top = isSearchShown
            ? scrollView.topAnchor.constraint(equalTo: searchBar.bottomAnchor, constant: 6)
            : scrollView.topAnchor.constraint(equalTo: topContainer.topAnchor)
        top.isActive = true
        scrollTopConstraint = top
    }

    func controlTextDidChange(_ obj: Notification) {
        guard (obj.object as? NSSearchField) === searchBar else { return }
        performFind(term: searchBar.stringValue)
    }

    func control(_ control: NSControl, textView: NSTextView, doCommandBy commandSelector: Selector) -> Bool {
        if commandSelector == #selector(NSResponder.insertNewline(_:)) {
            advanceMatch(forward: true)
            return true
        }
        if commandSelector == #selector(NSResponder.cancelOperation(_:)) {
            clearFind()
            return true
        }
        return false
    }

    private func performFind(term: String) {
        clearMatchHighlights()
        let ns = currentSource as NSString? ?? ""
        let fullRange = NSRange(location: 0, length: ns.length)
        var matches: [NSRange] = []
        if !term.isEmpty {
            var searchRange = fullRange
            while searchRange.location != NSNotFound {
                let found = ns.range(of: term, options: [.caseInsensitive], range: searchRange)
                if found.location == NSNotFound { break }
                matches.append(found)
                let nextLoc = found.location + found.length
                searchRange = NSRange(location: nextLoc, length: ns.length - nextLoc)
            }
        }
        matchRanges = matches
        currentMatchIndex = matches.isEmpty ? -1 : 0
        highlightMatches()
        updateMatchCount()
        if currentMatchIndex >= 0 {
            jumpToMatch(at: currentMatchIndex)
        }
    }

    private func advanceMatch(forward: Bool) {
        guard !matchRanges.isEmpty else { return }
        if forward {
            currentMatchIndex = (currentMatchIndex + 1) % matchRanges.count
        } else {
            currentMatchIndex = (currentMatchIndex - 1 + matchRanges.count) % matchRanges.count
        }
        jumpToMatch(at: currentMatchIndex)
        updateMatchCount()
    }

    private func jumpToMatch(at index: Int) {
        guard index >= 0, index < matchRanges.count else { return }
        let r = matchRanges[index]
        textView.setSelectedRange(r)
        textView.scrollRangeToVisible(r)
    }

    private func highlightMatches() {
        guard let storage = textView.textStorage else { return }
        storage.beginEditing()
        for r in matchRanges {
            storage.addAttribute(.backgroundColor, value: searchIndicatorColor, range: r)
        }
        storage.endEditing()
    }

    private func clearMatchHighlights() {
        guard let storage = textView.textStorage,
              let whole = storage.string as NSString? else { return }
        storage.beginEditing()
        storage.removeAttribute(.backgroundColor, range: NSRange(location: 0, length: whole.length))
        storage.endEditing()
    }

    private func updateMatchCount() {
        if matchRanges.isEmpty {
            matchCountLabel.stringValue = searchBar.stringValue.isEmpty ? "" : "No matches"
        } else {
            matchCountLabel.stringValue = "\(currentMatchIndex + 1)/\(matchRanges.count)"
        }
    }

    private func clearFind() {
        searchBar.stringValue = ""
        matchRanges = []
        currentMatchIndex = -1
        clearMatchHighlights()
        updateMatchCount()
        searchBar.isHidden = true
        matchCountLabel.isHidden = true
        updateScrollTop(isSearchShown: false)
    }

    /// Scrolls the source so the given 1-based line is visible and selects it.
    func scrollToLine(_ line: Int) {
        guard let source = currentSource else { return }
        let ns = source as NSString
        let totalLines = source.components(separatedBy: "\n").count
        let target = min(max(line, 1), totalLines)
        var charIndex = 0
        if target > 1 {
            var currentLine = 1
            var i = 0
            while currentLine < target && i < ns.length {
                if ns.character(at: i) == 10 { currentLine += 1 }
                i += 1
            }
            charIndex = i
        }
        let lineRange = ns.lineRange(for: NSRange(location: charIndex, length: 0))
        if lineRange.length > 0 {
            textView.setSelectedRange(lineRange)
            textView.scrollRangeToVisible(lineRange)
        }
    }

    @objc private func documentScrolled(_ notification: Notification) {
        lineNumberRuler?.needsDisplay = true
        // Debounce cursor-rect recomputation so the pointing hand tracks the
        // numbers without re-enumerating every frame during live scroll.
        let ruler = lineNumberRuler
        scrollSettleTimer?.invalidate()
        let t = Timer(timeInterval: 0.15, repeats: false) { [weak self] _ in
            guard let r = ruler else { return }
            self?.view.window?.invalidateCursorRects(for: r)
        }
        RunLoop.main.add(t, forMode: .common)
        scrollSettleTimer = t
    }

    /// Opens a popover to view/edit the note attached to the given line.
    private func showNotePopover(line: Int) {
        print("DEBUG showNotePopover: line=\(line) currentFileURL?=\(currentFileURL != nil)")
        notePopover?.close()
        guard let file = currentFileURL else { return }

        let fileURL = URL(fileURLWithPath: file.path)
        let controller = NotePopoverController(line: line, filePath: file.path)
        controller.onSave = { [weak self] text in
            NoteStore.shared.setNote(for: fileURL, line: line, text: text)
            self?.lineNumberRuler?.markedLines = NoteStore.shared.lineNumbers(for: fileURL)
            self?.lineNumberRuler?.needsDisplay = true
        }

        let popover = NSPopover()
        popover.behavior = .transient
        popover.contentViewController = controller
        popover.contentSize = NSSize(width: 280, height: 150)

        // Anchor the popover to the text view at the clicked line.
        let charIndex = characterIndex(forLine: line)
        let anchorRange = (textView.string as NSString).lineRange(for: NSRange(location: charIndex, length: 0))
        if let layoutManager = textView.layoutManager,
           let textContainer = textView.textContainer {
            let glyphRect = layoutManager.boundingRect(forGlyphRange: anchorRange, in: textContainer)
            let anchor = textView.convert(glyphRect, from: textView)
            notePopover = popover
            popover.show(relativeTo: anchor, of: textView, preferredEdge: .maxX)
        }
    }

    /// Returns the character index of the start of the given 1-based line.
    private func characterIndex(forLine line: Int) -> Int {
        let text = textView.string as NSString
        var index = 0
        var currentLine = 1
        while currentLine < line && index < text.length {
            if text.character(at: index) == 10 { currentLine += 1 }
            index += 1
        }
        return min(index, text.length)
    }
}

/// A vertical ruler that draws clickable line numbers beside the source text view.
/// AppKit keeps it in sync with the text view's vertical scrolling automatically.
final class LineNumberRulerView: NSRulerView {
    private var gutterWidth: CGFloat = 36

    /// Line numbers that carry a saved note; drawn with a marker and accent color.
    var markedLines: Set<Int> = []
    /// Line numbers flagged as >=80% vulnerable by the ML scan (line -> probability).
    var highRiskLines: [Int: Double] = [:]
    /// Total logical line count, set once when a file loads. Avoids recomputing
    /// (and reallocating) on every cursor-rect recomputation.
    var cachedLineCount: Int = 1
    /// Called when a line number is clicked (passes the 1-based line number).
    var onLineClick: ((Int) -> Void)?

    var gaugeWidth: CGFloat {
        get { gutterWidth }
        set {
            guard gutterWidth != newValue else { return }
            gutterWidth = newValue
            applyGutterSizing()
            // Force the scroll view to re-tile so it reserves the new thickness,
            // repositions the ruler, and insets the document view to match.
            scrollView?.tile()
        }
    }

    private func applyGutterSizing() {
        // NSRulerView sizes itself from its areas; the scroll view reserves
        // `requiredThickness` when tiling and insets the document view by it.
        // Setting ruleThickness (not frame.size.width) keeps the gutter width and
        // the reserved space in sync so the ruler never overlaps the text.
        ruleThickness = max(gutterWidth - reservedThicknessForMarkers, 0)
    }

    override func layout() {
        super.layout()
        ruleThickness = max(gutterWidth - reservedThicknessForMarkers, 0)
    }

    override var isFlipped: Bool { true }

    /// True 1-based logical line number for the line at `charIndex`, computed from
    /// the actual newlines in the source. Robust to scrolling and wrapped lines.
    private func logicalLineNumber(forCharIndex cIndex: Int, textView: NSTextView) -> Int {
        let prefix = textView.string.prefix(cIndex)
        return prefix.reduce(0) { $1 == "\n" ? $0 + 1 : $0 } + 1
    }

    override func draw(_ dirtyRect: NSRect) {
        guard let textView = clientView as? NSTextView,
              let layoutManager = textView.layoutManager,
              let textContainer = textView.textContainer else { return }

        // Fill the full gutter so scrolling never leaves blank streaks.
        NSColor.underPageBackgroundColor.setFill()
        bounds.fill()

        let visibleRect = textView.bounds.intersection(textView.visibleRect)
        let glyphRange = layoutManager.glyphRange(forBoundingRect: visibleRect, in: textContainer)
        if glyphRange.length == 0 { return }

        let paragraphStyle = NSMutableParagraphStyle()
        paragraphStyle.alignment = .right
        paragraphStyle.lineBreakMode = .byClipping

        let attrs: [NSAttributedString.Key: Any] = [
            .font: NSFont.monospacedDigitSystemFont(ofSize: 11, weight: .regular),
            .foregroundColor: NSColor.secondaryLabelColor,
            .paragraphStyle: paragraphStyle
        ]

        // Incremental line counter. Walk fragments FORWARD with
        // lineFragmentRect(forGlyphAt:effectiveRange:), which hands us each
        // fragment's glyph range cheaply — avoiding the very expensive reverse
        // glyphRange(forBoundingRect:) lookup per fragment.
        let ns = textView.string as NSString
        let firstChar = layoutManager.characterIndexForGlyph(at: glyphRange.location)
        let firstPrefix = ns.substring(with: NSRange(location: 0, length: firstChar))
        var currentLine = firstPrefix.reduce(0) { $1 == "\n" ? $0 + 1 : $0 } + 1
        var prevCharIndex = firstChar
        let endGlyph = glyphRange.location + glyphRange.length

        var glyphIndex = glyphRange.location
        while glyphIndex < endGlyph {
            var effRange = NSRange()
            let lineRect = layoutManager.lineFragmentRect(forGlyphAt: glyphIndex, effectiveRange: &effRange)
            if effRange.length == 0 { break }
            let charIndex = layoutManager.characterIndexForGlyph(at: effRange.location)

            if prevCharIndex < charIndex {
                let gap = ns.substring(with: NSRange(location: prevCharIndex, length: charIndex - prevCharIndex))
                currentLine += gap.reduce(0) { $1 == "\n" ? $0 + 1 : $0 }
            }
            prevCharIndex = charIndex

            // Skip continuation fragments of wrapped lines; only the first fragment
            // of each logical line gets a number (and the marker dot).
            if charIndex > 0 && ns.character(at: charIndex - 1) != 0x0A {
                glyphIndex = effRange.location + effRange.length
                continue
            }

            let numberValue = currentLine
            let number = String(numberValue) as NSString
            let size = number.size(withAttributes: attrs)
            // Convert the line's top from text-view coordinates into this ruler's
            // coordinates.
            let p = self.convert(NSPoint(x: 0, y: lineRect.origin.y), from: textView)
            let y = p.y + (lineRect.height - size.height) / 2
            let x = self.bounds.width - size.width - 6

            var color = NSColor.secondaryLabelColor
            if self.markedLines.contains(numberValue) {
                color = .controlAccentColor
                // Small marker dot next to the number.
                let dot = NSBezierPath(ovalIn: NSRect(x: 2, y: y + size.height / 2 - 3, width: 6, height: 6))
                NSColor.controlAccentColor.setFill()
                dot.fill()
            }
            if let prob = self.highRiskLines[numberValue] {
                // Draw a red marker bar on the left edge whose color scales with probability.
                let markerColor = NSColor.systemRed.withAlphaComponent(0.4 + 0.6 * CGFloat(min(max((prob - 0.8) / 0.2, 0.0), 1.0)))
                markerColor.setFill()
                NSRect(x: 0, y: y - 3, width: 3, height: lineRect.height).fill()
                color = .systemRed
            }
            let rich = NSMutableAttributedString(string: number as String, attributes: attrs)
            rich.addAttribute(.foregroundColor, value: color, range: NSRange(location: 0, length: rich.length))
            rich.draw(at: NSPoint(x: x, y: y))

            glyphIndex = effRange.location + effRange.length
        }
    }

    /// Clicking a line number opens a note editor for that line.
    override func mouseDown(with event: NSEvent) {
        guard let textView = clientView as? NSTextView,
              let layoutManager = textView.layoutManager,
              let textContainer = textView.textContainer else { return }

        // Click position in the text view's (document) coordinates, which are
        // scroll-independent. Compared directly against each fragment's
        // lineRect.origin.y, so there is no scroll/flip conversion to get wrong.
        let clickDocY = textView.convert(event.locationInWindow, from: nil).y

        layoutManager.ensureLayout(for: textContainer)
        let fullGlyphRange = layoutManager.glyphRange(for: textContainer)
        if fullGlyphRange.length == 0 { return }

        var hitLine: Int?
        layoutManager.enumerateLineFragments(forGlyphRange: fullGlyphRange) { _, lineRect, _, _, stop in
            if clickDocY >= lineRect.origin.y - 1 && clickDocY < lineRect.origin.y + lineRect.height + 1 {
                let fragGlyphRange = layoutManager.glyphRange(forBoundingRect: lineRect, in: textContainer)
                let charIndex = layoutManager.characterIndexForGlyph(at: fragGlyphRange.location)
                hitLine = self.logicalLineNumber(forCharIndex: charIndex, textView: textView)
                stop.pointee = true
            }
        }
        onLineClick?(hitLine ?? -1)
    }

    /// Show a pointing-hand cursor precisely over each visible line number (and
    /// the marker dot), with the arrow over the empty gutter. Recomputes the
    /// rects from the real number positions so it always lines up.
    override func resetCursorRects() {
        super.resetCursorRects()
        addCursorRect(bounds, cursor: .arrow)

        guard let textView = clientView as? NSTextView,
              let layoutManager = textView.layoutManager,
              let textContainer = textView.textContainer else { return }

        let paragraphStyle = NSMutableParagraphStyle()
        paragraphStyle.alignment = .right
        paragraphStyle.lineBreakMode = .byClipping
        let attrs: [NSAttributedString.Key: Any] = [
            .font: NSFont.monospacedDigitSystemFont(ofSize: 11, weight: .regular),
            .paragraphStyle: paragraphStyle
        ]

        let visibleRect = textView.bounds.intersection(textView.visibleRect)
        let glyphRange = layoutManager.glyphRange(forBoundingRect: visibleRect, in: textContainer)
        if glyphRange.length == 0 { return }

        // All numbers right-align at bounds.width - 6; use the widest number's
        // width (based on total line count) so multi-digit lines are covered too.
        let totalLines = cachedLineCount
        let widest = NSString(string: String(totalLines)).size(withAttributes: attrs).width

        let ns = textView.string as NSString
        let endGlyph = glyphRange.location + glyphRange.length
        var glyphIndex = glyphRange.location
        while glyphIndex < endGlyph {
            var effRange = NSRange()
            let lineRect = layoutManager.lineFragmentRect(forGlyphAt: glyphIndex, effectiveRange: &effRange)
            if effRange.length == 0 { break }
            glyphIndex = effRange.location + effRange.length
            let charIndex = layoutManager.characterIndexForGlyph(at: effRange.location)
            // Only the first fragment of each logical line gets a clickable number.
            if charIndex > 0 && ns.character(at: charIndex - 1) != 0x0A { continue }
            let p = self.convert(NSPoint(x: 0, y: lineRect.origin.y), from: textView)
            let x = self.bounds.width - widest - 6
            let pad: CGFloat = 8
            let handRect = NSRect(x: x - pad, y: p.y - 4,
                                  width: widest + pad * 2, height: lineRect.height + 8)
            self.addCursorRect(handRect, cursor: .pointingHand)
        }
    }
}

/// An NSTextView that lets the controller turn specific character ranges into
/// clickable regions without using NSTextView's `.link` machinery (which slows
/// scrolling on large documents). Mouse clicks over a registered function-name
/// range invoke `onFunctionClick`.
final class ClickableTextView: NSTextView {
    /// Attribute key used to tag clickable function names with their name as the value.
    static let functionNameKey = NSAttributedString.Key("ClickableFunctionName")
    /// Attribute key used to tag clickable class names with their name as the value.
    static let classNameKey = NSAttributedString.Key("ClickableClassName")
    /// Attribute key used to tag a call-site (a *call* of a project-defined
    /// function/method) with the called name as the value. Distinct from
    /// function names so the click handler can tell a call site (→ open the
    /// definition) from a definition site (→ open the dataflow diagram).
    static let callSiteKey = NSAttributedString.Key("ClickableCallSite")

    /// Character ranges (function name) that should trigger `onFunctionClick`.
    var functionRanges: [(name: String, range: NSRange)] = []
    /// Character ranges (class name) that should trigger `onClassClick`.
    var classRanges: [(name: String, range: NSRange)] = []
    /// Character ranges (call site) that should trigger `onCallSiteClick`.
    var callSiteRanges: [(name: String, range: NSRange)] = []
    var onFunctionClick: ((String) -> Void)?
    var onClassClick: ((String) -> Void)?
    /// Called when a *call site* is clicked — passes the called symbol's name.
    var onCallSiteClick: ((String) -> Void)?
    /// Called with the character index under the cursor; returns the type description
    /// to show in the hover tooltip, or nil to hide it. The controller wires this up
    /// to `TypeResolver.type(at:in:language:)` for C/C++/Java files only.
    var typeResolver: ((Int) -> String?)?
    /// The language name currently displayed (e.g. "C", "C++", "Java"); tooltip only
    /// shows when non-nil, so we don't attempt resolution for unsupported languages.
    var typeLanguageName: String?
    private var typePopover: NSPopover?
    private var typeLabel = NSTextField(labelWithString: "")
    /// The last character index for which we resolved + displayed a tooltip; used to
    /// avoid tearing the popover down/recreating it while the cursor lingers on the
    /// same identifier.
    private var lastTypeCharIndex: Int = NSNotFound
    private var wholeViewArea: NSTrackingArea?

    enum ClickTargetKind {
        case function
        case className
        case callSite
    }

    override var isFlipped: Bool { true }

    override func updateTrackingAreas() {
        super.updateTrackingAreas()
        if let old = wholeViewArea {
            removeTrackingArea(old)
        }
        // One tracking area over the whole view; mouseMoved drives the cursor on
        // hover (cursorUpdate does not fire reliably for hovers in NSTextView).
        let area = NSTrackingArea(
            rect: bounds,
            options: [.activeInKeyWindow, .mouseMoved, .inVisibleRect],
            owner: self,
            userInfo: nil
        )
        addTrackingArea(area)
        wholeViewArea = area
    }

    /// Resolves the clickable target at `point` (view coordinates) straight from
    /// the layout manager's current layout. Unlike a cached screen-rect lookup,
    /// this can never go stale: re-wraps, resizes and file switches are picked up
    /// immediately because the layout manager IS the current state.
    private func clickableTarget(at point: NSPoint) -> (kind: ClickTargetKind, name: String)? {
        guard let lm = layoutManager, let tc = textContainer else { return nil }
        let containerPoint = NSPoint(x: point.x - textContainerOrigin.x,
                                     y: point.y - textContainerOrigin.y)
        let glyphIndex = lm.glyphIndex(for: containerPoint, in: tc)
        guard glyphIndex != NSNotFound, glyphIndex < lm.numberOfGlyphs else { return nil }
        var effectiveGlyph = NSRange(location: 0, length: 0)
        let lineRect = lm.lineFragmentRect(forGlyphAt: glyphIndex, effectiveRange: &effectiveGlyph)
        // Small tolerance around the line fragment, mirroring the old rect insets.
        guard lineRect.insetBy(dx: -2, dy: -3).contains(containerPoint) else { return nil }
        let charIndex = lm.characterIndexForGlyph(at: glyphIndex)
        for entry in callSiteRanges where NSLocationInRange(charIndex, entry.range) {
            return (.callSite, entry.name)
        }
        for entry in functionRanges where NSLocationInRange(charIndex, entry.range) {
            return (.function, entry.name)
        }
        for entry in classRanges where NSLocationInRange(charIndex, entry.range) {
            return (.className, entry.name)
        }
        return nil
    }

    private func hasClickableTarget(at point: NSPoint) -> Bool {
        clickableTarget(at: point) != nil
    }

    override func mouseDown(with event: NSEvent) {
        let point = convert(event.locationInWindow, from: nil)
        if let target = clickableTarget(at: point) {
            switch target.kind {
            case .function: onFunctionClick?(target.name)
            case .className: onClassClick?(target.name)
            case .callSite: onCallSiteClick?(target.name)
            }
            return
        }
        super.mouseDown(with: event)
    }

    override func mouseMoved(with event: NSEvent) {
        let point = convert(event.locationInWindow, from: nil)
        // Clickable function/class/method names: don't show the type tooltip there,
        // otherwise the transient popover would consume the next click (dismissing
        // itself) and the click would never reach mouseDown.
        let clickableHit = hasClickableTarget(at: point)
        if clickableHit {
            hideTypeTooltip()
        }
        let typeHit = !clickableHit && updateTypeTooltip(at: point)
        if clickableHit || typeHit {
            NSCursor.pointingHand.set()
        } else {
            super.mouseMoved(with: event)
        }
    }

    /// Resolves the identifier under the cursor and shows/hides the type tooltip.
    /// Returns true if a type tooltip is currently shown for the hovered identifier.
    @discardableResult
    private func updateTypeTooltip(at point: NSPoint) -> Bool {
        guard typeLanguageName != nil, let resolver = typeResolver else {
            hideTypeTooltip()
            return false
        }
        // Find the character under the cursor.
        let layout = layoutManager
        let container = textContainer
        guard let lm = layout, let tc = container else { return false }
        let clampedX = min(max(point.x - textContainerOrigin.x, 0), tc.size.width)
        let clampedY = min(max(point.y - textContainerOrigin.y, 0), max(tc.size.height, 1))
        let containerPoint = NSPoint(x: clampedX, y: clampedY)
        let glyphIndex = lm.glyphIndex(for: containerPoint, in: tc)
        let charIndex = lm.characterIndexForGlyph(at: glyphIndex)

        // Same identifier as last time -> leave the popover alone.
        if charIndex == lastTypeCharIndex && typePopover?.isShown == true { return true }

        guard let text = resolver(charIndex), !text.isEmpty else {
            hideTypeTooltip()
            return false
        }
        lastTypeCharIndex = charIndex
        showTypeTooltip(text, anchorCharIndex: charIndex)
        return true
    }

    private func showTypeTooltip(_ text: String, anchorCharIndex: Int) {
        if typePopover == nil {
            let vc = NSViewController()
            let label = NSTextField(labelWithString: "")
            label.isEditable = false
            label.isBordered = false
            label.drawsBackground = false
            label.lineBreakMode = .byClipping
            label.font = NSFont.monospacedSystemFont(ofSize: 12, weight: .regular)
            label.textColor = .secondaryLabelColor
            label.translatesAutoresizingMaskIntoConstraints = false
            vc.view = NSView()
            vc.view.addSubview(label)
            NSLayoutConstraint.activate([
                label.leadingAnchor.constraint(equalTo: vc.view.leadingAnchor, constant: 10),
                label.trailingAnchor.constraint(equalTo: vc.view.trailingAnchor, constant: -10),
                label.topAnchor.constraint(equalTo: vc.view.topAnchor, constant: 8),
                label.bottomAnchor.constraint(equalTo: vc.view.bottomAnchor, constant: -8)
            ])
            let popover = NSPopover()
            popover.behavior = .transient
            popover.contentViewController = vc
            self.typePopover = popover
            self.typeLabel = label
        }
        typeLabel.stringValue = text

        // Grow the popover horizontally to fit the full type text on one line.
        let font = NSFont.monospacedSystemFont(ofSize: 12, weight: .regular)
        let textWidth = (text as NSString).size(withAttributes: [.font: font]).width
        let popWidth = CGFloat(max(60, Int(ceil(textWidth)) + 20))
        typePopover?.contentSize = NSSize(width: popWidth, height: 34)

        guard let lm = layoutManager, let tc = textContainer else { return }
        let ns = self.string as NSString
        guard anchorCharIndex < ns.length else { return }
        let charRange = NSRange(location: anchorCharIndex, length: 1)
        let glyphRange = lm.glyphRange(forCharacterRange: charRange, actualCharacterRange: nil)
        guard glyphRange.length > 0 else { return }
        var r = lm.boundingRect(forGlyphRange: glyphRange, in: tc)
        r = r.offsetBy(dx: textContainerOrigin.x, dy: textContainerOrigin.y)
        if let popover = typePopover {
            popover.show(relativeTo: r, of: self, preferredEdge: .maxY)
        }
    }

    func hideTypeTooltip() {
        lastTypeCharIndex = NSNotFound
        typePopover?.close()
    }
}

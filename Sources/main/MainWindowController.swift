// by cipher.org.uk
import AppKit

final class MainWindowController: NSWindowController, NSSearchFieldDelegate {
    private let fileTreeViewController = FileTreeViewController()
    private let flowPanel = FlowPanelViewController()
    private var sourceViewer: SourceViewer?
    private var splitView: NSSplitView!
    private var fileSearchController: FileSearchWindowController?
    private var scanController: ScanWindowController?
    private var notesController: NotesWindowController?
    private var wikiController: WikiWindowController?
    private var bugsController: BugListWindowController?
    private var aiController: AIWindowController?
    private var mlTrainController: MLTrainingWindowController?
    private var mlScanController: MLScanWindowController?
    private var classUsageController: ClassUsageWindowController?
    private var backtraceController: BacktraceAnalyserWindowController?
    private var variableFlowController: VariableFlowWindowController?
    private var entryPointsController: EntryPointsWindowController?
    /// Shared reachability window for the "Show reachability of '…'" feature.
    private var reachabilityController: ReachabilityWindowController?
    /// Shared complexity-distribution window for the context-menu chart.
    private var complexityController: ComplexityScatterWindowController?
    /// Cached project-wide call graph for reachability, invalidated when the
    /// project root changes.
    private var reachabilityGraphCache: (root: URL, graph: ProjectCallGraph)?
    /// Cancellation token for the in-flight reachability search, if any.
    private var reachabilityCancellation: VariableFlowCancellation?
    /// Shared dynamic-debugger window for the "Simulate '…' in the Debugger" feature.
    private var simulationController: SimDebugWindowController?
    /// Cached project-wide variable tracer, invalidated when the project root changes.
    private var variableFlowTracerCache: (root: URL, tracer: VariableFlowTracer)?
    /// Cancellation token for the in-flight variable-flow search, if any.
    private var variableFlowCancellation: VariableFlowCancellation?
    /// Load-time, project-wide source index (read + parsed once). Feeds the
    /// call-site popup index and the variable-flow tracer; the security scanner
    /// reuses its walk and file reads.
    private var projectSourceIndexCache: ProjectSourceIndex?
    private var sourceIndexCancellation: VariableFlowCancellation?
    var projectRootURL: URL?
    private var selectedLanguage: Language?
    private var bugBadgeView: BugBadgeView?
    /// Chronological list of files opened in the source viewer. The currently
    /// shown file is `fileHistory[historyIndex]`; entries after it form the
    /// forward stack that is dropped whenever a brand-new file is opened.
    private var fileHistory: [URL] = []
    private var historyIndex: Int = -1
    /// True while a back/forward/menu restore is in flight, so the restored file
    /// isn't pushed onto the history again.
    private var isRestoringHistory = false
    private weak var backHistoryButton: HistoryMenuButton?
    private weak var forwardHistoryButton: HistoryMenuButton?

    private final class BugBadgeView: NSView {
        private let countLabel = NSTextField(labelWithString: "")

        override init(frame: NSRect) {
            super.init(frame: frame)
            setup()
        }

        required init?(coder: NSCoder) {
            super.init(coder: coder)
            setup()
        }

        private func setup() {
            wantsLayer = true
            layer?.backgroundColor = NSColor.systemRed.cgColor
            layer?.cornerRadius = 8
            layer?.borderColor = NSColor.controlBackgroundColor.cgColor
            layer?.borderWidth = 1.5

            countLabel.textColor = .white
            countLabel.font = NSFont.systemFont(ofSize: 10, weight: .semibold)
            countLabel.alignment = .center
            countLabel.maximumNumberOfLines = 1
            countLabel.isBezeled = false
            countLabel.drawsBackground = false
            countLabel.isEditable = false
            countLabel.isSelectable = false
            countLabel.translatesAutoresizingMaskIntoConstraints = false

            addSubview(countLabel)
            NSLayoutConstraint.activate([
                countLabel.centerXAnchor.constraint(equalTo: centerXAnchor),
                countLabel.centerYAnchor.constraint(equalTo: centerYAnchor)
            ])
        }

        func update(count: Int) {
            let hasCount = count > 0
            isHidden = !hasCount
            if hasCount {
                countLabel.stringValue = count > 99 ? "99+" : "\(count)"
            }
        }
    }

    /// Toolbar button whose left click fires `action` on `target`, and whose
    /// press-and-hold (or Control-click) pops up a list of the last several
    /// files opened, letting the user jump straight to one.
    private final class HistoryMenuButton: NSButton {
        /// Builds the menu shown on hold; invoked lazily so it is always fresh.
        var menuProvider: (() -> NSMenu?)?
        private var holdTimer: Timer?
        private var didShowHoldMenu = false

        override func mouseDown(with event: NSEvent) {
            didShowHoldMenu = false
            holdTimer?.invalidate()
            isHighlighted = true
            let holdDuration: TimeInterval = 0.5
            holdTimer = Timer.scheduledTimer(withTimeInterval: holdDuration, repeats: false) { [weak self] _ in
                guard let self, let menu = self.menuProvider?(), !menu.items.isEmpty else { return }
                self.didShowHoldMenu = true
                self.isHighlighted = false
                menu.popUp(positioning: nil, at: NSPoint(x: 0, y: -4), in: self)
            }
        }

        override func mouseUp(with event: NSEvent) {
            let wasHoldMenu = didShowHoldMenu
            holdTimer?.invalidate()
            holdTimer = nil
            isHighlighted = false
            if wasHoldMenu { return }
            // A plain click: dispatch the ordinary action.
            if let action = action, target != nil {
                NSApp.sendAction(action, to: target, from: self)
            }
        }
    }

    convenience init() {
        let window = NSWindow(
            contentRect: NSRect(x: 0, y: 0, width: 1500, height: 820),
            styleMask: [.titled, .closable, .miniaturizable, .resizable],
            backing: .buffered,
            defer: false
        )
        window.title = "Karma Pro"
        // Prevent macOS from restoring a stale, narrow window frame that would crush
        // the source pane.
        window.isRestorable = false
        window.setFrameAutosaveName("")
        window.minSize = NSSize(width: 1280, height: 640)
        window.center()
        self.init(window: window)
        configureToolbar()
        configureContent()
    }

    /// Called after the splash, when the window is actually placed on screen.
    /// Forces a wide frame so the source pane is the largest, overriding any saved
    /// frame that macOS restoration would otherwise apply.
    override func showWindow(_ sender: Any?) {
        super.showWindow(sender)
        forceMainFrame()
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.3) { [weak self] in
            self?.forceMainFrame()
        }
    }

    private func forceMainFrame() {
        guard let window = window else { return }
        window.setFrameAutosaveName("")
        let screenFrame = window.screen?.visibleFrame ?? NSRect(x: 0, y: 0, width: 1400, height: 800)
        let width = min(1500, screenFrame.width)
        let height = min(820, screenFrame.height)
        var f = window.frame
        f.size = NSSize(width: width, height: height)
        guard let screen = window.screen else {
            window.setFrame(f, display: true)
            return
        }
        f.origin.x = screen.visibleFrame.midX - width / 2
        f.origin.y = screen.visibleFrame.midY - height / 2
        window.setFrame(f, display: true)
    }

    private func configureToolbar() {
        let toolbar = NSToolbar(identifier: "MainToolbar")
        toolbar.delegate = self
        toolbar.displayMode = .iconOnly
        window?.toolbar = toolbar
    }

    // MARK: - Project-wide index progress window

    /// Small centered window shown while the load-time project index is built.
    private let indexBuildController = IndexBuildWindowController()

    private func beginIndexProgress(projectName: String) {
        indexBuildController.begin(parent: window, projectName: projectName)
    }

    private func updateIndexProgress(done: Int, total: Int, startedAt: Date) {
        indexBuildController.update(done: done, total: total, startedAt: startedAt)
    }

    private func endIndexProgress() {
        indexBuildController.end()
    }

    /// Builds the project-wide, load-time source index (and the derived call-site
    /// and variable-flow indexes) off the main thread, showing the centered
    /// "Building project's index" window while it runs. Cancelling stops the
    /// work; partial results are discarded so nothing half-indexed is ever
    /// consumed.
    private func buildProjectSourceIndex(for root: URL) {
        sourceIndexCancellation?.cancel()
        let cancellation = VariableFlowCancellation()
        sourceIndexCancellation = cancellation
        let startedAt = Date()

        variableFlowTracerCache = nil
        projectSourceIndexCache = nil
        sourceViewer?.definitionIndex = nil
        beginIndexProgress(projectName: root.lastPathComponent)

        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            let index = ProjectSourceIndex(projectRoot: root,
                                           cancellation: cancellation,
                                           progress: { done, total in
                DispatchQueue.main.async {
                    self?.updateIndexProgress(done: done, total: total, startedAt: startedAt)
                }
            })
            guard let self = self, !index.wasCancelled, !cancellation.isCancelled else {
                DispatchQueue.main.async { self?.endIndexProgress() }
                return
            }

            // Derive the two viewer indexes in memory (no further I/O or parsing).
            let definitionIndex = DefinitionIndex.build(sourceIndex: index)
            let trace = VariableFlowTracer(sourceIndex: index)
            // Pre-build the project call graph in memory so Focus mode (and the
            // first reachability request) resolves directly from the cache without
            // blocking the UI on a first-use derivation.
            let callGraph = ProjectCallGraph(sourceIndex: index)

            DispatchQueue.main.async { [weak self] in
                guard let self = self, !cancellation.isCancelled else { return }
                self.sourceViewer?.definitionIndex = definitionIndex
                self.projectSourceIndexCache = index
                self.variableFlowTracerCache = (root.standardizedFileURL, trace)
                self.reachabilityGraphCache = (root.standardizedFileURL, callGraph)
                self.endIndexProgress()
            }
        }
    }

    private func configureContent() {
        splitView = NSSplitView()
        splitView.isVertical = true
        splitView.dividerStyle = .thin

        // Left: file tree
        let treeView = fileTreeViewController.view

        // Center/middle: source viewer
        let viewer = SourceViewer()
        self.sourceViewer = viewer

        // Right: flow panel (complexity + flowchart)
        let flowView = flowPanel.view

        treeView.translatesAutoresizingMaskIntoConstraints = false
        viewer.view.translatesAutoresizingMaskIntoConstraints = false
        flowView.translatesAutoresizingMaskIntoConstraints = false

        splitView.addArrangedSubview(treeView)
        splitView.addArrangedSubview(viewer.view)
        splitView.addArrangedSubview(flowView)
        // Tree and flow keep fixed widths (high priority); the source pane takes all
        // the remaining space and is the largest pane, never collapsed. All these
        // constraints are non-required so resizing the window is never blocked by
        // an unsolvable layout; the window minSize is what keeps the source wide.
        let treeWidth = treeView.widthAnchor.constraint(equalToConstant: 300)
        treeWidth.priority = NSLayoutConstraint.Priority(500)
        treeWidth.isActive = true
        let flowWidth = flowView.widthAnchor.constraint(equalToConstant: 320)
        flowWidth.priority = NSLayoutConstraint.Priority(500)
        flowWidth.isActive = true
        splitView.setHoldingPriority(NSLayoutConstraint.Priority(261), forSubviewAt: 0)
        splitView.setHoldingPriority(NSLayoutConstraint.Priority(241), forSubviewAt: 1)
        splitView.setHoldingPriority(NSLayoutConstraint.Priority(262), forSubviewAt: 2)
        // Keep the source from collapsing by guaranteeing the window can't get so
        // narrow the source disappears (resizable larger, bounded smaller).
        treeView.widthAnchor.constraint(greaterThanOrEqualToConstant: 220).isActive = true
        flowView.widthAnchor.constraint(greaterThanOrEqualToConstant: 260).isActive = true
        viewer.view.widthAnchor.constraint(greaterThanOrEqualToConstant: 500).isActive = true

        guard let content = window?.contentView else { return }
        content.addSubview(splitView)
        splitView.translatesAutoresizingMaskIntoConstraints = false
        NSLayoutConstraint.activate([
            splitView.topAnchor.constraint(equalTo: content.topAnchor),
            splitView.bottomAnchor.constraint(equalTo: content.bottomAnchor),
            splitView.leadingAnchor.constraint(equalTo: content.leadingAnchor),
            splitView.trailingAnchor.constraint(equalTo: content.trailingAnchor)
        ])
        // Set both dividers so the middle (source) keeps a healthy width.
        DispatchQueue.main.async { [weak self] in
            guard let sv = self?.splitView, sv.subviews.count >= 3 else { return }
            sv.setPosition(300, ofDividerAt: 0)
            sv.setPosition(sv.bounds.width - 320, ofDividerAt: 1)
        }

        fileTreeViewController.onSelectFile = { [weak self] url in
            self?.flowPanel.clear()
            self?.sourceViewer?.display(fileAt: url)
            self?.updateWindowTitle(forFile: url)
            self?.recordHistory(url)
        }

        viewer.onDiagramRequest = { [weak self] fileURL, functionName in
            guard self != nil else { return }
            let windowController = DataFlowWindowController(fileURL: fileURL, functionName: functionName)
            windowController.showWindow(nil)
        }

        viewer.onBacktraceRequest = { [weak self] in
            guard let self = self,
                  let projectRoot = self.projectRootURL else { return }
            let controller = BacktraceAnalyserWindowController(projectRoot: projectRoot) { [weak self] url, line in
                self?.showFile(at: url, line: line)
            }
            self.backtraceController = controller
            controller.showWindow(nil)
        }

        viewer.onVariableFlowRequest = { [weak self] fileURL, charIndex, variableName in
            guard let self = self,
                  let root = self.projectRootURL else { return }
            self.showVariableFlow(projectRoot: root, fileURL: fileURL, charIndex: charIndex, variableName: variableName)
        }

        viewer.onFindEntriesRequest = { [weak self] in
            self?.showFindEntries()
        }

        viewer.onReachabilityRequest = { [weak self] fileURL, functionName in
            guard let self = self,
                  let root = self.projectRootURL else { return }
            self.showReachability(projectRoot: root, fileURL: fileURL, functionName: functionName)
        }

        viewer.onComplexityRequest = { [weak self] _ in
            guard let self = self,
                  let root = self.projectRootURL else { return }
            let controller: ComplexityScatterWindowController
            if let existing = self.complexityController {
                controller = existing
            } else {
                controller = ComplexityScatterWindowController()
                controller.onOpenFile = { [weak self] url, line in
                    self?.showFile(at: url, line: line)
                }
                self.complexityController = controller
            }
            controller.loadProject(root: root)
            controller.showWindow(nil)
            controller.window?.makeKeyAndOrderFront(nil)
            NSApp.activate(ignoringOtherApps: true)
        }

        viewer.onSimulateRequest = { [weak self] fileURL, functionName in
            guard let self = self else { return }
            self.showSimulation(fileURL: fileURL, functionName: functionName)
        }

        viewer.onFunctionSelected = { [weak self] _, functionName, source, ext, definition in
            self?.flowPanel.show(functionName: functionName,
                                 source: source,
                                 fileExtension: ext,
                                 definition: definition)
        }

        viewer.onClassRequest = { [weak self] requestedClassName in
            guard let self = self,
                  let root = self.projectRootURL else { return }
            if self.classUsageController == nil || self.classUsageController!.requestedClass != requestedClassName {
                let controller = ClassUsageWindowController(className: requestedClassName)
                controller.onOpenFile = { [weak self] url, line in
                    self?.showFile(at: url, line: line)
                }
                self.classUsageController = controller
            }
            let controller = self.classUsageController!
            controller.load(root: root)
            controller.showWindow(nil)
            controller.window?.makeKeyAndOrderFront(nil)
            NSApp.activate(ignoringOtherApps: true)
        }

        viewer.onHowToFix = { [weak self] fileURL, line, lineText in
            guard let self = self,
                  let folder = self.projectRootURL else { return }
            let controller: AIWindowController
            if let existing = self.aiController {
                controller = existing
            } else {
                controller = AIWindowController()
                self.aiController = controller
            }
            controller.projectRootURL = folder
            controller.window?.title = "AI Assistant — \(folder.lastPathComponent)"
            controller.showWindow(nil)
            controller.window?.makeKeyAndOrderFront(nil)
            NSApp.activate(ignoringOtherApps: true)
            controller.askHowToFix(fileURL: fileURL, line: line, lineText: lineText)
        }

        // Focus mode: resolve the focused function's direct callers/callees from
        // the project call graph, and let a chip click pivot the review to that
        // function (possibly in another file) while staying focused.
        viewer.tunnelResolver = { [weak self] fileURL, functionName in
            guard let self = self,
                  let root = self.projectRootURL else { return (callers: [], callees: []) }
            let stdRoot = root.standardizedFileURL
            let graph: ProjectCallGraph?
            if let cached = self.reachabilityGraphCache, cached.root == stdRoot {
                graph = cached.graph
            } else if let pidx = self.projectSourceIndexCache, pidx.root == stdRoot {
                let built = ProjectCallGraph(sourceIndex: pidx)
                self.reachabilityGraphCache = (stdRoot, built)
                graph = built
            } else {
                graph = nil
            }
            guard let g = graph else { return (callers: [], callees: []) }
            let stdURL = fileURL.standardizedFileURL
            let ref = g.byName[functionName]?.first(where: { $0.fileURL == stdURL })
                ?? g.byName[functionName]?.first
            let callers: [(URL, String)] = (g.callers[functionName] ?? []).map {
                ($0.fileURL, $0.name)
            }
            var callees: [(URL, String)] = []
            if let ref = ref {
                for edge in g.callees[ref] ?? [] {
                    for c in g.byName[edge.calleeName] ?? [] {
                        callees.append((c.fileURL, c.name))
                    }
                }
            }
            return (callers: callers, callees: callees)
        }
        viewer.onTunnelPivot = { [weak self] url, functionName in
            guard let self = self else { return }
            self.flowPanel.clear()
            self.sourceViewer?.display(fileAt: url)
            self.updateWindowTitle(forFile: url)
            self.recordHistory(url)
            self.sourceViewer?.setFocusMode(functionName: functionName)
        }
    }

    func promptForDirectory() {
        let panel = NSOpenPanel()
        panel.canChooseDirectories = true
        panel.canChooseFiles = false
        panel.allowsMultipleSelection = false
        panel.prompt = "Browse"
        panel.message = "Choose a folder to browse its source code"

        panel.beginSheetModal(for: window!) { [weak self] response in
            guard response == .OK, let url = panel.url else {
                self?.showDirectoryRequiredAlert()
                return
            }
            self?.fileTreeViewController.load(directory: url)
            self?.projectRootURL = url
            self?.window?.representedURL = url
            self?.resetHistory()
            self?.variableFlowCancellation?.cancel()
            self?.variableFlowCancellation = nil
            self?.variableFlowTracerCache = nil
            self?.variableFlowController = nil
            self?.simulationController = nil
            self?.reachabilityCancellation?.cancel()
            self?.reachabilityCancellation = nil
            self?.reachabilityGraphCache = nil
            self?.reachabilityController = nil
            self?.complexityController = nil
            self?.buildProjectSourceIndex(for: url)
            self?.sourceViewer?.clear()
            self?.updateWindowTitle(forFile: nil)
        }
    }

    /// Computes the variable flow on a background queue and shows it in the
    /// project-wide trace window. Reuses the tracer and the window across
    /// requests so a rebuilt graph is cheap. The window opens immediately with a
    /// progress bar while the project is indexed; closing it cancels the search.
    private func showVariableFlow(projectRoot: URL, fileURL: URL, charIndex: Int, variableName: String) {
        // Fast path: the index is already built, so trace and show immediately.
        let stdRoot = projectRoot.standardizedFileURL
        if let cached = variableFlowTracerCache, cached.root == stdRoot {
            DispatchQueue.global(qos: .userInitiated).async { [weak self] in
                let result = cached.tracer.trace(variableName: variableName, in: fileURL, charIndex: charIndex)
                DispatchQueue.main.async {
                    self?.presentVariableFlow(result: result, variableName: variableName)
                }
            }
            return
        }

        // If the shared source index already exists for this root, derive the
        // tracer in memory (no further I/O, just parameter scanning) and
        // display the result directly without opening a separate progress
        // window.
        if let pidx = projectSourceIndexCache, pidx.root == stdRoot {
            let tracer = VariableFlowTracer(sourceIndex: pidx)
            variableFlowTracerCache = (stdRoot, tracer)
            DispatchQueue.global(qos: .userInitiated).async { [weak self] in
                let result = tracer.trace(variableName: variableName, in: fileURL, charIndex: charIndex)
                DispatchQueue.main.async {
                    self?.presentVariableFlow(result: result, variableName: variableName)
                }
            }
            return
        }

        // Last resort: build the index on demand from disk with its own
        // progress window, so the user still gets feedback.
        // Supersede any search that is already running.
        variableFlowCancellation?.cancel()
        let cancellation = VariableFlowCancellation()
        variableFlowCancellation = cancellation
        let startedAt = Date()

        let controller = variableFlowControllerInstance()
        controller.onCancel = { [weak self] in self?.variableFlowCancellation?.cancel() }
        controller.beginProgress(variableName: variableName)
        controller.showWindow(nil)
        controller.window?.makeKeyAndOrderFront(nil)
        NSApp.activate(ignoringOtherApps: true)

        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            let tracer = VariableFlowTracer(projectRoot: projectRoot,
                                            cancellation: cancellation,
                                            progress: { done, total in
                DispatchQueue.main.async {
                    controller.updateProgress(done: done, total: total, startedAt: startedAt)
                }
            })
            guard !cancellation.isCancelled, !tracer.wasCancelled else { return }
            let result = tracer.trace(variableName: variableName, in: fileURL, charIndex: charIndex)
            guard !cancellation.isCancelled else { return }
            DispatchQueue.main.async {
                guard let self = self, !cancellation.isCancelled else { return }
                self.variableFlowTracerCache = (projectRoot, tracer)
                self.variableFlowCancellation = nil
                controller.onCancel = nil
                controller.display(result: result, variableName: variableName)
            }
        }
    }

    /// Opens (or reuses) the "Find external entries" window and starts the project-wide
    /// entry-point enumeration. Reuses the shared source index when one exists;
    /// otherwise the window builds its own index with progress shown.
    private func showFindEntries() {
        guard let folder = projectRootURL else {
            let alert = NSAlert()
            alert.messageText = "No Folder Open"
            alert.informativeText = "Open a source folder before finding entry points."
            alert.addButton(withTitle: "Open Folder")
            alert.addButton(withTitle: "Cancel")
            if alert.runModal() == .alertFirstButtonReturn { promptForDirectory() }
            return
        }
        let controller: EntryPointsWindowController
        if let existing = entryPointsController {
            controller = existing
        } else {
            let created = EntryPointsWindowController()
            created.onOpenLocation = { [weak self] url, line in
                self?.showFile(at: url, line: line)
            }
            entryPointsController = created
            controller = created
        }
        controller.showWindow(nil)
        controller.window?.makeKeyAndOrderFront(nil)
        NSApp.activate(ignoringOtherApps: true)
        let stdRoot = folder.standardizedFileURL
        let index = (projectSourceIndexCache?.root == stdRoot) ? projectSourceIndexCache : nil
        controller.begin(projectRoot: stdRoot, sourceIndex: index)
    }

    /// Returns the shared variable-flow window, creating and wiring it if needed.
    private func variableFlowControllerInstance() -> VariableFlowWindowController {
        if let existing = variableFlowController { return existing }
        let controller = VariableFlowWindowController()
        controller.onOpenLocation = { [weak self] url, line in
            self?.showFile(at: url, line: line)
        }
        variableFlowController = controller
        return controller
    }

    /// Presents a finished trace in the (possibly new) shared window.
    private func presentVariableFlow(result: VariableFlowResult, variableName: String) {
        let controller = variableFlowControllerInstance()
        controller.onCancel = nil
        controller.display(result: result, variableName: variableName)
        controller.showWindow(nil)
        controller.window?.makeKeyAndOrderFront(nil)
        NSApp.activate(ignoringOtherApps: true)
    }

    /// Returns the shared reachability window, creating and wiring it if needed.
    private func reachabilityControllerInstance() -> ReachabilityWindowController {
        if let existing = reachabilityController { return existing }
        let controller = ReachabilityWindowController()
        controller.onOpenLocation = { [weak self] url, line in
            self?.showFile(at: url, line: line)
        }
        reachabilityController = controller
        return controller
    }

    /// Presents a finished reachability walk in the (possibly new) shared window.
    private func presentReachability(result: ReachabilityResult,
                                     graph: ProjectCallGraph,
                                     fileURL: URL,
                                     functionName: String) {
        let controller = reachabilityControllerInstance()
        controller.onCancel = nil
        controller.display(result: result, graph: graph, fileURL: fileURL, functionName: functionName)
        // If the user closed the window while the walk ran, don't surprise them
        // by reopening it — the cached graph makes a repeat request instant.
        guard controller.window?.isVisible == true else { return }
        controller.showWindow(nil)
        controller.window?.makeKeyAndOrderFront(nil)
        NSApp.activate(ignoringOtherApps: true)
    }

    /// Shows the project-wide reachability of a function right-clicked in the
    /// source viewer. The window is shown immediately with an "Analysing"
    /// spinner (reachability walks can be slow on large projects, so they must
    /// not block or look like a hang), then the graph is reused or built in the
    /// background and the result is rendered when ready.
    private func showReachability(projectRoot: URL, fileURL: URL, functionName: String) {
        let stdRoot = projectRoot.standardizedFileURL

        // Show the window with a spinner right away; every path below replaces
        // it with the finished diagram. Keeps a large-project walk from freezing
        // the UI while the reachability analysis runs in the background.
        let controller = reachabilityControllerInstance()
        controller.showWindow(nil)
        controller.window?.makeKeyAndOrderFront(nil)
        NSApp.activate(ignoringOtherApps: true)

        // Fast path: the call graph is already built, so walk and show immediately.
        if let cached = reachabilityGraphCache, cached.root == stdRoot {
            controller.onCancel = nil
            controller.beginAnalysis(functionName: functionName)
            DispatchQueue.global(qos: .userInitiated).async { [weak self] in
                let result = cached.graph.reachability(of: functionName, in: fileURL)
                DispatchQueue.main.async {
                    self?.presentReachability(result: result, graph: cached.graph,
                                              fileURL: fileURL, functionName: functionName)
                }
            }
            return
        }

        // If the shared source index already exists for this root, derive the
        // call graph in memory (no further I/O) and display the result directly.
        if let pidx = projectSourceIndexCache, pidx.root == stdRoot {
            controller.onCancel = nil
            controller.beginAnalysis(functionName: functionName)
            DispatchQueue.global(qos: .userInitiated).async { [weak self] in
                let graph = ProjectCallGraph(sourceIndex: pidx)
                let result = graph.reachability(of: functionName, in: fileURL)
                DispatchQueue.main.async {
                    guard let self = self else { return }
                    self.reachabilityGraphCache = (stdRoot, graph)
                    self.presentReachability(result: result, graph: graph,
                                             fileURL: fileURL, functionName: functionName)
                }
            }
            return
        }

        // Last resort: build the index on demand from disk. The spinner stays up
        // while the graph is built; once built, switch to an indeterminate
        // spinner since the reachability walk itself has no unit-of-work.
        reachabilityCancellation?.cancel()
        let cancellation = VariableFlowCancellation()
        reachabilityCancellation = cancellation
        let startedAt = Date()

        controller.onCancel = { [weak self] in self?.reachabilityCancellation?.cancel() }
        controller.beginProgress(functionName: functionName)

        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            let graph = ProjectCallGraph(projectRoot: projectRoot,
                                         cancellation: cancellation,
                                         progress: { done, total in
                DispatchQueue.main.async {
                    controller.updateProgress(done: done, total: total, startedAt: startedAt)
                }
            })
            guard !cancellation.isCancelled, !graph.wasCancelled else { return }
            // The disk read is done; switch to the indeterminate spinner while
            // the reachability walk (the slow part on big projects) runs.
            DispatchQueue.main.async {
                controller.beginAnalysis(functionName: functionName)
            }
            let result = graph.reachability(of: functionName, in: fileURL)
            guard !cancellation.isCancelled else { return }
            DispatchQueue.main.async {
                guard let self = self, !cancellation.isCancelled else { return }
                self.reachabilityGraphCache = (stdRoot, graph)
                self.reachabilityCancellation = nil
                controller.onCancel = nil
                controller.display(result: result, graph: graph,
                                   fileURL: fileURL, functionName: functionName)
            }
        }
    }

    private func showDirectoryRequiredAlert() {
        let alert = NSAlert()
        alert.messageText = "No Folder Selected"
        alert.informativeText = "A folder is required to browse source code."
        alert.addButton(withTitle: "Choose Folder")
        alert.addButton(withTitle: "Quit")
        alert.addButton(withTitle: "Cancel")
        NSApp.activate(ignoringOtherApps: true)
        let response = alert.runModal()
        // First button: open the folder chooser again. Third button: dismiss the
        // dialog and leave the app running without a folder.
        if response == .alertFirstButtonReturn {
            promptForDirectory()
        } else if response == .alertSecondButtonReturn {
            NSApp.terminate(nil)
        }
        // Otherwise (Cancel) do nothing and keep the app alive.
    }
}

extension NSToolbarItem.Identifier {
    static let toggleSidebar = NSToolbarItem.Identifier("toggleSidebar")
    static let openFolder = NSToolbarItem.Identifier("openFolder")
    static let historyBack = NSToolbarItem.Identifier("historyBack")
    static let historyForward = NSToolbarItem.Identifier("historyForward")
    static let historyGroup = NSToolbarItem.Identifier("historyGroup")
    static let search = NSToolbarItem.Identifier("search")
    static let language = NSToolbarItem.Identifier("language")
    static let findInFile = NSToolbarItem.Identifier("findInFile")
    static let searchFiles = NSToolbarItem.Identifier("searchFiles")
    static let securityScan = NSToolbarItem.Identifier("securityScan")
    static let notes = NSToolbarItem.Identifier("notes")
    static let wiki = NSToolbarItem.Identifier("wiki")
    static let bugs = NSToolbarItem.Identifier("bugs")
    static let ai = NSToolbarItem.Identifier("ai")
    static let mlTrain = NSToolbarItem.Identifier("mlTrain")
    static let mlScan = NSToolbarItem.Identifier("mlScan")
}

extension MainWindowController: NSToolbarDelegate {
    func toolbarDefaultItemIdentifiers(_ toolbar: NSToolbar) -> [NSToolbarItem.Identifier] {
        return [.historyGroup, .openFolder, .toggleSidebar, .language, .findInFile, .searchFiles, .search, .flexibleSpace, .securityScan, .mlTrain, .mlScan, .notes, .wiki, .bugs, .ai]
    }

    func toolbarAllowedItemIdentifiers(_ toolbar: NSToolbar) -> [NSToolbarItem.Identifier] {
        return [.historyGroup, .openFolder, .toggleSidebar, .language, .findInFile, .searchFiles, .securityScan, .mlTrain, .mlScan, .notes, .wiki, .bugs, .ai, .flexibleSpace, .search]
    }

    func toolbar(_ toolbar: NSToolbar, itemForItemIdentifier itemIdentifier: NSToolbarItem.Identifier, willBeInsertedIntoToolbar flag: Bool) -> NSToolbarItem? {
        switch itemIdentifier {
        case .historyBack, .historyForward:
            return makeHistoryToolbarItem(identifier: itemIdentifier)
        case .historyGroup:
            return makeHistoryToolbarGroup()
        case .openFolder:
            let item = NSToolbarItem(itemIdentifier: itemIdentifier)
            item.label = "Open Folder"
            item.toolTip = "Open a source code folder to browse"
            item.image = NSImage(systemSymbolName: "folder", accessibilityDescription: "Open folder")
            item.isBordered = true
            item.target = self
            item.action = #selector(openFolderClicked)
            return item
        case .toggleSidebar:
            let item = NSToolbarItem(itemIdentifier: itemIdentifier)
            item.label = "Toggle Sidebar"
            item.toolTip = "Show or hide the file sidebar"
            item.image = NSImage(systemSymbolName: "sidebar.left", accessibilityDescription: "Toggle sidebar")
            item.isBordered = true
            item.target = self
            item.action = #selector(toggleSidebar)
            return item
        case .language:
            let item = NSToolbarItem(itemIdentifier: itemIdentifier)
            item.label = "Language"
            item.view = makeLanguagePopup()
            return item
        case .search:
            let item = NSSearchToolbarItem(itemIdentifier: itemIdentifier)
            item.searchField.delegate = self
            item.label = "Search"
            item.searchField.placeholderString = "Find files…"
            return item
        case .findInFile:
            let item = NSToolbarItem(itemIdentifier: itemIdentifier)
            item.label = "Find in File"
            item.toolTip = "Find text within the current file"
            item.image = NSImage(systemSymbolName: "text.magnifyingglass", accessibilityDescription: "Find in file")
            item.isBordered = true
            item.target = self
            item.action = #selector(findInFileClicked)
            return item
        case .searchFiles:
            let item = NSToolbarItem(itemIdentifier: itemIdentifier)
            item.label = "Search in Files"
            item.toolTip = "Search text across all files in the project"
            item.image = NSImage(systemSymbolName: "doc.text.magnifyingglass", accessibilityDescription: "Search all files")
            item.isBordered = true
            item.target = self
            item.action = #selector(searchFilesClicked)
            return item
        case .securityScan:
            let item = NSToolbarItem(itemIdentifier: itemIdentifier)
            item.label = "Security Scan"
            item.toolTip = "Scan the project for common vulnerabilities"
            let baseImage = NSImage(systemSymbolName: "shield.lefthalf.filled", accessibilityDescription: "Scan project for vulnerabilities")
            item.image = tintedImage(baseImage, with: .systemRed)
            item.isBordered = true
            item.target = self
            item.action = #selector(securityScanClicked)
            return item
        case .notes:
            let item = NSToolbarItem(itemIdentifier: itemIdentifier)
            item.label = "Notes"
            item.toolTip = "Show all notes and go to their locations"
            let baseImage = NSImage(systemSymbolName: "note.text", accessibilityDescription: "Show all notes for this project")
            item.image = tintedImage(baseImage, with: .systemOrange)
            item.isBordered = true
            item.target = self
            item.action = #selector(notesClicked)
            return item
        case .wiki:
            let item = NSToolbarItem(itemIdentifier: itemIdentifier)
            item.label = "Wiki"
            item.toolTip = "Open the private research wiki"
            let baseImage = NSImage(systemSymbolName: "books.vertical", accessibilityDescription: "Open the private research wiki")
            item.image = tintedImage(baseImage, with: .systemPurple)
            item.isBordered = true
            item.target = self
            item.action = #selector(wikiClicked)
            return item
        case .bugs:
            let item = NSToolbarItem(itemIdentifier: itemIdentifier)
            item.label = "Bugs"
            item.toolTip = "Open the bug tracker to view, search, and create bug reports"

            let button = NSButton()
            button.bezelStyle = .rounded
            button.image = tintedImage(NSImage(systemSymbolName: "ladybug", accessibilityDescription: "Bug tracker"), with: .systemGreen)
            button.imagePosition = .imageOnly
            button.isBordered = true
            button.target = self
            button.action = #selector(bugsClicked)
            button.toolTip = item.toolTip

            let badge = BugBadgeView()
            badge.translatesAutoresizingMaskIntoConstraints = false
            button.addSubview(badge)
            NSLayoutConstraint.activate([
                badge.topAnchor.constraint(equalTo: button.topAnchor, constant: -6),
                badge.trailingAnchor.constraint(equalTo: button.trailingAnchor, constant: 6),
                badge.widthAnchor.constraint(equalToConstant: 18),
                badge.heightAnchor.constraint(equalToConstant: 18)
            ])

            self.bugBadgeView = badge
            item.view = button
            updateBugBadge()
            NotificationCenter.default.addObserver(self, selector: #selector(updateBugBadge),
                                                   name: .bugStoreDidChange, object: nil)
            return item
        case .ai:
            let item = NSToolbarItem(itemIdentifier: itemIdentifier)
            item.label = "AI"
            item.toolTip = "Open the AI assistant for the current project"
            let baseImage = NSImage(systemSymbolName: "sparkles", accessibilityDescription: "AI assistant")
            item.image = tintedImage(baseImage, with: .systemIndigo)
            item.isBordered = true
            item.target = self
            item.action = #selector(aiClicked)
            return item
        case .mlTrain:
            let item = NSToolbarItem(itemIdentifier: itemIdentifier)
            item.label = "Train ML"
            item.toolTip = "Train the Bayesian classifier from patch files"
            let baseImage = NSImage(systemSymbolName: "brain.head.profile", accessibilityDescription: "Train Bayesian classifier from patches")
            item.image = tintedImage(baseImage, with: .systemPurple)
            item.isBordered = true
            item.target = self
            item.action = #selector(mlTrainClicked)
            return item
        case .mlScan:
            let item = NSToolbarItem(itemIdentifier: itemIdentifier)
            item.label = "ML Scan"
            item.toolTip = "Scan the project with a trained model and highlight risky lines"
            let baseImage = NSImage(systemSymbolName: "scope", accessibilityDescription: "Scan project with a trained model")
            item.image = tintedImage(baseImage, with: .systemTeal)
            item.isBordered = true
            item.target = self
            item.action = #selector(mlScanClicked)
            return item
        default:
            return nil
        }
    }

    /// Builds a single back/forward toolbar button. A click navigates; a
    /// press-and-hold pops up the recent-files menu.
    private func makeHistoryToolbarItem(identifier: NSToolbarItem.Identifier) -> NSToolbarItem {
        let item = NSToolbarItem(itemIdentifier: identifier)
        let button = buttonForHistoryItem(identifier: identifier)
        if identifier == .historyBack {
            item.label = "Back"
            item.toolTip = "Go to the previously opened file (hold to choose)"
            button.toolTip = "Go back (hold for recent files)"
            item.image = NSImage(systemSymbolName: "chevron.left", accessibilityDescription: "Go back")
            item.action = #selector(goBackInHistory)
            self.backHistoryButton = button
        } else {
            item.label = "Forward"
            item.toolTip = "Go to the next opened file (hold to choose)"
            button.toolTip = "Go forward (hold for recent files)"
            item.image = NSImage(systemSymbolName: "chevron.right", accessibilityDescription: "Go forward")
            item.action = #selector(goForwardInHistory)
            self.forwardHistoryButton = button
        }
        button.target = self
        button.action = identifier == .historyBack ? #selector(goBackInHistory) : #selector(goForwardInHistory)
        button.menuProvider = { [weak self] in self?.historyMenu() }
        item.isBordered = true
        item.view = button
        updateHistoryButtonStates()
        return item
    }

    /// Groups Back + Forward into a single segmented toolbar control so they
    /// sit together as one unit on the left of "Open Folder".
    private func makeHistoryToolbarGroup() -> NSToolbarItemGroup {
        let back = makeHistoryToolbarItem(identifier: .historyBack)
        let forward = makeHistoryToolbarItem(identifier: .historyForward)
        let group = NSToolbarItemGroup(itemIdentifier: .historyGroup)
        group.label = "History"
        group.toolTip = "Navigate between recently opened files"
        group.subitems = [back, forward]
        group.controlRepresentation = .expanded
        return group
    }

    /// Creates the custom bordered button view backing a history toolbar item.
    private func buttonForHistoryItem(identifier: NSToolbarItem.Identifier) -> HistoryMenuButton {
        let button = HistoryMenuButton()
        button.bezelStyle = .texturedRounded
        button.imagePosition = .imageOnly
        button.isBordered = true
        button.image = NSImage(systemSymbolName: identifier == .historyBack ? "chevron.left" : "chevron.right",
                               accessibilityDescription: nil)
        return button
    }

    private func makeLanguagePopup() -> NSView {
        let popup = NSPopUpButton(frame: NSRect(x: 0, y: 0, width: 200, height: 26), pullsDown: false)
        popup.addItems(withTitles: Language.supported.map { $0.name })
        popup.target = self
        popup.action = #selector(languageChanged(_:))
        return popup
    }

    /// Returns a copy of `image` tinted red with a black outline, for the red/black
    /// security scan toolbar button.
    private func tintedImage(_ image: NSImage?, with tint: NSColor) -> NSImage? {
        guard let image = image else { return nil }
        let size = image.size
        let result = NSImage(size: size)
        result.lockFocus()
        let rect = NSRect(origin: .zero, size: size)
        // Black border/outline ring behind the icon.
        NSColor.black.setStroke()
        let ring = NSBezierPath(ovalIn: rect.insetBy(dx: 0.5, dy: 0.5))
        ring.lineWidth = 2
        ring.stroke()
        // Draw the icon tinted red.
        image.draw(in: rect, from: .zero, operation: .sourceOver, fraction: 1.0)
        tint.setFill()
        rect.fill(using: .sourceAtop)
        result.unlockFocus()
        return result
    }

    @objc private func languageChanged(_ sender: NSPopUpButton) {
        let name = sender.titleOfSelectedItem ?? ""
        let lang: Language?
        if name == "All Languages" {
            lang = nil
        } else {
            lang = Language.supported.first { $0.name == name }
        }
        selectedLanguage = lang
        fileTreeViewController.selectedLanguage = lang
    }

    @objc private func openFolderClicked() {
        promptForDirectory()
    }

    @objc private func toggleSidebar() {
        let treeView = fileTreeViewController.view
        treeView.isHidden.toggle()
    }

    @objc private func findInFileClicked() {
        sourceViewer?.activateFind()
    }

    @objc private func searchFilesClicked() {
        let controller = FileSearchWindowController(folderURL: projectRootURL, language: selectedLanguage)
        controller.onOpenResult = { [weak self] url, line in
            self?.showFile(at: url, line: line)
        }
        fileSearchController = controller
        controller.showWindow(nil)
        controller.window?.makeKeyAndOrderFront(nil)
        NSApp.activate(ignoringOtherApps: true)
    }

    /// Loads a file in the source viewer and scrolls to the given 1-based line.
    private func showFile(at url: URL, line: Int) {
        flowPanel.clear()
        sourceViewer?.display(fileAt: url)
        sourceViewer?.scrollToLine(line)
        updateWindowTitle(forFile: url)
        recordHistory(url)
    }

    /// Discards all history (used when opening a brand-new folder).
    private func resetHistory() {
        fileHistory.removeAll()
        historyIndex = -1
        updateHistoryButtonStates()
    }

    /// Adds a file to the browser-style open history unless it equals the
    /// current entry. Opening anything new discards the forward stack.
    private func recordHistory(_ url: URL) {
        guard !isRestoringHistory else { return }
        if historyIndex >= 0, historyIndex < fileHistory.count,
           fileHistory[historyIndex].standardizedFileURL == url.standardizedFileURL {
            return
        }
        if historyIndex < fileHistory.count - 1 {
            fileHistory.removeSubrange((historyIndex + 1)...)
        }
        fileHistory.append(url)
        historyIndex = fileHistory.count - 1
        updateHistoryButtonStates()
    }

    /// Jumps to a specific history entry (from the press-and-hold menu),
    /// dropping the forward stack past that point like a browser.
    @objc private func goBackInHistory() {
        navigateHistory(by: -1)
    }

    @objc private func goForwardInHistory() {
        navigateHistory(by: 1)
    }

    private func navigateHistory(by delta: Int) {
        let target = historyIndex + delta
        guard !fileHistory.isEmpty, (0..<fileHistory.count).contains(target) else { return }
        historyIndex = target
        isRestoringHistory = true
        showFile(at: fileHistory[historyIndex], line: 1)
        isRestoringHistory = false
        updateHistoryButtonStates()
    }

    @objc private func historyMenuChosen(_ sender: NSMenuItem) {
        guard let index = sender.representedObject as? Int, (0..<fileHistory.count).contains(index) else { return }
        historyIndex = index
        if historyIndex < fileHistory.count - 1 {
            fileHistory.removeSubrange((historyIndex + 1)...)
        }
        isRestoringHistory = true
        showFile(at: fileHistory[historyIndex], line: 1)
        isRestoringHistory = false
        updateHistoryButtonStates()
    }

    /// Menu shown on press-and-hold: the last 10 files opened, most recent
    /// first, taken from the whole history (including any forward entries).
    /// Choosing one jumps to it and, like a browser, discards everything after.
    private func historyMenu() -> NSMenu {
        let menu = NSMenu()
        let shown = min(fileHistory.count, 10)
        guard shown > 0 else {
            menu.addItem(withTitle: "No Files Opened Yet", action: nil, keyEquivalent: "")
            return menu
        }
        for i in stride(from: fileHistory.count - 1, through: fileHistory.count - shown, by: -1) {
            let url = fileHistory[i]
            let item = NSMenuItem(title: url.lastPathComponent, action: #selector(historyMenuChosen(_:)), keyEquivalent: "")
            item.target = self
            item.representedObject = i
            item.toolTip = url.path
            menu.addItem(item)
        }
        return menu
    }

    private func updateHistoryButtonStates() {
        backHistoryButton?.isEnabled = historyIndex > 0 && !fileHistory.isEmpty
        forwardHistoryButton?.isEnabled = (historyIndex >= 0 && historyIndex < fileHistory.count - 1)
    }

    /// Opens the dynamic-debugger simulation window for a function in a project
    /// file clicked via the "Simulate '…' in the Debugger" context-menu item.
    private func showSimulation(fileURL: URL, functionName: String) {
        if simulationController == nil {
            let controller = SimDebugWindowController(
                sourceIndex: projectSourceIndexCache,
                fileURL: fileURL,
                functionName: functionName
            )
            controller.onOpenFile = { [weak self] url, line in
                self?.showFile(at: url, line: line)
            }
            controller.onFinished = { [weak self] in
                self?.simulationController = nil
            }
            simulationController = controller
        } else {
            simulationController?.reload(fileURL: fileURL, functionName: functionName)
        }
        simulationController?.showWindow(nil)
        simulationController?.window?.makeKeyAndOrderFront(nil)
    }

    /// Sets the window title to "<project> Project" with the currently-open file's
    /// name shown in parentheses next to "Project", e.g. "MyApp Project (App.java)".
    /// The represented URL tracks the open file so the title bar offers a tooltip
    /// (and Command-click path menu) with the full file path; with no file open it
    /// falls back to the project root.
    private func updateWindowTitle(forFile url: URL?) {
        let projectName = projectRootURL?.lastPathComponent ?? "Project"
        if let fileURL = url {
            window?.title = "\(projectName) Project (\(fileURL.lastPathComponent))"
        } else {
            window?.title = "\(projectName) Project"
        }
        window?.representedURL = url ?? projectRootURL
    }

    @objc private func securityScanClicked() {
        guard let folder = projectRootURL else {
            let alert = NSAlert()
            alert.messageText = "No Folder Open"
            alert.informativeText = "Open a source folder before running a security scan."
            alert.addButton(withTitle: "Open Folder")
            alert.addButton(withTitle: "Cancel")
            let response = alert.runModal()
            if response == .alertFirstButtonReturn {
                promptForDirectory()
            }
            return
        }

        let controller: ScanWindowController
        if let existing = scanController {
            controller = existing
        } else {
            controller = ScanWindowController()
            controller.onOpenResult = { [weak self] url, line in
                self?.showFile(at: url, line: line)
            }
            scanController = controller
        }
        controller.sourceIndex = projectSourceIndexCache
        controller.showWindow(nil)
        controller.window?.makeKeyAndOrderFront(nil)
        NSApp.activate(ignoringOtherApps: true)
        controller.load(folder: folder)
    }

    @objc private func notesClicked() {
        let controller: NotesWindowController
        if let existing = notesController {
            controller = existing
        } else {
            controller = NotesWindowController()
            controller.onOpenNote = { [weak self] path, line in
                let url = URL(fileURLWithPath: path)
                self?.showFile(at: url, line: line)
            }
            notesController = controller
        }
        controller.projectRootURL = projectRootURL
        controller.reloadNotes()
        controller.showWindow(nil)
        controller.window?.makeKeyAndOrderFront(nil)
        NSApp.activate(ignoringOtherApps: true)
        if let folder = projectRootURL {
            controller.window?.title = "Notes — \((folder as NSURL).lastPathComponent ?? "")"
        }
    }

    @objc private func bugsClicked() {
        openBugVault()
    }

    @objc private func wikiClicked() {
        let controller: WikiWindowController
        if let existing = wikiController {
            controller = existing
        } else {
            controller = WikiWindowController()
            wikiController = controller
        }
        controller.reload()
        controller.showWindow(nil)
        controller.window?.makeKeyAndOrderFront(nil)
        NSApp.activate(ignoringOtherApps: true)
    }

    @objc private func updateBugBadge() {
        BugStore.shared.reload()
        let openStatuses: Set<String> = ["Open", "In Progress"]
        let count = BugStore.shared.allBugs().filter { openStatuses.contains($0.status) }.count
        bugBadgeView?.update(count: count)
    }

    @objc private func aiClicked() {
        guard let folder = projectRootURL else {
            let alert = NSAlert()
            alert.messageText = "No Project Selected"
            alert.informativeText = "You need to first select a project before using the AI assistant."
            alert.addButton(withTitle: "Open Folder")
            alert.addButton(withTitle: "Cancel")
            NSApp.activate(ignoringOtherApps: true)
            let response = alert.runModal()
            if response == .alertFirstButtonReturn {
                promptForDirectory()
            }
            return
        }

        let controller: AIWindowController
        if let existing = aiController {
            controller = existing
        } else {
            controller = AIWindowController()
            aiController = controller
        }
        controller.projectRootURL = folder
        controller.window?.title = "AI Assistant — \(folder.lastPathComponent)"
        controller.showWindow(nil)
        controller.window?.makeKeyAndOrderFront(nil)
        NSApp.activate(ignoringOtherApps: true)
    }

    private func openBugVault() {
        BugStore.shared.reload()
        let controller: BugListWindowController
        if let existing = bugsController {
            controller = existing
        } else {
            controller = BugListWindowController()
            bugsController = controller
        }
        controller.reload()
        controller.showWindow(nil)
        controller.window?.makeKeyAndOrderFront(nil)
        NSApp.activate(ignoringOtherApps: true)
    }

    @objc private func mlTrainClicked() {
        if let existing = mlTrainController {
            existing.showWindow(nil)
            existing.window?.makeKeyAndOrderFront(nil)
            NSApp.activate(ignoringOtherApps: true)
            return
        }
        let controller = MLTrainingWindowController()
        mlTrainController = controller
        controller.showWindow(nil)
        controller.window?.makeKeyAndOrderFront(nil)
        NSApp.activate(ignoringOtherApps: true)
    }

    @objc private func mlScanClicked() {
        let folder = projectRootURL
        guard folder != nil else {
            let alert = NSAlert()
            alert.messageText = "No Folder Open"
            alert.informativeText = "Open a source folder before running an ML scan."
            alert.addButton(withTitle: "OK")
            alert.runModal()
            return
        }
        let controller = MLScanWindowController(projectRoot: folder)
        controller.onScanFinished = { [weak self] in
            self?.sourceViewer?.refreshVulnerabilityHighlights()
        }
        controller.onOpenFile = { [weak self] url in
            self?.showFile(at: url, line: 1)
        }
        mlScanController = controller
        controller.showWindow(nil)
        controller.window?.makeKeyAndOrderFront(nil)
        NSApp.activate(ignoringOtherApps: true)
    }

    func controlTextDidChange(_ obj: Notification) {
        guard let field = obj.object as? NSSearchField else { return }
        fileTreeViewController.filter(query: field.stringValue)
    }
}

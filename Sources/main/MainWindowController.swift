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
            let tracer = VariableFlowTracer(sourceIndex: index)

            DispatchQueue.main.async { [weak self] in
                guard let self = self, !cancellation.isCancelled else { return }
                self.sourceViewer?.definitionIndex = definitionIndex
                self.projectSourceIndexCache = index
                self.variableFlowTracerCache = (root.standardizedFileURL, tracer)
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
        }

        viewer.onDiagramRequest = { [weak self] fileURL, functionName in
            guard self != nil else { return }
            let windowController = DataFlowWindowController(fileURL: fileURL, functionName: functionName)
            windowController.showWindow(nil)
        }

        viewer.onBacktraceRequest = { [weak self] in
            guard let self = self,
                  let projectRoot = self.window?.representedURL ?? self.projectRootURL else { return }
            let controller = BacktraceAnalyserWindowController(projectRoot: projectRoot) { [weak self] url, line in
                self?.showFile(at: url, line: line)
            }
            self.backtraceController = controller
            controller.showWindow(nil)
        }

        viewer.onVariableFlowRequest = { [weak self] fileURL, charIndex, variableName in
            guard let self = self,
                  let root = self.window?.representedURL ?? self.projectRootURL else { return }
            self.showVariableFlow(projectRoot: root, fileURL: fileURL, charIndex: charIndex, variableName: variableName)
        }

        viewer.onFindEntriesRequest = { [weak self] in
            self?.showFindEntries()
        }

        viewer.onReachabilityRequest = { [weak self] fileURL, functionName in
            guard let self = self,
                  let root = self.window?.representedURL ?? self.projectRootURL else { return }
            self.showReachability(projectRoot: root, fileURL: fileURL, functionName: functionName)
        }

        viewer.onSimulateRequest = { [weak self] fileURL, functionName in
            guard let self = self else { return }
            self.showSimulation(fileURL: fileURL, functionName: functionName)
        }

        viewer.onFunctionSelected = { [weak self] _, functionName, source, ext in
            self?.flowPanel.show(functionName: functionName, source: source, fileExtension: ext)
        }

        viewer.onClassRequest = { [weak self] requestedClassName in
            guard let self = self,
                  let root = self.window?.representedURL ?? self.projectRootURL else { return }
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
                  let folder = self.window?.representedURL ?? self.projectRootURL else { return }
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
            self?.variableFlowCancellation?.cancel()
            self?.variableFlowCancellation = nil
            self?.variableFlowTracerCache = nil
            self?.variableFlowController = nil
            self?.simulationController = nil
            self?.reachabilityCancellation?.cancel()
            self?.reachabilityCancellation = nil
            self?.reachabilityGraphCache = nil
            self?.reachabilityController = nil
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
        guard let folder = window?.representedURL ?? projectRootURL else {
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
        controller.showWindow(nil)
        controller.window?.makeKeyAndOrderFront(nil)
        NSApp.activate(ignoringOtherApps: true)
    }

    /// Shows the project-wide reachability of a function right-clicked in the
    /// source viewer. Reuses the cached call graph and the window across
    /// requests so a rebuilt diagram is cheap; builds the graph in the
    /// background (with a progress window only when the tree must be re-read
    /// from disk) and displays the result when ready.
    private func showReachability(projectRoot: URL, fileURL: URL, functionName: String) {
        let stdRoot = projectRoot.standardizedFileURL

        // Fast path: the call graph is already built, so walk and show immediately.
        if let cached = reachabilityGraphCache, cached.root == stdRoot {
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
        // call graph in memory (no further I/O) and display the result directly
        // without a separate progress window.
        if let pidx = projectSourceIndexCache, pidx.root == stdRoot {
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

        // Last resort: build the index on demand from disk with its own
        // progress window, so the user still gets feedback.
        reachabilityCancellation?.cancel()
        let cancellation = VariableFlowCancellation()
        reachabilityCancellation = cancellation
        let startedAt = Date()

        let controller = reachabilityControllerInstance()
        controller.onCancel = { [weak self] in self?.reachabilityCancellation?.cancel() }
        controller.beginProgress(functionName: functionName)
        controller.showWindow(nil)
        controller.window?.makeKeyAndOrderFront(nil)
        NSApp.activate(ignoringOtherApps: true)

        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            let graph = ProjectCallGraph(projectRoot: projectRoot,
                                         cancellation: cancellation,
                                         progress: { done, total in
                DispatchQueue.main.async {
                    controller.updateProgress(done: done, total: total, startedAt: startedAt)
                }
            })
            guard !cancellation.isCancelled, !graph.wasCancelled else { return }
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
        return [.openFolder, .toggleSidebar, .language, .findInFile, .searchFiles, .search, .flexibleSpace, .securityScan, .mlTrain, .mlScan, .notes, .wiki, .bugs, .ai]
    }

    func toolbarAllowedItemIdentifiers(_ toolbar: NSToolbar) -> [NSToolbarItem.Identifier] {
        return [.openFolder, .toggleSidebar, .language, .findInFile, .searchFiles, .securityScan, .mlTrain, .mlScan, .notes, .wiki, .bugs, .ai, .flexibleSpace, .search]
    }

    func toolbar(_ toolbar: NSToolbar, itemForItemIdentifier itemIdentifier: NSToolbarItem.Identifier, willBeInsertedIntoToolbar flag: Bool) -> NSToolbarItem? {
        switch itemIdentifier {
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
        let controller = FileSearchWindowController(folderURL: window?.representedURL, language: selectedLanguage)
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
    private func updateWindowTitle(forFile url: URL?) {
        let projectName = window?.representedURL?.lastPathComponent ?? projectRootURL?.lastPathComponent ?? "Project"
        if let fileURL = url {
            window?.title = "\(projectName) Project (\(fileURL.lastPathComponent))"
        } else {
            window?.title = "\(projectName) Project"
        }
    }

    @objc private func securityScanClicked() {
        guard let folder = window?.representedURL ?? projectRootURL else {
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
        controller.projectRootURL = window?.representedURL
        controller.reloadNotes()
        controller.showWindow(nil)
        controller.window?.makeKeyAndOrderFront(nil)
        NSApp.activate(ignoringOtherApps: true)
        if let folder = window?.representedURL {
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
        guard let folder = window?.representedURL ?? projectRootURL else {
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
        let folder = window?.representedURL ?? projectRootURL
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

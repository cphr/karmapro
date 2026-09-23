// by cipher.org.uk
import AppKit

/// Window that project-wide finds user-controlled entry points (receive-API
/// calls and taint-source reads) in the open project and plots the data flow
/// from the selected entry. Groups are listed by receive category with remote/
/// local labels; indirect categories (file reads, persisted data,
/// deserialization) are collected lazily behind a toggle so the default result
/// set is the primary, remote-receiving surface.
final class EntryPointsWindowController: NSWindowController, NSOutlineViewDataSource, NSOutlineViewDelegate, NSWindowDelegate {
    private static let titleText = "Find external entries to the application"
    private let titleLabel = NSTextField(labelWithString: "")
    private let captionLabel = NSTextField(wrappingLabelWithString: "")
    private let progressBar = NSProgressIndicator()
    private let progressStack = NSStackView()
    private let progressLabel = NSTextField(labelWithString: "")
    private let indirectToggle = NSButton(checkboxWithTitle: "Include indirect entries (file reads, persisted data, serialization)", target: nil, action: nil)
    private let outlineView = NSOutlineView()
    private let diagramView = DataFlowDiagramView()
    private let diagramCaption = NSTextField(wrappingLabelWithString: "")
    private let countLabel = NSTextField(labelWithString: "")

    var onOpenLocation: ((URL, Int) -> Void)?
    private var onCancel: (() -> Void)?

    private var isBusy = false
    private var projectRoot: URL?
    private var sourceIndex: ProjectSourceIndex?
    private var tracer: VariableFlowTracer?
    private var cancellation: VariableFlowCancellation?
    private var primaryGroups: [EntryGroup] = []
    private var indirectGroups: [EntryGroup] = []
    private var indirectCollected = false
    private var showIndirect = false
    private var truncated = false
    private var items: [OutlineItem] = []
    private var nodeLocations: [String: (URL, Int)] = [:]
    private let outlineColumn = NSTableColumn(identifier: NSUserInterfaceItemIdentifier("entry"))

    /// One row in the outline. A class so NSOutlineView gets stable object
    /// identity (expansion and selection rely on `===` between items).
    private final class OutlineItem {
        let group: EntryGroup?
        let site: EntrySite?
        var children: [OutlineItem] = []

        init(group: EntryGroup) {
            self.group = group
            self.site = nil
            self.children = group.sites.map { OutlineItem(site: $0) }
        }

        init(site: EntrySite) {
            self.group = nil
            self.site = site
            self.children = []
        }
    }

    convenience init() {
        let window = EscClosableWindow(
            contentRect: NSRect(x: 0, y: 0, width: 1180, height: 760),
            styleMask: [.titled, .closable, .resizable, .miniaturizable],
            backing: .buffered,
            defer: false
        )
        window.title = Self.titleText
        window.minSize = NSSize(width: 820, height: 480)
        self.init(window: window)
        buildContent()
    }

    override func showWindow(_ sender: Any?) {
        super.showWindow(sender)
        window?.center()
    }

    // MARK: - View construction

    private func buildContent() {
        guard let content = window?.contentView else { return }
        window?.delegate = self

        let header = NSStackView()
        header.orientation = .vertical
        header.alignment = .leading
        header.spacing = 6
        header.translatesAutoresizingMaskIntoConstraints = false
        content.addSubview(header)

        titleLabel.font = NSFont.systemFont(ofSize: 16, weight: .semibold)
        titleLabel.textColor = .labelColor
        header.addArrangedSubview(titleLabel)

        captionLabel.font = NSFont.systemFont(ofSize: 11)
        captionLabel.textColor = .secondaryLabelColor
        header.addArrangedSubview(captionLabel)

        let controlRow = NSStackView()
        controlRow.orientation = .horizontal
        controlRow.alignment = .centerY
        controlRow.spacing = 12

        indirectToggle.target = self
        indirectToggle.action = #selector(toggleIndirect(_:))
        indirectToggle.font = NSFont.systemFont(ofSize: 11)
        indirectToggle.state = .off

        countLabel.font = NSFont.systemFont(ofSize: 11, weight: .medium)
        countLabel.textColor = .secondaryLabelColor

        progressBar.style = .bar
        progressBar.isIndeterminate = false
        progressBar.minValue = 0
        progressBar.maxValue = 1
        progressBar.doubleValue = 0
        progressBar.controlSize = .small
        progressBar.translatesAutoresizingMaskIntoConstraints = false
        progressBar.widthAnchor.constraint(equalToConstant: 180).isActive = true
        progressStack.orientation = .horizontal
        progressStack.alignment = .centerY
        progressStack.spacing = 8
        progressLabel.font = NSFont.systemFont(ofSize: 11)
        progressLabel.textColor = .secondaryLabelColor
        progressStack.addArrangedSubview(progressBar)
        progressStack.addArrangedSubview(progressLabel)
        progressStack.isHidden = true

        controlRow.addArrangedSubview(indirectToggle)
        controlRow.addArrangedSubview(countLabel)
        controlRow.addArrangedSubview(NSView())
        controlRow.addArrangedSubview(progressStack)
        header.addArrangedSubview(controlRow)

        // Left: grouped entry-point list.
        outlineColumn.title = "Entry Points"
        outlineColumn.resizingMask = .autoresizingMask
        outlineView.addTableColumn(outlineColumn)
        outlineView.outlineTableColumn = outlineColumn
        outlineView.headerView = nil
        outlineView.dataSource = self
        outlineView.delegate = self
        outlineView.rowSizeStyle = .default
        outlineView.usesAlternatingRowBackgroundColors = true
        outlineView.target = self
        outlineView.doubleAction = #selector(doubleClickedOutline(_:))

        let scroll = NSScrollView()
        scroll.documentView = outlineView
        scroll.hasVerticalScroller = true
        scroll.drawsBackground = true

        // Right: trace graph.
        let rightStack = NSStackView()
        rightStack.orientation = .vertical
        rightStack.alignment = .leading
        rightStack.spacing = 8
        diagramCaption.font = NSFont.systemFont(ofSize: 11)
        diagramCaption.textColor = .secondaryLabelColor
        diagramView.translatesAutoresizingMaskIntoConstraints = false
        diagramView.onNodeClick = { [weak self] name in
            guard let self = self, let loc = self.nodeLocations[name] else { return }
            self.onOpenLocation?(loc.0, loc.1)
        }
        rightStack.addArrangedSubview(diagramCaption)
        rightStack.addArrangedSubview(diagramView)

        let split = NSSplitView()
        split.isVertical = true
        split.dividerStyle = .thin
        split.translatesAutoresizingMaskIntoConstraints = false
        split.addArrangedSubview(scroll)
        split.addArrangedSubview(rightStack)
        scroll.widthAnchor.constraint(greaterThanOrEqualToConstant: 360).isActive = true
        rightStack.widthAnchor.constraint(greaterThanOrEqualToConstant: 400).isActive = true
        content.addSubview(split)

        NSLayoutConstraint.activate([
            header.topAnchor.constraint(equalTo: content.topAnchor, constant: 14),
            header.leadingAnchor.constraint(equalTo: content.leadingAnchor, constant: 16),
            header.trailingAnchor.constraint(equalTo: content.trailingAnchor, constant: -16),
            diagramCaption.widthAnchor.constraint(equalTo: rightStack.widthAnchor),
            diagramView.widthAnchor.constraint(equalTo: rightStack.widthAnchor),
            diagramView.heightAnchor.constraint(greaterThanOrEqualToConstant: 360),
            split.topAnchor.constraint(equalTo: header.bottomAnchor, constant: 12),
            split.bottomAnchor.constraint(equalTo: content.bottomAnchor),
            split.leadingAnchor.constraint(equalTo: content.leadingAnchor),
            split.trailingAnchor.constraint(equalTo: content.trailingAnchor)
        ])
    }

    // MARK: - Flow control

    /// Clears results and caches when a new project is loaded, so a previous
    /// project's groups and toggle state never leak into the next one.
    private func reset() {
        primaryGroups = []
        indirectGroups = []
        indirectCollected = false
        showIndirect = false
        indirectToggle.state = .off
        truncated = false
        items = []
        nodeLocations = [:]
        titleLabel.stringValue = Self.titleText
        captionLabel.stringValue = ""
        countLabel.stringValue = ""
        outlineView.reloadData()
        diagramCaption.stringValue = ""
        diagramView.clear()
    }

    /// Starts the project-wide entry-point enumeration. If a source index for
    /// this root already exists it is used directly; otherwise one is built from
    /// disk with progress shown in this window.
    func begin(projectRoot: URL, sourceIndex: ProjectSourceIndex?) {
        reset()
        let root = projectRoot.standardizedFileURL
        self.projectRoot = root
        if let idx = sourceIndex, idx.root == root {
            tracer = VariableFlowTracer(sourceIndex: idx)
            self.sourceIndex = idx
            collectPrimary()
            return
        }
        cancellation?.cancel()
        let cancel = VariableFlowCancellation()
        cancellation = cancel
        onCancel = { cancel.cancel() }
        setBusy(true, message: "Building the project index…")
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            let index = ProjectSourceIndex(projectRoot: root,
                                           cancellation: cancel,
                                           progress: { done, total in
                DispatchQueue.main.async {
                    self?.setProgress(done: done, total: total)
                }
            })
            DispatchQueue.main.async {
                guard let self = self, !cancel.isCancelled, !index.wasCancelled else {
                    self?.setBusy(false)
                    return
                }
                self.sourceIndex = index
                self.tracer = VariableFlowTracer(sourceIndex: index)
                self.cancellation = nil
                self.onCancel = nil
                self.collectPrimary()
            }
        }
    }

    private func collectPrimary() {
        guard let index = sourceIndex else { return }
        cancellation?.cancel()
        let cancel = VariableFlowCancellation()
        cancellation = cancel
        onCancel = { cancel.cancel() }
        setBusy(true, message: "Finding entry points…")
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            let groups = EntryPointCollector.collect(sourceIndex: index,
                                                     includeIndirect: false,
                                                     progress: { done, total in
                DispatchQueue.main.async {
                    self?.setProgress(done: done, total: total)
                }
            })
            guard !cancel.isCancelled else { return }
            DispatchQueue.main.async {
                guard let self = self, !cancel.isCancelled else { return }
                self.primaryGroups = groups
                self.truncated = EntryPointCollector.truncationWarning
                self.cancellation = nil
                self.onCancel = nil
                self.setBusy(false)
                self.reload()
            }
        }
    }

    /// Lazily collects the indirect tier when the toggle is flipped on the first
    /// time. The result is cached for the session.
    @objc private func toggleIndirect(_ sender: Any?) {
        showIndirect = indirectToggle.state == .on
        if showIndirect && !indirectCollected {
            collectIndirect { [weak self] in
                self?.indirectCollected = true
                self?.reload()
            }
        } else {
            reload()
        }
    }

    private func collectIndirect(_ completion: @escaping () -> Void) {
        guard let index = sourceIndex else { return }
        cancellation?.cancel()
        let cancel = VariableFlowCancellation()
        cancellation = cancel
        onCancel = { cancel.cancel() }
        setBusy(true, message: "Finding indirect entries…")
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            let groups = EntryPointCollector.collect(sourceIndex: index,
                                                     includeIndirect: true,
                                                     progress: { done, total in
                DispatchQueue.main.async {
                    self?.setProgress(done: done, total: total)
                }
            })
            guard !cancel.isCancelled else { return }
            DispatchQueue.main.async {
                guard let self = self, !cancel.isCancelled else { return }
                self.indirectGroups = groups.filter { $0.confidence == .indirect }
                self.cancellation = nil
                self.onCancel = nil
                self.setBusy(false)
                completion()
            }
        }
    }

    // MARK: - Results display

    private var displayGroups: [EntryGroup] {
        var result = primaryGroups
        if showIndirect { result += indirectGroups }
        return result
    }

    private func reload() {
        items = displayGroups.map { OutlineItem(group: $0) }

        let siteCount = displayGroups.reduce(0) { $0 + $1.sites.count }
        let groupCount = displayGroups.count
        var count = "\(siteCount) entry point\(siteCount == 1 ? "" : "s") across \(groupCount) categor\(groupCount == 1 ? "y" : "ies")"
        if truncated { count += " — capped at \(EntryPointCollector.siteCap); run again after narrowing the project" }
        countLabel.stringValue = count

        outlineView.reloadData()
        for item in items where item.group != nil {
            outlineView.expandItem(item, expandChildren: false)
        }
    }

    private func setBusy(_ busy: Bool, message: String = "") {
        isBusy = busy
        progressStack.isHidden = !busy
        progressBar.doubleValue = 0
        progressLabel.stringValue = message
        titleLabel.stringValue = busy ? "\(Self.titleText) — searching…" : Self.titleText
    }

    private func setProgress(done: Int, total: Int) {
        guard isBusy else { return }
        if total > 0 { progressBar.doubleValue = Double(done) / Double(total) }
        progressLabel.stringValue = "\(done) of \(total) source files"
    }

    // MARK: - Tracing the selected entry

    private func trace(site: EntrySite) {
        guard let variable = site.entryVariable else {
            displayInline(site: site)
            return
        }
        guard let tracer else {
            diagramCaption.stringValue = "Project index is not ready."
            diagramView.clear()
            nodeLocations = [:]
            return
        }
        diagramCaption.stringValue = "Tracing “\(variable)” from \(site.fileURL.lastPathComponent):\(site.line)…"
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            let result = tracer.trace(variableName: variable, in: site.fileURL, charIndex: site.charIndex)
            DispatchQueue.main.async {
                guard let self = self else { return }
                self.displayTrace(result: result, site: site, variable: variable)
            }
        }
    }

    private func displayTrace(result: VariableFlowResult, site: EntrySite, variable: String) {
        guard !result.nodes.isEmpty else {
            diagramCaption.stringValue = "No flow found for “\(variable)” from \(site.fileURL.lastPathComponent):\(site.line)."
            diagramView.clear()
            nodeLocations = [:]
            return
        }

        let graph = CallGraph()
        var names: [String: String] = [:]
        var used: Set<String> = []
        for node in result.nodes.sorted(by: { $0.depth < $1.depth }) {
            var name = node.functionName
            if used.contains(name) { name = "\(node.functionName) (\(node.fileHint))" }
            var candidate = name
            var n = 2
            while used.contains(candidate) { candidate = "\(name) \(n)"; n += 1 }
            used.insert(candidate)
            names[node.id] = candidate
        }

        var locations: [String: (URL, Int)] = [:]
        for node in result.nodes {
            guard let display = names[node.id] else { continue }
            // The start frame is the function enclosing the selected entry site;
            // jumping to its first variable mention (node.lines.first) lands on
            // an earlier line when several sites live in the same function
            // (user_input.ts:7/8/9). Use the site's own line instead.
            let line = (node.isStart && node.fileURL == site.fileURL)
                ? site.line
                : (node.lines.first ?? 1)
            locations[display] = (node.fileURL, line)
            _ = graph.node(for: display)
        }

        var edges: [(String, String)] = []
        for edge in result.edges {
            guard let a = names[edge.from], let b = names[edge.to], a != b else { continue }
            graph.addDataFlow(from: a, to: b)
            edges.append((a, b))
        }

        // Origin box: named after the entry's locality, it is the first node the
        // flow leaves (Remote/Local) and is drawn as a square by the view.
        let originLabel = site.origin == .internet ? "Remote" : "Local"
        let startName = result.nodes.first(where: { $0.isStart }).flatMap { names[$0.id] }
        var rankEdges = edges
        if let startName {
            _ = graph.node(for: originLabel)
            graph.addDataFlow(from: originLabel, to: startName)
            rankEdges.insert((originLabel, startName), at: 0)
            diagramView.originNodeNames = [originLabel]
        }
        diagramView.flowStyle = FlowEdgeStyle(color: .systemRed,
                                              dashes: [10, 4, 2, 4],
                                              lineWidth: 3,
                                              phaseStep: 4)
        diagramView.animatedOnlyEdges = true
        diagramView.layoutDirection = .topToBottom
        diagramView.layoutSourceNodes = startName == nil ? [] : [originLabel]
        nodeLocations = locations
        diagramView.display(graph: graph,
                            callEdges: rankEdges,
                            dataEdges: rankEdges,
                            highlight: startName)

        let flowCount = result.edges.count
        let fileCount = Set(result.nodes.map { $0.fileURL.path }).count
        diagramCaption.stringValue = "Flow of “\(variable)” (\(site.apiPath)) — \(flowCount) hop\(flowCount == 1 ? "" : "s") across \(fileCount) file\(fileCount == 1 ? "" : "s"), coming in from \(originLabel). "
            + "Click any node to open it."
    }

    /// Entries whose received value is consumed inline (not stored in a variable)
    /// can't have traced flows, but the user should still be able to inspect the
    /// site: draw one `filename:line` box source-connected to its Internet/Local
    /// origin. Clicking it opens the file at that line.
    private func displayInline(site: EntrySite) {
        let originLabel = site.origin == .internet ? "Remote" : "Local"
        let nodeLabel = "\(site.fileURL.lastPathComponent):\(site.line)"
        let graph = CallGraph()
        _ = graph.node(for: originLabel)
        _ = graph.node(for: nodeLabel)
        graph.addDataFlow(from: originLabel, to: nodeLabel)

        nodeLocations = [nodeLabel: (site.fileURL, site.line)]
        diagramView.originNodeNames = [originLabel]
        diagramView.flowStyle = FlowEdgeStyle(color: .systemRed,
                                              dashes: [10, 4, 2, 4],
                                              lineWidth: 3,
                                              phaseStep: 4)
        diagramView.animatedOnlyEdges = true
        diagramView.layoutDirection = .topToBottom
        diagramView.layoutSourceNodes = [originLabel]
        diagramView.display(graph: graph,
                            callEdges: [(originLabel, nodeLabel)],
                            dataEdges: [(originLabel, nodeLabel)],
                            highlight: nodeLabel)
        diagramCaption.stringValue = "“\(site.apiName)” receives external \(originLabel.lowercased()) data here, but it's consumed inline (not stored in a variable), so there's no variable flow to trace. Click the box to open the source."
    }

    // MARK: - Outline data source / delegate

    func outlineView(_ outlineView: NSOutlineView, numberOfChildrenOfItem item: Any?) -> Int {
        if let groupItem = item as? OutlineItem, groupItem.group != nil {
            return groupItem.children.count
        }
        if item == nil { return items.count }
        return 0
    }

    func outlineView(_ outlineView: NSOutlineView, child index: Int, ofItem item: Any?) -> Any {
        if let groupItem = item as? OutlineItem, groupItem.group != nil {
            return groupItem.children[index]
        }
        return items[index]
    }

    func outlineView(_ outlineView: NSOutlineView, isItemExpandable item: Any) -> Bool {
        (item as? OutlineItem)?.group != nil
    }

    func outlineView(_ outlineView: NSOutlineView, viewFor tableColumn: NSTableColumn?, item: Any) -> NSView? {
        guard let outlineItem = item as? OutlineItem else { return nil }
        let cell = NSTableCellView()
        let label = NSTextField(labelWithString: "")
        label.translatesAutoresizingMaskIntoConstraints = false
        label.lineBreakMode = .byTruncatingMiddle
        cell.addSubview(label)
        NSLayoutConstraint.activate([
            label.leadingAnchor.constraint(equalTo: cell.leadingAnchor, constant: 2),
            label.trailingAnchor.constraint(equalTo: cell.trailingAnchor, constant: -4),
            label.centerYAnchor.constraint(equalTo: cell.centerYAnchor)
        ])

        if let group = outlineItem.group {
            let count = group.sites.count
            let badge: String
            switch (group.confidence, group.origin) {
            case (.primary, .internet): badge = "  ◉ remote"
            case (.primary, .local): badge = "  ◈ local"
            case (.indirect, _): badge = "  ~ indirect"
            }
            label.attributedStringValue = attributed(
                "\(group.category)",
                font: NSFont.systemFont(ofSize: 12, weight: .semibold),
                color: .labelColor
            ) + attributed(" — \(count) site\(count == 1 ? "" : "s")", font: NSFont.systemFont(ofSize: 12), color: .secondaryLabelColor)
                + attributed(badge, font: NSFont.monospacedSystemFont(ofSize: 11, weight: .regular), color: group.origin == .internet ? .systemBlue : .systemGreen)
        } else if let site = outlineItem.site {
            label.attributedStringValue = attributed(
                "\(relativePath(of: site.fileURL)):\(site.line)",
                font: NSFont.monospacedSystemFont(ofSize: 11, weight: .medium),
                color: .labelColor
            ) + attributed("  \(site.snippet.isEmpty ? "→ " + site.apiPath : site.snippet)",
                           font: NSFont.systemFont(ofSize: 11),
                           color: .secondaryLabelColor)
        }
        return cell
    }

    /// Path of `url` relative to the scanned project root, so files that share a
    /// base name (SearchServlet.java in several folders) stay distinct in the list.
    private func relativePath(of url: URL) -> String {
        guard let root = projectRoot else { return url.lastPathComponent }
        let rootPath = root.path
        let path = url.path
        if path.hasPrefix(rootPath + "/") {
            return String(path.dropFirst(rootPath.count + 1))
        }
        return url.lastPathComponent
    }

    private func attributed(_ text: String, font: NSFont, color: NSColor) -> NSAttributedString {
        NSAttributedString(string: text, attributes: [.font: font, .foregroundColor: color])
    }

    func outlineViewSelectionDidChange(_ notification: Notification) {
        let row = outlineView.selectedRow
        guard row >= 0, let item = outlineView.item(atRow: row) as? OutlineItem, let site = item.site else { return }
        trace(site: site)
    }

    @objc private func doubleClickedOutline(_ sender: Any?) {
        let row = outlineView.clickedRow
        guard row >= 0, let item = outlineView.item(atRow: row) as? OutlineItem else { return }
        if let site = item.site {
            onOpenLocation?(site.fileURL, site.line)
        }
    }

    // MARK: - Window delegate

    func windowWillClose(_ notification: Notification) {
        if isBusy { onCancel?() }
        isBusy = false
        cancellation = nil
        onCancel = nil
    }
}

private func + (lhs: NSAttributedString, rhs: NSAttributedString) -> NSAttributedString {
    let combined = NSMutableAttributedString(attributedString: lhs)
    combined.append(rhs)
    return combined
}
// by cipher.org.uk
import AppKit

final class FileTreeViewController: NSViewController, NSOutlineViewDataSource, NSOutlineViewDelegate {
    var onSelectFile: ((URL) -> Void)?

    private var outlineView: NSOutlineView!
    private var rootNode: FileNode?
    private var filteredRoot: FileNode?

    /// Nullable language filter. When set (not "All"), only that language's files show.
    var selectedLanguage: Language? {
        didSet { applyLanguageFilter() }
    }

    /// When reviewing a pull request, the repo-relative paths it adds or
    /// modifies. Nil outside PR review, which shows the whole project.
    ///
    /// The filter is applied on top of the language filter rather than instead
    /// of it, so "this PR, Java only" is a meaningful combination instead of one
    /// silently winning over the other.
    private var prChangedPaths: Set<String>?
    private var prChangedRoots: Set<String>?

    /// Set by the pull-request layer to show the A/M badge next to changed files.
    var changeBadges: [String: String] = [:]

    /// Set while the user has asked to see the whole project instead of just
    /// the pull request's changed files.
    private var showingAllFiles = false

    /// Called when the Show All toggle changes the tree, so the banner can
    /// reflect the state it is responsible for.
    var onFilterModeChanged: ((Bool) -> Void)?

    /// True while the tree is pruned to the pull request's changed files.
    var isShowingChangedFilesOnly: Bool { prChangedPaths != nil && !showingAllFiles }

    func setPullRequestFilter(paths: Set<String>?) {
        prChangedPaths = paths
        prChangedRoots = nil
        showingAllFiles = false
        if let paths = paths {
            // Precompute the top-level directory names so the pruned tree can be
            // built without re-walking it on every filter change.
            prChangedRoots = Set(paths.map { ($0 as NSString).pathComponents.first ?? $0 })
        }
        applyLanguageFilter()
        reloadAndExpand()
    }

    /// Switches between the pull request's changed files and the whole project.
    /// The pull request filter is kept intact, so switching back is exact rather
    /// than a re-request from the forge.
    func setShowingAllFiles(_ showAll: Bool) {
        guard prChangedPaths != nil else { return }
        showingAllFiles = showAll
        applyLanguageFilter()
        reloadAndExpand()
        onFilterModeChanged?(showAll)
    }

    private func reloadAndExpand() {
        guard isViewLoaded, rootNode != nil else { return }
        outlineView.reloadData()
        if filterQuery.isEmpty, let root = currentRoot() {
            outlineView.expandItem(root, expandChildren: true)
        }
    }

    /// When filtering, we show a flat list of matching files.
    private var filterQuery: String = ""
    private var filteredResults: [FileNode] = []

    private let folderIcon = NSImage(systemSymbolName: "folder", accessibilityDescription: nil)
    private let fileIcon = NSImage(systemSymbolName: "doc", accessibilityDescription: nil)

    override func loadView() {
        let scrollView = NSScrollView()
        scrollView.hasVerticalScroller = true
        scrollView.hasHorizontalScroller = true
        scrollView.autohidesScrollers = true
        scrollView.borderType = .noBorder

        outlineView = NSOutlineView(frame: NSRect(x: 0, y: 0, width: 300, height: 600))
        outlineView.usesAlternatingRowBackgroundColors = true
        outlineView.rowSizeStyle = .default
        outlineView.headerView = nil
        outlineView.autoresizingMask = [.width]
        outlineView.style = .sourceList

        let column = NSTableColumn(identifier: .nameColumn)
        column.resizingMask = .autoresizingMask
        column.width = 260
        outlineView.addTableColumn(column)
        outlineView.outlineTableColumn = column

        outlineView.dataSource = self
        outlineView.delegate = self

        outlineView.target = self
        outlineView.action = #selector(outlineClicked(_:))
        outlineView.doubleAction = #selector(outlineDoubleClicked(_:))

        scrollView.documentView = outlineView
        self.view = scrollView
    }

    override func viewDidLoad() {
        super.viewDidLoad()
    }

    /// Empties the tree, as though no project had ever been opened.
    ///
    /// Leaving a pull request review used to leave the file tree standing: the
    /// nodes pointed into the session's temporary checkout, which was then
    /// deleted, so every row the user clicked afterwards produced "Could not
    /// read file:" in the source viewer. Clearing the root is what makes the
    /// closed-review window look like the app has nothing open.
    func clear() {
        rootNode = nil
        filteredRoot = nil
        prChangedPaths = nil
        prChangedRoots = nil
        showingAllFiles = false
        changeBadges = [:]
        outlineView.collapseItem(nil, collapseChildren: true)
        outlineView.reloadData()
    }

    func load(directory url: URL) {
        let node = FileNode(url: url, isDirectory: true)
        node.loadDeeply()
        rootNode = node
        applyLanguageFilter()
        outlineView.reloadData()
        if let root = currentRoot() {
            outlineView.expandItem(root, expandChildren: true)
        }
    }

    /// The node to display at the top of the tree (full root, or filtered).
    ///
    /// Returns nil until a directory has been loaded. It used to force-unwrap
    /// `rootNode`, which trapped when the tree was touched before any project
    /// was open - which is exactly what leaving a pull request review did on
    /// startup.
    func currentRoot() -> FileNode? {
        filteredRoot ?? rootNode
    }

    private func applyLanguageFilter() {
        guard let root = rootNode else { return }
        if prChangedPaths != nil, showingAllFiles {
            // Showing every file of the project while a pull request is open.
            // The language filter still applies, because that is a deliberate
            // user choice; the pull request pruning is what Show All undoes.
            filteredRoot = selectedLanguage.map {
                FileTreeViewController.filter(node: root, language: $0)
            } ?? root
        } else if prChangedPaths != nil {
            // PR filter first, then language, so the pruned tree only walks the
            // handful of files the PR touched rather than the whole project.
            let prFiltered = FileTreeViewController.filter(node: root) { [weak self] node in
                guard let self = self, self.prChangedPaths != nil else { return true }
                return self.matchesPullRequest(path: node)
            }
            if let lang = selectedLanguage {
                filteredRoot = FileTreeViewController.filter(node: prFiltered, language: lang)
            } else {
                filteredRoot = prFiltered
            }
        } else if let lang = selectedLanguage {
            filteredRoot = FileTreeViewController.filter(node: root, language: lang)
        } else {
            filteredRoot = nil
        }
        reloadAndExpand()
    }

    /// True when a node is inside the set of paths a pull request changed.
    ///
    /// Matched on the path relative to the project root, because the diff is
    /// reported repo-relative while the tree holds absolute URLs.
    private func matchesPullRequest(path node: FileNode) -> Bool {
        guard let paths = prChangedPaths, let root = rootNode else { return true }
        let base = root.url.standardizedFileURL.path
        let full = node.url.standardizedFileURL.path
        var relative = full
        if full.hasPrefix(base) {
            relative = String(full.dropFirst(base.count))
        }
        while relative.hasPrefix("/") { relative.removeFirst() }

        if node.isDirectory {
            // Keep a directory when any changed path sits beneath it.
            let prefix = relative.isEmpty ? "" : relative + "/"
            return paths.contains { $0 == relative || $0.hasPrefix(prefix) }
        }
        return paths.contains(relative)
    }

    /// Returns a pruned copy of node keeping only files matching `language` (dirs kept if they contain matches).
    private static func filter(node: FileNode, language: Language) -> FileNode {
        guard node.isDirectory else {
            return language.contains(node.url) ? node : FileNode.prunedCopy(of: node)
        }
        let filtered = FileNode.prunedCopy(of: node)
        for child in node.children {
            if child.isDirectory {
                let sub = filter(node: child, language: language)
                if !sub.children.isEmpty {
                    filtered.children.append(sub)
                }
            } else if language.contains(child.url) {
                filtered.children.append(child)
            }
        }
        return filtered
    }

    /// Returns a pruned copy of node keeping only files accepted by `predicate`.
    private static func filter(node: FileNode, predicate: (FileNode) -> Bool) -> FileNode {
        guard node.isDirectory else {
            return predicate(node) ? node : FileNode.prunedCopy(of: node)
        }
        let filtered = FileNode.prunedCopy(of: node)
        for child in node.children {
            if child.isDirectory {
                let sub = filter(node: child, predicate: predicate)
                if !sub.children.isEmpty {
                    filtered.children.append(sub)
                }
            } else if predicate(child) {
                filtered.children.append(child)
            }
        }
        return filtered
    }

    func filter(query: String) {
        let trimmed = query.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        filterQuery = trimmed
        filteredResults = []

        if !trimmed.isEmpty {
            guard var root = rootNode else { return }
            root.loadDeeply()
            root = rootNode!
            collectMatchingFiles(from: root, query: trimmed)
        }

        outlineView.reloadData()
    }

    private func collectMatchingFiles(from node: FileNode, query: String) {
        for child in node.children {
            if child.name.lowercased().contains(query) {
                filteredResults.append(child)
            }
            if child.isDirectory {
                collectMatchingFiles(from: child, query: query)
            }
        }
    }

    // MARK: - Actions

    @objc private func outlineClicked(_ sender: Any?) {
        let row = outlineView.clickedRow
        openFile(atRow: row)
    }

    @objc private func outlineDoubleClicked(_ sender: Any?) {
        let row = outlineView.clickedRow
        if let node = node(at: row), node.isDirectory {
            outlineView.expandItem(node)
        }
    }

    private func openFile(atRow row: Int) {
        guard let node = node(at: row), !node.isDirectory else { return }
        onSelectFile?(node.url)
    }

    func node(at row: Int) -> FileNode? {
        guard row >= 0 else { return nil }
        if !filterQuery.isEmpty {
            return row < filteredResults.count ? filteredResults[row] : nil
        }
        guard row < outlineView.numberOfRows else { return nil }
        return outlineView.item(atRow: row) as? FileNode
    }

    // MARK: - NSOutlineViewDataSource

    func outlineView(_ outlineView: NSOutlineView, numberOfChildrenOfItem item: Any?) -> Int {
        if filterQuery.isEmpty {
            guard let node = item as? FileNode else {
                let root = rootNode
                return root == nil ? 0 : 1
            }
            return node.children.count
        } else {
            return item == nil ? filteredResults.count : 0
        }
    }

    func outlineView(_ outlineView: NSOutlineView, child index: Int, ofItem item: Any?) -> Any {
        if filterQuery.isEmpty {
            if let node = item as? FileNode {
                return node.children[index]
            }
            // The single top-level child. Unreachable while rootNode is nil,
            // because numberOfChildrenOfItem reports 0 in that case, so the
            // fallback is only here to satisfy the non-optional return type.
            if let root = currentRoot() { return root }
            return FileNode(url: URL(fileURLWithPath: NSTemporaryDirectory()), isDirectory: true)
        } else {
            return filteredResults[index]
        }
    }

    func outlineView(_ outlineView: NSOutlineView, isItemExpandable item: Any) -> Bool {
        guard let node = item as? FileNode else { return false }
        if !filterQuery.isEmpty { return false }
        return node.isDirectory && !node.children.isEmpty
    }

    // MARK: - NSOutlineViewDelegate

    func outlineView(_ outlineView: NSOutlineView, viewFor tableColumn: NSTableColumn?, item: Any) -> NSView? {
        guard let node = item as? FileNode else { return nil }
        let identifier = NSUserInterfaceItemIdentifier("FileCell")
        let cell: NSTableCellView
        if let reused = outlineView.makeView(withIdentifier: identifier, owner: self) as? NSTableCellView {
            cell = reused
        } else {
            cell = NSTableCellView()
            cell.identifier = identifier
            let textField = NSTextField(labelWithString: "")
            textField.lineBreakMode = .byTruncatingMiddle
            textField.translatesAutoresizingMaskIntoConstraints = false
            let imageView = NSImageView()
            imageView.translatesAutoresizingMaskIntoConstraints = false
            cell.addSubview(textField)
            cell.textField = textField
            cell.addSubview(imageView)
            cell.imageView = imageView
            NSLayoutConstraint.activate([
                imageView.leadingAnchor.constraint(equalTo: cell.leadingAnchor, constant: 2),
                imageView.centerYAnchor.constraint(equalTo: cell.centerYAnchor),
                imageView.widthAnchor.constraint(equalToConstant: 16),
                imageView.heightAnchor.constraint(equalToConstant: 16),
                textField.leadingAnchor.constraint(equalTo: imageView.trailingAnchor, constant: 4),
                textField.trailingAnchor.constraint(equalTo: cell.trailingAnchor, constant: -4),
                textField.centerYAnchor.constraint(equalTo: cell.centerYAnchor)
            ])
        }
        let relPath = node.name
        if !node.isDirectory, let badge = changeBadges[relPath] {
            // "A" / "M" badge so the user can see at a glance which files the PR
            // added versus modified without opening each one.
            cell.textField?.stringValue = "\(badge)  \(node.name)"
            cell.textField?.textColor = badge == "A" ? .systemGreen : .systemOrange
        } else {
            cell.textField?.stringValue = node.name
            cell.textField?.textColor = .labelColor
        }
        cell.imageView?.image = node.isDirectory ? folderIcon : fileIcon
        return cell
    }

    func outlineView(_ outlineView: NSOutlineView, shouldSelectItem item: Any) -> Bool {
        guard let node = item as? FileNode else { return false }
        return !node.isDirectory
    }
}

extension NSUserInterfaceItemIdentifier {
    static let nameColumn = NSUserInterfaceItemIdentifier("nameColumn")
}

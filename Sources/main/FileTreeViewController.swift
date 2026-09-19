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

    func load(directory url: URL) {
        let node = FileNode(url: url, isDirectory: true)
        node.loadDeeply()
        rootNode = node
        applyLanguageFilter()
        outlineView.reloadData()
        outlineView.expandItem(currentRoot(), expandChildren: true)
    }

    /// The node to display at the top of the tree (full root or language-filtered root).
    func currentRoot() -> FileNode {
        filteredRoot ?? rootNode!
    }

    private func applyLanguageFilter() {
        guard let root = rootNode else { return }
        if let lang = selectedLanguage {
            filteredRoot = FileTreeViewController.filter(node: root, language: lang)
        } else {
            filteredRoot = nil
        }
        outlineView.reloadData()
        if filterQuery.isEmpty {
            outlineView.expandItem(currentRoot(), expandChildren: true)
        }
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
            return currentRoot()
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
        cell.textField?.stringValue = node.name
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

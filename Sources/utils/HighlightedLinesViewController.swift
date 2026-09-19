// by cipher.org.uk
import AppKit

/// Compact clickable table at the top of the source viewer that lists every line
/// flagged by the ML scan for the currently open file (Line / Probability / Preview).
/// Clicking a row asks the source viewer to scroll to that line.
final class HighlightedLinesViewController: NSViewController, NSTableViewDataSource, NSTableViewDelegate {

    /// Called when the user clicks a row; passes the 1-based source line number.
    var onSelectLine: ((Int) -> Void)?

    private struct Row {
        let line: Int
        let prob: Double
        let preview: String
    }

    private let headerLabel = NSTextField(labelWithString: "")
    private var rows: [Row] = []

    private let lineColumn = NSTableColumn(identifier: NSUserInterfaceItemIdentifier("line"))
    private let probColumn = NSTableColumn(identifier: NSUserInterfaceItemIdentifier("prob"))
    private let previewColumn = NSTableColumn(identifier: NSUserInterfaceItemIdentifier("preview"))

    private let tableView = NSTableView()
    private let scrollView = NSScrollView()

    override func loadView() {
        headerLabel.font = NSFont.systemFont(ofSize: 12, weight: .semibold)
        headerLabel.textColor = .secondaryLabelColor
        headerLabel.translatesAutoresizingMaskIntoConstraints = false

        lineColumn.title = "Line"
        lineColumn.width = 64
        lineColumn.minWidth = 56
        lineColumn.resizingMask = []
        probColumn.title = "Probability"
        probColumn.width = 72
        probColumn.minWidth = 64
        probColumn.resizingMask = []
        previewColumn.title = "Preview"
        previewColumn.width = 420
        previewColumn.minWidth = 160

        tableView.addTableColumn(lineColumn)
        tableView.addTableColumn(probColumn)
        tableView.addTableColumn(previewColumn)
        tableView.dataSource = self
        tableView.delegate = self
        tableView.usesAlternatingRowBackgroundColors = true
        tableView.rowSizeStyle = .custom
        tableView.usesAutomaticRowHeights = true
        tableView.target = self
        tableView.action = #selector(rowClicked)
        tableView.allowsEmptySelection = true
        tableView.headerView = NSTableHeaderView()

        scrollView.hasVerticalScroller = true
        scrollView.hasHorizontalScroller = false
        scrollView.autohidesScrollers = true
        scrollView.borderType = .noBorder
        scrollView.documentView = tableView
        scrollView.translatesAutoresizingMaskIntoConstraints = false

        let root = NSView()
        root.addSubview(headerLabel)
        root.addSubview(scrollView)

        NSLayoutConstraint.activate([
            headerLabel.topAnchor.constraint(equalTo: root.topAnchor, constant: 6),
            headerLabel.leadingAnchor.constraint(equalTo: root.leadingAnchor, constant: 12),
            headerLabel.trailingAnchor.constraint(lessThanOrEqualTo: root.trailingAnchor, constant: -12),
            scrollView.topAnchor.constraint(equalTo: headerLabel.bottomAnchor, constant: 4),
            scrollView.bottomAnchor.constraint(equalTo: root.bottomAnchor),
            scrollView.leadingAnchor.constraint(equalTo: root.leadingAnchor),
            scrollView.trailingAnchor.constraint(equalTo: root.trailingAnchor)
        ])

        // Non-required so the pane can collapse when hidden without blocking window resize.
        // (Priority 999 keeps it at its fixed height while visible, but lets it drop to zero
        // when the results table is empty and the pane is collapsed.)
        let height = root.heightAnchor.constraint(equalToConstant: 140)
        height.priority = NSLayoutConstraint.Priority(999)
        height.isActive = true

        self.view = root
    }

    @objc private func rowClicked() {
        let row = tableView.clickedRow
        guard row >= 0 && row < rows.count else { return }
        onSelectLine?(rows[row].line)
    }

    /// Rebuilds the table for the current file. Lines are passed in already filtered
    /// to the active scan threshold. The pane collapses (isHidden) when there are no
    /// flagged lines so the source code fills the whole viewer.
    func configure(lines: [Int: Double], source: String?) {
        rows = lines.sorted { $0.key < $1.key }.map { (line, prob) in
            let preview = Self.preview(forLine: line, in: source)
            return Row(line: line, prob: prob, preview: preview)
        }
        headerLabel.stringValue = rows.isEmpty
            ? "Bayes highlighted lines"
            : "Bayes highlighted lines (\(rows.count))"
        tableView.reloadData()
        view.isHidden = rows.isEmpty
    }

    var highlightedCount: Int { rows.count }

    /// Returns the trimmed text of `line` (1-based) from `source` for the preview column.
    private static func preview(forLine line: Int, in source: String?) -> String {
        guard let source = source else { return "" }
        let ns = source as NSString
        var lineStart = 0
        var current = 1
        var end = 0
        while current < line && end < ns.length {
            if ns.character(at: end) == 10 { current += 1 }
            end += 1
        }
        lineStart = end
        while end < ns.length && ns.character(at: end) != 10 { end += 1 }
        guard end > lineStart else { return "" }
        return ns.substring(with: NSRange(location: lineStart, length: end - lineStart)).trimmingCharacters(in: .whitespaces)
    }

    // MARK: - NSTableViewDataSource / NSTableViewDelegate

    func numberOfRows(in tableView: NSTableView) -> Int { rows.count }

    func tableView(_ tableView: NSTableView, viewFor tableColumn: NSTableColumn?, row: Int) -> NSView? {
        guard let tableColumn = tableColumn else { return nil }
        let id = tableColumn.identifier.rawValue
        let cell = tableView.makeView(withIdentifier: tableColumn.identifier, owner: self)
            as? NSTableCellView ?? NSTableCellView()
        cell.identifier = tableColumn.identifier

        let label: NSTextField
        if let existing = cell.textField {
            label = existing
        } else {
            label = NSTextField(labelWithString: "")
            label.lineBreakMode = .byTruncatingTail
            label.font = NSFont.monospacedSystemFont(ofSize: 12, weight: .regular)
            label.translatesAutoresizingMaskIntoConstraints = false
            cell.addSubview(label)
            cell.textField = label
            NSLayoutConstraint.activate([
                label.leadingAnchor.constraint(equalTo: cell.leadingAnchor, constant: 2),
                label.trailingAnchor.constraint(equalTo: cell.trailingAnchor, constant: -2),
                label.centerYAnchor.constraint(equalTo: cell.centerYAnchor)
            ])
        }

        let r = rows[row]
        switch id {
        case "line":
            label.stringValue = "\(r.line)"
            label.textColor = .labelColor
        case "prob":
            let pct = Int((r.prob * 100).rounded())
            label.stringValue = "\(pct)%"
            label.textColor = Self.riskColor(r.prob)
        default:
            label.stringValue = r.preview
            label.textColor = .labelColor
        }
        return cell
    }

    /// Maps a probability to a risk color: green -> yellow -> red.
    private static func riskColor(_ prob: Double) -> NSColor {
        let t = min(max((prob - 0.6) / 0.4, 0.0), 1.0)
        if let g = NSColor.systemGreen.usingColorSpace(.sRGB),
           let r = NSColor.systemRed.usingColorSpace(.sRGB) {
            let red = g.redComponent + (r.redComponent - g.redComponent) * CGFloat(t)
            let green = g.greenComponent + (r.greenComponent - g.greenComponent) * CGFloat(t)
            let blue = g.blueComponent + (r.blueComponent - g.blueComponent) * CGFloat(t)
            return NSColor(calibratedRed: red, green: green, blue: blue, alpha: 1.0)
        }
        return .systemRed
    }
}

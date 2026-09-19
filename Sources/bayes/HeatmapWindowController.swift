// by cipher.org.uk
import AppKit

/// Presents the results of the most recent ML project scan as a color heatmap:
/// one cell per scanned file, colored by how many lines were flagged. Files with
/// the most flagged lines glow hottest (red) and cool toward blue as the flagged
/// count drops, so risk concentration is visible at a glance.
final class HeatmapWindowController: NSWindowController {

    private let heatmapView = HeatmapView()
    private let summaryLabel = NSTextField(wrappingLabelWithString: "No scan results yet.")
    private let refreshButton = NSButton(title: "Refresh", target: nil, action: nil)
    private var scrollView: NSScrollView!

    var projectRoot: URL?

    /// Invoked when the user clicks a heatmap cell; passes the file's URL.
    var onOpenFile: ((URL) -> Void)?

    convenience init() {
        let window = EscClosableWindow(
            contentRect: NSRect(x: 0, y: 0, width: 920, height: 620),
            styleMask: [.titled, .closable, .miniaturizable, .resizable],
            backing: .buffered,
            defer: false
        )
        window.title = "ML Scan Heatmap"
        window.minSize = NSSize(width: 640, height: 420)
        self.init(window: window)
        window.delegate = self
        buildContent()
    }

    private func buildContent() {
        guard let content = window?.contentView else { return }

        heatmapView.onOpenFile = { [weak self] url in
            self?.onOpenFile?(url)
        }

        summaryLabel.font = NSFont.systemFont(ofSize: 12)
        summaryLabel.textColor = .secondaryLabelColor
        summaryLabel.setContentHuggingPriority(.defaultLow, for: .horizontal)
        summaryLabel.translatesAutoresizingMaskIntoConstraints = false

        refreshButton.bezelStyle = .rounded
        refreshButton.target = self
        refreshButton.action = #selector(refreshClicked)

        let headerRow = NSStackView(views: [summaryLabel, refreshButton])
        headerRow.orientation = .horizontal
        headerRow.alignment = .centerY
        headerRow.spacing = 10
        headerRow.translatesAutoresizingMaskIntoConstraints = false

        scrollView = NSScrollView()
        scrollView.documentView = heatmapView
        scrollView.hasVerticalScroller = true
        scrollView.autohidesScrollers = true
        scrollView.drawsBackground = true
        scrollView.translatesAutoresizingMaskIntoConstraints = false

        let legend = LegendView()
        legend.translatesAutoresizingMaskIntoConstraints = false

        content.addSubview(headerRow)
        content.addSubview(scrollView)
        content.addSubview(legend)

        NSLayoutConstraint.activate([
            headerRow.topAnchor.constraint(equalTo: content.topAnchor, constant: 12),
            headerRow.leadingAnchor.constraint(equalTo: content.leadingAnchor, constant: 16),
            headerRow.trailingAnchor.constraint(equalTo: content.trailingAnchor, constant: -16),
            legend.bottomAnchor.constraint(equalTo: content.bottomAnchor, constant: -12),
            legend.leadingAnchor.constraint(equalTo: content.leadingAnchor, constant: 16),
            legend.trailingAnchor.constraint(equalTo: content.trailingAnchor, constant: -16),
            legend.heightAnchor.constraint(equalToConstant: 46),
            scrollView.topAnchor.constraint(equalTo: headerRow.bottomAnchor, constant: 8),
            scrollView.leadingAnchor.constraint(equalTo: content.leadingAnchor),
            scrollView.trailingAnchor.constraint(equalTo: content.trailingAnchor),
            scrollView.bottomAnchor.constraint(equalTo: legend.topAnchor, constant: -8)
        ])

        reload()
    }

    /// Re-reads the shared scan store and redraws the heatmap for the current
    /// project root.
    func reload() {
        let entries = MLScanResultStore.shared.flaggedCounts()
        heatmapView.files = entries.map { entry in
            HeatmapCell(path: entry.path,
                        name: MLScanResultStore.shared.displayPath(entry.path, under: projectRoot),
                        flagged: entry.flagged)
        }
        relayoutDocumentView()

        let totalFiles = entries.count
        let totalFlagged = entries.reduce(0) { $0 + $1.flagged }
        if let hottest = entries.first, totalFiles > 0 {
            let name = MLScanResultStore.shared.displayPath(hottest.path, under: projectRoot)
            summaryLabel.stringValue = "\(totalFiles) file(s) flagged, \(totalFlagged) line(s) total. Hottest: \(name) (\(hottest.flagged))."
        } else {
            summaryLabel.stringValue = "No scan results yet — run an ML Project Scan."
        }
    }

    /// Sizes the scroll view's document view so it fills the clip width and is as
    /// tall as its content, enabling vertical scrolling when there are many files.
    private func relayoutDocumentView() {
        let clipWidth = scrollView?.contentView.bounds.width ?? 600
        heatmapView.layoutContent(forWidth: clipWidth)
    }

    @objc private func refreshClicked() {
        reload()
    }

    override func showWindow(_ sender: Any?) {
        super.showWindow(sender)
        relayoutDocumentView()
    }
}

extension HeatmapWindowController: NSWindowDelegate {
    func windowDidResize(_ notification: Notification) {
        relayoutDocumentView()
    }
}

/// A single heatmap cell: the file it represents, how to display it, and how many
/// lines were flagged.
struct HeatmapCell {
    let path: String
    let name: String
    let flagged: Int
}

/// The custom-drawn heatmap grid. Cells are laid out left-to-right, top-to-bottom
/// in a wrapping grid; each cell's fill ramps cold (blue) to hot (red) based on
/// the file's flagged-line count relative to the hottest file. Cells are clickable
/// and report which file was clicked via a callback.
final class HeatmapView: NSView {

    var files: [HeatmapCell] = [] {
        didSet { needsDisplay = true }
    }

    /// Invoked when the user clicks a cell; passes the clicked file's URL.
    var onOpenFile: ((URL) -> Void)?

    private let cellSize: CGFloat = 84
    private let captionHeight: CGFloat = 30
    private let gap: CGFloat = 10

    override var isFlipped: Bool { true }

    /// Number of columns that fit the current bounds width.
    private var columns: Int { max(1, Int((bounds.width - gap) / (cellSize + gap))) }

    /// Sets the view's frame so it fills the given clip width and is as tall as
    /// its content, which lets the enclosing scroll view page vertically.
    func layoutContent(forWidth width: CGFloat) {
        let cols = max(1, Int((width - gap) / (cellSize + gap)))
        let rows = files.isEmpty ? 1 : Int(ceil(Double(files.count) / Double(cols)))
        let height = rows == 0 ? 0 : CGFloat(rows) * (cellSize + captionHeight + gap) + gap
        setFrameSize(NSSize(width: max(width, 1), height: max(0, height)))
    }

    override func mouseDown(with event: NSEvent) {
        let point = convert(event.locationInWindow, from: nil)
        let cols = columns
        let index = gridIndex(at: point, cols: cols)
        if index >= 0 && index < files.count {
            onOpenFile?(URL(fileURLWithPath: files[index].path))
        }
        super.mouseDown(with: event)
    }

    /// Maps a point in view coordinates to the cell grid index, or -1 if no cell
    /// is under the point (e.g. between cells or in a caption gap).
    private func gridIndex(at point: NSPoint, cols: Int) -> Int {
        let cellW = cellSize + gap
        let rowH = cellSize + captionHeight + gap
        let col = Int((point.x - gap) / cellW)
        let row = Int((point.y - gap) / rowH)
        guard col >= 0 && col < cols, row >= 0 else { return -1 }
        let x = gap + CGFloat(col) * cellW
        let y = gap + CGFloat(row) * rowH
        guard point.x >= x && point.x <= x + cellSize &&
              point.y >= y && point.y <= y + cellSize else { return -1 }
        return row * cols + col
    }

    override func draw(_ dirtyRect: NSRect) {
        NSColor.windowBackgroundColor.setFill()
        dirtyRect.fill()

        guard !files.isEmpty else {
            let text = "No scan results. Run an ML Project Scan first." as NSString
            let attrs: [NSAttributedString.Key: Any] = [
                .font: NSFont.systemFont(ofSize: 14),
                .foregroundColor: NSColor.secondaryLabelColor
            ]
            text.draw(at: NSPoint(x: 20, y: 20), withAttributes: attrs)
            return
        }

        let maxFlags = files.map { $0.flagged }.max() ?? 1
        let cols = max(1, Int((bounds.width - gap) / (cellSize + gap)))
        var col = 0
        var row = 0

        for file in files {
            let intensity = maxFlags == 0 ? 0.0 : Double(file.flagged) / Double(maxFlags)
            let color = Self.heatColor(intensity)
            let x = gap + CGFloat(col) * (cellSize + gap)
            let y = gap + CGFloat(row) * (cellSize + captionHeight + gap)
            let rect = NSRect(x: x, y: y, width: cellSize, height: cellSize)

            color.setFill()
            NSBezierPath(roundedRect: rect, xRadius: 6, yRadius: 6).fill()

            let dark = intensity > 0.6
            let textColor = dark ? NSColor.white : NSColor.black
            let countTitle = "\(file.flagged)" as NSString
            let countAttrs: [NSAttributedString.Key: Any] = [
                .font: NSFont.boldSystemFont(ofSize: 14),
                .foregroundColor: textColor
            ]
            let countSize = countTitle.size(withAttributes: countAttrs)
            countTitle.draw(at: NSPoint(x: rect.midX - countSize.width / 2,
                                        y: rect.midY - countSize.height / 2),
                            withAttributes: countAttrs)

            let nameTitle = file.name as NSString
            var nameFont = NSFont.systemFont(ofSize: 11)
            if nameTitle.size(withAttributes: [.font: nameFont]).width > cellSize - 4 {
                nameFont = NSFont.systemFont(ofSize: 9)
            }
            let paragraph = NSMutableParagraphStyle()
            paragraph.lineBreakMode = .byTruncatingMiddle
            let drawRect = NSRect(x: x, y: y + cellSize + 2, width: cellSize, height: captionHeight)
            let finalAttrs: [NSAttributedString.Key: Any] = [
                .font: nameFont,
                .foregroundColor: NSColor.labelColor,
                .paragraphStyle: paragraph
            ]
            nameTitle.draw(in: drawRect, withAttributes: finalAttrs)

            col += 1
            if col >= cols {
                col = 0
                row += 1
            }
        }
    }

    /// Maps a normalized 0...1 intensity to a cold-to-hot color running
    /// blue → teal → green → yellow → red.
    static func heatColor(_ t: Double) -> NSColor {
        let stops: [(pos: Double, r: CGFloat, g: CGFloat, b: CGFloat)] = [
            (0.00, 0.24, 0.39, 0.86),
            (0.25, 0.31, 0.74, 0.71),
            (0.50, 0.35, 0.78, 0.31),
            (0.75, 0.95, 0.78, 0.24),
            (1.00, 0.91, 0.24, 0.18)
        ]
        let clamped = min(max(t, 0), 1)
        guard clamped <= stops[0].pos || clamped >= stops.last!.pos else {
            var prev = stops[0]
            for stop in stops[1...] {
                if clamped <= stop.pos {
                    let span = stop.pos - prev.pos
                    let f = span <= 0 ? 0 : CGFloat((clamped - prev.pos) / span)
                    return NSColor(calibratedRed: prev.r + (stop.r - prev.r) * f,
                                   green: prev.g + (stop.g - prev.g) * f,
                                   blue: prev.b + (stop.b - prev.b) * f,
                                   alpha: 1)
                }
                prev = stop
            }
            return NSColor(calibratedRed: stops.last!.r, green: stops.last!.g, blue: stops.last!.b, alpha: 1)
        }
        return clamped <= stops[0].pos
            ? NSColor(calibratedRed: stops[0].r, green: stops[0].g, blue: stops[0].b, alpha: 1)
            : NSColor(calibratedRed: stops.last!.r, green: stops.last!.g, blue: stops.last!.b, alpha: 1)
    }
}

/// A horizontal gradient bar with "cold" and "hot" labels, clarifying the scale.
final class LegendView: NSView {
    override var isFlipped: Bool { true }

    override func draw(_ dirtyRect: NSRect) {
        let barRect = NSRect(x: 0, y: 8, width: bounds.width, height: 16)
        let gradient = NSGradient(colors: [
            HeatmapView.heatColor(0.0),
            HeatmapView.heatColor(0.5),
            HeatmapView.heatColor(1.0)
        ])!
        gradient.draw(in: barRect, angle: 0)

        let paragraph = NSMutableParagraphStyle()
        paragraph.alignment = .left
        let cold: [NSAttributedString.Key: Any] = [
            .font: NSFont.systemFont(ofSize: 11),
            .foregroundColor: NSColor.secondaryLabelColor,
            .paragraphStyle: paragraph
        ]
        ("Cold (fewer flagged lines)" as NSString).draw(at: NSPoint(x: 0, y: 28), withAttributes: cold)

        let rightParagraph = NSMutableParagraphStyle()
        rightParagraph.alignment = .right
        var hot = cold
        hot[.paragraphStyle] = rightParagraph
        ("Hot (most flagged lines)" as NSString).draw(in: NSRect(x: 0, y: 28, width: bounds.width, height: 18), withAttributes: hot)
    }
}

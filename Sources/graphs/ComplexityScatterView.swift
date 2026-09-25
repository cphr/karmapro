// by cipher.org.uk
import AppKit

/// Scatter plot of functions in a project: X is the source order of the
/// function (file by file), Y is its cyclomatic complexity. Each function is
/// drawn as a colour-coded point (green → yellow → red by complexity) labelled
/// with its complexity number. `file` is set for project-wide plots so a click /
/// hover can name the owning file.
final class ComplexityScatterView: NSView {

    struct Point {
        let name: String
        let complexity: Int
        let line: Int
        let file: URL?
    }

    var points: [Point] = [] {
        didSet { needsDisplay = true }
    }

    /// Placeholder text shown when there are no points to plot.
    var placeholderText = "No functions found in this file" {
        didSet { needsDisplay = true }
    }

    /// Fired when a point is clicked.
    var onSelect: ((Point) -> Void)?
    /// Fired when the mouse hovers over / leaves a point (nil on leave).
    var onHover: ((Point?) -> Void)?

    private var hoveredIndex: Int?

    private let leftMargin: CGFloat = 46
    private let rightMargin: CGFloat = 24
    private let topMargin: CGFloat = 18
    private let bottomMargin: CGFloat = 40

    override var isFlipped: Bool { false }

    init() {
        super.init(frame: .zero)
        wantsLayer = true
    }

    required init?(coder: NSCoder) {
        fatalError("init(coder:) has not been implemented")
    }

    override func updateTrackingAreas() {
        super.updateTrackingAreas()
        trackingAreas.forEach { removeTrackingArea($0) }
        addTrackingArea(NSTrackingArea(
            rect: bounds,
            options: [.mouseMoved, .mouseEnteredAndExited, .activeInKeyWindow, .inVisibleRect],
            owner: self,
            userInfo: nil
        ))
    }

    // MARK: - Interaction

    override func mouseMoved(with event: NSEvent) {
        let p = convert(event.locationInWindow, from: nil)
        let idx = pointIndex(near: p, tolerance: 14)
        if idx != hoveredIndex {
            hoveredIndex = idx
            if let idx = idx {
                onHover?(points[idx])
            } else {
                onHover?(nil)
            }
            needsDisplay = true
        }
    }

    override func mouseExited(with event: NSEvent) {
        hoveredIndex = nil
        onHover?(nil)
        needsDisplay = true
    }

    override func mouseDown(with event: NSEvent) {
        let p = convert(event.locationInWindow, from: nil)
        guard let idx = pointIndex(near: p, tolerance: 18),
              idx < points.count else { return }
        onSelect?(points[idx])
    }

    private func pointIndex(near p: CGPoint, tolerance: CGFloat) -> Int? {
        guard !points.isEmpty else { return nil }
        let (maxC, plot, xFor, yFor) = chartGeometry()
        var best: Int?
        var bestDist = tolerance * tolerance
        for (i, pt) in points.enumerated() {
            let dx = xFor(i) - p.x
            let dy = yFor(pt.complexity, maxC, plot) - p.y
            let d = dx * dx + dy * dy
            if d <= bestDist {
                bestDist = d
                best = i
            }
        }
        return best
    }

    // MARK: - Drawing

    override func draw(_ dirtyRect: NSRect) {
        NSColor.controlBackgroundColor.setFill()
        dirtyRect.fill()

        guard !points.isEmpty else {
            drawCenteredPlaceholder(placeholderText)
            return
        }

        let (maxC, plot, xFor, yFor) = chartGeometry()
        drawAxes(plot: plot, maxC: maxC)

        // Points (grid geometry is a tuple; draw after axes).
        var lastLabeled: CGPoint?
        for (i, pt) in points.enumerated() {
            let center = CGPoint(x: xFor(i), y: yFor(pt.complexity, maxC, plot))
            let isHovered = i == hoveredIndex
            let color = complexityColor(pt.complexity, maxC: maxC)

            let ring = NSBezierPath(ovalIn: NSRect(x: center.x - 9, y: center.y - 9,
                                                   width: 18, height: 18))
            color.setFill()
            ring.fill()

            if isHovered {
                let halo = NSBezierPath(ovalIn: NSRect(x: center.x - 12, y: center.y - 12,
                                                       width: 24, height: 24))
                NSColor.controlAccentColor.setStroke()
                halo.lineWidth = 2
                halo.stroke()
            }

            // Skip the in-point number when the chart is too crowded for it to be
            // legible; hovering any point still reveals its details via onHover.
            let showsLabel = isHovered || lastLabeled == nil ||
                (abs(center.x - lastLabeled!.x) >= 22 || abs(center.y - lastLabeled!.y) >= 12)

            if showsLabel {
                let label = "\(pt.complexity)" as NSString
                let attrs: [NSAttributedString.Key: Any] = [
                    .font: NSFont.monospacedSystemFont(ofSize: 9, weight: .bold),
                    .foregroundColor: NSColor.white
                ]
                let size = label.size(withAttributes: attrs)
                label.draw(at: CGPoint(x: center.x - size.width / 2, y: center.y - size.height / 2),
                           withAttributes: attrs)
                lastLabeled = center
            }
        }
    }

    /// Returns the max complexity, the plot rect, and the coordinate functions.
    /// Geometry is computed once here so draw/hit-testing stay consistent.
    private func chartGeometry() -> (maxC: Int, plot: CGRect, xFor: (Int) -> CGFloat, yFor: (Int, Int, CGRect) -> CGFloat) {
        let maxC = max(points.map { $0.complexity }.max() ?? 1, 1)
        let plot = CGRect(
            x: leftMargin,
            y: bottomMargin,
            width: max(bounds.width - leftMargin - rightMargin, 10),
            height: max(bounds.height - topMargin - bottomMargin, 10)
        )
        func xFor(_ i: Int) -> CGFloat {
            guard points.count > 1 else { return plot.midX }
            return plot.minX + (CGFloat(i) / CGFloat(points.count - 1)) * plot.width
        }
        func yFor(_ c: Int, maxC: Int, in plot: CGRect) -> CGFloat {
            plot.minY + (CGFloat(c) / CGFloat(maxC)) * plot.height
        }
        return (maxC, plot, xFor, yFor)
    }

    private func drawAxes(plot: CGRect, maxC: Int) {
        // Frame the plot area.
        let frame = NSBezierPath()
        frame.move(to: CGPoint(x: plot.minX, y: plot.minY))
        frame.line(to: CGPoint(x: plot.maxX, y: plot.minY))
        frame.line(to: CGPoint(x: plot.maxX, y: plot.maxY))
        frame.line(to: CGPoint(x: plot.minX, y: plot.maxY))
        frame.close()
        NSColor.separatorColor.setStroke()
        frame.lineWidth = 1
        frame.stroke()

        // Y ticks: 0, step, ... maxC.
        let step = max(1, Int(ceil(Double(maxC) / 6.0)))
        NSColor.secondaryLabelColor.setStroke()
        let textColor = NSColor.secondaryLabelColor
        for y in stride(from: 0, through: maxC, by: step) {
            let yy = (CGFloat(y) / CGFloat(maxC)) * plot.height + plot.minY
            let line = NSBezierPath()
            line.move(to: CGPoint(x: plot.minX, y: yy))
            line.line(to: CGPoint(x: plot.minX - 4, y: yy))
            NSColor.secondaryLabelColor.setStroke()
            line.lineWidth = 1
            line.stroke()
            (String(y) as NSString).draw(
                at: CGPoint(x: plot.minX - leftMargin + 4, y: yy - 6),
                withAttributes: [.font: NSFont.systemFont(ofSize: 10), .foregroundColor: textColor]
            )
        }

        // X axis caption + endpoints.
        ("source order →" as NSString).draw(
            at: CGPoint(x: plot.maxX - 90, y: plot.minY - 20),
            withAttributes: [.font: NSFont.systemFont(ofSize: 10), .foregroundColor: textColor]
        )
        ("1" as NSString).draw(
            at: CGPoint(x: plot.minX - 6, y: plot.minY - 20),
            withAttributes: [.font: NSFont.systemFont(ofSize: 10), .foregroundColor: textColor]
        )
        (String(points.count) as NSString).draw(
            at: CGPoint(x: plot.maxX - 12, y: plot.minY - 20),
            withAttributes: [.font: NSFont.systemFont(ofSize: 10), .foregroundColor: textColor]
        )
    }

    /// Green → yellow → red by complexity (heatmap-style).
    private func complexityColor(_ c: Int, maxC: Int) -> NSColor {
        let t = min(max(CGFloat(c) / CGFloat(maxC), 0), 1)
        let stops: [(CGFloat, (CGFloat, CGFloat, CGFloat))] = [
            (0.0, (0.18, 0.65, 0.22)),
            (0.5, (0.95, 0.80, 0.20)),
            (1.0, (0.85, 0.18, 0.12))
        ]
        for i in 0..<(stops.count - 1) {
            let (t0, c0) = stops[i]
            let (t1, c1) = stops[i + 1]
            if t >= t0 && t <= t1 {
                let u = (t - t0) / (t1 - t0)
                let r = c0.0 + (c1.0 - c0.0) * u
                let g = c0.1 + (c1.1 - c0.1) * u
                let b = c0.2 + (c1.2 - c0.2) * u
                return NSColor(calibratedRed: r, green: g, blue: b, alpha: 1)
            }
        }
        return NSColor.systemRed
    }

    private func drawCenteredPlaceholder(_ text: String) {
        let attrs: [NSAttributedString.Key: Any] = [
            .font: NSFont.systemFont(ofSize: 13),
            .foregroundColor: NSColor.secondaryLabelColor
        ]
        let s = text as NSString
        let size = s.size(withAttributes: attrs)
        s.draw(at: CGPoint(x: (bounds.width - size.width) / 2, y: (bounds.height - size.height) / 2),
               withAttributes: attrs)
    }
}
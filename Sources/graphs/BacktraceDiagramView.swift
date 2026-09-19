// by cipher.org.uk
import AppKit

/// Renders a pasted stacktrace as a left-to-right chain of clickable frame
/// nodes. Each node shows the function name, source file and line number.
/// Clicking a node fires `onNodeClick` so the source browser can jump to it.
final class BacktraceDiagramView: NSView {

    struct FrameNode {
        let functionName: String
        let fileHint: String
        let fileURL: URL?
        let line: Int
    }

    /// Fired when a frame node is clicked without being dragged.
    /// Passes the resolved file URL (nil if the file was not found in the
    /// open project) and the line number.
    var onNodeClick: ((URL?, Int) -> Void)?

    private var frames: [FrameNode] = []
    private var nodeRects: [CGRect] = []
    private var scale: CGFloat = 1
    private var offsetY: CGFloat = 0
    private var offsetX: CGFloat = 0

    private var clickNode: Int?

    private let nodeWidth: CGFloat = 196
    private let nodeHeight: CGFloat = 80
    private let laneWidth: CGFloat = 56
    private let pad: CGFloat = 24

    override var isFlipped: Bool { true }

    init() {
        super.init(frame: .zero)
        wantsLayer = true
        layer?.masksToBounds = true
    }

    required init?(coder: NSCoder) {
        fatalError("init(coder:) has not been implemented")
    }

    func display(frames: [FrameNode]) {
        self.frames = frames
        recomputeLayout()
        needsDisplay = true
    }

    private func combWidth() -> CGFloat {
        guard !frames.isEmpty else { return pad * 2 + nodeWidth }
        return pad * 2 + CGFloat(frames.count) * nodeWidth + CGFloat(frames.count - 1) * laneWidth
    }

    private func recomputeLayout() {
        let contentWidth = combWidth()
        scale = min(1, (bounds.width - 4) / max(contentWidth, 1))
        scale = max(0.1, scale)
        offsetX = (bounds.width - contentWidth * scale) / 2
        offsetY = (bounds.height - nodeHeight * scale) / 2

        nodeRects = []
        for i in 0..<frames.count {
            let x = offsetX + pad * scale + CGFloat(i) * (nodeWidth + laneWidth) * scale
            nodeRects.append(CGRect(x: x, y: offsetY, width: nodeWidth * scale, height: nodeHeight * scale))
        }
    }

    override func layout() {
        super.layout()
        recomputeLayout()
    }

    // MARK: - Hit testing & click

    private func nodeIndex(at point: CGPoint) -> Int? {
        for (i, rect) in nodeRects.enumerated() where rect.contains(point) {
            return i
        }
        return nil
    }

    override func mouseDown(with event: NSEvent) {
        clickNode = nodeIndex(at: convert(event.locationInWindow, from: nil))
    }

    override func mouseUp(with event: NSEvent) {
        defer { clickNode = nil }
        guard let clicked = clickNode,
              clicked == nodeIndex(at: convert(event.locationInWindow, from: nil)) else { return }
        let node = frames[clicked]
        onNodeClick?(node.fileURL, node.line)
    }

    // MARK: - Drawing

    override func draw(_ dirtyRect: NSRect) {
        NSColor.controlBackgroundColor.setFill()
        dirtyRect.fill()

        drawArrows()

        for (i, node) in frames.enumerated() {
            drawNode(rect: nodeRects[i], node: node)
        }

        if frames.isEmpty {
            let attrs: [NSAttributedString.Key: Any] = [
                .font: NSFont.systemFont(ofSize: 13),
                .foregroundColor: NSColor.secondaryLabelColor
            ]
            ("Analyse a stacktrace to see its frames here." as NSString)
                .draw(at: CGPoint(x: 20, y: 20), withAttributes: attrs)
        }
    }

    private func drawArrows() {
        guard frames.count > 1 else { return }
        for i in 0..<(nodeRects.count - 1) {
            let from = nodeRects[i]
            let next = nodeRects[i + 1]
            let start = CGPoint(x: from.maxX + 2, y: from.midY)
            let end = CGPoint(x: next.minX - 2, y: next.midY)
            NSColor.tertiaryLabelColor.setStroke()
            let path = NSBezierPath()
            path.move(to: start)
            path.line(to: end)
            path.lineWidth = 1.5
            path.stroke()
            drawArrowhead(from: start, to: end)
        }
    }

    private func drawArrowhead(from: CGPoint, to: CGPoint) {
        let angle = atan2(to.y - from.y, to.x - from.x)
        let len: CGFloat = 7
        let path = NSBezierPath()
        path.move(to: to)
        path.line(to: CGPoint(x: to.x - len * cos(angle - 0.4), y: to.y - len * sin(angle - 0.4)))
        path.move(to: to)
        path.line(to: CGPoint(x: to.x - len * cos(angle + 0.4), y: to.y - len * sin(angle + 0.4)))
        path.lineWidth = 1.5
        path.stroke()
    }

    private func drawNode(rect: CGRect, node: FrameNode) {
        let path = NSBezierPath(roundedRect: rect, xRadius: 9, yRadius: 9)

        let unresolved = node.fileURL == nil
        let fill: NSColor = unresolved
            ? NSColor(calibratedRed: 0.85, green: 0.22, blue: 0.16, alpha: 0.12)
            : NSColor.windowBackgroundColor
        fill.setFill()
        path.fill()

        let stroke: NSColor = unresolved ? .systemRed : .controlAccentColor
        stroke.setStroke()
        path.lineWidth = unresolved ? 1.6 : 1.2
        path.stroke()

        let textX = rect.minX + 12
        let textWidth = rect.width - 24

        // Function name
        let nameParagraph = NSMutableParagraphStyle()
        nameParagraph.lineBreakMode = .byTruncatingTail
        let nameAttrs: [NSAttributedString.Key: Any] = [
            .font: NSFont.systemFont(ofSize: 12, weight: .semibold),
            .foregroundColor: NSColor.labelColor,
            .paragraphStyle: nameParagraph
        ]
        (node.functionName.isEmpty ? "(unknown)" as NSString : node.functionName as NSString)
            .draw(in: CGRect(x: textX, y: rect.minY + 10, width: textWidth, height: 16), withAttributes: nameAttrs)

        // File + line
        let fileParagraph = NSMutableParagraphStyle()
        fileParagraph.lineBreakMode = .byTruncatingMiddle
        let fileAttrs: [NSAttributedString.Key: Any] = [
            .font: NSFont.monospacedSystemFont(ofSize: 11, weight: .regular),
            .foregroundColor: unresolved ? NSColor.systemRed : NSColor.secondaryLabelColor,
            .paragraphStyle: fileParagraph
        ]
        let fileText = "\(node.fileHint):\(node.line)" + (unresolved ? "  (not found)" : "")
        (fileText as NSString)
            .draw(in: CGRect(x: textX, y: rect.midY + 4, width: textWidth, height: 15), withAttributes: fileAttrs)
    }
}
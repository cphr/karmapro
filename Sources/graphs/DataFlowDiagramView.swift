// by cipher.org.uk
import AppKit

/// Visual settings for the animated data-flow edges. The default matches the
/// app's other diagrams (orange `[8,6]` dash); the "Find external entries"
/// window overrides this so its flows are visibly distinct.
struct FlowEdgeStyle {
    var color: NSColor = .systemOrange
    var dashes: [CGFloat] = [8, 6]
    var lineWidth: CGFloat = 2.5
    /// Dash-phase drift per animation tick (pulse speed).
    var phaseStep: CGFloat = 2.0
}

/// Renders a call/dataflow graph with animated edges showing data flowing
/// between function nodes. Drawn natively with Core Graphics + Core Animation.
final class DataFlowDiagramView: NSView {
    private var graph: CallGraph?
    private var diagramLayout: GraphLayout.Result?
    private var callEdges: [(String, String)] = []
    private var dataEdges: [(String, String)] = []

    // Mapping from layout coordinates to view coordinates so the graph is
    // scaled and centered to fill the entire visible frame.
    private var graphScale: CGFloat = 1
    private var graphOffset: CGPoint = .zero

    // Animation
    private var lineDashPhase: CGFloat = 0

    // Highlighted node (the function the user clicked)
    var highlightNode: String? {
        didSet { needsDisplay = true }
    }

    /// Fired when a node is clicked without being dragged. Passes the node's name.
    var onNodeClick: ((String) -> Void)?

    /// When true, `callEdges` are used only for layout ranking; only the animated
    /// dashed `dataEdges` are drawn (no solid call arrows).
    var animatedOnlyEdges = false

    /// Overridable style for the animated data-flow edges.
    var flowStyle = FlowEdgeStyle()

    /// Node names drawn as square "origin" boxes (no ƒ glyph) — the Internet /
    /// Local source nodes injected by the external-entries window.
    var originNodeNames: Set<String> = []

    /// Node names drawn with an amber outline — the topmost boxes in the
    /// reachability window's "no path from any entry point" state.
    var outlinedNodeNames: Set<String> = []

    /// Node names drawn as grey boxes with black text — the forward (callee)
    /// overlay in the reachability window's combined diagram.
    var greyedNodeNames: Set<String> = []

    /// Per-name fill/stroke colour for origin boxes, overriding the default
    /// accent (e.g. the amber "Topmost" terminal box).
    var originNodeColors: [String: NSColor] = [:]

    /// Layout direction forwarded to `GraphLayout.layered`. The external-entries
    /// window uses `.topToBottom` so flows descend from the origin box.
    var layoutDirection: GraphLayout.Direction = .leftToRight

    /// Nodes pinned to rank 0 (top) in `.topToBottom` mode.
    var layoutSourceNodes: Set<String> = []

    // Zoom / pan state
    private var hasUserViewTransform = false
    private let minScale: CGFloat = 0.4
    private let maxScale: CGFloat = 6.0

    // Panning drag
    private var panning = false
    private var panStartPoint: CGPoint = .zero
    private var panStartOffset: CGPoint = .zero

    override var isFlipped: Bool { true }

    private let nodeCornerRadius: CGFloat = 6
    private let nodePadding: CGFloat = 8

    init() {
        super.init(frame: .zero)
        wantsLayer = true
        // Same flipped-view-in-container layer-sync hazard as FlowChartView:
        // clip the layer to the view's frame so the graph can never paint over
        // the pane title above it.
        layer?.masksToBounds = true
    }

    required init?(coder: NSCoder) {
        fatalError("init(coder:) has not been implemented")
    }

    func display(graph: CallGraph, callEdges: [(String, String)], dataEdges: [(String, String)], highlight: String?) {
        self.graph = graph
        self.callEdges = callEdges
        self.dataEdges = dataEdges
        self.highlightNode = highlight
        self.diagramLayout = GraphLayout.layered(graph: graph, callEdges: callEdges,
                                             direction: layoutDirection,
                                             sourceNodes: layoutSourceNodes)
        // Re-fit for every new graph — a stale user transform from a previous
        // diagram would render the new one at an unrelated scale/offset.
        hasUserViewTransform = false
        recenter()
        needsDisplay = true
    }

    /// Empties the canvas (no graph) while a new trace is being computed.
    func clear() {
        graph = nil
        callEdges = []
        dataEdges = []
        highlightNode = nil
        diagramLayout = nil
        originNodeNames = []
        outlinedNodeNames = []
        greyedNodeNames = []
        originNodeColors = [:]
        layoutSourceNodes = []
        hasUserViewTransform = false
        needsDisplay = true
    }

    /// Recomputes the scale/offset that map the layout to fill this view's bounds.
    private func recenter() {
        if hasUserViewTransform { return }
        guard let d = diagramLayout else { return }
        let contentW = max(d.size.width, 1)
        let contentH = max(d.size.height, 1)
        let pad: CGFloat = 48
        let scW = (bounds.width - pad) / contentW
        let scH = (bounds.height - pad) / contentH
        graphScale = max(minScale, min(scW, scH, 3.0))
        graphOffset = CGPoint(
            x: (bounds.width - contentW * graphScale) / 2,
            y: (bounds.height - contentH * graphScale) / 2
        )
    }

    override func layout() {
        super.layout()
        recenter()
    }

    // MARK: - Node frames

    private func nodeRect(for name: String) -> CGRect {
        guard let d = diagramLayout, let pos = d.positions[name] else { return .zero }
        let s = graphScale
        return CGRect(
            x: pos.x * s + graphOffset.x,
            y: pos.y * s + graphOffset.y,
            width: nodeSize(for: name).width * s,
            height: nodeSize(for: name).height * s
        )
    }

    private func nodeSize(for name: String) -> NSSize {
        // Fixed-size box matching GraphLayout's spacing so nodes never overlap.
        // Function names are truncated to fit (see drawNode).
        return NSSize(width: 128, height: 34)
    }

    private func edgeEndpoints(from: String, to: String) -> (CGPoint, CGPoint) {
        let r1 = nodeRect(for: from)
        let r2 = nodeRect(for: to)
        // Source: bottom center of from-node; Target: top center of to-node
        let p1 = CGPoint(x: r1.midX, y: r1.maxY)
        let p2 = CGPoint(x: r2.midX, y: r2.minY)
        return (p1, p2)
    }

    /// Builds an orthogonal (L-shaped) path: vertical → horizontal → vertical,
    /// routing through a horizontal channel halfway between the two nodes' layers.
    /// This keeps edges in dedicated lanes and avoids crossing over nodes.
    private func orthogonalPath(from start: CGPoint, to end: CGPoint) -> NSBezierPath {
        let path = NSBezierPath()
        path.move(to: start)

        // Mid-Y between the two nodes — this is the horizontal channel.
        // Using a fixed offset from the start node's bottom ensures consistent lanes.
        let channelY = (start.y + end.y) / 2

        // Vertical segment from start down/up to channel
        path.line(to: CGPoint(x: start.x, y: channelY))
        // Horizontal segment across the channel
        path.line(to: CGPoint(x: end.x, y: channelY))
        // Vertical segment from channel to end
        path.line(to: end)

        return path
    }

    // MARK: - Dragging (rearrange nodes)

    private var draggingNode: String?
    private var dragStartPoint: CGPoint = .zero
    private var dragStartLayoutPos: CGPoint = .zero
    private var possibleClickNode: String?

    private func nodeAt(point: CGPoint) -> String? {
        guard diagramLayout != nil else { return nil }
        for name in diagramLayout!.positions.keys {
            if nodeRect(for: name).contains(point) { return name }
        }
        return nil
    }

    override func mouseDown(with event: NSEvent) {
        let p = convert(event.locationInWindow, from: nil)
        possibleClickNode = nodeAt(point: p)
        if let node = nodeAt(point: p) {
            draggingNode = node
            dragStartPoint = p
            dragStartLayoutPos = diagramLayout?.positions[node] ?? .zero
            NSCursor.closedHand.set()
        } else {
            panning = true
            hasUserViewTransform = true
            panStartPoint = p
            panStartOffset = graphOffset
            NSCursor.openHand.set()
        }
    }

    override func mouseDragged(with event: NSEvent) {
        let p = convert(event.locationInWindow, from: nil)
        // Any movement cancels a pending click.
        if draggingNode != nil, let start = dragStartPoint as CGPoint? {
            let moved = hypot(p.x - start.x, p.y - start.y)
            if moved > 4 { possibleClickNode = nil }
        }
        if let node = draggingNode, var d = diagramLayout {
            let dx = (p.x - dragStartPoint.x) / graphScale
            let dy = (p.y - dragStartPoint.y) / graphScale
            d.positions[node] = CGPoint(x: dragStartLayoutPos.x + dx, y: dragStartLayoutPos.y + dy)
            diagramLayout = d
            needsDisplay = true
        } else if panning {
            graphOffset = CGPoint(x: panStartOffset.x + (p.x - panStartPoint.x),
                                  y: panStartOffset.y + (p.y - panStartPoint.y))
            needsDisplay = true
        }
    }

    override func mouseUp(with event: NSEvent) {
        if let clicked = possibleClickNode {
            onNodeClick?(clicked)
        }
        draggingNode = nil
        possibleClickNode = nil
        panning = false
        NSCursor.arrow.set()
    }

    // MARK: - Zoom

    override func magnify(with event: NSEvent) {
        zoom(by: 1 + event.magnification, at: convert(event.locationInWindow, from: nil))
    }

    override func scrollWheel(with event: NSEvent) {
        // ⌘-scroll zooms; plain scrolling is ignored (see FlowChartView).
        let wantsZoom = event.modifierFlags.contains(.command)
        guard wantsZoom else { return }
        let delta = event.hasPreciseScrollingDeltas ? event.scrollingDeltaY : event.scrollingDeltaY * 10
        let factor: CGFloat = max(0.2, min(3.0, 1 + delta / 60))
        zoom(by: factor, at: convert(event.locationInWindow, from: nil))
    }

    private func zoom(by factor: CGFloat, at point: CGPoint) {
        guard diagramLayout != nil, factor > 0 else { return }
        let newScale = max(minScale, min(maxScale, graphScale * factor))
        let s = newScale / graphScale
        if s == 1 || s.isNaN { return }
        hasUserViewTransform = true
        guard !graphScale.isZero else { return }
        let contentPoint = CGPoint(x: (point.x - graphOffset.x) / graphScale,
                                   y: (point.y - graphOffset.y) / graphScale)
        graphScale = newScale
        graphOffset = CGPoint(x: point.x - contentPoint.x * graphScale,
                              y: point.y - contentPoint.y * graphScale)
        needsDisplay = true
    }

    // MARK: - Drawing

    override func draw(_ dirtyRect: NSRect) {
        guard let graph = graph else { return }

        // Background
        NSColor.controlBackgroundColor.setFill()
        dirtyRect.fill()

        // Edges
        drawEdges()

        // Nodes
        for name in graph.nodes.keys {
            let rect = nodeRect(for: name)
            let isHighlighted = name == highlightNode
            drawNode(rect: rect, name: name, highlighted: isHighlighted)
        }

        // Legend
        drawLegend()
    }

    private func drawNode(rect: CGRect, name: String, highlighted: Bool) {
        let isOrigin = originNodeNames.contains(name)
        let isGreyed = greyedNodeNames.contains(name)
        let originColor = originNodeColors[name] ?? .controlAccentColor
        let path = isOrigin
            ? NSBezierPath(rect: rect)
            : NSBezierPath(roundedRect: rect, xRadius: nodeCornerRadius, yRadius: nodeCornerRadius)

        let fill: NSColor = highlighted
            ? NSColor(calibratedRed: 0.25, green: 0.60, blue: 1.0, alpha: 0.85)  // accent highlight
            : (isOrigin ? originColor.withAlphaComponent(0.08)
                        : (isGreyed ? NSColor(calibratedWhite: 0.78, alpha: 1) : NSColor.windowBackgroundColor))
        fill.setFill()
        path.fill()

        let stroke: NSColor = highlighted ? .controlAccentColor
            : (isOrigin ? originColor : (isGreyed ? NSColor.systemGray : .separatorColor))
        stroke.setStroke()
        path.lineWidth = highlighted ? 2.5 : (isOrigin ? 1.6 : 1.0)
        path.stroke()

        // Node icon (function 'f' glyph, or a square marker for origin boxes)
        let iconColor: NSColor = isGreyed
            ? .black
            : (highlighted ? .white : (isOrigin ? originColor : .secondaryLabelColor))
        let attrs: [NSAttributedString.Key: Any] = [
            .font: NSFont.systemFont(ofSize: 11, weight: .heavy),
            .foregroundColor: iconColor
        ]
        let icon = (isOrigin ? "◼" : "ƒ") as NSString
        icon.draw(at: CGPoint(x: rect.minX + 8, y: rect.midY - 6), withAttributes: attrs)

        // Function name
        let para = NSMutableParagraphStyle()
        para.lineBreakMode = .byTruncatingTail
        let textAttrs: [NSAttributedString.Key: Any] = [
            .font: NSFont.systemFont(ofSize: 10, weight: .medium),
            .foregroundColor: isGreyed ? NSColor.black : NSColor.labelColor,
            .paragraphStyle: para
        ]
        let textRect = CGRect(x: rect.minX + 23, y: rect.midY - 6, width: rect.width - 26, height: 14)
        (name as NSString).draw(in: textRect, withAttributes: textAttrs)

        // Amber "topmost reached" halo (reachability's no-entry state): drawn
        // last so it stays on top of the fill and the regular stroke.
        if outlinedNodeNames.contains(name) {
            let halo = NSBezierPath(roundedRect: rect.insetBy(dx: -3, dy: -3),
                                    xRadius: nodeCornerRadius + 3,
                                    yRadius: nodeCornerRadius + 3)
            NSColor.systemOrange.withAlphaComponent(0.14).setFill()
            halo.fill()
            NSColor.systemOrange.setStroke()
            halo.lineWidth = 2.5
            halo.stroke()
        }
    }

    private func drawEdges() {
        // Data edges (dashed, animated) drawn UNDER call edges.
        for (from, to) in dataEdges {
            drawEdge(from: from, to: to, isCall: false)
        }
        // Call edges (solid arrows)
        if !animatedOnlyEdges {
            for (from, to) in callEdges {
                drawEdge(from: from, to: to, isCall: true)
            }
        }
    }

    private func drawEdge(from: String, to: String, isCall: Bool) {
        let (p1, p2) = edgeEndpoints(from: from, to: to)

        // Shorten the line so it doesn't run under node borders.
        let start = pointOnLine(p1, p2, distance: 8)
        let end = pointOnLine(p2, p1, distance: 8)

        let path = orthogonalPath(from: start, to: end)

        if isCall {
            // Solid call arrow
            let color: NSColor = (from == highlightNode || to == highlightNode)
                ? .controlAccentColor : NSColor.secondaryLabelColor
            color.setStroke()
            path.lineWidth = 1.5
            path.stroke()
            drawArrowhead(from: start, to: end, color: color)
        } else {
            // Animated dashed data edge (style overridable)
            flowStyle.color.setStroke()
            path.lineWidth = flowStyle.lineWidth
            path.setLineDash(flowStyle.dashes, count: flowStyle.dashes.count, phase: lineDashPhase)
            path.stroke()
            drawArrowhead(from: start, to: end, color: flowStyle.color)
        }
    }

    private func drawArrowhead(from: CGPoint, to: CGPoint, color: NSColor) {
        let angle = atan2(to.y - from.y, to.x - from.x)
        let arrowLen: CGFloat = 9
        let path = NSBezierPath()
        path.move(to: to)
        path.line(to: CGPoint(x: to.x - arrowLen * cos(angle - 0.4), y: to.y - arrowLen * sin(angle - 0.4)))
        path.move(to: to)
        path.line(to: CGPoint(x: to.x - arrowLen * cos(angle + 0.4), y: to.y - arrowLen * sin(angle + 0.4)))
        color.setStroke()
        path.lineWidth = 2
        path.stroke()
    }

    private func pointOnLine(_ from: CGPoint, _ to: CGPoint, distance: CGFloat) -> CGPoint {
        let dx = to.x - from.x
        let dy = to.y - from.y
        let len = sqrt(dx * dx + dy * dy)
        guard len > 0 else { return from }
        return CGPoint(x: from.x + dx / len * distance, y: from.y + dy / len * distance)
    }

    private func drawLegend() {
        let x: CGFloat = 14
        var y: CGFloat = 14

        // Call legend
        NSColor.secondaryLabelColor.setStroke()
        let callPath = NSBezierPath()
        callPath.move(to: CGPoint(x: x, y: y))
        callPath.line(to: CGPoint(x: x + 26, y: y))
        callPath.lineWidth = 1.5
        callPath.stroke()
        drawString("Function call", at: CGPoint(x: x + 34, y: y - 8))

        // Data legend
        y += 24
        NSColor.systemOrange.setStroke()
        let dataPath = NSBezierPath()
        dataPath.move(to: CGPoint(x: x, y: y))
        dataPath.line(to: CGPoint(x: x + 26, y: y))
        dataPath.setLineDash([6, 4], count: 2, phase: 0)
        dataPath.lineWidth = 2.5
        dataPath.stroke()
        drawString("Data flow (animated)", at: CGPoint(x: x + 34, y: y - 8))
    }

    private func drawString(_ s: String, at p: CGPoint) {
        let attrs: [NSAttributedString.Key: Any] = [
            .font: NSFont.systemFont(ofSize: 11),
            .foregroundColor: NSColor.secondaryLabelColor
        ]
        (s as NSString).draw(at: p, withAttributes: attrs)
    }

    // MARK: - Animation

    override func viewDidMoveToWindow() {
        super.viewDidMoveToWindow()
        stopTicker()
        if window != nil {
            startTicker()
        }
    }

    private var ticker: Timer?
    private func startTicker() {
        ticker = Timer.scheduledTimer(withTimeInterval: 1.0 / 30.0, repeats: true) { [weak self] _ in
            guard let self = self, self.window != nil else { return }
            self.lineDashPhase -= self.flowStyle.phaseStep
            self.setNeedsDisplay(self.bounds)
        }
    }
    private func stopTicker() {
        ticker?.invalidate()
        ticker = nil
    }

    deinit {
        stopTicker()
    }
}

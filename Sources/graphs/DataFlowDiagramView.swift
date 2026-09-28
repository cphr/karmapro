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

    // Per-edge lane offsets: every edge sharing a corridor (same source row,
    // same target row) gets its own vertical offset so parallel edges between
    // two ranks no longer paint over one another. Keyed by direction+pair.
    private var edgeLanes: [String: CGFloat] = [:]

    /// "One-path" focus mode: when non-nil, only the named nodes (plus their
    /// revealed neighbours) are drawn and hit-testable; every other node in the
    /// graph stays hidden until revealed via a node's ⊕ badge. nil = draw the
    /// whole graph. Used by the reachability window so a huge reverse caller
    /// chain starts focused on a single readable path instead of everything at once.
    var focusNodes: Set<String>? {
        didSet { needsDisplay = true }
    }

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

    /// When set, the diagram uses a butterfly layout centred on this node
    /// (callers fan out to the left, callees to the right). Used by the
    /// "Show flow diagram for" window; leave nil for the other diagrams.
    var layoutCenterNode: String?

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
        computeLayout()
        // Re-fit for every new graph — a stale user transform from a previous
        // diagram would render the new one at an unrelated scale/offset.
        hasUserViewTransform = false
        recenter()
        computeEdgeLanes()
        needsDisplay = true
    }

    /// Lays out the graph. In focus mode the layout runs over only the visible
    /// (focus-path) nodes and their edges, so a few revealed functions are packed
    /// tightly instead of staying at their far-apart positions in the full graph.
    private func computeLayout() {
        guard let graph = graph else { return }
        if let focus = focusNodes {
            let visible = graph.nodes.keys.filter { isNodeVisible($0) }
            let sub = CallGraph()
            for name in visible { _ = sub.node(for: name) }
            let subEdges = (callEdges + dataEdges).filter {
                isNodeVisible($0) && isNodeVisible($1)
            }
            for e in subEdges { sub.addCall(from: e.0, to: e.1) }
            if let center = layoutCenterNode, focus.contains(center) {
                self.diagramLayout = GraphLayout.butterfly(graph: sub, callEdges: subEdges, center: center)
            } else {
                self.diagramLayout = GraphLayout.layered(graph: sub, callEdges: subEdges,
                                                     direction: layoutDirection,
                                                     sourceNodes: layoutSourceNodes.filter { focus.contains($0) })
            }
        } else if let center = layoutCenterNode {
            self.diagramLayout = GraphLayout.butterfly(graph: graph, callEdges: callEdges, center: center)
        } else {
            self.diagramLayout = GraphLayout.layered(graph: graph, callEdges: callEdges,
                                                 direction: layoutDirection,
                                                 sourceNodes: layoutSourceNodes)
        }
    }

    /// Empty key for a directed edge, direction-tagged so a call and a data
    /// edge between the same two nodes never share a lane.
    private func edgeKey(_ from: String, _ to: String, isCall: Bool) -> String {
        (isCall ? "C" : "D") + "\u{1}" + from + "\u{1}" + to
    }

    /// Assigns each edge a lane offset within its corridor. A corridor is the
    /// set of edges connecting the same two node rows; without lanes they would
    /// all collapse onto the shared `(start.y + end.y)/2` channel. Offsets are
    /// centred so the corridor reads as a band of parallel spokes.
    private func computeEdgeLanes() {
        edgeLanes = [:]
        guard let d = diagramLayout else { return }
        let laneSpacing: CGFloat = 6
        var corridors: [String: [(String, String, Bool)]] = [:]
        var corridorOrder: [String] = []
        func register(_ from: String, _ to: String, isCall: Bool) {
            guard isNodeVisible(from), isNodeVisible(to) else { return }
            guard let p1 = d.positions[from], let p2 = d.positions[to] else { return }
            // Round to the row pair so near-identical lanes group together.
            let key = "\(Int(p1.y.rounded()))\u{1}\(Int(p2.y.rounded()))"
            if corridors[key] == nil { corridorOrder.append(key) }
            corridors[key, default: []].append((from, to, isCall))
        }
        for (from, to) in callEdges { register(from, to, isCall: true) }
        for (from, to) in dataEdges { register(from, to, isCall: false) }
        for key in corridorOrder {
            guard let edges = corridors[key] else { continue }
            let n = edges.count
            for (i, e) in edges.enumerated() {
                let offset = (CGFloat(i) - CGFloat(n - 1) / 2) * laneSpacing
                edgeLanes[edgeKey(e.0, e.1, isCall: e.2)] = offset
            }
        }
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
        layoutCenterNode = nil
        focusNodes = nil
        hasUserViewTransform = false
        needsDisplay = true
    }

    /// True when `name` is drawn in focus mode (or focus mode is off and the
    /// whole graph is visible).
    private func isNodeVisible(_ name: String) -> Bool {
        focusNodes == nil || focusNodes?.contains(name) == true
    }

    /// True when `name` has at least one neighbour (caller or callee) in the full
    /// graph that is currently hidden — such nodes get a ⊕ reveal badge.
    private func hasHiddenNeighbors(_ name: String) -> Bool {
        guard focusNodes != nil, diagramLayout != nil else { return false }
        for (from, to) in callEdges + dataEdges {
            if from == name, !isNodeVisible(to) { return true }
            if to == name, !isNodeVisible(from) { return true }
        }
        return false
    }

    /// Reveals the hidden neighbours of `name` by adding them to `focusNodes`,
    /// then re-lays-out and re-fits so the expanded set stays tightly packed.
    private func reveal(_ name: String) {
        guard var focus = focusNodes, diagramLayout != nil else { return }
        for (from, to) in callEdges + dataEdges {
            if from == name, !isNodeVisible(to) { _ = focus.insert(to) }
            if to == name, !isNodeVisible(from) { _ = focus.insert(from) }
        }
        focusNodes = focus
        computeLayout()
        hasUserViewTransform = false
        recenter()
        computeEdgeLanes()
        needsDisplay = true
    }

    /// Rect of the small ⊕ expand badge shown top-right on nodes that have
    /// hidden neighbours (view coordinates). Nil when `name` has nothing to reveal.
    private func expandBadgeRect(for name: String) -> CGRect? {
        guard hasHiddenNeighbors(name) else { return nil }
        let r = nodeRect(for: name)
        let s: CGFloat = 13
        return CGRect(x: r.maxX - s - 3, y: r.minY + 3, width: s, height: s)
    }

    /// Recomputes the scale/offset that map the layout to fill this view's bounds.
    /// In focus mode the view is fitted to the visible (focus-path) nodes rather
    /// than the whole hidden graph, so the focused chain stays large and readable.
    /// Skips zero-sized bounds (the view isn't laid out yet — e.g. display() ran
    /// before the window was shown); `layout()`/`draw()` re-fit once real bounds exist.
    private func recenter() {
        if hasUserViewTransform { return }
        guard let d = diagramLayout else { return }
        guard bounds.width > 0, bounds.height > 0 else { return }
        let visible = d.positions.keys.filter { isNodeVisible($0) }
        let nodeW = nodeSize(for: "").width
        let nodeH = nodeSize(for: "").height
        let contentW: CGFloat
        let contentH: CGFloat
        var originX: CGFloat = 0
        var originY: CGFloat = 0
        if visible.isEmpty {
            contentW = max(d.size.width, 1)
            contentH = max(d.size.height, 1)
        } else {
            var minX = CGFloat.greatestFiniteMagnitude
            var minY = CGFloat.greatestFiniteMagnitude
            var maxX = -CGFloat.greatestFiniteMagnitude
            var maxY = -CGFloat.greatestFiniteMagnitude
            for n in visible {
                guard let p = d.positions[n] else { continue }
                minX = min(minX, p.x); minY = min(minY, p.y)
                maxX = max(maxX, p.x + nodeW); maxY = max(maxY, p.y + nodeH)
            }
            contentW = max(maxX - minX, 1)
            contentH = max(maxY - minY, 1)
            originX = minX
            originY = minY
        }
        let pad: CGFloat = 48
        let scW = (bounds.width - pad) / contentW
        let scH = (bounds.height - pad) / contentH
        graphScale = max(minScale, min(scW, scH, 3.0))
        graphOffset = CGPoint(
            x: (bounds.width - contentW * graphScale) / 2 - originX * graphScale,
            y: (bounds.height - contentH * graphScale) / 2 - originY * graphScale
        )
        lastFitBounds = bounds
    }

    /// Bounds used by the most recent `recenter()` — used to detect when the view
    /// has grown/been laid out so `draw()` can re-fit a diagram that was built
    /// before the window existed (which would otherwise sit off-center).
    private var lastFitBounds: CGRect = .zero

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
    /// routing through a lane within the corridor between the two nodes' layers.
    /// This keeps edges in dedicated lanes and avoids crossing over nodes.
    /// `lane` vertically offsets the shared channel so parallel corridors read
    /// as spokes instead of collapsing onto one line.
    private func orthogonalPath(from start: CGPoint, to end: CGPoint, lane: CGFloat = 0) -> NSBezierPath {
        let path = NSBezierPath()
        path.move(to: start)

        // Mid-Y between the two nodes — this is the horizontal channel.
        // Using a fixed offset from the start node's bottom ensures consistent lanes.
        let channelY = (start.y + end.y) / 2 + lane

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
        for name in diagramLayout!.positions.keys where isNodeVisible(name) {
            if nodeRect(for: name).contains(point) { return name }
        }
        return nil
    }

    override func mouseDown(with event: NSEvent) {
        let p = convert(event.locationInWindow, from: nil)
        // Focus-mode ⊕ badge: clicking it reveals that node's hidden neighbours
        // instead of starting a drag or firing a normal node click.
        if focusNodes != nil, diagramLayout != nil {
            for name in diagramLayout!.positions.keys where isNodeVisible(name) {
                if let badge = expandBadgeRect(for: name), badge.contains(p) {
                    reveal(name)
                    return
                }
            }
        }
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

        // Re-fit if the view has been laid out/grown since the last recenter.
        // display() often runs before the window gets real bounds, so this keeps
        // even small diagrams centred on first paint instead of needing a resize.
        if diagramLayout != nil, bounds != lastFitBounds {
            recenter()
        }

        // Background
        NSColor.controlBackgroundColor.setFill()
        dirtyRect.fill()

        // Edges
        drawEdges()

        // Nodes
        for name in graph.nodes.keys where isNodeVisible(name) {
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

        // Focus-mode ⊕ reveal badge: drawn on hidden-neighbour nodes so the user
        // can expand the focused path one hop at a time.
        if let badge = expandBadgeRect(for: name) {
            let bp = NSBezierPath(ovalIn: badge)
            NSColor.controlAccentColor.setFill()
            bp.fill()
            let plus = "+" as NSString
            let pa: [NSAttributedString.Key: Any] = [
                .font: NSFont.systemFont(ofSize: 11, weight: .bold),
                .foregroundColor: NSColor.white
            ]
            let ps = plus.size(withAttributes: pa)
            plus.draw(at: CGPoint(x: badge.midX - ps.width / 2, y: badge.midY - ps.height / 2),
                      withAttributes: pa)
        }
    }

    private func drawEdges() {
        // Data edges (dashed, animated) drawn UNDER call edges.
        for (from, to) in dataEdges where isNodeVisible(from) && isNodeVisible(to) {
            drawEdge(from: from, to: to, isCall: false)
        }
        // Call edges (solid arrows). A pair that is also a data edge is drawn
        // only as the animated dashed line (a call carries data flow), so the
        // solid duplicate is skipped. Purely-call pairs still render solid.
        if !animatedOnlyEdges {
            let dataPairs = Set(dataEdges.filter { isNodeVisible($0) && isNodeVisible($1) }
                                            .map { $0 + "\u{1}" + $1 })
            for (from, to) in callEdges where isNodeVisible(from) && isNodeVisible(to)
                && !dataPairs.contains(from + "\u{1}" + to) {
                drawEdge(from: from, to: to, isCall: true)
            }
        }
    }

    private func drawEdge(from: String, to: String, isCall: Bool) {
        let (p1, p2) = edgeEndpoints(from: from, to: to)

        // Shorten the line so it doesn't run under node borders.
        let start = pointOnLine(p1, p2, distance: 8)
        let end = pointOnLine(p2, p1, distance: 8)

        let lane = (edgeLanes[edgeKey(from, to, isCall: isCall)] ?? 0) * graphScale
        let path = orthogonalPath(from: start, to: end, lane: lane)

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
            // Re-fit on attach to a real window: the initial layout pass may have
            // run while the view still had zero-sized bounds (diagram built in a
            // controller init before the window is shown).
            recenter()
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

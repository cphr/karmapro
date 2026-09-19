// by cipher.org.uk
import AppKit

/// Renders a function's control-flow flowchart (from `ControlFlowParser`) as
/// draggable, auto-scaling blocks that fit the visible frame.
final class FlowChartView: NSView {
    private var flow: ControlFlowParser?

    // Layout: position per node id (layout coords), scaling/offset to fit frame.
    private var positions: [Int: CGPoint] = [:]
    private var contentSize: CGSize = .zero
    private var graphScale: CGFloat = 1
    private var graphOffset: CGPoint = .zero

    override var isFlipped: Bool { true }

    // Dragging
    private var draggingNode: Int?
    private var dragStartPoint: CGPoint = .zero
    private var dragStartLayoutPos: CGPoint = .zero

    // Panning when zoomed
    private var panning = false
    private var panStartPoint: CGPoint = .zero
    private var panStartOffset: CGPoint = .zero
    private var hasUserViewTransform = false

    // Zoom bounds
    private let minScale: CGFloat = 0.15
    private let maxScale: CGFloat = 6.0

    private let hGap: CGFloat = 40
    private let vGap: CGFloat = 44

    init() {
        super.init(frame: .zero)
        wantsLayer = true
        // The chart is a flipped view inside a non-flipped container. AppKit's
        // layer sync can composite this backing layer with a vertical offset
        // (content observed painting over the complexity header above the
        // chart). Clipping the layer to the view's own frame makes that
        // impossible: the flowchart can never paint outside its pane.
        layer?.masksToBounds = true
    }

    required init?(coder: NSCoder) {
        fatalError("init(coder:) has not been implemented")
    }

    func show(_ flow: ControlFlowParser) {
        self.flow = flow
        // Each new chart re-fits the frame: a stale user transform (pan/zoom left
        // over from a previous function) would otherwise render the new graph at
        // an unrelated scale/offset — effectively making it invisible.
        hasUserViewTransform = false
        computeLayout()
        recenter()
        needsDisplay = true
    }

    func clear() {
        flow = nil
        positions = [:]
        needsDisplay = true
    }

    // MARK: - Layout

    private func nodeKind(_ n: ControlFlowParser.Node) -> ControlFlowParser.Node.Kind {
        n.kind
    }

    private func nodeLabel(_ n: ControlFlowParser.Node) -> String {
        switch n.kind {
        case .block(let t): return t
        case .decision(let t): return t
        case .switchCase(let t): return t
        case .entry: return "START"
        case .exit: return "END"
        case .join: return ""
        }
    }

    private func isDecision(_ k: ControlFlowParser.Node.Kind) -> Bool {
        if case .decision = k { return true }; return false
    }
    private func isSwitchCase(_ k: ControlFlowParser.Node.Kind) -> Bool {
        if case .switchCase = k { return true }; return false
    }
    private func isEntryExit(_ k: ControlFlowParser.Node.Kind) -> Bool {
        k == .entry || k == .exit
    }

    private func nodeSize(_ n: ControlFlowParser.Node) -> NSSize {
        let text = nodeLabel(n) as NSString
        let font = NSFont.systemFont(ofSize: 11, weight: .medium)
        let maxW: CGFloat = 220
        let ts = text.boundingRect(
            with: NSSize(width: maxW, height: .greatestFiniteMagnitude),
            options: [.usesLineFragmentOrigin, .usesFontLeading],
            attributes: [.font: font]
        )
        var w = ceil(ts.width) + 20
        var h = ceil(ts.height) + 16
        switch n.kind {
        case .decision:
            w = max(w, 64); h = max(h, 44)
        case .switchCase:
            w = max(w, 56); h = max(h, 28)
        case .entry, .exit:
            w = max(w, 56); h = max(h, 28)
        case .join:
            w = 16; h = 16
        default:
            w = max(w, 80); h = max(h, 30)
        }
        return NSSize(width: w, height: h)
    }

    private func computeLayout() {
        guard let flow = flow else { positions = [:]; contentSize = .zero; return }
        let nodes = flow.nodes
        let byID = Dictionary(uniqueKeysWithValues: nodes.map { ($0.id, $0) })

        // Longest-path layering, ignoring back-edges.
        var level: [Int: Int] = [:]
        func levelOf(_ id: Int) -> Int {
            if let l = level[id] { return l }
            let incoming = flow.edges.filter { !$0.isBackEdge && $0.to == id }
            var l = 0
            for e in incoming { l = max(l, levelOf(e.from) + 1) }
            level[id] = l
            return l
        }
        for n in nodes { _ = levelOf(n.id) }
        _ = byID

        var layers: [Int: [Int]] = [:]
        for n in nodes { layers[level[n.id] ?? 0, default: []].append(n.id) }

        // Layer extents.
        var maxRowWidth: CGFloat = 0
        var rowHeights: [Int: CGFloat] = [:]
        var rowWidths: [Int: CGFloat] = [:]
        for (l, ids) in layers {
            let sorted = ids.sorted()
            var w: CGFloat = 0
            var maxH: CGFloat = 0
            for id in sorted {
                let s = nodeSize(byID[id]!)
                if w > 0 { w += hGap }
                w += s.width
                maxH = max(maxH, s.height)
            }
            rowWidths[l] = w
            rowHeights[l] = maxH
            maxRowWidth = max(maxRowWidth, w)
        }

        // Place nodes centered per row, stacked top to bottom.
        var yAccum: CGFloat = 0
        let maxLevel = (level.values.max() ?? 0)
        for l in 0...maxLevel {
            let ids = (layers[l] ?? []).sorted()
            guard !ids.isEmpty else { continue }
            let rowW = rowWidths[l] ?? 0
            var x = (maxRowWidth - rowW) / 2
            for id in ids {
                let s = nodeSize(byID[id]!)
                positions[id] = CGPoint(x: x, y: yAccum)
                x += s.width + hGap
            }
            yAccum += (rowHeights[l] ?? 30) + vGap
        }

        contentSize = CGSize(width: maxRowWidth, height: yAccum + 10)
    }

    private func recenter() {
        if hasUserViewTransform { return }
        let contentW = max(contentSize.width, 1)
        let contentH = max(contentSize.height, 1)
        let pad: CGFloat = 40
        let scW = (bounds.width - pad) / contentW
        let scH = (bounds.height - pad) / contentH
        graphScale = max(minScale, min(scW, scH, 2.5))
        graphOffset = CGPoint(
            x: (bounds.width - contentW * graphScale) / 2,
            y: (bounds.height - contentH * graphScale) / 2
        )
    }

    /// Re-fits and centers the flowchart in the available frame, discarding any
    /// previous pan/zoom so the whole graph is visible. Called by the Center button.
    func center() {
        hasUserViewTransform = false
        recenter()
        needsDisplay = true
    }

    override func layout() {
        super.layout()
        recenter()
    }

    private func nodeRect(_ id: Int) -> CGRect {
        guard let p = positions[id] else { return .zero }
        guard let flow = flow, let n = flow.nodes.first(where: { $0.id == id }) else { return .zero }
        let s = nodeSize(n)
        return CGRect(x: p.x * graphScale + graphOffset.x,
                      y: p.y * graphScale + graphOffset.y,
                      width: s.width * graphScale,
                      height: s.height * graphScale)
    }

    // MARK: - Dragging

    private func nodeAt(point: CGPoint) -> Int? {
        guard let flow = flow else { return nil }
        for n in flow.nodes where n.kind != .entry && n.kind != .exit && n.kind != .join {
            if nodeRect(n.id).insetBy(dx: -4, dy: -4).contains(point) { return n.id }
        }
        return nil
    }

    override func mouseDown(with event: NSEvent) {
        let p = convert(event.locationInWindow, from: nil)
        if let id = nodeAt(point: p) {
            draggingNode = id
            dragStartPoint = p
            dragStartLayoutPos = positions[id] ?? .zero
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
        if let id = draggingNode {
            positions[id] = CGPoint(x: dragStartLayoutPos.x + (p.x - dragStartPoint.x) / graphScale,
                                    y: dragStartLayoutPos.y + (p.y - dragStartPoint.y) / graphScale)
            needsDisplay = true
        } else if panning {
            graphOffset = CGPoint(x: panStartOffset.x + (p.x - panStartPoint.x),
                                  y: panStartOffset.y + (p.y - panStartPoint.y))
            needsDisplay = true
        }
    }

    override func mouseUp(with event: NSEvent) {
        draggingNode = nil
        panning = false
        NSCursor.arrow.set()
    }

    // MARK: - Zoom

    override func magnify(with event: NSEvent) {
        zoom(by: 1 + event.magnification, at: convert(event.locationInWindow, from: nil))
    }

    override func scrollWheel(with event: NSEvent) {
        // Scroll events must NOT zoom: the user scrolling source text with the
        // cursor resting over this panel would otherwise shrink/pan the chart a
        // little at a time until it becomes an invisible speck (and because the
        // transform is sticky, every later chart inherits it). Zoom stays on
        // pinch (magnify) and ⌘-scroll.
        let wantsZoom = event.modifierFlags.contains(.command)
        guard wantsZoom else { return }
        let delta = event.hasPreciseScrollingDeltas ? event.scrollingDeltaY : event.scrollingDeltaY * 10
        let factor: CGFloat = max(0.2, min(3.0, 1 + delta / 60))
        zoom(by: factor, at: convert(event.locationInWindow, from: nil))
    }

    private func zoom(by factor: CGFloat, at point: CGPoint) {
        guard flow != nil, factor > 0 else { return }
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
        guard let flow = flow else { return }
        NSColor.controlBackgroundColor.setFill()
        dirtyRect.fill()

        // Edges first.
        for e in flow.edges {
            drawEdge(e)
        }
        // Nodes.
        for n in flow.nodes {
            drawNode(n)
        }
    }

    private func nodeColor(_ kind: ControlFlowParser.Node.Kind) -> NSColor {
        switch kind {
        case .entry: return NSColor(calibratedRed: 0.20, green: 0.60, blue: 0.35, alpha: 1.0)
        case .exit: return NSColor(calibratedRed: 0.78, green: 0.30, blue: 0.30, alpha: 1.0)
        case .decision: return NSColor.controlAccentColor
        case .switchCase: return NSColor.systemOrange
        case .join: return .separatorColor
        default: return .windowBackgroundColor
        }
    }

    private func textColor(for kind: ControlFlowParser.Node.Kind) -> NSColor {
        switch kind {
        case .entry, .exit: return .white
        case .decision: return .white
        case .switchCase: return .black
        default: return .labelColor
        }
    }

    private func drawNode(_ n: ControlFlowParser.Node) {
        let rect = nodeRect(n.id)
        if n.kind == .join {
            NSColor.separatorColor.setFill()
            NSBezierPath(ovalIn: rect).fill()
            return
        }
        let color = nodeColor(n.kind)
        color.setFill()
        let radius: CGFloat = (n.kind == .entry || n.kind == .exit) ? rect.height / 2 : 6
        NSBezierPath(roundedRect: rect, xRadius: radius, yRadius: radius).fill()

        if !isDecision(n.kind) {
            // subtle border
            let stroke = isSwitchCase(n.kind) ? NSColor.systemOrange : NSColor.separatorColor
            stroke.setStroke()
            NSBezierPath(roundedRect: rect, xRadius: radius, yRadius: radius).stroke()
        }

        // Text
        let text = nodeLabel(n) as NSString
        if text.length == 0 { return }
        let attrs: [NSAttributedString.Key: Any] = [
            .font: NSFont.systemFont(ofSize: 11, weight: .medium),
            .foregroundColor: textColor(for: n.kind)
        ]
        let insets: CGFloat = 6
        let tr = rect.insetBy(dx: insets, dy: insets)
        let para = NSMutableParagraphStyle()
        para.lineBreakMode = .byTruncatingTail
        para.alignment = .center
        var mAttrs = attrs
        mAttrs[.paragraphStyle] = para
        if n.kind == .entry || n.kind == .exit || isSwitchCase(n.kind) {
            text.draw(in: tr, withAttributes: mAttrs)
        } else {
            text.draw(in: tr, withAttributes: attrs)
        }
    }

    private func drawEdge(_ e: ControlFlowParser.Edge) {
        let r1 = nodeRect(e.from)
        let r2 = nodeRect(e.to)
        let c1 = CGPoint(x: r1.midX, y: r1.midY)
        let c2 = CGPoint(x: r2.midX, y: r2.midY)

        let color: NSColor
        if e.isBackEdge {
            color = NSColor.systemBlue
        } else if e.branch == "T" {
            color = NSColor.systemGreen
        } else if e.branch == "F" {
            color = NSColor.systemRed
        } else {
            color = NSColor.secondaryLabelColor
        }
        color.setStroke()

        let path = NSBezierPath()
        path.lineWidth = e.isBackEdge ? 1.3 : 1.0
        if e.isBackEdge {
            path.move(to: c1)
            path.curve(to: c2, controlPoint1: c1, controlPoint2: c2)
            path.stroke()
        } else {
            path.move(to: c1)
            path.line(to: c2)
            path.stroke()
        }

        if let b = e.branch, b == "T" || b == "F" {
            // label mid-edge
            let mid = CGPoint(x: (c1.x + c2.x) / 2 + 6, y: (c1.y + c2.y) / 2)
            let attrs: [NSAttributedString.Key: Any] = [
                .font: NSFont.systemFont(ofSize: 10, weight: .bold),
                .foregroundColor: (b == "T") ? NSColor.systemGreen : NSColor.systemRed
            ]
            (b as NSString).draw(at: mid, withAttributes: attrs)
        }
    }
}

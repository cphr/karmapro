// by cipher.org.uk
import AppKit

/// Renders the refined variable-flow diagram: a flowchart of the enclosing
/// function (highlighting the statements that use the traced variable) with
/// "callee boxes" on the right — one per call site where the value was passed to
/// a project-defined function. Each box lists the callee's own source lines
/// where the mapped parameter is used, and may nest further callee boxes
/// recursively. A "call" arrow runs from the call statement into the box; a
/// "return" arrow reconnects the box to the statement just after the call.
///
/// Charts via `ControlFlowParser` for the C/ObjC/C++/Java/C#/Kotlin/Go/Rust/
/// Python/Ruby dialects. For languages it cannot chart (PHP/JS/Swift/Solidity)
/// the start frame degrades to the same box style, so the trace stays readable.
///
/// Clicking a highlighted flowchart statement opens its line in the caller file;
/// clicking a source line inside a box opens the callee file/line.
final class VariableFlowDiagramView: NSView {

    /// Fired when a node / source line is clicked (opened in the source viewer).
    var onOpenLocation: ((URL, Int) -> Void)?

    // MARK: - Model

    private var resultInput: VariableFlowResult?

    /// A flowchart statement node plus its mapped file line and highlight state.
    private struct FlowViewNode {
        let id: Int
        let kind: ControlFlowParser.Node.Kind
        let line: Int?
        let highlighted: Bool
        let size: CGSize
    }

    /// Layout-time record describing one callout box (root or nested).
    private struct BoxRender {
        var rect: CGRect
        let header: String
        let subtitle: String
        let rows: [(line: Int, text: String)]
        let moreCount: Int
        let deeperCollapsed: Bool
    }

    /// A clickable source region inside a callout box (a callee use line).
    private struct Tap {
        let rect: CGRect
        let url: URL
        let line: Int
    }

    // Build state
    private var flowNodes: [FlowViewNode] = []
    private var flowEdges: [ControlFlowParser.Edge] = []
    private var flowPositions: [Int: CGPoint] = [:]
    private var boxRenders: [String: BoxRender] = [:]
    private var rootBoxIDs: [String] = []
    private var callEdges: [(anchor: Int, box: String)] = []
    private var returnEdges: [(box: String, target: Int)] = []
    private var calloutTaps: [Tap] = []
    private var contentSize: CGSize = .zero
    private var startFileURL: URL?

    // View transform
    private var graphScale: CGFloat = 1
    private var graphOffset: CGPoint = .zero
    private var hasUserViewTransform = false
    private let minScale: CGFloat = 0.15
    private let maxScale: CGFloat = 6.0

    // Interaction
    private var panning = false
    private var panStartPoint: CGPoint = .zero
    private var panStartOffset: CGPoint = .zero
    private var draggingFlow: Int?
    private var draggingBox: String?
    private var dragStartPoint: CGPoint = .zero
    private var dragStartFlowPos: CGPoint = .zero
    private var dragStartBoxRect: CGRect = .zero
    private var downPoint: CGPoint = .zero
    private var didMove = false

    override var isFlipped: Bool { true }

    // Layout metrics (layout space).
    private enum LM {
        static let hGap: CGFloat = 40
        static let vGap: CGFloat = 44
        static let boxW: CGFloat = 320
        static let panelGap: CGFloat = 96
        static let pad: CGFloat = 8
        static let headerH: CGFloat = 18
        static let subtitleH: CGFloat = 12
        static let rowH: CGFloat = 16
        static let maxRows = 10
        static let childIndent: CGFloat = 14
        static let maxNest = 4
    }

    init() {
        super.init(frame: .zero)
        wantsLayer = true
        layer?.masksToBounds = true
    }

    required init?(coder: NSCoder) {
        fatalError("init(coder:) has not been implemented")
    }

    // MARK: - Entry point

    func display(result: VariableFlowResult) {
        resultInput = result
        startFileURL = result.nodes.first(where: { $0.isStart })?.fileURL
        flowNodes = []
        flowEdges = []
        flowPositions = [:]
        boxRenders = [:]
        rootBoxIDs = []
        callEdges = []
        returnEdges = []
        calloutTaps = []
        childBoxCounter = 0
        contentSize = .zero

        if !result.nodes.isEmpty, !result.startFunction.isEmpty,
           let flow = ControlFlowParser.analyze(source: result.startFileSource,
                                                ext: result.startFileExt,
                                                functionName: result.startFunction) {
            buildFlowArtwork(result: result, flow: flow)
        } else if !result.nodes.isEmpty {
            buildFallbackArtwork(result: result)
        }

        hasUserViewTransform = false
        recenter()
        needsDisplay = true
    }

    /// Empties the canvas while a new trace is being computed.
    func clear() {
        resultInput = nil
        startFileURL = nil
        flowNodes = []
        flowEdges = []
        flowPositions = [:]
        boxRenders = [:]
        rootBoxIDs = []
        callEdges = []
        returnEdges = []
        calloutTaps = []
        childBoxCounter = 0
        contentSize = .zero
        hasUserViewTransform = false
        needsDisplay = true
    }

    // MARK: - Flowchart artwork (chartable dialects)

    private func buildFlowArtwork(result: VariableFlowResult, flow: ControlFlowParser) {
        var bodyRange = NSRange(location: NSNotFound, length: 0)
        for def in diagramDefinitions(source: result.startFileSource, ext: result.startFileExt)
            where def.name == result.startFunction {
            bodyRange = def.bodyRange
            break
        }
        let lang = DiagramLanguage.from(ext: result.startFileExt)
        let indentation = lang?.usesIndentation == true
        let startLines = Set(result.nodes.first(where: { $0.isStart })?.lines ?? [])

        let views: [FlowViewNode] = flow.nodes.map { n in
            let line = n.sourceLine ?? ControlFlowParser.line(forOffset: n.loc,
                                                             bodyRange: bodyRange,
                                                             in: result.startFileSource,
                                                             indentationNormalized: indentation)
            return FlowViewNode(id: n.id,
                                kind: n.kind,
                                line: line,
                                highlighted: line.map { startLines.contains($0) } ?? false,
                                size: Self.flowNodeSize(n.kind))
        }
        flowNodes = views
        flowEdges = flow.edges

        // Longest-path layering (ignoring back edges), as in FlowChartView.
        var level: [Int: Int] = [:]
        func levelOf(_ id: Int) -> Int {
            if let l = level[id] { return l }
            var l = 0
            for e in flowEdges where !e.isBackEdge && e.to == id {
                l = max(l, levelOf(e.from) + 1)
            }
            level[id] = l
            return l
        }
        for n in flow.nodes { _ = levelOf(n.id) }

        var layers: [Int: [Int]] = [:]
        for n in flow.nodes { layers[level[n.id] ?? 0, default: []].append(n.id) }
        let maxLevel = (level.values.max() ?? 0)

        var rowWidths: [Int: CGFloat] = [:]
        var rowHeights: [Int: CGFloat] = [:]
        var maxRowWidth: CGFloat = 0
        for (l, ids) in layers {
            let sorted = ids.sorted()
            var w: CGFloat = 0
            var h: CGFloat = 0
            for id in sorted {
                let s = views.first { $0.id == id }?.size ?? CGSize(width: 80, height: 30)
                if w > 0 { w += LM.hGap }
                w += s.width
                h = max(h, s.height)
            }
            rowWidths[l] = w
            rowHeights[l] = h
            maxRowWidth = max(maxRowWidth, w)
        }

        var yAccum: CGFloat = 0
        var flowMaxX: CGFloat = 0
        for l in 0...maxLevel {
            let ids = (layers[l] ?? []).sorted()
            guard !ids.isEmpty else { continue }
            let rowW = rowWidths[l] ?? 0
            var x = (maxRowWidth - rowW) / 2
            for id in ids {
                let s = views.first { $0.id == id }?.size ?? CGSize(width: 80, height: 30)
                flowPositions[id] = CGPoint(x: x, y: yAccum)
                x += s.width + LM.hGap
                flowMaxX = max(flowMaxX, x - LM.hGap)
            }
            yAccum += (rowHeights[l] ?? 30) + LM.vGap
        }
        let flowMaxY = max(yAccum - LM.vGap, 0)

        // Callee boxes (the start frame's direct children).
        let callouts = VariableFlowTracer.calloutTree(from: result).first?.children ?? []
        guard !callouts.isEmpty else {
            contentSize = CGSize(width: max(flowMaxX, 200) + 30,
                                 height: max(flowMaxY, 60) + 20)
            return
        }

        func draggableKinds(_ k: ControlFlowParser.Node.Kind) -> Bool {
            switch k {
            case .block, .decision, .switchCase: return true
            default: return false
            }
        }
        func flowNode(line exact: Int) -> Int? {
            flowNodes.first { $0.line == exact && draggableKinds($0.kind) }?.id
        }
        func returnTarget(after line: Int) -> Int? {
            if let best = flowNodes
                .filter({ draggableKinds($0.kind) && ($0.line ?? -1) > line })
                .min(by: { ($0.line ?? Int.max) < ($1.line ?? Int.max) }) {
                return best.id
            }
            return flowNodes.first { $0.kind == .exit }?.id
        }
        // Where execution resumes after the statement at `anchor` (structural,
        // so a call in an `if`/loop condition rejoins after the whole construct
        // rather than jumping into a branch body).
        func continuationTarget(after anchor: Int) -> Int? {
            ControlFlowParser.continuationNode(after: anchor, nodes: flow.nodes, edges: flow.edges)
        }

        // Order top-level boxes by their anchor's vertical flow position.
        var anchored: [(order: CGFloat, line: Int, co: VariableFlowCallout)] = callouts.map { co in
            let order: CGFloat
            if let id = flowNode(line: co.callLine), let p = flowPositions[id] {
                order = p.y
            } else {
                order = .greatestFiniteMagnitude
            }
            return (order: order, line: co.callLine, co: co)
        }
        anchored.sort { a, b in
            if a.order != b.order { return a.order < b.order }
            return a.line < b.line
        }

        let panelX = flowMaxX + LM.panelGap
        var prevBottom: CGFloat = -CGFloat.greatestFiniteMagnitude
        var maxBoxBottom: CGFloat = 0

        for item in anchored {
            let anchor = flowNode(line: item.line)
            let size = sizeOf(item.co, depth: 0)
            let anchorCenterY: CGFloat
            if let id = anchor, let p = flowPositions[id],
               let n = flowNodes.first(where: { $0.id == id }) {
                anchorCenterY = p.y + n.size.height / 2
            } else {
                anchorCenterY = 0
            }
            let y = max(anchorCenterY - size.height / 2, prevBottom + 18)
            let rect = CGRect(x: panelX, y: y, width: size.width, height: size.height)
            let boxID = nextBoxID()
            placeBox(boxID: boxID, co: item.co, in: rect, depth: 0)
            rootBoxIDs.append(boxID)
            maxBoxBottom = max(maxBoxBottom, rect.maxY)
            prevBottom = rect.maxY
            if let a = anchor {
                callEdges.append((anchor: a, box: boxID))
                if let t = continuationTarget(after: a) ?? returnTarget(after: item.line) {
                    returnEdges.append((box: boxID, target: t))
                }
            }
        }

        let width = max(flowMaxX, panelX + LM.boxW) + 30
        let height = max(flowMaxY, maxBoxBottom) + 20
        contentSize = CGSize(width: width, height: height)
    }

    /// Builds the "no flowchart" fallback: the start frame as a wide box on the
    /// left with its traced-use lines, callee boxes stacked to the right.
    private func buildFallbackArtwork(result: VariableFlowResult) {
        guard let start = result.nodes.first(where: { $0.isStart }) ?? result.nodes.first else { return }
        let children = VariableFlowTracer.calloutTree(from: result).first?.children ?? []
        let startBox = VariableFlowCallout(callLine: 0,
                                           functionName: result.startFunction,
                                           variableName: result.variableName,
                                           fileURL: start.fileURL,
                                           fileHint: start.fileHint,
                                           useLines: zip(start.lines, start.useText)
                                                .map { (line: $0, text: $1) },
                                           children: [])

        let rootSize = sizeOf(startBox, depth: 0)
        let rootRect = CGRect(x: 20, y: 20, width: rootSize.width, height: rootSize.height)
        let rootID = nextBoxID()
        placeBox(boxID: rootID, co: startBox, in: rootRect, depth: 0)
        rootBoxIDs = [rootID]

        guard !children.isEmpty else {
            contentSize = CGSize(width: rootRect.maxX + 30, height: rootRect.maxY + 30)
            return
        }

        let panelX = rootRect.maxX + LM.panelGap
        var y: CGFloat = rootRect.minY
        var maxBottom = rootRect.maxY
        for child in children {
            let size = sizeOf(child, depth: 0)
            let rect = CGRect(x: panelX, y: y, width: size.width, height: size.height)
            let id = nextBoxID()
            placeBox(boxID: id, co: child, in: rect, depth: 0)
            rootBoxIDs.append(id)
            maxBottom = max(maxBottom, rect.maxY)
            y = rect.maxY + 18
        }
        contentSize = CGSize(width: panelX + LM.boxW + 30, height: maxBottom + 20)
    }

    // MARK: - Box geometry

    /// Height of one callout box (recursive over nested children).
    private func sizeOf(_ co: VariableFlowCallout, depth: Int) -> CGSize {
        var h = LM.pad + LM.headerH + 3 + LM.subtitleH + 3
        h += CGFloat(min(co.useLines.count, LM.maxRows)) * LM.rowH
        if co.useLines.count > LM.maxRows { h += LM.rowH }
        if !co.children.isEmpty {
            h += 12
            if depth >= LM.maxNest {
                h += 14
            } else {
                for c in co.children { h += 8 + sizeOf(c, depth: depth + 1).height }
            }
        }
        h += 10
        return CGSize(width: LM.boxW, height: h)
    }

    /// Records a callout box at `rect` (recursively), including its clickable rows.
    private func placeBox(boxID: String, co: VariableFlowCallout, in rect: CGRect, depth: Int) {
        let header: String
        let subtitle: String
        if co.callLine == 0 {
            header = co.variableName.isEmpty
                ? co.functionName
                : "\(co.functionName) · \(co.variableName)"
            subtitle = co.fileHint
        } else {
            header = "\(co.functionName) (\(co.variableName))"
            subtitle = "\(co.fileHint) — called from line \(co.callLine)"
        }

        var rows: [(line: Int, text: String)] = []
        for pair in co.useLines.prefix(LM.maxRows) {
            rows.append((line: pair.line,
                         text: pair.text.replacingOccurrences(of: "\t", with: "  ")))
        }
        let moreCount = max(0, co.useLines.count - LM.maxRows)
        let deeperCollapsed = !co.children.isEmpty && depth >= LM.maxNest

        if !co.children.isEmpty && depth < LM.maxNest {
            let childX = rect.minX + LM.childIndent
            let childW = rect.width - LM.childIndent * 2
            var childY = rect.minY + LM.pad + LM.headerH + 3 + LM.subtitleH + 3
                + CGFloat(min(co.useLines.count, LM.maxRows)) * LM.rowH
            if co.useLines.count > LM.maxRows { childY += LM.rowH }
            childY += 12
            for c in co.children {
                let size = sizeOf(c, depth: depth + 1)
                let childRect = CGRect(x: childX, y: childY, width: childW, height: size.height)
                placeBox(boxID: nextBoxID(), co: c, in: childRect, depth: depth + 1)
                childY += size.height + 8
            }
        }

        boxRenders[boxID] = BoxRender(rect: rect,
                                      header: header,
                                      subtitle: subtitle,
                                      rows: rows,
                                      moreCount: moreCount,
                                      deeperCollapsed: deeperCollapsed)

        var y = rect.minY + LM.pad + LM.headerH + 3 + LM.subtitleH + 3
        for row in rows {
            calloutTaps.append(Tap(
                rect: CGRect(x: rect.minX + LM.pad - 2, y: y - 1,
                             width: rect.width - LM.pad * 2 + 4, height: LM.rowH + 2),
                url: co.fileURL, line: row.line))
            y += LM.rowH
        }
    }

    private var childBoxCounter = 0
    private func nextBoxID() -> String {
        childBoxCounter += 1
        return "b\(childBoxCounter)"
    }

    // MARK: - Transform

    private func recenter() {
        if hasUserViewTransform { return }
        guard contentSize.width > 0, contentSize.height > 0 else { return }
        let sW = max(contentSize.width, 300)
        let sH = max(contentSize.height, 200)
        let scW = (bounds.width - 40) / sW
        let scH = (bounds.height - 40) / sH
        graphScale = max(minScale, min(scW, scH, 2.0))
        graphOffset = CGPoint(
            x: (bounds.width - sW * graphScale) / 2,
            y: (bounds.height - sH * graphScale) / 2
        )
    }

    override func layout() {
        super.layout()
        recenter()
    }

    private func viewRect(_ r: CGRect) -> CGRect {
        CGRect(x: r.minX * graphScale + graphOffset.x,
               y: r.minY * graphScale + graphOffset.y,
               width: r.width * graphScale,
               height: r.height * graphScale)
    }

    private func flowNodeRect(_ id: Int) -> CGRect {
        guard let p = flowPositions[id],
              let n = flowNodes.first(where: { $0.id == id }) else { return .zero }
        return viewRect(CGRect(x: p.x, y: p.y, width: n.size.width, height: n.size.height))
    }

    private func boxRect(_ id: String) -> CGRect {
        guard let r = boxRenders[id]?.rect else { return .zero }
        return viewRect(r)
    }

    // MARK: - Interaction

    private func isDraggableFlow(_ k: ControlFlowParser.Node.Kind) -> Bool {
        switch k {
        case .block, .decision, .switchCase: return true
        default: return false
        }
    }

    private func flowAt(point: CGPoint) -> Int? {
        for n in flowNodes where isDraggableFlow(n.kind) {
            if flowNodeRect(n.id).insetBy(dx: -4, dy: -4).contains(point) { return n.id }
        }
        return nil
    }

    private func boxAt(point: CGPoint) -> String? {
        for id in rootBoxIDs {
            if boxRect(id).contains(point) { return id }
        }
        return nil
    }

    override func mouseDown(with event: NSEvent) {
        let p = convert(event.locationInWindow, from: nil)
        downPoint = p
        didMove = false
        if let id = flowAt(point: p) {
            draggingFlow = id
            dragStartPoint = p
            dragStartFlowPos = flowPositions[id] ?? .zero
            NSCursor.closedHand.set()
        } else if let id = boxAt(point: p) {
            draggingBox = id
            dragStartPoint = p
            dragStartBoxRect = boxRenders[id]?.rect ?? .zero
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
        if hypot(p.x - downPoint.x, p.y - downPoint.y) > 4 { didMove = true }
        if let id = draggingFlow {
            flowPositions[id] = CGPoint(
                x: dragStartFlowPos.x + (p.x - dragStartPoint.x) / graphScale,
                y: dragStartFlowPos.y + (p.y - dragStartPoint.y) / graphScale)
            needsDisplay = true
        } else if draggingBox != nil {
            let dx = (p.x - dragStartPoint.x) / graphScale
            let dy = (p.y - dragStartPoint.y) / graphScale
            let original = dragStartBoxRect
            for (bid, r) in Array(boxRenders) where original.contains(r.rect) {
                boxRenders[bid]?.rect = r.rect.offsetBy(dx: dx, dy: dy)
            }
            for i in calloutTaps.indices where original.contains(calloutTaps[i].rect) {
                let t = calloutTaps[i]
                calloutTaps[i] = Tap(rect: t.rect.offsetBy(dx: dx, dy: dy), url: t.url, line: t.line)
            }
            needsDisplay = true
        } else if panning {
            graphOffset = CGPoint(x: panStartOffset.x + (p.x - panStartPoint.x),
                                  y: panStartOffset.y + (p.y - panStartPoint.y))
            needsDisplay = true
        }
    }

    override func mouseUp(with event: NSEvent) {
        defer {
            draggingFlow = nil
            draggingBox = nil
            panning = false
            NSCursor.arrow.set()
        }
        guard !didMove, let result = resultInput else { return }
        let p = convert(event.locationInWindow, from: nil)

        for tap in calloutTaps {
            if viewRect(tap.rect).insetBy(dx: -2, dy: -2).contains(p) {
                onOpenLocation?(tap.url, tap.line)
                return
            }
        }
        if let id = flowAt(point: p),
           let line = flowNodes.first(where: { $0.id == id })?.line,
           let url = startFileURL ?? result.nodes.first?.fileURL {
            onOpenLocation?(url, line)
        }
    }

    override func magnify(with event: NSEvent) {
        zoom(by: 1 + event.magnification, at: convert(event.locationInWindow, from: nil))
    }

    override func scrollWheel(with event: NSEvent) {
        guard event.modifierFlags.contains(.command) else { return }
        let delta = event.hasPreciseScrollingDeltas ? event.scrollingDeltaY : event.scrollingDeltaY * 10
        let factor: CGFloat = max(0.2, min(3.0, 1 + delta / 60))
        zoom(by: factor, at: convert(event.locationInWindow, from: nil))
    }

    private func zoom(by factor: CGFloat, at point: CGPoint) {
        guard contentSize.width > 0, factor > 0, !graphScale.isZero else { return }
        let newScale = max(minScale, min(maxScale, graphScale * factor))
        let s = newScale / graphScale
        if s == 1 || s.isNaN { return }
        hasUserViewTransform = true
        let contentPoint = CGPoint(x: (point.x - graphOffset.x) / graphScale,
                                   y: (point.y - graphOffset.y) / graphScale)
        graphScale = newScale
        graphOffset = CGPoint(x: point.x - contentPoint.x * graphScale,
                              y: point.y - contentPoint.y * graphScale)
        needsDisplay = true
    }

    // MARK: - Drawing

    private static func flowNodeSize(_ kind: ControlFlowParser.Node.Kind) -> CGSize {
        let text: String
        switch kind {
        case .block(let t), .decision(let t), .switchCase(let t): text = t
        case .entry: text = "START"
        case .exit: text = "END"
        case .join: return CGSize(width: 16, height: 16)
        }
        let font = NSFont.systemFont(ofSize: 11, weight: .medium)
        let maxW: CGFloat = 220
        let ts = (text as NSString).boundingRect(
            with: NSSize(width: maxW, height: .greatestFiniteMagnitude),
            options: [.usesLineFragmentOrigin, .usesFontLeading],
            attributes: [.font: font])
        var w = ceil(ts.width) + 20
        var h = ceil(ts.height) + 16
        switch kind {
        case .decision:
            w = max(w, 64); h = max(h, 44)
        case .switchCase:
            w = max(w, 56); h = max(h, 28)
        case .entry, .exit:
            w = max(w, 56); h = max(h, 28)
        default:
            w = max(w, 80); h = max(h, 30)
        }
        return CGSize(width: w, height: h)
    }

    override func draw(_ dirtyRect: NSRect) {
        NSColor.controlBackgroundColor.setFill()
        dirtyRect.fill()

        guard resultInput != nil else {
            let attrs: [NSAttributedString.Key: Any] = [
                .font: NSFont.systemFont(ofSize: 13),
                .foregroundColor: NSColor.secondaryLabelColor
            ]
            ("No variable flow to display." as NSString)
                .draw(at: CGPoint(x: 20, y: 20), withAttributes: attrs)
            return
        }
        if flowPositions.isEmpty, boxRenders.isEmpty { return }

        drawFlowEdges()
        drawOutEdges()
        drawBoxes()
        drawFlowNodes()
        drawBoxContent()
    }

    // MARK: Flowchart internals

    private func drawFlowEdges() {
        for e in flowEdges {
            let r1 = flowNodeRect(e.from)
            let r2 = flowNodeRect(e.to)
            guard r1.width > 0, r2.width > 0 else { continue }
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
                let mid = CGPoint(x: (c1.x + c2.x) / 2 + 6, y: (c1.y + c2.y) / 2)
                let attrs: [NSAttributedString.Key: Any] = [
                    .font: NSFont.systemFont(ofSize: 10, weight: .bold),
                    .foregroundColor: (b == "T") ? NSColor.systemGreen : NSColor.systemRed
                ]
                (b as NSString).draw(at: mid, withAttributes: attrs)
            }
        }
    }

    // MARK: Call / return edges

    private func drawOutEdges() {
        for e in callEdges {
            let a = flowNodeRect(e.anchor)
            let b = boxRect(e.box)
            guard a.width > 0, b.width > 0 else { continue }
            let start = CGPoint(x: a.midX, y: a.maxY)
            let end = CGPoint(x: b.midX, y: b.minY)
            let midY = (start.y + end.y) / 2
            let path = NSBezierPath()
            path.move(to: start)
            path.line(to: CGPoint(x: start.x, y: midY))
            path.line(to: CGPoint(x: end.x, y: midY))
            path.line(to: end)
            NSColor.systemBlue.setStroke()
            path.lineWidth = 1.6
            path.stroke()
            drawArrowhead(to: end, from: start)
            let attrs: [NSAttributedString.Key: Any] = [
                .font: NSFont.systemFont(ofSize: 10, weight: .bold),
                .foregroundColor: NSColor.systemBlue
            ]
            ("call" as NSString).draw(at: CGPoint(x: end.x - 26, y: midY - 12), withAttributes: attrs)
        }

        for e in returnEdges {
            let b = boxRect(e.box)
            let t = flowNodeRect(e.target)
            guard b.width > 0, t.width > 0 else { continue }
            let start = CGPoint(x: b.minX, y: b.midY)
            let end = CGPoint(x: t.maxX, y: t.midY)
            let channelX = max(t.maxX + 26, b.minX - 40)
            let path = NSBezierPath()
            path.move(to: start)
            path.line(to: CGPoint(x: channelX, y: start.y))
            path.line(to: CGPoint(x: channelX, y: end.y))
            path.line(to: end)
            NSColor.systemPurple.setStroke()
            path.lineWidth = 1.6
            path.stroke()
            drawArrowhead(to: end, from: start)
            let attrs: [NSAttributedString.Key: Any] = [
                .font: NSFont.systemFont(ofSize: 10, weight: .bold),
                .foregroundColor: NSColor.systemPurple
            ]
            ("return" as NSString).draw(at: CGPoint(x: channelX + 4, y: end.y - 6), withAttributes: attrs)
        }
    }

    private func drawArrowhead(to: CGPoint, from: CGPoint) {
        guard !from.x.isNaN, !from.y.isNaN, !to.x.isNaN, !to.y.isNaN,
              hypot(to.x - from.x, to.y - from.y) > 0.5 else { return }
        let angle = atan2(to.y - from.y, to.x - from.x)
        let len: CGFloat = 9
        let path = NSBezierPath()
        path.move(to: to)
        path.line(to: CGPoint(x: to.x - len * cos(angle - 0.4), y: to.y - len * sin(angle - 0.4)))
        path.move(to: to)
        path.line(to: CGPoint(x: to.x - len * cos(angle + 0.4), y: to.y - len * sin(angle + 0.4)))
        NSColor.labelColor.setStroke()
        path.lineWidth = 2
        path.stroke()
    }

    // MARK: Flow node shapes

    private func drawFlowNodes() {
        for n in flowNodes {
            if n.kind == .join {
                let rect = flowNodeRect(n.id)
                if rect.width > 0 {
                    NSColor.separatorColor.setFill()
                    NSBezierPath(ovalIn: rect).fill()
                }
                continue
            }
            let rect = flowNodeRect(n.id)
            guard rect.width > 0 else { continue }
            drawFlowShape(n, rect: rect)
        }
    }

    private func shapeColor(_ k: ControlFlowParser.Node.Kind) -> NSColor {
        switch k {
        case .entry: return NSColor(calibratedRed: 0.20, green: 0.60, blue: 0.35, alpha: 1.0)
        case .exit: return NSColor(calibratedRed: 0.78, green: 0.30, blue: 0.30, alpha: 1.0)
        case .decision: return .controlAccentColor
        case .switchCase: return .systemOrange
        case .join: return .separatorColor
        default: return .windowBackgroundColor
        }
    }

    private func drawFlowShape(_ n: FlowViewNode, rect: CGRect) {
        let color = shapeColor(n.kind)
        color.setFill()
        let radius: CGFloat = (n.kind == .entry || n.kind == .exit) ? rect.height / 2 : 6
        let rounded = NSBezierPath(roundedRect: rect, xRadius: radius, yRadius: radius)
        rounded.fill()

        if n.highlighted {
            NSColor.systemYellow.withAlphaComponent(0.22).setFill()
            rounded.fill()
        }

        let border: NSColor
        switch n.kind {
        case .decision: border = n.highlighted ? NSColor.systemYellow : .controlAccentColor
        case .switchCase: border = NSColor.systemOrange
        case .entry: border = NSColor(calibratedRed: 0.20, green: 0.60, blue: 0.35, alpha: 1.0).withAlphaComponent(0.6)
        case .exit: border = NSColor(calibratedRed: 0.78, green: 0.30, blue: 0.30, alpha: 1.0).withAlphaComponent(0.6)
        default: border = n.highlighted ? NSColor.systemYellow : .separatorColor
        }
        border.setStroke()
        let strokePath = NSBezierPath(roundedRect: rect.insetBy(dx: 0.75, dy: 0.75),
                                      xRadius: radius, yRadius: radius)
        strokePath.lineWidth = n.highlighted ? 3.0 : 1.0
        strokePath.stroke()

        let text = nodeLabel(n)
        if text.isEmpty { return }
        let textColor: NSColor
        switch n.kind {
        case .entry, .exit, .decision: textColor = n.highlighted ? NSColor(calibratedWhite: 0.9, alpha: 1) : .white
        case .switchCase: textColor = .black
        default:
            textColor = n.highlighted ? NSColor(calibratedRed: 0.45, green: 0.38, blue: 0.05, alpha: 1) : .labelColor
        }
        let attrs: [NSAttributedString.Key: Any] = [
            .font: NSFont.systemFont(ofSize: 11, weight: .medium),
            .foregroundColor: textColor
        ]
        let para = NSMutableParagraphStyle()
        para.lineBreakMode = .byTruncatingTail
        para.alignment = .center
        var mAttrs = attrs
        mAttrs[.paragraphStyle] = para
        (text as NSString).draw(in: rect.insetBy(dx: 6, dy: 6), withAttributes: mAttrs)
    }

    private func nodeLabel(_ n: FlowViewNode) -> String {
        switch n.kind {
        case .block(let t): return t
        case .decision(let t): return t
        case .switchCase(let t): return t
        case .entry: return "START"
        case .exit: return "END"
        case .join: return ""
        }
    }

    // MARK: Callout boxes

    private func drawBoxes() {
        for (id, render) in boxRenders {
            let rect = viewRect(render.rect)
            guard rect.width > 0 else { continue }
            let isRoot = rootBoxIDs.contains(id)
            let path = NSBezierPath(roundedRect: rect, xRadius: 8, yRadius: 8)
            NSColor.textBackgroundColor.setFill()
            path.fill()
            let stroke = isRoot ? NSColor.separatorColor : NSColor.separatorColor.withAlphaComponent(0.6)
            stroke.setStroke()
            path.lineWidth = 1.4
            path.stroke()
        }
    }

    private func drawBoxContent() {
        for (_, render) in boxRenders {
            let rect = viewRect(render.rect)
            guard rect.width > 0 else { continue }

            var y = rect.minY + 8 * graphScale

            // Header
            let headerAttrs: [NSAttributedString.Key: Any] = [
                .font: NSFont.systemFont(ofSize: 12 * graphScale, weight: .bold),
                .foregroundColor: NSColor.labelColor
            ]
            (render.header as NSString).draw(at: CGPoint(x: rect.minX + 8, y: y),
                                             withAttributes: headerAttrs)
            y += 18 * graphScale

            // Subtitle
            let subAttrs: [NSAttributedString.Key: Any] = [
                .font: NSFont.systemFont(ofSize: 9 * graphScale),
                .foregroundColor: NSColor.secondaryLabelColor
            ]
            (render.subtitle as NSString).draw(at: CGPoint(x: rect.minX + 8, y: y),
                                               withAttributes: subAttrs)
            y += (12 + 3) * graphScale

            // Code rows
            let numAttrs: [NSAttributedString.Key: Any] = [
                .font: NSFont.monospacedSystemFont(ofSize: 9 * graphScale, weight: .regular),
                .foregroundColor: NSColor.tertiaryLabelColor
            ]
            let codeAttrs: [NSAttributedString.Key: Any] = [
                .font: NSFont.monospacedSystemFont(ofSize: 10 * graphScale, weight: .regular),
                .foregroundColor: NSColor.labelColor
            ]
            for row in render.rows {
                let num = "L\(row.line)"
                (num as NSString).draw(at: CGPoint(x: rect.minX + 8, y: y), withAttributes: numAttrs)
                let codeRect = CGRect(x: rect.minX + 8 + 34 * graphScale,
                                      y: y, width: rect.width - 44 * graphScale, height: 16 * graphScale)
                let para = NSMutableParagraphStyle()
                para.lineBreakMode = .byTruncatingTail
                var attrs = codeAttrs
                attrs[.paragraphStyle] = para
                (row.text as NSString).draw(in: codeRect, withAttributes: attrs)
                y += 16 * graphScale
            }
            if render.moreCount > 0 {
                y += 16 * graphScale
            }

            // Collapsed-nesting hint
            if render.deeperCollapsed {
                let hintAttrs: [NSAttributedString.Key: Any] = [
                    .font: NSFont.systemFont(ofSize: 9 * graphScale),
                    .foregroundColor: NSColor.secondaryLabelColor
                ]
                ("… deeper calls collapsed" as NSString)
                    .draw(at: CGPoint(x: rect.minX + 8, y: y), withAttributes: hintAttrs)
            }
        }
    }
}
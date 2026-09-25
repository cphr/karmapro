// by cipher.org.uk
import Foundation

/// A 2D position for a graph node.
public struct LayoutPosition {
    public let name: String
    public var x: CGFloat
    public var y: CGFloat
}

/// Computes a layered (hierarchical) layout for a CallGraph with edge-crossing
/// reduction via the barycenter heuristic. Nodes are grouped into ranks;
/// within each rank they are reordered to minimize crossings with adjacent ranks.
public enum GraphLayout {

    /// Rank-to-axis mapping: how a layer is translated into screen coordinates.
    public enum Direction {
        /// Layers run down the screen (rank 0 at the top), nodes spread across.
        case topToBottom
        /// Keeps the historical layout the app's other diagrams use.
        case leftToRight
    }

    /// Output of the layout pass.
    public struct Result {
        public var positions: [String: CGPoint] = [:]
        public var layerCount: Int = 0
        public var size: CGSize = .zero
    }

    /// Lays out the graph. `callEdges` defines direction used for ranking.
    /// - Parameters:
    ///   - direction: how layers are placed (`.topToBottom` starts from the
    ///     `sourceNodes`, which are pinned to rank 0 / the top).
    ///   - sourceNodes: nodes forced to rank 0 in `.topToBottom` mode (e.g. the
    ///     Internet/Local origin box) so flow runs downwards from them.
    public static func layered(graph: CallGraph, callEdges: [(String, String)],
                               direction: Direction = .leftToRight,
                               sourceNodes: Set<String> = []) -> Result {
        var result = Result()
        let names = Set(graph.nodes.keys)

        // Build outgoing/incoming edges per node (from -> to).
        var outgoing: [String: [String]] = [:]
        var incoming: [String: [String]] = [:]
        for (a, b) in callEdges {
            outgoing[a, default: []].append(b)
            incoming[b, default: []].append(a)
        }

        // Compute ranks. Default mode: longest-path layering from sinks
        // (keeps historical behaviour for the app's other diagrams). TopDown
        // mode: longest path FROM the source nodes, so the origin tops the flow.
        var rank: [String: Int] = [:]
        if direction == .topToBottom {
            var inProgress: Set<String> = []
            func depthOf(_ n: String, _ d: Int) {
                if inProgress.contains(n) { return }
                if let existing = rank[n], existing >= d { return }
                rank[n] = d
                inProgress.insert(n)
                for next in outgoing[n] ?? [] { depthOf(next, d + 1) }
                inProgress.remove(n)
            }
            for s in sourceNodes { depthOf(s, 0) }
            for n in names where rank[n] == nil { depthOf(n, 0) }
        } else {
            var inProgress: Set<String> = []
            func rankOf(_ n: String) -> Int {
                if let r = rank[n] { return r }
                if inProgress.contains(n) { return 0 }
                inProgress.insert(n)
                defer { inProgress.remove(n) }
                if outgoing[n] == nil {
                    rank[n] = 0
                    return 0
                }
                var r = 0
                for next in outgoing[n] ?? [] {
                    r = max(r, rankOf(next) + 1)
                }
                rank[n] = r
                return r
            }
            for n in names { _ = rankOf(n) }
        }

        let maxRank = rank.values.max() ?? 0
        result.layerCount = maxRank + 1

        // Group nodes by rank.
        var layers: [Int: [String]] = [:]
        for (n, r) in rank {
            layers[r, default: []].append(n)
        }

        // Node sizing (uniform; kept in sync with DataFlowDiagramView.nodeSize).
        let nodeWidth: CGFloat = 128
        let nodeHeight: CGFloat = 34
        let hGap: CGFloat = 44
        let vGap: CGFloat = 56
        let maxPerRow = 9

        // Sort nodes within each rank by barycenter heuristic to reduce crossings.
        // Iterate multiple passes (up-down and down-up) for better convergence.
        let layersCount = maxRank + 1
        for _ in 0..<5 {  // few passes of barycenter sweeps
            // Downward pass: for each rank, order by avg position of outgoing neighbors.
            for r in 0..<layersCount {
                guard var nodes = layers[r], !nodes.isEmpty else { continue }
                if r + 1 < layersCount {
                    let nextRankNodes = layers[r + 1] ?? []
                    let nextPos = Dictionary(uniqueKeysWithValues: nextRankNodes.enumerated().map { ($1, $0) })
                    nodes.sort { a, b in
                        let aAvg = barycenter(of: a, to: outgoing, in: nextPos)
                        let bAvg = barycenter(of: b, to: outgoing, in: nextPos)
                        if aAvg != bAvg { return aAvg < bAvg }
                        return a < b
                    }
                }
                layers[r] = nodes
            }
            // Upward pass: order by avg position of incoming neighbors.
            for r in stride(from: layersCount - 1, through: 0, by: -1) {
                guard var nodes = layers[r], !nodes.isEmpty else { continue }
                if r > 0 {
                    let prevRankNodes = layers[r - 1] ?? []
                    let prevPos = Dictionary(uniqueKeysWithValues: prevRankNodes.enumerated().map { ($1, $0) })
                    nodes.sort { a, b in
                        let aAvg = barycenter(of: a, to: incoming, in: prevPos)
                        let bAvg = barycenter(of: b, to: incoming, in: prevPos)
                        if aAvg != bAvg { return aAvg < bAvg }
                        return a < b
                    }
                }
                layers[r] = nodes
            }
        }

        // Assign final x positions using the now-ordered layers.
        var maxWidth: CGFloat = 0
        var maxRowIndex = 0
        for r in 0...maxRank {
            let nodes = layers[r] ?? []
            if nodes.isEmpty { continue }

            let rows = max(1, (nodes.count + maxPerRow - 1) / maxPerRow)
            var idx = 0
            for row in 0..<rows {
                let end = min(idx + maxPerRow, nodes.count)
                let rowNodes = Array(nodes[idx..<end])
                idx = end
                let count = CGFloat(rowNodes.count)
                let total = nodeWidth + (count - 1) * (nodeWidth + hGap)
                maxWidth = max(maxWidth, total)
                let rowY = CGFloat(r) * (nodeHeight + vGap) + CGFloat(row) * (nodeHeight + 18)
                var x = total / 2
                for n in rowNodes {
                    result.positions[n] = CGPoint(x: x - nodeWidth / 2, y: rowY)
                    x += nodeWidth + hGap
                }
                maxRowIndex = max(maxRowIndex, row)
            }
        }

        let height = CGFloat(maxRank) * (nodeHeight + vGap)
            + CGFloat(maxRowIndex) * (nodeHeight + 18)
            + nodeHeight + 40
        result.size = CGSize(width: max(maxWidth, 400), height: height)
        return result
    }

    /// Computes a butterfly layout for a call graph viewed from `center`: the
    /// center function sits in the middle column, its transitive callers fan out
    /// to the left, its transitive callees to the right, and any unrelated
    /// function is stacked in a compact block to the far right. Node order
    /// within each column uses the barycenter heuristic to reduce crossings.
    public static func butterfly(graph: CallGraph, callEdges: [(String, String)], center: String?) -> Result {
        let names = Set(graph.nodes.keys)
        guard let center = center, names.contains(center) else {
            // No usable center: fall back to the plain layered layout.
            return layered(graph: graph, callEdges: callEdges, direction: .leftToRight)
        }

        var outgoing: [String: [String]] = [:]
        var incoming: [String: [String]] = [:]
        for (a, b) in callEdges where names.contains(a) && names.contains(b) {
            outgoing[a, default: []].append(b)
            incoming[b, default: []].append(a)
        }

        // Transitive closures from the center along the two edge directions.
        func closure(start: Set<String>, edges: [String: [String]]) -> Set<String> {
            var visited = start
            var frontier = start
            while !frontier.isEmpty {
                var next: Set<String> = []
                for n in frontier {
                    for m in edges[n] ?? [] where !visited.contains(m) {
                        visited.insert(m)
                        next.insert(m)
                    }
                }
                frontier = next
            }
            return visited
        }
        let ancestors = closure(start: [center], edges: incoming)
        let descendants = closure(start: [center], edges: outgoing)
        let callers = ancestors.subtracting([center])
        var callees = descendants.subtracting([center])
        // Nodes on a cycle with the center sit above it: keep them on the caller
        // side so the center's own column never holds more than one node.
        callees.subtract(callers)
        let others = names.subtracting([center]).subtracting(callers).subtracting(callees)

        // Longest-path distance from the center in each direction. Caller side:
        // follow OUTGOING edges (a caller calls the node closer to the center);
        // callee side: follow INCOMING edges (a node called by the one closer to
        // the center). A shared rank never collides: the partitions are disjoint.
        var rank: [String: Int] = [:]
        rank[center] = 0
        var inProgress: Set<String> = []
        func rankTo(n: String, via edgeKind: [String: [String]], allowed: Set<String>) -> Int {
            if let r = rank[n] { return r }
            if inProgress.contains(n) { return 0 }
            inProgress.insert(n)
            defer { inProgress.remove(n) }
            var r = 0
            for c in edgeKind[n] ?? [] where allowed.contains(c) || c == center {
                r = max(r, rankTo(n: c, via: edgeKind, allowed: allowed) + 1)
            }
            rank[n] = r
            return r
        }
        for n in callers { _ = rankTo(n: n, via: outgoing, allowed: callers) }
        for n in callees { _ = rankTo(n: n, via: incoming, allowed: callees) }

        // Column index per node: callers negative, center 0, callees positive,
        // unrelated stacked in a block to the far right.
        var columns: [Int: [String]] = [:]
        columns[0] = [center]
        var maxFwd = 0
        for n in callees {
            let c = max(1, rank[n] ?? 1)
            maxFwd = max(maxFwd, c)
            columns[c, default: []].append(n)
        }
        for n in callers {
            let c = max(1, rank[n] ?? 1)
            columns[-c, default: []].append(n)
        }
        let otherCol = maxFwd + 1
        if !others.isEmpty {
            columns[otherCol] = Array(others).sorted()
        }

        let nodeWidth: CGFloat = 128
        let nodeHeight: CGFloat = 34
        let hGap: CGFloat = 44
        let rowGap: CGFloat = 18

        // Order nodes within each column to reduce crossings (barycenter sweeps).
        func neighborAvg(of node: String, from positions: [String: Int]) -> Double {
            var sum = 0.0
            var count = 0
            for n in (outgoing[node] ?? []) + (incoming[node] ?? []) {
                if let idx = positions[n] { sum += Double(idx); count += 1 }
            }
            return count > 0 ? sum / Double(count) : .infinity
        }
        let minCol = columns.keys.min() ?? 0
        let maxCol = columns.keys.max() ?? 0
        for _ in 0..<5 {
            for col in minCol...maxCol {
                guard var nodes = columns[col], nodes.count > 1,
                      let left = columns[col - 1], !left.isEmpty else { continue }
                let pos = Dictionary(uniqueKeysWithValues: left.enumerated().map { ($1, $0) })
                nodes.sort { a, b in
                    let aa = neighborAvg(of: a, from: pos)
                    let bb = neighborAvg(of: b, from: pos)
                    if aa != bb { return aa < bb }
                    return a < b
                }
                columns[col] = nodes
            }
            for col in stride(from: maxCol, through: minCol, by: -1) {
                guard var nodes = columns[col], nodes.count > 1,
                      let right = columns[col + 1], !right.isEmpty else { continue }
                let pos = Dictionary(uniqueKeysWithValues: right.enumerated().map { ($1, $0) })
                nodes.sort { a, b in
                    let aa = neighborAvg(of: a, from: pos)
                    let bb = neighborAvg(of: b, from: pos)
                    if aa != bb { return aa < bb }
                    return a < b
                }
                columns[col] = nodes
            }
        }

        // Assign coordinates. Each column is a vertical stack; columns share the
        // same horizontal spacing so the butterfly reads callers → center → callees.
        var result = Result()
        let colSpacing: CGFloat = nodeWidth + hGap
        var maxRows = 1
        for col in minCol...maxCol {
            guard let nodes = columns[col], !nodes.isEmpty else { continue }
            let x = CGFloat(col) * colSpacing + (colSpacing - nodeWidth) / 2
            var y: CGFloat = 0
            for n in nodes {
                result.positions[n] = CGPoint(x: x, y: y)
                y += nodeHeight + rowGap
            }
            maxRows = max(maxRows, nodes.count)
        }

        let minX = result.positions.values.map { $0.x }.min() ?? 0
        let maxX = (result.positions.values.map { $0.x }.max() ?? 0) + nodeWidth
        result.layerCount = maxCol - minCol + 1
        let height = CGFloat(maxRows) * (nodeHeight + rowGap) + 40
        result.size = CGSize(width: max(maxX - minX + hGap * 2, 400), height: height)
        return result
    }

    /// Average index of a node's neighbors in the target rank (barycenter heuristic).
    private static func barycenter(of node: String,
                                    to edges: [String: [String]],
                                    in targetIndex: [String: Int]) -> Double {
        guard let neighbors = edges[node], !neighbors.isEmpty else { return .infinity }
        var sum = 0.0
        var count = 0
        for n in neighbors {
            if let idx = targetIndex[n] { sum += Double(idx); count += 1 }
        }
        return count > 0 ? sum / Double(count) : .infinity
    }
}

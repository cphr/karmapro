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

    /// Output of the layout pass.
    public struct Result {
        public var positions: [String: CGPoint] = [:]
        public var layerCount: Int = 0
        public var size: CGSize = .zero
    }

    /// Lays out the graph. `callEdges` defines direction used for ranking.
    public static func layered(graph: CallGraph, callEdges: [(String, String)]) -> Result {
        var result = Result()
        let names = Set(graph.nodes.keys)

        // Build outgoing/incoming edges per node (from -> to).
        var outgoing: [String: [String]] = [:]
        var incoming: [String: [String]] = [:]
        for (a, b) in callEdges {
            outgoing[a, default: []].append(b)
            incoming[b, default: []].append(a)
        }

        // Compute ranks (longest-path layering).
        var rank: [String: Int] = [:]
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

        let maxRank = rank.values.max() ?? 0
        result.layerCount = maxRank + 1

        // Group nodes by rank.
        var layers: [Int: [String]] = [:]
        for (n, r) in rank {
            layers[r, default: []].append(n)
        }

        // Node sizing (uniform).
        let nodeWidth: CGFloat = 160
        let nodeHeight: CGFloat = 52
        let hGap: CGFloat = 70
        let vGap: CGFloat = 90
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

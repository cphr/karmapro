// by cipher.org.uk
import Foundation

/// A directed graph describing how data/calls flow between functions in a file.
public final class CallGraph {
    /// A single function node in the graph.
    public final class Node {
        public let name: String
        public var callers: [String] = []   // functions that call this one
        public var callees: [String] = []   // functions this one calls
        public var dataSources: [String] = [] // functions/globals whose output feeds into this
        public var dataTargets: [String] = [] // functions/globals that consume this function's output

        public init(name: String) {
            self.name = name
        }
    }

    public private(set) var nodes: [String: Node] = [:]

    public init() {}

    /// The names of all functions in the graph.
    public var functionNames: [String] {
        Array(nodes.keys).sorted()
    }

    public func node(for name: String) -> Node {
        if let existing = nodes[name] {
            return existing
        }
        let n = Node(name: name)
        nodes[name] = n
        return n
    }

    public func hasNode(_ name: String) -> Bool {
        nodes[name] != nil
    }

    /// Records that `from` calls `to`.
    public func addCall(from: String, to: String) {
        guard from != to else { return }
        let fromNode = node(for: from)
        let toNode = node(for: to)
        if !fromNode.callees.contains(to) { fromNode.callees.append(to) }
        if !toNode.callers.contains(from) { toNode.callers.append(from) }
    }

    /// Records that data flows from `from` to `to` (from's output used by `to`).
    public func addDataFlow(from: String, to: String) {
        guard from != to else { return }
        let fromNode = node(for: from)
        let toNode = node(for: to)
        if !fromNode.dataTargets.contains(to) { fromNode.dataTargets.append(to) }
        if !toNode.dataSources.contains(from) { toNode.dataSources.append(from) }
    }

    /// Removes any nodes that are not real defined functions in this file
    /// (used to prune external/library calls).
    public func pruneTo(defined: Set<String>) {
        for name in nodes.keys {
            if !defined.contains(name) {
                nodes.removeValue(forKey: name)
            }
        }
        // Rebuild neighbour lists to drop pruned references.
        for node in nodes.values {
            node.callers = node.callers.filter { nodes[$0] != nil }
            node.callees = node.callees.filter { nodes[$0] != nil }
            node.dataSources = node.dataSources.filter { nodes[$0] != nil }
            node.dataTargets = node.dataTargets.filter { nodes[$0] != nil }
        }
    }
}

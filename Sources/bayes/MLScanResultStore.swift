// by cipher.org.uk
import Foundation

/// Holds per-file, per-line classifier probabilities produced by a project scan,
/// so the source view can highlight vulnerable lines when a file is opened.
/// Stored globally (not persisted) for the current session.
final class MLScanResultStore {
    static let shared = MLScanResultStore()

    /// file path -> (delta applied) -> [line : 0...1 probability of "bad"]
    private var results: [String: [Int: Double]] = [:]
    /// The name of the model whose results are currently loaded ("" if none).
    private(set) var activeModelName = ""
    /// The bad-probability threshold (0...1) used by the most recent scan.
    /// Highlights and the results table use this so they match the user's slider.
    private(set) var activeThreshold: Double = 0.80

    private init() {}

    func currentModelName() -> String { activeModelName }

    /// Normalizes a file path so scan-time and display-time keys always match.
    /// Resolves symlinks (which strips a leading "/private" on /tmp, /var, etc.)
    /// and standardizes the path.
    static func normalizePath(_ path: String) -> String {
        let url = URL(fileURLWithPath: path).resolvingSymlinksInPath().standardizedFileURL
        return url.path
    }

    /// Clears all stored results (e.g. when switching models or rescanning).
    func clear() {
        results = [:]
        activeModelName = ""
        activeThreshold = 0.80
    }

    func setResults(_ newResults: [String: [Int: Double]], modelName: String, threshold: Double = 0.80) {
        activeModelName = modelName
        activeThreshold = max(0.01, min(threshold, 1.0))
        var normalized: [String: [Int: Double]] = [:]
        for (path, lines) in newResults {
            normalized[Self.normalizePath(path)] = lines
        }
        results = normalized
    }

    /// Returns [line : probability] for a given file path ("" if none).
    func probabilities(forFile path: String) -> [Int: Double] {
        return results[Self.normalizePath(path)] ?? [:]
    }

    /// Returns the lines at or above the active scan threshold for a given file, or empty.
    func highRiskLines(forFile path: String, threshold: Double? = nil) -> [Int: Double] {
        guard let m = results[Self.normalizePath(path)] else { return [:] }
        let thresh = threshold ?? activeThreshold
        var out: [Int: Double] = [:]
        for (line, prob) in m where prob >= thresh {
            out[line] = prob
        }
        return out
    }

    func anyResults() -> Bool { !results.isEmpty }

    /// Returns every scanned file (normalized path) with the number of lines it
    /// has flagged at the active scan threshold, sorted hottest-first. Used by the
    /// heatmap window to rank files from most to least flagged.
    func flaggedCounts() -> [(path: String, flagged: Int)] {
        let thresh = activeThreshold
        var out: [(path: String, flagged: Int)] = []
        for (path, lines) in results {
            let count = lines.values.filter { $0 >= thresh }.count
            if count > 0 {
                out.append((path, count))
            }
        }
        out.sort { $0.flagged > $1.flagged }
        return out
    }

    /// Relative path of a scanned file under a project root, for display. Falls
    /// back to the last path component if the file is outside the root.
    func displayPath(_ path: String, under root: URL?) -> String {
        guard let root = root else { return (path as NSString).lastPathComponent }
        let rootPath = root.standardizedFileURL.path
        if path.hasPrefix(rootPath + "/") {
            return String(path.dropFirst(rootPath.count + 1))
        }
        return (path as NSString).lastPathComponent
    }
}

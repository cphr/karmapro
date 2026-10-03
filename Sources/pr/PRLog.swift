import Foundation

/// Minimal diagnostic log for the pull request feature.
///
/// Menu-bar and window-controller code is hard to exercise from a test harness,
/// so the few places where "the user clicked and nothing happened" has to be
/// distinguished from "the code ran and the window stayed hidden" write a line
/// here. Tokens are never passed in: callers log titles, selectors and
/// booleans only.
enum PRLog {
    /// Path in the app's own support directory, so it is easy to find after the
    /// fact and travels with the app's data rather than a shared temp file.
    private static var url: URL? = {
        let base = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first?
            .appendingPathComponent("KarmaPro", isDirectory: true)
        guard let base = base else { return nil }
        try? FileManager.default.createDirectory(at: base, withIntermediateDirectories: true)
        return base.appendingPathComponent("pr.log")
    }()

    static func write(_ message: String) {
        guard let url = url else { return }
        let stamp = ISO8601DateFormatter().string(from: Date())
        let line = "\(stamp) \(message)\n"
        if let handle = try? FileHandle(forWritingTo: url) {
            defer { try? handle.close() }
            _ = try? handle.seekToEnd()
            _ = try? handle.write(contentsOf: Data(line.utf8))
        } else {
            _ = try? Data(line.utf8).write(to: url)
        }
    }
}

// by cipher.org.uk
import AppKit

final class AppDelegate: NSObject, NSApplicationDelegate {
    private var windowController: MainWindowController?
    private var splashController: SplashWindowController?

    var currentProjectRootURL: URL? {
        return windowController?.projectRootURL ?? (NSApp.keyWindow?.windowController as? MainWindowController)?.projectRootURL
    }

    func applicationDidFinishLaunching(_ notification: Notification) {
        NSApp.activate(ignoringOtherApps: true)

        // Update dock badge whenever the bug store changes.
        NotificationCenter.default.addObserver(self, selector: #selector(updateDockBadge),
                                               name: .bugStoreDidChange, object: nil)
        updateDockBadge()

        // Show the "Karma Pro" splash for 3 seconds before revealing the main window.
        let splash = SplashWindowController()
        splashController = splash
        splash.onFinished = { [weak self] in
            self?.finishLaunching()
        }
        splash.start()
    }

    private func finishLaunching() {
        let wc = MainWindowController()
        windowController = wc
        wc.showWindow(nil)

        // Prompt for a directory to browse.
        wc.promptForDirectory()
    }

    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool {
        return true
    }

    @objc private func updateDockBadge() {
        BugStore.shared.reload()
        let openStatuses: Set<String> = ["Open", "In Progress"]
        let openBugs = BugStore.shared.allBugs().filter { openStatuses.contains($0.status) }.count
        NSApp.dockTile.badgeLabel = openBugs > 0 ? "\(openBugs)" : ""
    }

    func applicationShouldRestoreApplicationState(_ app: NSApplication) -> Bool {
        return false
    }

    func applicationShouldRestoreSecureApplicationState(_ app: NSApplication) -> Bool {
        return false
    }

    func applicationSupportsSecureRestorableState(_ app: NSApplication) -> Bool {
        return true
    }
}

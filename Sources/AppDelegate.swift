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

        // Pull-request support is installed here rather than in the splash
        // callback so the menu-bar item exists for the whole session.
        installPullRequestSupport()

        // Starts the daily update gate. Nothing is requested until the user has
        // opted in, so a fresh install contacts GitHub for nothing.
        updateTarget.install()

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

    /// Installs the pull-request menu-bar item and wires it to the main window.
    ///
    /// Polling only starts when the user has enabled monitoring, so a fresh
    /// install shows the menu item and nothing else: no repository is contacted
    /// until they ask for it.
    private func installPullRequestSupport() {
        let coordinator = PRReviewCoordinator.shared
        coordinator.setMainWindowProvider { [weak self] in
            self?.windowController ?? (NSApp.keyWindow?.windowController as? MainWindowController)
        }
        coordinator.install()
    }

    /// Keeps the app running when the last window closes, but only while
    /// pull-request monitoring is on.
    ///
    /// A menu-bar poller has to survive its own window being closed, otherwise
    /// closing the editor silently stops alerts. With monitoring off, the
    /// previous behaviour is kept so a normal session still quits as expected.
    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool {
        return !PRStore.shared.monitoringEnabled
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

// by cipher.org.uk
import AppKit

/// Owns the pull-request feature's shared state: the poller, the menu-bar item
/// and the review currently on screen.
///
/// A single instance exists for the life of the process. It is the only place
/// that can start a review, which keeps the "only one review at a time" rule
/// enforceable: starting a second one tears the first down here rather than
/// relying on every caller to remember.
final class PRReviewCoordinator {
    static let shared = PRReviewCoordinator()

    /// The poller. Exposed so the menu can render results; polls are only ever
    /// started through this class.
    let monitor = PRMonitor()
    private var menuBar: PRMenuBarController?

    var menuTitles: [String] { menuBar?.menuTitles ?? [] }
    private var activeSession: PRReviewSession?

    /// Supplies the open main window. Set by the app delegate so the PR layer
    /// never has to know how the main window is owned.
    var mainWindowProvider: (() -> MainWindowController?)?

    /// Presents an alert as a sheet on the main window, returning true when it
    /// did. Returning false tells the caller to fall back to a modal, so an
    /// alert is never presented twice.
    var alertPresenter: ((NSAlert) -> Bool)?

    /// True once the menu-bar item is installed.
    private(set) var isInstalled = false

    private init() {}

    /// Installs the menu-bar item and starts polling if the user had already
    /// enabled monitoring in a previous launch.
    ///
    /// PR monitoring stays off until the user turns it on, so installing the
    /// item never causes network traffic on a fresh install.
    func install() {
        guard !isInstalled else { return }
        isInstalled = true

        let menuBar = PRMenuBarController(coordinator: self)
        self.menuBar = menuBar
        menuBar.install()

        monitor.onChange = { [weak menuBar] in menuBar?.rebuildFromMonitor() }
        PRNotifier.shared.onReview = { [weak self] item in self?.startReview(item) }
        PRNotifier.shared.onIgnore = { [weak self] item in
            self?.monitor.dismiss(item)
            self?.menuBar?.rebuildFromMonitor()
        }
        PRNotifier.shared.publishStatus()
        PRNotifier.shared.registerActions()
        PRNotifier.shared.install()
        monitor.start()
    }

    func uninstall() {
        monitor.stop()
        menuBar?.uninstall()
        menuBar = nil
        activeSession?.tearDown()
        activeSession = nil
        isInstalled = false
    }

    func setMainWindowProvider(_ provider: @escaping () -> MainWindowController?) {
        mainWindowProvider = provider
        menuBar?.mainWindowProvider = provider
        alertPresenter = { alert in
            // A status-item menu click never activates the app, so it is
            // activated here: a sheet attached to a background window looks
            // exactly like nothing happening.
            NSApp.activate(ignoringOtherApps: true)
            guard let window = provider()?.window, window.isVisible else { return false }
            alert.beginSheetModal(for: window, completionHandler: nil)
            return true
        }
        menuBar?.alertPresenter = alertPresenter
    }

    /// Polling state changed in the menu.
    func monitoringDidChange() {
        monitor.monitoringDidChange()
    }

    func pollNow() {
        monitor.pollNow()
    }

    /// Called when a repository is added or removed, so the poll is redone. A
    /// newly added repository is muted for that poll: its existing pull
    /// requests are pre-existing, not news, and the user only wants to hear
    /// about a pull request that appears from here on.
    func repositoriesDidChange(mutedRepoIDs: Set<String> = []) {
        monitor.silenceFirstPoll(for: mutedRepoIDs)
        monitor.pollNow()
    }

    /// Materialises a PR and opens it in the main window.
    func startReview(_ item: PRActionItem) {
        guard GitRunner.isAvailable() else {
            presentAlert(title: "Git is not available", message: GitRunner.unavailableMessage)
            return
        }
        guard let main = mainWindowProvider?() else {
            presentAlert(title: "Main window unavailable",
                         message: "Open a folder in Karma Pro first, then review the pull request.")
            return
        }

        // Only one review at a time: two checkouts would otherwise fight over
        // the file tree and the scan window.
        activeSession?.tearDown()
        activeSession = nil

        let workspace = monitor.workspaceURL(for: item.pr, repo: item.repo)
        let localPath = item.repo.localPath.map { URL(fileURLWithPath: $0) }

        // The fetch is started before the window is shown. Showing a modal first
        // and fetching afterwards would make the user dismiss a "preparing"
        // window before any preparation had begun, so it is presented as a sheet
        // and dismissed when the work completes.
        let progress = PRProgressPanelController(for: item)
        let key = item.pr.fingerprint(remoteKey: item.repo.id)
        presentingPanels[key] = progress
        let cancelled = Cancellation()

        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            do {
                // git needs the same credential the REST API does: cloning a
                // private repository without one makes git try to open a
                // terminal and ask for a username, which cannot work from a
                // windowed app. Resolved here so the token is read from the
                // Keychain on the background queue and never held on the main
                // one.
                let auth = GitAuth(provider: item.repo.provider,
                                   token: PRStore.shared.token(for: item.repo) ?? "")
                let checkout = try GitRunner.prepare(repo: item.repo,
                                                     pr: item.pr,
                                                     workspace: workspace,
                                                     depth: item.repo.depth,
                                                     localPath: localPath,
                                                     auth: auth.token.isEmpty ? nil : auth,
                                                     progress: { stage, fraction in
                    DispatchQueue.main.async {
                        progress.update(fraction: fraction, stage: stage)
                    }
                })
                DispatchQueue.main.async {
                    guard let self = self else { return }
                    let panel = self.presentingPanels.removeValue(forKey: key)
                    panel?.dismiss(cancelledByUser: panel?.wasCancelled == true || cancelled.flag)
                    // The user pressed Cancel: drop the checkout rather than
                    // opening a review they have already dismissed.
                    if cancelled.flag || panel?.wasCancelled == true {
                        GitRunner.cleanup(workspace, localPath: localPath)
                        return
                    }
                    let session = PRReviewSession(repo: item.repo, pr: item.pr, checkout: checkout)
                    self.activeSession = session
                    NSApp.activate(ignoringOtherApps: true)
                    main.openPullRequestReview(session)
                }
            } catch {
                DispatchQueue.main.async {
                    let panel = self?.presentingPanels.removeValue(forKey: key)
                    panel?.dismiss(cancelledByUser: cancelled.flag)
                    if cancelled.flag { return }
                    self?.presentAlert(title: "Could not prepare the review",
                                       message: error.localizedDescription)
                }
            }
        }

        progress.present(over: main.window) { cancelled.flag = true }
    }

    /// Discards the checkout of a review the user closed.
    func didCloseSession(_ session: PRReviewSession) {
        if activeSession === session {
            activeSession = nil
        }
    }

    // MARK: - Alerts

    /// Progress windows currently on screen, keyed by PR so a completion can
    /// dismiss exactly the one it belongs to.
    private var presentingPanels: [String: PRProgressPanelController] = [:]

    /// True while a review's checkout is open, so the repository dialog can
    /// refuse to clear the cache out from under it.
    var hasActiveReview: Bool { activeSession != nil }

    /// A plain box to carry a cancellation flag across queues, since the fetch
    /// runs detached from the alert that could cancel it.
    private final class Cancellation {
        var flag = false
    }

    /// Shows an alert as a sheet on the main window so the main thread is never
    /// blocked and a fetch can already be in flight behind it.
    private func present(_ alert: NSAlert) {
        // A status-item menu click never activates the app, so without this the
        // sheet is attached to a window that is behind whatever the user is
        // looking at, and appears to do nothing.
        NSApp.activate(ignoringOtherApps: true)
        if let window = mainWindowProvider?()?.window, window.isVisible {
            alert.beginSheetModal(for: window, completionHandler: nil)
        } else {
            alert.runModal()
        }
    }

    private func presentAlert(title: String, message: String) {
        let alert = NSAlert()
        alert.messageText = title
        alert.informativeText = message
        alert.addButton(withTitle: "OK")
        if let presenter = alertPresenter, presenter(alert) { return }
        NSApp.activate(ignoringOtherApps: true)
        _ = alert.runModal()
    }

}
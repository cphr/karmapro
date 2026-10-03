// by cipher.org.uk
import AppKit

/// The menu-bar entry point for the whole pull-request feature.
///
/// Everything lives behind one `NSStatusItem` by design: the user asked for all
/// PR controls to be in the menu bar rather than in a Preferences window, so
/// the only things that ever appear as separate windows are the two small
/// dialogs the menu can launch (accounts and repositories).
final class PRMenuBarController: NSObject, NSMenuDelegate {
    private weak var coordinator: PRReviewCoordinator?
    private var statusItem: NSStatusItem!
    private let store = PRStore.shared

    var mainWindowProvider: (() -> MainWindowController?)?
    var alertPresenter: ((NSAlert) -> Bool)?

    private var accountsWindow: AccountsWindowController?
    private var reposWindow: MonitoredReposWindowController?

    init(coordinator: PRReviewCoordinator) {
        self.coordinator = coordinator
        super.init()
    }

    func install() {
        statusItem = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)
        if let button = statusItem.button {
            button.image = PRMenuBarController.makeStatusImage()
            button.imagePosition = .imageOnly
            button.toolTip = "Karma Pro pull requests monitoring"
        }
        let menu = NSMenu()
        menu.delegate = self
        // Automatic item validation is the reason a visible menu entry can be a
        // dead click: NSMenu disables any item whose action the target fails to
        // validate, and Swift's @objc menu actions are not always recognised as
        // validatable. This menu is built explicitly, so validation has nothing
        // to add and is switched off.
        menu.autoenablesItems = false
        statusItem.menu = menu
        rebuild()
    }

    /// Draws the status icon rather than using an SF Symbol.
    ///
    /// A template image is recoloured by macOS to match the menu bar, which
    /// would make a filled lens indistinguishable from an outline one, so this
    /// is drawn as a real (non-template) image: a white filled lens with a ring
    /// and handle around it.
    private static func makeStatusImage() -> NSImage {
        drawStatusImage(active: true)
    }

    /// The menu bar icon, faded while monitoring is off.
    ///
    /// A filled white lens reads as "working", which is a lie when polling is
    /// switched off, so the idle icon differs — but only in strength, not in
    /// shape. Drawing it hollow and grey was the first attempt and it read as a
    /// genuinely disabled control: at 18pt on a busy menu bar it was hard to
    /// find at all, which is the worst possible failure for the one icon that
    /// has to be glanceable. The idle icon keeps the same filled lens and the
    /// same ring and handle, drawn at reduced alpha instead, so it is clearly
    /// present but plainly not working.
    ///
    /// Drawn as a real (non-template) image because a template image is
    /// recoloured by macOS and would throw away the two-tone distinction.
    private static func drawStatusImage(active: Bool) -> NSImage {
        let size = NSSize(width: 18, height: 18)
        let lensDiameter: CGFloat = 11
        let lensRect = NSRect(x: 1, y: 4, width: lensDiameter, height: lensDiameter)
        let lens = NSBezierPath(ovalIn: lensRect)

        // Menu bar foreground at rest, and a faded version of the same colour
        // when idle. The idle alpha is well above the point where the shape
        // disappears against the bar, which is why it is a fade rather than the
        // hollow outline this replaced.
        let fill = active ? NSColor.white : NSColor.white.withAlphaComponent(0.55)
        let stroke = active ? NSColor.black : NSColor.black.withAlphaComponent(0.40)

        let image = NSImage(size: size, flipped: false) { rect in
            // Filled in both states, so the icon stays the same recognisable
            // shape and only loses strength.
            fill.setFill()
            lens.fill()

            // Ring and handle, so the icon stays legible in light and dark bars.
            let ring = NSBezierPath(ovalIn: lensRect.insetBy(dx: 0.75, dy: 0.75))
            ring.lineWidth = 1.2
            stroke.setStroke()
            ring.stroke()

            let handle = NSBezierPath()
            handle.lineWidth = 2.0
            handle.lineCapStyle = .round
            handle.move(to: NSPoint(x: lensRect.maxX - 1.5, y: lensRect.minY + 1.5))
            handle.line(to: NSPoint(x: rect.maxX - 1.5, y: 1.5))
            stroke.setStroke()
            handle.stroke()

            return true
        }
        image.isTemplate = false
        return image
    }

    /// Re-applies the icon and tooltip to match the monitoring state.
    ///
    /// Called from `rebuild`, which runs on install and on every state change,
    /// so the icon cannot disagree with the menu it opens.
    private func refreshStatusItemAppearance() {
        let enabled = store.monitoringEnabled
        if let button = statusItem.button {
            button.image = PRMenuBarController.drawStatusImage(active: enabled)
            button.toolTip = enabled
                ? "Karma Pro pull requests monitoring"
                : "Karma Pro pull requests monitoring (off)"
            // Also the accessibility state, so the dimmed icon is not the only
            // thing telling a screen reader monitoring is paused.
            button.setAccessibilityLabel(enabled
                ? "Pull request monitoring"
                : "Pull request monitoring, off")
        }
    }

    func uninstall() {
        if let statusItem = statusItem { NSStatusBar.system.removeStatusItem(statusItem) }
        statusItem = nil
    }

    private var monitor: PRMonitor? { coordinator?.monitor }

    /// The coordinator owns the poller, so the menu reads its published state
    /// rather than running polls of its own.
    private var pollError: String? { monitor?.currentErrorSummary }

    func rebuildFromMonitor() {
        rebuild()
    }

    // MARK: - Menu construction

    /// Rebuilds the menu from current state. Simpler and less bug-prone than
    /// incrementally mutating items, and the item count is small and fixed.
    /// The live menu's titles, for verification that nothing pull-request
    /// shaped has crept back in.
    var menuTitles: [String] { statusItem.menu?.items.map { $0.title } ?? [] }

    private func rebuild() {
        refreshStatusItemAppearance()
        guard let menu = statusItem.menu else { return }
        menu.removeAllItems()

        guard store.monitoringEnabled else {
            let off = NSMenuItem(title: "Pull request monitoring is off", action: nil, keyEquivalent: "")
            off.isEnabled = false
            menu.addItem(off)
            menu.addItem(.separator())
            menu.addItem(makeItem("Enable Monitoring…", #selector(enableMonitoring)))
            menu.addItem(makeItem("Manage Repositories…", #selector(showRepos)))
            menu.addItem(makeItem("Accounts…", #selector(showAccounts)))
            menu.addItem(.separator())
            menu.addItem(makeItem("Quit Karma Pro", #selector(quitApp)))
            return
        }

        // The pull request list deliberately does not live here. A status menu
        // that changes shape on every poll cannot be scanned, and listing
        // pull requests in it competes with the menu's actual job. New pull
        // requests arrive as macOS notifications instead, where they do not
        // interrupt a review that is already under way.
        if let error = pollError, !error.isEmpty {
            menu.addItem(disabledItem(error))
            menu.addItem(.separator())
        }

        menu.addItem(makeItem("Check Now", #selector(checkNow)))
        // Confirms notifications work without waiting for a poll, which is the
        // difference between "broken" and "nothing new happened" when nothing
        // is appearing.
        menu.addItem(makeItem("Disable Monitoring", #selector(disableMonitoring)))
        menu.addItem(.separator())
        addScanDepthItems(to: menu)
        addNotifyItems(to: menu)
        menu.addItem(.separator())
        menu.addItem(makeItem("Manage Repositories…", #selector(showRepos)))
        menu.addItem(makeItem("Accounts…", #selector(showAccounts)))
        menu.addItem(makeItem("About Pull Request Reviews", #selector(showAbout)))
        menu.addItem(.separator())
        let quit = makeItem("Quit Karma Pro", #selector(quitApp))
        quit.keyEquivalent = "q"
        menu.addItem(quit)
    }

    private func makeItem(_ title: String, _ action: Selector) -> NSMenuItem {
        let item = NSMenuItem(title: title, action: action, keyEquivalent: "")
        item.target = self
        // With automatic validation off, enabled state is set here instead.
        item.isEnabled = true
        return item
    }

    /// Rebuilt each time the menu opens, so the open-pull-request count and the
    /// last error are current rather than as of the last poll.
    func menuWillOpen(_ menu: NSMenu) {
        rebuild()
    }

    private func disabledItem(_ title: String, indented: Bool = false) -> NSMenuItem {
        let item = NSMenuItem(title: title, action: nil, keyEquivalent: "")
        item.isEnabled = false
        item.indentationLevel = indented ? 1 : 0
        return item
    }

    private func addScanDepthItems(to menu: NSMenu) {
        menu.addItem(disabledItem("Scan depth:"))
        for depth in PRKind.Depth.allCases {
            let item = makeItem(depth.title, #selector(setDepth(_:)))
            item.state = (store.defaultDepth == depth) ? .on : .off
            item.representedObject = depth.rawValue
            item.indentationLevel = 1
            item.toolTip = depth.explanation
            menu.addItem(item)
        }
    }

    private func addNotifyItems(to menu: NSMenu) {
        menu.addItem(disabledItem("Alert me about new PRs:"))
        for style in PRKind.NotifyStyle.allCases {
            let item = makeItem(style.title, #selector(setNotifyStyle(_:)))
            item.state = (store.notifyStyle == style) ? .on : .off
            item.representedObject = style.rawValue
            item.indentationLevel = 1
            menu.addItem(item)
        }
    }

    // MARK: - Menu actions

    @objc private func enableMonitoring() {
        guard !store.repos.isEmpty else {
            presentNoReposAlert()
            return
        }
        guard GitRunner.isAvailable() else {
            presentAlert(title: "Git is not available", message: GitRunner.unavailableMessage)
            return
        }
        store.monitoringEnabled = true
        coordinator?.repositoriesDidChange()
        rebuild()
    }

    @objc private func disableMonitoring() {
        store.monitoringEnabled = false
        coordinator?.monitoringDidChange()
        rebuild()
    }

    @objc private func checkNow() {
        coordinator?.pollNow()
    }

    @objc private func setDepth(_ sender: NSMenuItem) {
        guard let raw = sender.representedObject as? String,
              let depth = PRKind.Depth(rawValue: raw) else { return }
        store.defaultDepth = depth
        rebuild()
    }

    @objc private func setNotifyStyle(_ sender: NSMenuItem) {
        guard let raw = sender.representedObject as? String,
              let style = PRKind.NotifyStyle(rawValue: raw) else { return }
        store.notifyStyle = style
        rebuild()
    }

    @objc private func showRepos() {
        NSApp.activate(ignoringOtherApps: true)
        if reposWindow == nil {
            let controller = MonitoredReposWindowController()
            var addedRepoIDs: Set<String> = []
            controller.onRepoAdded = { addedRepoIDs.insert($0) }
            // Clearing the cache deletes the files an open review is reading.
            controller.isReviewActive = { [weak coordinator] in
                coordinator?.hasActiveReview ?? false
            }
            controller.onChange = { [weak self] in
                // Anything added since the last change should not be announced.
                let muted = addedRepoIDs
                addedRepoIDs = []
                self?.coordinator?.repositoriesDidChange(mutedRepoIDs: muted)
                self?.rebuild()
            }
            reposWindow = controller
        }
        // Poll detail is shown here rather than in the menu, which is too narrow
        // to display a provider error and would resize to fit it.
        reposWindow?.setPollError(monitor?.currentError)
        // Authorization is read when the dialog opens, so "no notifications
        // appear" has an answer on screen instead of only in a log file. The
        // notifier holds this closure, so it is set every time the dialog is
        // shown rather than only when the controller is built.
        let repos = reposWindow
        PRNotifier.shared.onStatusChange = { [weak repos] status, note in
            repos?.setNotificationStatus(status, note)
        }
        PRNotifier.shared.publishStatus()
        reposWindow?.showWindow(nil)
        reposWindow?.window?.makeKeyAndOrderFront(nil)
    }

    @objc private func showAccounts() {
        NSApp.activate(ignoringOtherApps: true)
        if accountsWindow == nil {
            accountsWindow = AccountsWindowController()
        }
        accountsWindow?.showWindow(nil)
        accountsWindow?.window?.makeKeyAndOrderFront(nil)
    }

    @objc private func showAbout() {
        presentAlert(title: "Pull Request Reviews", message: """
            Karma Pro watches the repositories you list and alerts you when a new pull request arrives.

            • Public repositories need no credentials.
            • Private repositories are opt-in per repository and use a read-only token you supply, stored in your Keychain.
            • Reviews are read-only: Karma Pro never approves, comments on, or posts to any pull request.
            • Reports are Markdown files you save yourself.

            Pull requests are polled while Karma Pro is running. Nothing is fetched when the app is closed.
            """)
    }

    @objc private func quitApp() {
        NSApp.terminate(nil)
    }

    // MARK: - Alerts

    private func presentNoReposAlert() {
        let alert = NSAlert()
        alert.messageText = "No repositories yet"
        alert.informativeText = "Add a repository to watch before enabling monitoring."
        alert.addButton(withTitle: "Manage Repositories…")
        alert.addButton(withTitle: "Cancel")

        if let window = mainWindowProvider?()?.window, window.isVisible {
            // Sheets are attached to the main window, which needs the app active
            // to be seen at all.
            NSApp.activate(ignoringOtherApps: true)
            alert.beginSheetModal(for: window, completionHandler: { [weak self] response in
                if response == .alertFirstButtonReturn { self?.showRepos() }
            })
            return
        }
        NSApp.activate(ignoringOtherApps: true)
        if alert.runModal() == .alertFirstButtonReturn {
            showRepos()
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
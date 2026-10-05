// by cipher.org.uk
import AppKit
import UserNotifications

let app = NSApplication.shared
if let darkAppearance = NSAppearance(named: .darkAqua) {
    app.appearance = darkAppearance
}
// Load the bundle icon so the Dock / Cmd-Tab tile shows the app's magnifying-glass + lock
// icon reliably (independent of macOS icon-cache behavior).
if let bundleIcon = NSImage(named: NSImage.Name("AppIcon")) {
    app.applicationIconImage = bundleIcon
}

// Build a minimal main menu with an About item crediting cipher.org.uk.
// The target is kept alive for the app's lifetime so the menu item stays enabled.
final class AboutMenuItemTarget: NSObject {
    private var splash: SplashWindowController?
    private var hideWorkItem: DispatchWorkItem?

    @objc func showAbout(_ sender: Any?) {
        let splash = SplashWindowController()
        splash.showWindow(nil)
        NSApp.activate(ignoringOtherApps: true)
        self.splash = splash
        hideWorkItem?.cancel()
        let work = DispatchWorkItem { [weak self] in
            self?.splash?.window?.orderOut(nil)
            self?.splash = nil
        }
        hideWorkItem = work
        DispatchQueue.main.asyncAfter(deadline: .now() + 5.0, execute: work)
    }
}

let aboutTarget = AboutMenuItemTarget()

/// Owns the three update menu items and the daily check behind them.
///
/// The check runs at most once every 24 hours, gated on a stored date rather
/// than on a 24 hour timer, so relaunching the app does not re-hit GitHub and a
/// machine that was asleep catches up as soon as it wakes.
///
/// Nothing here can change a user preference on its own: a failed check reports
/// the failure and stops, and never touches the automatic-check setting.
final class UpdateMenuTarget: NSObject, NSMenuDelegate {
    /// How often the daily gate is consulted. Cheap — a stored-date read and a
    /// comparison — and it means a check lands close to 24 hours after the last
    /// one even across sleep, unlike a timer set to exactly 24 hours.
    private static let gateInterval: TimeInterval = 300

    private var checkItem: NSMenuItem?
    private var automaticItem: NSMenuItem?
    private var availableItem: NSMenuItem?
    private var gateTimer: Timer?
    private var checkInFlight = false

    /// Called once at launch, after the run loop is running.
    func install() {
        gateTimer = Timer.scheduledTimer(withTimeInterval: Self.gateInterval, repeats: true) { [weak self] _ in
            self?.runAutomaticCheckIfDue()
        }
        runAutomaticCheckIfDue()
    }

    /// Builds the update section and appends it to the application menu, in the
    /// order: check, separator, automatic, availability, separator. The
    /// availability row collapses away when nothing newer is known, which leaves
    /// a single clean separator rather than two stacked together.
    func attach(to menu: NSMenu) {
        let check = NSMenuItem(title: "Check for Updates…",
                               action: #selector(checkForUpdates(_:)),
                               keyEquivalent: "")
        check.target = self
        menu.addItem(check)
        checkItem = check

        menu.addItem(NSMenuItem.separator())

        let automatic = NSMenuItem(title: "Check for Updates Automatically",
                                   action: #selector(toggleAutomaticChecks(_:)),
                                   keyEquivalent: "")
        automatic.target = self
        menu.addItem(automatic)
        automaticItem = automatic
        refreshAutomaticItem()

        let available = NSMenuItem(title: "Update Available",
                                   action: #selector(openKnownUpdate(_:)),
                                   keyEquivalent: "")
        available.target = self
        available.isHidden = true
        menu.addItem(available)
        availableItem = available
        refreshAvailableItem()

        menu.addItem(NSMenuItem.separator())
    }

    // MARK: - Menu actions

    @objc func checkForUpdates(_ sender: Any?) {
        runCheck()
    }

    @objc func toggleAutomaticChecks(_ sender: Any?) {
        UpdateSettings.automaticChecksEnabled.toggle()
        refreshAutomaticItem()
        // Turning it on checks straight away if the daily gate allows it, so the
        // setting visibly does something rather than waiting out a day.
        runAutomaticCheckIfDue()
    }

    @objc func openKnownUpdate(_ sender: Any?) {
        // The stored release's own page, so Download always lands on the exact
        // release that was detected rather than on a list to search.
        let url = UpdateSettings.knownNewerPageURL.flatMap(URL.init(string:))
            ?? UpdateChecker.fallbackPage
        NSWorkspace.shared.open(url)
    }

    // MARK: - Menu state

    func menuNeedsUpdate(_ menu: NSMenu) {
        refreshAutomaticItem()
        refreshAvailableItem()
    }

    /// Keeps the checkmark honest even if the setting changed outside the menu.
    private func refreshAutomaticItem() {
        automaticItem?.state = UpdateSettings.automaticChecksEnabled ? .on : .off
    }

    /// The update row exists only while a newer release is known. Hiding it
    /// rather than disabling it keeps the menu from growing a dead entry.
    private func refreshAvailableItem() {
        guard let item = availableItem else { return }
        if let version = UpdateSettings.knownNewerVersion,
           VersionComparator.isNewer(tag: version, than: UpdateChecker.currentVersion) {
            item.title = "Update \(version) Available"
            item.isHidden = false
        } else {
            item.isHidden = true
        }
    }

    // MARK: - Checking

    private func runAutomaticCheckIfDue() {
        guard UpdateSettings.automaticChecksEnabled, !checkInFlight else { return }
        guard UpdateSettings.isCheckDue() else { return }
        // Stand aside while a scan has the front of the app, so the check does
        // not compete with it. The gate means a skipped check simply happens on
        // the next tick instead of being lost.
        guard !scanIsInForeground else { return }
        runCheck()
    }

    private func runCheck() {
        guard !checkInFlight else { return }
        checkInFlight = true
        checkItem?.title = "Checking…"
        checkItem?.isEnabled = false

        UpdateChecker.check { [weak self] outcome in
            guard let self = self else { return }
            self.checkInFlight = false
            self.checkItem?.title = "Check for Updates…"
            self.checkItem?.isEnabled = true
            // Recorded whatever the result, so a failure cannot retry in a loop.
            UpdateSettings.lastCheckDate = Date()
            self.apply(outcome)
        }
    }

    private func apply(_ outcome: UpdateChecker.Outcome) {
        switch outcome {
        case .upToDate(let current):
            UpdateSettings.clearKnownNewerVersionIfNotNewer(than: current)
            refreshAvailableItem()
            showAlert(title: "You're up to date",
                      message: "Karma Pro \(current) is the latest release.",
                      buttons: ["OK"])

        case .updateAvailable(let release):
            UpdateSettings.knownNewerVersion = release.version
            UpdateSettings.knownNewerPageURL = release.pageURL.absoluteString
            refreshAvailableItem()
            // Foreground: ask. Background: leave a notification and rely on the
            // menu row, so an update is never only visible behind a permission.
            if NSApp.isActive {
                showUpdateAlert(release)
            } else {
                postNotification(for: release)
            }

        case .failed:
            // Shown for an automatic check too, bounded to once a day by the
            // cadence. Silence here would be indistinguishable from "no news".
            showAlert(title: "Can't Currently Check for Updates",
                      message: "Karma Pro couldn't check GitHub for a newer release.",
                      buttons: ["OK"])
        }
    }

    // MARK: - Presenting

    private func showUpdateAlert(_ release: UpdateChecker.Release) {
        let age = UpdateChecker.agePhrase(since: release.publishedAt)
        var message = "You have \(UpdateChecker.currentVersion)."
        if !age.isEmpty { message += " Version \(release.version) was released \(age)." }

        let alert = NSAlert()
        alert.messageText = "Karma Pro \(release.version) Is Available"
        alert.informativeText = message
        alert.addButton(withTitle: "Download")
        alert.addButton(withTitle: "Later")
        NSApp.activate(ignoringOtherApps: true)
        if alert.runModal() == .alertFirstButtonReturn {
            NSWorkspace.shared.open(release.pageURL)
        }
        // "Later" deliberately keeps the offer: the menu row stays until the
        // running version catches up, so the choice only silences the alert.
    }

    private func showAlert(title: String, message: String, buttons: [String]) {
        let alert = NSAlert()
        alert.messageText = title
        alert.informativeText = message
        for button in buttons { alert.addButton(withTitle: button) }
        NSApp.activate(ignoringOtherApps: true)
        alert.runModal()
    }

    /// Only notifies when permission is already granted. The update check never
    /// prompts for it: the menu row carries the same information for free.
    private func postNotification(for release: UpdateChecker.Release) {
        let center = UNUserNotificationCenter.current()
        center.getNotificationSettings { settings in
            guard settings.authorizationStatus == .authorized
               || settings.authorizationStatus == .provisional else { return }
            let content = UNMutableNotificationContent()
            content.title = "Karma Pro \(release.version) Is Available"
            var body = "You have \(UpdateChecker.currentVersion)."
            let age = UpdateChecker.agePhrase(since: release.publishedAt)
            if !age.isEmpty { body += " Version \(release.version) was released \(age)." }
            content.body = body
            center.add(UNNotificationRequest(identifier: "karma.update.available",
                                            content: content, trigger: nil))
        }
    }

    /// The scanner exposes no "is scanning" flag, and the update work keeps
    /// `ScanWindowController` untouched, so a visible key scan window stands in
    /// for one. Deliberately conservative: a check that waits here runs on the
    /// next tick instead of being skipped for the day.
    private var scanIsInForeground: Bool {
        NSApp.windows.contains {
            $0.isVisible && $0.isKeyWindow && $0.windowController is ScanWindowController
        }
    }
}

let updateTarget = UpdateMenuTarget()

final class HelpMenuTarget: NSObject {
    private var helpController: HelpWindowController?

    @objc func showHelp(_ sender: Any?) {
        if helpController == nil {
            helpController = HelpWindowController()
        }
        helpController?.showWindow(nil)
        helpController?.window?.makeKeyAndOrderFront(nil)
        NSApp.activate(ignoringOtherApps: true)
    }
}

let helpTarget = HelpMenuTarget()

final class LicensingMenuTarget: NSObject {
    private var licensingController: LicensingWindowController?

    @objc func scanProjectLicenses(_ sender: Any?) {
        // Find current project root if available from delegate/windowController
        let rootURL: URL? = (NSApp.delegate as? AppDelegate)?.currentProjectRootURL
        let controller = LicensingWindowController(projectRoot: rootURL)
        controller.showWindow(nil)
        controller.window?.makeKeyAndOrderFront(nil)
        NSApp.activate(ignoringOtherApps: true)
        licensingController = controller
    }
}

let licensingTarget = LicensingMenuTarget()

func makeMainMenu() -> NSMenu {
    let mainMenu = NSMenu()

    let appMenuItem = NSMenuItem()
    mainMenu.addItem(appMenuItem)
    let appMenu = NSMenu()
    let aboutItem = NSMenuItem(title: "About Karma Pro",
                                action: #selector(AboutMenuItemTarget.showAbout(_:)),
                                keyEquivalent: "")
    aboutItem.target = aboutTarget
    appMenu.addItem(aboutItem)

    // Update support. The check item disables itself while a request is in
    // flight so a double-click cannot start two; the automatic item is a
    // user-owned preference and is never changed by a check; the availability
    // row is hidden unless a newer release is actually known.
    updateTarget.attach(to: appMenu)

    appMenu.addItem(NSMenuItem.separator())
    appMenu.addItem(NSMenuItem(title: "Quit Karma Pro",
                                action: #selector(NSApplication.terminate(_:)),
                                keyEquivalent: "q"))
    appMenuItem.submenu = appMenu
    appMenu.delegate = updateTarget

    // Standard Edit menu: without it, Cut/Copy/Paste/Select All shortcuts
    // (Cmd+X/C/V/A) are never dispatched to text fields, which broke pasting
    // e.g. an OpenRouter API key into the AI window. The nil targets let the
    // actions flow down the responder chain to the focused control.
    let editMenuItem = NSMenuItem()
    mainMenu.addItem(editMenuItem)
    let editMenu = NSMenu(title: "Edit")
    editMenu.addItem(NSMenuItem(title: "Undo", action: #selector(UndoManager.undo), keyEquivalent: "z"))
    editMenu.addItem(NSMenuItem(title: "Redo", action: #selector(UndoManager.redo), keyEquivalent: "Z"))
    editMenu.addItem(NSMenuItem.separator())
    editMenu.addItem(NSMenuItem(title: "Cut", action: #selector(NSText.cut(_:)), keyEquivalent: "x"))
    editMenu.addItem(NSMenuItem(title: "Copy", action: #selector(NSText.copy(_:)), keyEquivalent: "c"))
    editMenu.addItem(NSMenuItem(title: "Paste", action: #selector(NSText.paste(_:)), keyEquivalent: "v"))
    editMenu.addItem(NSMenuItem(title: "Delete", action: #selector(NSText.delete(_:)), keyEquivalent: ""))
    editMenu.addItem(NSMenuItem(title: "Select All", action: #selector(NSText.selectAll(_:)), keyEquivalent: "a"))
    editMenuItem.submenu = editMenu

    let licensingMenuItem = NSMenuItem()
    mainMenu.addItem(licensingMenuItem)
    let licensingMenu = NSMenu(title: "Licensing")
    let scanLicensesItem = NSMenuItem(title: "Scan Licenses",
                                     action: #selector(LicensingMenuTarget.scanProjectLicenses(_:)),
                                     keyEquivalent: "l")
    scanLicensesItem.target = licensingTarget
    licensingMenu.addItem(scanLicensesItem)
    licensingMenuItem.submenu = licensingMenu

    let helpMenuItem = NSMenuItem()
    mainMenu.addItem(helpMenuItem)
    let helpMenu = NSMenu(title: "Help")
    let helpItem = NSMenuItem(title: "Karma Pro Help",
                              action: #selector(HelpMenuTarget.showHelp(_:)),
                              keyEquivalent: "?")
    helpItem.target = helpTarget
    helpMenu.addItem(helpItem)
    helpMenuItem.submenu = helpMenu

    return mainMenu
}

app.mainMenu = makeMainMenu()

let delegate = AppDelegate()
app.delegate = delegate
app.setActivationPolicy(.regular)
app.run()

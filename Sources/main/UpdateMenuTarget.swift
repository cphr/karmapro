// by cipher.org.uk
import AppKit
import UserNotifications

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

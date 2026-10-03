// by cipher.org.uk
import AppKit
import UserNotifications

/// Delivers new-pull-request alerts as macOS notifications, and nothing else.
///
/// Two decisions are baked in here. Alerts never appear inside the app: a sheet
/// over the review window interrupts a review in progress, which is exactly when
/// a new pull request is least welcome. And a single poll can surface dozens of
/// pull requests in a busy repository, so the batch is capped and the true total
/// is stated in the message rather than silently truncating.
final class PRNotifier: NSObject, UNUserNotificationCenterDelegate {
    static let shared = PRNotifier()

    /// Most pull requests announced for one poll. The rest are remembered so a
    //  later Review still resolves, but they are not announced.
    static let maxAlertsPerPoll = 5

    private static let category = "karma.pr.new"
    private static let reviewAction = "karma.pr.review"
    private static let notNowAction = "karma.pr.notnow"
    private static let ignoreAction = "karma.pr.ignore"
    private static let pendingReviewKey = "karma.pr.pendingReview"

    private let center = UNUserNotificationCenter.current()

    /// Pull requests posted since the last poll, so a notification response can
    /// be resolved back to the repository and pull request it refers to.
    private var byIdentifier: [String: PRActionItem] = [:]

    /// Set when the user picks Review. Always delivered on the main thread.
    var onReview: ((PRActionItem) -> Void)?

    /// Set when the user picks Ignore, so the watch list can drop it.
    var onIgnore: ((PRActionItem) -> Void)?

    private override init() {
        super.init()
    }

    func install() {
        center.delegate = self
    }

    /// Asked only once the user has actually turned notifications on.
    ///
    /// The result is logged and published because "no notifications appear" is
    /// otherwise indistinguishable from "nothing was ever posted", and the two
    /// have completely different fixes.
    func requestAuthorization() {
        center.requestAuthorization(options: [.alert, .sound]) { granted, error in
            let note = "notification authorization: granted=\(granted) error=\(error.map { "\($0.localizedDescription)" } ?? "none")"
            PRLog.write(note)
            DispatchQueue.main.async {
                self.authorizationNote = note
                self.onStatusChange?(self.authorizationStatus, note)
            }
            self.publishStatus()
        }
    }

    /// Current authorization, for display in the repository dialog.
    func publishStatus() {
        center.getNotificationSettings { settings in
            let value = settings.authorizationStatus
            let readable: String
            switch value {
            case .authorized: readable = "authorized"
            case .provisional: readable = "provisional"
            case .ephemeral: readable = "ephemeral"
            case .denied: readable = "denied"
            case .notDetermined: readable = "not requested"
            @unknown default: readable = "unknown"
            }
            DispatchQueue.main.async {
                self.authorizationStatus = readable
                self.onStatusChange?(readable, self.authorizationNote)
            }
        }
    }

    /// Posted on the main queue whenever the authorization state is re-read, so
    /// the repository dialog can explain a silence the user cannot otherwise
    /// account for.
    var onStatusChange: ((String, String) -> Void)?

    /// The last line written about authorization, shown in the dialog.
    private(set) var authorizationNote = ""
    private(set) var authorizationStatus = "unknown"

    /// Posts at most `maxAlertsPerPoll` notifications, newest first.
    func deliver(_ fresh: [PRActionItem], allowSound: Bool) {
        guard !fresh.isEmpty else { return }

        // "Last" is taken as most recently updated, which is also how the
        // provider list is ordered, so the cap keeps the most relevant work.
        let sorted = fresh.sorted { lhs, rhs in
            let left = lhs.pr.updatedAt ?? Date.distantPast
            let right = rhs.pr.updatedAt ?? Date.distantPast
            return left > right
        }
        let shown = Array(sorted.prefix(Self.maxAlertsPerPoll))
        let total = sorted.count

        for item in shown {
            let identifier = identifier(for: item)
            byIdentifier[identifier] = item

            let content = UNMutableNotificationContent()
            content.title = "\(item.repo.repoSlug) #\(item.pr.number)"
            content.body = body(for: item, total: total, shown: shown.count)
            content.categoryIdentifier = Self.category
            if allowSound { content.sound = .default }

            let request = UNNotificationRequest(identifier: identifier,
                                                content: content,
                                                trigger: nil)
            center.add(request) { error in
                if let error = error {
                    PRLog.write("notification \(identifier) failed: \(error.localizedDescription)")
                }
            }
        }
        PRLog.write("posted \(shown.count) of \(total) new pull requests as notifications")

        // Remember the rest so a later Review action on them still works, even
        // though they were never announced.
        for item in sorted.dropFirst(Self.maxAlertsPerPoll) {
            byIdentifier[identifier(for: item)] = item
        }
    }

    /// The message always states how many pull requests arrived, so a capped
    /// batch cannot be mistaken for the whole story.
    private func body(for item: PRActionItem, total: Int, shown: Int) -> String {
        let headline = "#\(item.pr.number) \(item.pr.title) — \(item.pr.author)"
        guard total > 1 else { return headline }
        if total > shown {
            return "\(headline)\n\(total) new since you last looked — \(shown) most recent shown, the rest are in the menu bar menu."
        }
        return "\(headline)\n\(total) new since you last looked."
    }

    private func identifier(for item: PRActionItem) -> String {
        item.pr.fingerprint(remoteKey: item.repo.id)
    }

    private func item(for identifier: String) -> PRActionItem? {
        byIdentifier[identifier]
    }

    private func review(_ item: PRActionItem) {
        if Thread.isMainThread {
            onReview?(item)
        } else {
            DispatchQueue.main.async { self.onReview?(item) }
        }
    }

    private func ignore(_ item: PRActionItem) {
        if Thread.isMainThread {
            onIgnore?(item)
        } else {
            DispatchQueue.main.async { self.onIgnore?(item) }
        }
    }

    // MARK: - Notification responses

    func userNotificationCenter(_ center: UNUserNotificationCenter,
                                didReceive response: UNNotificationResponse,
                                withCompletionHandler completionHandler: @escaping () -> Void) {
        let identifier = response.notification.request.identifier
        switch response.actionIdentifier {
        case Self.reviewAction:
            // Only an explicit Review starts work. The default action is the
            // click on the notification body, which used to be treated as
            // Review too -- so simply reading a notification was enough to start
            // a download and a checkout nobody asked for. The body click now
            // falls through to nothing: macOS has already brought the app
            // forward by the time this runs, which is all it should do.
            if let item = item(for: identifier) {
                review(item)
            } else {
                // Cold start: the app was launched by this click, so no poll has
                // run yet and the pull request is not in memory. The request is
                // parked and honoured once the first poll has filled the list.
                UserDefaults.standard.set(identifier, forKey: Self.pendingReviewKey)
            }
        case UNNotificationDefaultActionIdentifier, Self.notNowAction,
             UNNotificationDismissActionIdentifier:
            break
        case Self.ignoreAction:
            if let item = item(for: identifier) {
                PRStore.shared.ignore(item.pr, repo: item.repo)
                ignore(item)
            }
        default:
            break
        }
        completionHandler()
    }

    func userNotificationCenter(_ center: UNUserNotificationCenter,
                                willPresent notification: UNNotification,
                                withCompletionHandler completionHandler: @escaping (UNNotificationPresentationOptions) -> Void) {
        // Shown even while the app is frontmost: a new pull request is worth
        // knowing about, and it no longer interrupts with a sheet.
        completionHandler([.banner, .sound])
    }

    // MARK: - Deferred review

    /// Registers the three actions. Called once at startup.
    func registerActions() {
        // No .foreground: that option tells macOS to launch or bring the app to
        // the front on the action, which for an app that is already running
        // looked like a second launch. The review runs wherever the app
        // already is, and startReview activates the window only when it has
        // something to show.
        let review = UNNotificationAction(identifier: Self.reviewAction,
                                          title: "Review", options: [])
        let notNow = UNNotificationAction(identifier: Self.notNowAction,
                                           title: "Not Now", options: [])
        let ignore = UNNotificationAction(identifier: Self.ignoreAction,
                                          title: "Ignore", options: [.destructive])
        let category = UNNotificationCategory(identifier: Self.category,
                                              actions: [review, notNow, ignore],
                                              intentIdentifiers: [],
                                              options: [])
        center.setNotificationCategories([category])
    }

    /// Folds a review requested from a cold launch into the live list.
    ///
    /// Called after each poll; returns the pull request to open if one was
    /// parked while the app was not running.
    static func consumePendingReview(among items: [PRActionItem]) -> PRActionItem? {
        let defaults = UserDefaults.standard
        guard let identifier = defaults.string(forKey: pendingReviewKey) else { return nil }
        defaults.removeObject(forKey: pendingReviewKey)
        return items.first { $0.pr.fingerprint(remoteKey: $0.repo.id) == identifier }
    }
}

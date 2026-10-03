// by cipher.org.uk
import Foundation
import UserNotifications

/// One pull request the user can act on from the menu.
struct PRActionItem {
    let repo: MonitoredRepo
    let pr: PullRequest
    /// True when this PR has not been seen in a previous poll.
    let isNew: Bool
}

/// Polls monitored repositories while Karma Pro is running.
///
/// Polling is strictly in-process: there is no background agent, no launch
/// daemon and no notification scheduling outside the app, so nothing is
/// fetched when Karma Pro is not running. Each enabled repo is queried
/// concurrently, one failure never blocks the others, and a PR is only
/// announced the first time a given head commit is seen.
final class PRMonitor {
    /// Called on the main queue whenever the menu's contents should change.
    var onChange: (() -> Void)?
    /// Called on the main queue for a newly-seen PR.

    private(set) var items: [PRActionItem] = []
    private var timer: Timer?
    private var isPolling = false
    private let store = PRStore.shared

    /// Fingerprints already announced, so a refresh is silent. Seeded from the
    /// persisted ignore list so an ignored PR is not announced again.
    private var seenFingerprints: Set<String> = []

    /// Repositories whose first poll must stay silent. Adding a repository is
    /// not a request to be told about everything already open on it; only pull
    /// requests that appear afterwards should notify.
    private var silentFirstPoll: Set<String> = []
    private var lastError: String?

    /// Location temporary review checkouts are created under.
    private let workspaceRoot: URL = PRMonitor.cacheRoot

    var isMonitoringEnabled: Bool { store.monitoringEnabled }
    /// Full detail, for the repositories dialog.
    var currentError: String? { lastError }

    /// Compact form for the status menu.
    ///
    /// A status menu sizes itself to its widest item, so a provider error
    /// containing a response body would stretch the whole menu across the
    /// screen. The menu therefore gets a fixed-width summary and the detail is
    /// kept for the dialog that can actually display it.
    var currentErrorSummary: String? {
        guard let lastError = lastError, !lastError.isEmpty else { return nil }
        let count = lastError.split(separator: "\n").count
        return count == 1 ? "1 repository failed \u{2014} see Watched Repositories"
                          : "\(count) repositories failed \u{2014} see Watched Repositories"
    }

    // MARK: - On-disk cache

    /// Where every temporary review checkout lives.
    ///
    /// Shared as a static so the repositories dialog can report and clear it
    /// without needing a monitor instance, and so both agree on one path.
    static let cacheRoot: URL = {
        let base = FileManager.default.urls(for: .cachesDirectory, in: .userDomainMask).first
            ?? URL(fileURLWithPath: NSTemporaryDirectory())
        let dir = base.appendingPathComponent("KarmaPro/PRReviews", isDirectory: true)
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        return dir
    }()

    /// Total size of the review checkouts on disk.
    ///
    /// Checkouts are real Git clones and they are not small, and nothing else
    /// tells the user they are there, so the dialog states the figure rather
    /// than leaving a folder to grow unnoticed in the caches directory.
    static func cacheSize() -> Int64 {
        let keys: [URLResourceKey] = [.isRegularFileKey, .fileAllocatedSizeKey, .totalFileAllocatedSizeKey]
        guard let enumerator = FileManager.default.enumerator(
            at: cacheRoot, includingPropertiesForKeys: keys) else { return 0 }
        var total: Int64 = 0
        for case let url as URL in enumerator {
            let values = try? url.resourceValues(forKeys: Set(keys))
            guard values?.isRegularFile == true else { continue }
            total += Int64(values?.totalFileAllocatedSize ?? values?.fileAllocatedSize ?? 0)
        }
        return total
    }

    /// Empties the review cache and reports how much was reclaimed.
    ///
    /// The root directory itself is kept, so anything holding a URL under it
    /// still has somewhere to write.
    @discardableResult
    static func clearCache() throws -> Int64 {
        let before = cacheSize()
        let children = try FileManager.default.contentsOfDirectory(
            at: cacheRoot, includingPropertiesForKeys: nil)
        for child in children {
            try FileManager.default.removeItem(at: child)
        }
        return before
    }

    /// User-readable size, e.g. "1.4 GB".
    static func formattedSize(_ bytes: Int64) -> String {
        let units = ["bytes", "KB", "MB", "GB", "TB"]
        var value = Double(max(0, bytes))
        var unit = 0
        while value >= 1024, unit < units.count - 1 {
            value /= 1024
            unit += 1
        }
        return unit == 0 ? "\(Int(value)) \(units[unit])"
                         : String(format: "%.1f %@", value, units[unit])
    }

    /// Directories named after the PR, so repeated reviews of the same PR
    /// reuse a path and any previous checkout is replaced cleanly.
    func workspaceURL(for pr: PullRequest, repo: MonitoredRepo) -> URL {
        workspaceRoot
            .appendingPathComponent(sanitize(repo.repoSlug), isDirectory: true)
            .appendingPathComponent(sanitize("\(repo.provider)-\(pr.number)"), isDirectory: true)
    }

    // MARK: - Lifecycle

    /// How long after launch the first poll waits.
    ///
    /// Polling starts straight away at launch today, which puts a Keychain
    /// authorization dialog in front of the user before the menu bar item has
    /// even finished appearing. Waiting a minute costs nothing: the interval is
    /// measured in minutes anyway, and a token saved during that first minute is
    /// picked up by the deferred poll.
    private static let startupDelay: TimeInterval = 60

    private var pendingPoll: DispatchWorkItem?

    func start() {
        stop()
        guard store.monitoringEnabled else { return }
        requestNotificationPermission()
        let poll = DispatchWorkItem { [weak self] in self?.pollNow() }
        pendingPoll = poll
        DispatchQueue.main.asyncAfter(deadline: .now() + Self.startupDelay, execute: poll)
        scheduleTimer()
    }

    func stop() {
        pendingPoll?.cancel()
        pendingPoll = nil
        timer?.invalidate()
        timer = nil
    }

    /// Called when the master switch is toggled in the menu.
    func monitoringDidChange() {
        if store.monitoringEnabled {
            seenFingerprints.removeAll()
            start()
        } else {
            stop()
            items = []
            onChange?()
        }
    }

    private func scheduleTimer() {
        let minutes = max(1, store.pollingIntervalMinutes)
        // Polls go to a background queue, but the timer itself must be created
        // on the main run loop to fire.
        DispatchQueue.main.async { [weak self] in
            guard let self = self, store.monitoringEnabled else { return }
            let timer = Timer(timeInterval: Double(minutes) * 60, repeats: true) { [weak self] _ in
                self?.pollNow()
            }
            RunLoop.main.add(timer, forMode: .common)
            self.timer = timer
        }
    }

    func setInterval(minutes: Int) {
        store.pollingIntervalMinutes = max(1, minutes)
        if store.monitoringEnabled { start() }
    }

    // MARK: - Polling

    /// Fetches every enabled repo concurrently and rebuilds the menu list.
    func pollNow() {
        guard store.monitoringEnabled else { return }
        guard !isPolling else { return }
        isPolling = true

        let repos = store.repos.filter(\.enabled)
        guard !repos.isEmpty else {
            isPolling = false
            lastError = nil
            items = []
            onChange?()
            return
        }

        // Track per-repo results by repo id so concurrent finishes cannot mix up
        // which response belongs to which repository.
        let lock = NSLock()
        var collected: [String: Result<[PullRequest], PRMessageError>] = [:]
        let group = DispatchGroup()

        for repo in repos {
            group.enter()
            DispatchQueue.global(qos: .utility).async {
                // A private repo with no credential is skipped with a clear
                // reason rather than generating a 401 every poll.
                let token = self.store.token(for: repo)
                if repo.visibility.needsCredentials, token == nil {
                    lock.lock()
                    collected[repo.id] = .failure(PRMessageError("No access token saved for this private repository. Add one in Accounts…."))
                    lock.unlock()
                    group.leave()
                    return
                }
                let adapter = ForgeRegistry.adapter(for: repo.provider, token: token)
                do {
                    let prs = try adapter.openPullRequests(for: repo)
                    lock.lock()
                    collected[repo.id] = .success(prs)
                    lock.unlock()
                } catch {
                    lock.lock()
                    collected[repo.id] = .failure(PRMessageError(error.localizedDescription))
                    lock.unlock()
                }
                group.leave()
            }
        }

        group.notify(queue: .main) { [weak self] in
            guard let self = self else { return }
            self.isPolling = false
            self.rebuild(from: collected, repos: repos)
        }
    }

    private func rebuild(from collected: [String: Result<[PullRequest], PRMessageError>], repos: [MonitoredRepo]) {
        var newItems: [PRActionItem] = []
        var problems: [String] = []
        var freshItems: [PRActionItem] = []

        var muted: Set<String> = []
        for repo in repos {
            guard let result = collected[repo.id] else { continue }
            if silentFirstPoll.contains(repo.id) { muted.insert(repo.id) }
            switch result {
            case .success(let prs):
                for pr in prs where repo.wantsAlert(for: pr) {
                    let item = PRActionItem(repo: repo, pr: pr, isNew: false)
                    newItems.append(item)

                    let identity = identity(for: pr, repo: repo)
                    if muted.contains(repo.id) {
                        seenFingerprints.insert(identity)
                        continue
                    }
                    if store.isIgnored(pr, repo: repo) { continue }
                    if !seenFingerprints.contains(identity) {
                        seenFingerprints.insert(identity)
                        freshItems.append(PRActionItem(repo: repo, pr: pr, isNew: true))
                    }
                }
            case .failure(let message):
                problems.append("\(repo.repoSlug): \(message)")
            }
        }
        silentFirstPoll.subtract(muted)

        items = newItems
        // A single failing repo should not leave a permanent error banner when
        // others succeeded; surface it but keep it dismissible.
        lastError = problems.isEmpty ? nil : problems.joined(separator: "\n")

        // One batch, so the notifier can cap it and state the real total.
        // "Off" has to stop the alert, not just the sound: a user who turned
        // notifications off and still gets banners has been ignored.
        if store.notifyStyle != .off {
            PRNotifier.shared.deliver(freshItems, allowSound: store.notifyStyle == .bannerAndSound)
        }

        // A review requested from a notification while the app was closed can
        // only be started once there is something to open.
        if let parked = PRNotifier.consumePendingReview(among: items) {
            PRReviewCoordinator.shared.startReview(parked)
        }
        onChange?()
    }

    /// Marks every currently-listed PR as already seen, so the first poll after
    /// adding a repository does not alert for everything already open. This is
    /// what keeps adding a repo from producing a wall of notifications.
    /// Mutes the next poll of the given repositories.
    func silenceFirstPoll(for repoIDs: Set<String>) {
        silentFirstPoll.formUnion(repoIDs)
    }

    private func identity(for pr: PullRequest, repo: MonitoredRepo) -> String {
        // Bitbucket's list payload carries no head SHA, so fall back to the
        // updated timestamp as the change signal.
        pr.headSHA.isEmpty
            ? "\(repo.id)#\(pr.id)@\(pr.updatedAt?.timeIntervalSince1970 ?? 0)"
            : pr.fingerprint(remoteKey: repo.id)
    }

    /// Drops a pull request from the watch list without forgetting it: the
    /// ignore is recorded in the store, so it stays out of future notifications.
    func dismiss(_ item: PRActionItem) {
        store.ignore(item.pr, repo: item.repo)
        items.removeAll { $0.repo.id == item.repo.id && $0.pr.id == item.pr.id }
        onChange?()
    }

    func remove(_ item: PRActionItem) {
        store.ignore(item.pr, repo: item.repo)
        items.removeAll { $0.repo.id == item.repo.id && $0.pr.id == item.pr.id }
        onChange?()
    }

    // MARK: - Notifications

    private func requestNotificationPermission() {
        // Only asked once the user has actually chosen a notifying style, so a
        // fresh install that has not enabled monitoring is never prompted.
        guard store.notifyStyle != .off else { return }
        PRNotifier.shared.requestAuthorization()
    }

    /// Path-safe name for a filesystem component.
    private func sanitize(_ raw: String) -> String {
        let allowed = CharacterSet.alphanumerics.union(CharacterSet(charactersIn: "-_."))
        let mapped = raw.unicodeScalars.map { allowed.contains($0) ? Character($0) : "-" }
        return String(mapped)
    }
}
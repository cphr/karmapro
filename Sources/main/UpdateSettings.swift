// by cipher.org.uk
import Foundation

/// Persisted state for the update check: three keys and nothing more.
///
/// There is deliberately no install date. Comparing a release's publication date
/// against the date the app was installed cannot detect a newer release for
/// someone who installed after that release shipped — on Friday's install of a
/// Tuesday release, the install date is newer, so the app reports "up to date"
/// while the user is behind — and reinstalling would move that date later still,
/// hiding every release published before it. The check compares versions
/// instead, so it needs no memory of when the app arrived.
enum UpdateSettings {
    private static let automaticKey = "autoCheckEnabled"
    private static let lastCheckKey = "lastCheckDate"
    private static let knownVersionKey = "lastKnownVersion"
    private static let knownURLKey = "lastKnownURL"

    private static var defaults: UserDefaults { .standard }

    /// Whether the user has opted into the daily check. Off until they ask.
    static var automaticChecksEnabled: Bool {
        get { defaults.bool(forKey: automaticKey) }
        set { defaults.set(newValue, forKey: automaticKey) }
    }

    /// When the last check was **attempted**, whether or not it succeeded.
    ///
    /// Recorded on every attempt rather than only on success so a network that
    /// is down cannot be retried in a tight loop, and so a failure is bounded to
    /// the same once-a-day cadence as a success.
    static var lastCheckDate: Date? {
        get { defaults.object(forKey: lastCheckKey) as? Date }
        set {
            if let newValue {
                defaults.set(newValue, forKey: lastCheckKey)
            } else {
                defaults.removeObject(forKey: lastCheckKey)
            }
        }
    }

    /// Newest release seen, kept so the menu can offer it between checks. Held
    /// across launches rather than living in memory: an update the user was
    /// told about should still be offered tomorrow without asking again.
    static var knownNewerVersion: String? {
        get { defaults.string(forKey: knownVersionKey) }
        set {
            if let newValue {
                defaults.set(newValue, forKey: knownVersionKey)
            } else {
                defaults.removeObject(forKey: knownVersionKey)
            }
        }
    }

    /// The stored release's own page, kept so the menu can offer it between
    /// checks and on later launches.
    ///
    /// Stored rather than rebuilt from the version on demand: a release tagged
    /// `0.14` with no `v` would need `.../tag/0.14`, so reconstructing the URL
    /// from the version alone would 404 for exactly the bare-tag case the
    /// comparison accepts.
    static var knownNewerPageURL: String? {
        get { defaults.string(forKey: knownURLKey) }
        set {
            if let newValue {
                defaults.set(newValue, forKey: knownURLKey)
            } else {
                defaults.removeObject(forKey: knownURLKey)
            }
        }
    }

    /// True when a daily check is due: never attempted, or at least 24 hours
    /// since the last attempt.
    ///
    /// Lives here rather than in the menu target so the rule can be exercised
    /// directly instead of by waiting a day.
    static func isCheckDue(now: Date = Date()) -> Bool {
        guard let last = lastCheckDate else { return true }
        return now.timeIntervalSince(last) >= 24 * 60 * 60
    }

    /// Forgets the stored release, used once the running version has caught up
    /// with it so the menu stops offering something already installed.
    static func clearKnownNewerVersionIfNotNewer(than current: String) {
        guard let known = knownNewerVersion, !VersionComparator.isNewer(tag: known, than: current) else {
            return
        }
        knownNewerVersion = nil
        knownNewerPageURL = nil
    }
}

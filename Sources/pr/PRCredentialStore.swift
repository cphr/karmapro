// by cipher.org.uk
import Foundation
import LocalAuthentication
import Security

/// Token storage backed by the macOS Keychain.

enum PRCredentialStore {
    private static let service = "karmapro.pullrequests"

    /// The one Keychain item that holds every token.
    private static let itemAccount = "tokens"

    /// Where tokens were kept before the service was renamed, as one item per
    /// account. Read once, folded into the new item and then deleted, so
    /// renaming the key does not cost the user their saved tokens.
    private static let legacyService = "uk.cipher.karmapro.forge"

    /// Authorizes once per session and is then reused, so macOS prompts at most
    /// once for all of this feature's Keychain access.
    private static let authContext: LAContext = {
        let context = LAContext()
        context.touchIDAuthenticationAllowableReuseDuration = 600
        context.localizedReason = "Karma Pro is reading the pull request tokens you saved."
        return context
    }()

    /// All known tokens, or nil while they have not been read this session.
    private static var cache: [String: String]?

    /// Whether the cache can answer without touching the Keychain.
    private static var didLoad = false

    /// Set once a call has failed because this build cannot use the Data
    /// Protection keychain, so the older file-based keychain is used instead.
    private static var usesClassicKeychain = false

    /// What the UI may safely say about an account without reading anything.
    static func cachedState(identity: String) -> (isCached: Bool, token: String?) {
        guard let cache = cache else { return (false, nil) }
        return (true, cache[identity])
    }

    /// Drops everything held in memory.
    ///
    /// Called when monitoring is switched off so a later switch back on reads
    /// the Keychain once, freshly, rather than reusing a token that may have
    /// been rotated while monitoring was off.
    static func invalidateSessionCache() {
        cache = nil
        didLoad = false
    }

    enum KeychainError: LocalizedError {
        case unexpectedStatus(OSStatus)
        case malformedData

        var errorDescription: String? {
            switch self {
            case .unexpectedStatus(let status):
                let message = SecCopyErrorMessageString(status, nil) as String? ?? "status \(status)"
                return "Keychain error: \(message)"
            case .malformedData:
                return "Keychain error: stored token could not be read."
            }
        }
    }

    // MARK: - Reading

    /// The token for an identity, or nil when there is none.
    ///
    /// - Parameter prompt: when false the Keychain is not touched at all and
    ///   only the session cache is consulted, so merely running the app cannot
    ///   put a Keychain dialog in front of the user.
    static func token(identity: String, prompt: Bool = true) -> String? {
        if let cache = cache { return cache[identity] }
        guard prompt else { return nil }
        // One read answers for every account, so this prompts at most once for
        // the whole session however many accounts the user has.
        guard load() else {
            // The read did not complete, so whether this account has a token is
            // unknown. Reporting "no" would make a private repository look like
            // it had no credentials because of a cancelled unlock.
            return nil
        }
        if let token = cache?[identity] { return token }
        return migrateLegacyToken(identity: identity)
    }

    /// Moves one token out of the old keychain key and into the current one.
    ///
    /// Asked only about the account that came back empty. Reading the old key
    /// in bulk on every load made a save, a listing and a launch each raise a
    /// second authorization prompt for a service that is normally empty.
    private static func migrateLegacyToken(identity: String) -> String? {
        guard let data = readItem(service: legacyService, account: identity),
              let token = String(data: data, encoding: .utf8),
              !token.isEmpty else { return nil }
        var merged = cache ?? [:]
        merged[identity] = token
        // Written before the old entry is removed, so a failure here leaves the
        // token exactly where it was rather than losing it.
        guard (try? writeItem(merged)) != nil else { return nil }
        cache = merged
        deleteLegacyItem(identity: identity)
        PRLog.write("moved a pull request token for \(identity) from the old keychain key to \(service)")
        return token
    }

    static func hasToken(identity: String, prompt: Bool = true) -> Bool {
        token(identity: identity, prompt: prompt) != nil
    }

    /// Reads every token in one go, at most once per session.
    ///
    /// Returns false when the read could not be completed, so the caller treats
    /// the answer as unknown rather than as "no tokens exist".
    private static func load() -> Bool {
        if didLoad { return cache != nil }
        guard let data = readItem(service: service, account: itemAccount) else { return false }
        let found = (try? JSONDecoder().decode([String: String].self, from: data)) ?? [:]
        // A token entered earlier in this session wins over whatever the
        // Keychain still holds for it.
        cache = cache.map { existing in existing.merging(found) { $1 } } ?? found
        didLoad = true
        return true
    }

    // MARK: - Writing

    /// Stores (or replaces) the read-only token for a host+user pair.
    /// - Parameter identity: stable per-account key, e.g. "github|alice".
    static func setToken(_ token: String, identity: String) throws {
        let trimmed = token.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else {
            try deleteToken(identity: identity)
            return
        }
        // The token is already in hand here, so this read is what saves every
        // later one: the item is read at most once per session from now on.
        guard load() else { throw KeychainError.malformedData }
        var tokens = cache ?? [:]
        tokens[identity] = trimmed
        cache = tokens
        try writeItem(tokens)
    }

    static func deleteToken(identity: String) throws {
        guard load() else { throw KeychainError.malformedData }
        var tokens = cache ?? [:]
        tokens.removeValue(forKey: identity)
        cache = tokens
        try writeItem(tokens)
    }

    /// Removes every token this app owns. Used when the user asks to forget all
    /// accounts; it never touches unrelated Keychain items.
    static func deleteAll() {
        deleteAll(in: service)
        deleteAll(in: legacyService)
        invalidateSessionCache()
    }

    /// Removes one entry left behind under the old service.
    private static func deleteLegacyItem(identity: String) {
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: legacyService,
            kSecAttrAccount as String: identity
        ]
        if usesClassicKeychain {
            query[kSecUseDataProtectionKeychain as String] = false
        }
        SecItemDelete(query as CFDictionary)
    }

    private static func deleteAll(in service: String) {
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service
        ]
        if usesClassicKeychain {
            query[kSecUseDataProtectionKeychain as String] = false
        }
        SecItemDelete(query as CFDictionary)
    }

    /// Reads one item's contents, preferring the Data Protection keychain.
    ///
    /// The Data Protection keychain is scoped to the app and carries no
    /// per-item access list. The file-based keychain records which binary may
    /// read each item, so a build signed differently from the one that saved the
    /// token is asked about separately from unlocking — a second dialog that no
    /// amount of app-side caching can remove. A build that is not entitled for
    /// the Data Protection keychain, such as an ad-hoc signed one, falls back.
    private static func readItem(service: String, account: String) -> Data? {
        func attempt(_ dataProtection: Bool) -> (OSStatus, Data?) {
            var query: [String: Any] = [
                kSecClass as String: kSecClassGenericPassword,
                kSecAttrService as String: service,
                kSecAttrAccount as String: account,
                kSecReturnData as String: true,
                kSecMatchLimit as String: kSecMatchLimitOne,
                kSecUseAuthenticationContext as String: authContext
            ]
            if dataProtection {
                query[kSecUseDataProtectionKeychain as String] = true
            }
            var result: CFTypeRef?
            let status = SecItemCopyMatching(query as CFDictionary, &result)
            return (status, result as? Data)
        }

        if usesClassicKeychain {
            let result = attempt(false)
            return log(result.0, data: result.1)
        }
        let first = attempt(true)
        switch first.0 {
        case errSecSuccess:
            return log(first.0, data: first.1)
        case errSecItemNotFound:
            // A build that fell back writes to the file-based keychain, and a
            // lookup there reports "not found" rather than "no entitlement", so
            // not-found has to be checked in both places. Checking only the
            // first meant every token read back as absent after a relaunch,
            // while the item itself sat in the keychain the whole time.
            let second = attempt(false)
            if second.0 == errSecSuccess {
                usesClassicKeychain = true
                return log(second.0, data: second.1)
            }
            return log(first.0, data: first.1)
        case errSecMissingEntitlement, errSecNotAvailable, errSecParam:
            usesClassicKeychain = true
            let second = attempt(false)
            return log(second.0, data: second.1)
        default:
            return log(first.0, data: first.1)
        }
    }

    /// Turns a read outcome into a result, treating "nothing stored" as a
    /// successful empty answer and anything else as unknown.
    private static func log(_ status: OSStatus, data: Data?) -> Data? {
        switch status {
        case errSecSuccess:
            return data
        case errSecItemNotFound:
            return Data()
        case errSecUserCanceled, errSecAuthFailed:
            // Deliberately not remembered, so the next poll can ask again rather
            // than treating a cancelled unlock as "this account has no token".
            return nil
        default:
            let message = SecCopyErrorMessageString(status, nil) as String? ?? "status \(status)"
            PRLog.write("keychain read of \(service) failed: \(message) (\(status))")
            return nil
        }
    }

    /// Writes the whole token set as one item.
    private static func writeItem(_ tokens: [String: String]) throws {
        let data = try JSONEncoder().encode(tokens)
        let attributes: [String: Any] = [
            kSecValueData as String: data,
            kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlocked
        ]

        func attempt(_ dataProtection: Bool) -> OSStatus {
            var query: [String: Any] = [
                kSecClass as String: kSecClassGenericPassword,
                kSecAttrService as String: service,
                kSecAttrAccount as String: itemAccount
            ]
            if dataProtection {
                query[kSecUseDataProtectionKeychain as String] = true
            }
            let status = SecItemUpdate(query as CFDictionary, attributes as CFDictionary)
            if status == errSecSuccess { return status }
            guard status == errSecItemNotFound else { return status }
            var insert = query
            insert.merge(attributes) { _, new in new }
            return SecItemAdd(insert as CFDictionary, nil)
        }

        if usesClassicKeychain {
            let status = attempt(false)
            guard status == errSecSuccess else { throw KeychainError.unexpectedStatus(status) }
            return
        }
        let first = attempt(true)
        switch first {
        case errSecSuccess:
            return
        case errSecMissingEntitlement, errSecNotAvailable, errSecParam:
            usesClassicKeychain = true
            let second = attempt(false)
            guard second == errSecSuccess else { throw KeychainError.unexpectedStatus(second) }
        default:
            throw KeychainError.unexpectedStatus(first)
        }
    }
}

/// One saved account. The token itself is never part of this struct — only the
/// identity used to look it up in the Keychain.
struct PRAccount: Codable, Equatable {
    /// Keychain lookup key, e.g. "github|github.com|alice".
    ///
    /// The host is part of it because two accounts can share a provider and a
    /// username label while belonging to different forges — the same person on
    /// github.com and on a GitHub Enterprise install — and without the host the
    /// second one silently replaced the first. Accounts saved by an earlier
    /// build used "provider|username"; `migratedIdentity` repairs those on load
    /// and moves the Keychain entry across, so no saved token is lost.
    var identity: String
    /// Forge provider id, e.g. "github".
    var provider: String
    /// Login or token label the user recognises.
    var username: String
    /// API root, so a self-hosted GitLab account is distinct from gitlab.com.
    var baseURL: String

    var providerName: String {
        switch provider {
        case "gitlab": return "GitLab"
        case "bitbucket": return "Bitbucket"
        case "gitea": return "Gitea / Forgejo"
        default: return "GitHub"
        }
    }

    /// Which saved account (if any) applies to a monitored repo. Public repos
    /// deliberately match nothing so they keep working with no credentials.
    ///
    /// Both sides are put through the same host-to-API-root derivation before
    /// comparing. Comparing the stored strings directly meant an account saved
    /// as "codeberg.org" never matched a repository detected as
    /// "https://codeberg.org/api/v1", so a private Gitea or self-hosted GitLab
    /// repository silently never found its token and every request went out
    /// unauthenticated. 
    func matches(_ repo: MonitoredRepo) -> Bool {
        guard repo.visibility.needsCredentials else { return false }
        guard provider == repo.provider else { return false }
        return normalizedAPIHost == repo.normalizedAPIHost
    }

    /// The provider host this account belongs to, recovered from the stored
    /// baseURL. `https://api.github.com` is github.com, `https://codeberg.org/
    /// api/v1` is codeberg.org, and a saved bare host is taken as-is.
    var normalizedAPIHost: String? { PRHost.apiHost(baseURL) }

    /// The identity this account should have now: provider|host|username.
    ///
    /// Returns the existing identity unchanged when it already carries a host,
    /// so this is safe to run over a freshly saved account.
    var migratedIdentity: String {
        // Only the pre-host form is migrated. Rewriting an identity that already
        // has a host would strand the token: the move in resolveToken only runs
        // while this process remembers the old key.
        guard identity.split(separator: "|").count == 2 else { return identity }
        guard let host = normalizedAPIHost else { return identity }
        return "\(provider)|\(host)|\(username)"
    }
}

/// Accounts plus the app-wide PR preferences, persisted together in
/// Application Support so a relaunch restores the menu exactly as the user
/// left it.
final class PRStore {
    static let shared = PRStore()

    private(set) var accounts: [PRAccount] = []
    private(set) var repos: [MonitoredRepo] = []
    var defaultDepth: PRKind.Depth = .changedOnly { didSet { persistUnlessLoading() } }
    var notifyStyle: PRKind.NotifyStyle = .banner { didSet { persistUnlessLoading() } }
    var pollingIntervalMinutes: Int = 15 { didSet { persistUnlessLoading() } }
    /// Master switch. Off by default: a fresh install never calls out to any
    /// forge until the user turns PR monitoring on from the menu.
    ///
    /// Persisted as soon as it changes. It used to be a plain property written
    /// only when some unrelated setting happened to save the file, so switching
    /// monitoring off did not survive a restart and the app came back polling.
    var monitoringEnabled: Bool = false {
        didSet {
            guard monitoringEnabled != oldValue else { return }
            persistUnlessLoading()
            if !monitoringEnabled {
                // Nothing may reach the Keychain while monitoring is off, and
                // nothing is left over from the session that just ended.
                PRCredentialStore.invalidateSessionCache()
            }
        }
    }
    /// PR fingerprints the user chose to ignore. Keyed by
    /// `repoId#prId@headSHA` so re-opening an ignored PR after new commits
    /// alerts again, which is the behaviour people expect.
    private(set) var ignoredPRs: Set<String> = []

    private let fileURL: URL

    /// Set while `load()` restores saved values, so the `didSet` observers do
    /// not write the file back out half-restored.
    private var isLoading = false

    private init() {
        let base = FileManager.default
            .urls(for: .applicationSupportDirectory, in: .userDomainMask).first
            ?? URL(fileURLWithPath: NSTemporaryDirectory())
        let dir = base.appendingPathComponent("KarmaPro", isDirectory: true)
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        fileURL = dir.appendingPathComponent("PullRequests.json")
        load()
    }

    // MARK: - Accounts

    func saveAccount(_ account: PRAccount, token: String) throws {
        var account = account
        account.identity = account.migratedIdentity
        try PRCredentialStore.setToken(token, identity: account.identity)
        if let index = accounts.firstIndex(where: { $0.identity == account.identity }) {
            accounts[index] = account
        } else {
            accounts.append(account)
        }
        persist()
    }

    /// Re-keys accounts saved before the host joined the identity.
    @discardableResult
    private func migrateAccountIdentities() -> Bool {
        var changed = false
        for index in accounts.indices {
            let old = accounts[index].identity
            let new = accounts[index].migratedIdentity
            guard new != old else { continue }
            legacyIdentityFor[new] = old
            accounts[index].identity = new
            changed = true
        }
        return changed
    }

    /// New identity -> the older identity its Keychain entry may still use.
    private var legacyIdentityFor: [String: String] = [:]

    /// The token for an account, moving a legacy Keychain entry across on the
    /// first read that needs it.
    private func resolveToken(identity: String, prompt: Bool) -> String? {
        if let token = PRCredentialStore.token(identity: identity, prompt: prompt) { return token }
        guard let old = legacyIdentityFor[identity] else { return nil }
        // Still not found under the current key, so try the one this account was
        // saved under before the host joined its identity.
        guard let legacy = PRCredentialStore.token(identity: old, prompt: prompt) else { return nil }
        try? PRCredentialStore.setToken(legacy, identity: identity)
        try? PRCredentialStore.deleteToken(identity: old)
        legacyIdentityFor.removeValue(forKey: identity)
        return legacy
    }

    /// Saved accounts that can actually authenticate this repository.
    func accounts(for repo: MonitoredRepo) -> [PRAccount] {
        accounts.filter { $0.matches(repo) && $0.normalizedAPIHost == repo.normalizedAPIHost }
    }

    func removeAccount(_ account: PRAccount) throws {
        try PRCredentialStore.deleteToken(identity: account.identity)
        accounts.removeAll { $0.identity == account.identity }
        persist()
    }

    /// - Parameter prompt: whether this lookup may put a Keychain dialog in
    ///   front of the user. Callers that only display state, or that run in the
    ///   background, pass the monitoring switch so an idle app never asks.
    func token(for repo: MonitoredRepo, prompt: Bool = true) -> String? {
        guard let account = resolvedAccount(for: repo) else { return nil }
        return resolveToken(identity: account.identity, prompt: prompt)
    }

    /// True when a poll with this repository would carry a real token.
    ///
    /// Distinct from "an account matched": a matched account whose Keychain
    /// entry has gone reports nothing, and sending no token produces a 401 that
    /// reads like bad credentials rather than a missing account.
    func hasUsableToken(for repo: MonitoredRepo, prompt: Bool = true) -> Bool {
        guard let token = token(for: repo, prompt: prompt) else { return false }
        return !token.isEmpty
    }


    func resolvedAccount(for repo: MonitoredRepo) -> PRAccount? {
        guard repo.visibility.needsCredentials else { return nil }
        let usable = accounts.filter { $0.matches(repo) }
        if let identity = repo.accountIdentity,
           let chosen = usable.first(where: { $0.identity == identity }) {
            return chosen
        }
        return usable.first
    }

    /// The account a repo should use, and whether it actually has a usable
    /// token. Private repos with no credential are reported rather than
    /// silently failing every poll.
    func accountStatus(for repo: MonitoredRepo, prompt: Bool = false) -> (account: PRAccount?, hasToken: Bool) {
        guard repo.visibility.needsCredentials else { return (nil, true) }
        guard let account = resolvedAccount(for: repo) else { return (nil, false) }
        return (account, hasUsableToken(for: repo, prompt: prompt))
    }

    // MARK: - Repositories

    func addRepo(_ repo: MonitoredRepo) {
        repos.removeAll { $0.id == repo.id }
        repos.append(repo)
        persist()
    }

    func updateRepo(_ repo: MonitoredRepo) {
        if let index = repos.firstIndex(where: { $0.id == repo.id }) {
            repos[index] = repo
        } else {
            repos.append(repo)
        }
        persist()
    }

    func removeRepo(_ repo: MonitoredRepo) {
        repos.removeAll { $0.id == repo.id }
        persist()
    }

    func repo(withID id: String) -> MonitoredRepo? {
        repos.first { $0.id == id }
    }

    // MARK: - Ignored PRs

    func isIgnored(_ pr: PullRequest, repo: MonitoredRepo) -> Bool {
        ignoredPRs.contains(pr.fingerprint(remoteKey: repo.id))
    }

    func ignore(_ pr: PullRequest, repo: MonitoredRepo) {
        ignoredPRs.insert(pr.fingerprint(remoteKey: repo.id))
        persist()
    }

    func unignoreAll() {
        ignoredPRs.removeAll()
        persist()
    }

    // MARK: - Persistence

    private struct Snapshot: Codable {
        var accounts: [PRAccount] = []
        var repos: [MonitoredRepo] = []
        var defaultDepth: PRKind.Depth = .changedOnly
        var notifyStyle: PRKind.NotifyStyle = .banner
        var pollingIntervalMinutes: Int = 15
        var monitoringEnabled: Bool = false
        var ignoredPRs: [String] = []
    }

    private func load() {
        guard let data = try? Data(contentsOf: fileURL) else { return }
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        guard let snapshot = try? decoder.decode(Snapshot.self, from: data) else { return }
        isLoading = true
        defer { isLoading = false }
        accounts = snapshot.accounts
        repos = snapshot.repos
        defaultDepth = snapshot.defaultDepth
        notifyStyle = snapshot.notifyStyle
        pollingIntervalMinutes = snapshot.pollingIntervalMinutes
        monitoringEnabled = snapshot.monitoringEnabled
        ignoredPRs = Set(snapshot.ignoredPRs)
        // Deliberately last. This re-keys accounts, and it used to save the file
        // at that moment — before the saved preferences above had been restored —
        // so a launch that migrated an account rewrote the user's monitoring
        // setting back to its "off" default and it silently stopped being
        // remembered.
        // Before the identity migration, because the migration re-keys the
        // Keychain entry from the provider segment of the identity.
        var repaired = repairContradictoryAccounts()
        if migrateAccountIdentities() { repaired = true }
        if repaired { persist() }
    }

    /// Corrects accounts whose stored provider contradicts their own host.
    private func repairContradictoryAccounts() -> Bool {
        var changed = false
        for index in accounts.indices {
            guard let host = accounts[index].normalizedAPIHost,
                  let correct = PRHost.provider(ofHost: host),
                  accounts[index].provider != correct,
                  let baseURL = ForgeDetector.apiBaseURL(provider: correct, host: host)
            else { continue }
            PRLog.write("PR account \"\(accounts[index].username)\" was saved as \(accounts[index].provider) on \(host); using \(correct) instead.")
            accounts[index].provider = correct
            accounts[index].baseURL = baseURL
            changed = true
        }
        return changed
    }

    private func persistUnlessLoading() {
        guard !isLoading else { return }
        persist()
    }

    private func persist() {
        let snapshot = Snapshot(accounts: accounts,
                                repos: repos,
                                defaultDepth: defaultDepth,
                                notifyStyle: notifyStyle,
                                pollingIntervalMinutes: pollingIntervalMinutes,
                                monitoringEnabled: monitoringEnabled,
                                ignoredPRs: Array(ignoredPRs))
        guard let data = try? JSONEncoder().encode(snapshot) else { return }
        try? data.write(to: fileURL, options: .atomic)
    }
}
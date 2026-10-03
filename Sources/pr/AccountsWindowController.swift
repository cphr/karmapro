// by cipher.org.uk
import AppKit

/// Small dialog for adding, testing and removing read-only forge credentials.
///
/// Launched from the menu bar rather than existing as a Preferences pane, in
/// line with the decision that every PR control lives in the menu. The token
/// field is a secure text field and the value is handed straight to the
/// Keychain; it is never displayed again, never written to the prefs file and
/// never logged.
final class AccountsWindowController: NSWindowController, NSTextFieldDelegate {
    private let store = PRStore.shared

    private let tableView = NSTableView()
    private let providerPopUp = NSPopUpButton()
    private let usernameField = NSTextField()
    private let tokenField = NSSecureTextField()
    /// Host the account belongs to. Needed because a self-hosted forge is not
    /// gitlab.com or github.com, and an account with no way to name its host
    /// could never be matched to the repository it was created for.
    private let hostField = NSTextField()
    private let statusLabel = NSTextField(labelWithString: "")
    private let testButton = NSButton()
    private let removeButton = NSButton()
    private let saveButton = NSButton()

    /// Which provider the new-account form is set to.
    private let providers: [(id: String, name: String)] = [
        ("github", "GitHub"),
        ("gitlab", "GitLab"),
        ("gitea", "Gitea / Forgejo / Codeberg"),
        ("bitbucket", "Bitbucket")
    ]

    private var rows: [PRAccount] = []

    convenience init() {
        // Same as the rest of the app's popups: ESC closes it.
        let window = EscClosableWindow(contentRect: NSRect(x: 0, y: 0, width: 620, height: 430),
                              styleMask: [.titled, .closable, .miniaturizable],
                              backing: .buffered,
                              defer: false)
        window.title = "Pull Request Accounts"
        window.center()
        self.init(window: window)
        buildUI()
        reload()
    }

    // MARK: - Layout

    private func buildUI() {
        guard let window = window, let content = window.contentView else { return }

        let explain = NSTextField(wrappingLabelWithString: """
            Read-only credentials for private repositories.

            Karma Pro never approves, comments on, or posts to a pull request, so a token with read-only scope is enough. \
            Tokens are stored in your macOS Keychain and are never written to Karma Pro's settings or included in a report.

            Public repositories need no account at all — you only need one for repositories you mark private.
            """)
        explain.font = .systemFont(ofSize: 11)
        explain.textColor = .secondaryLabelColor

        // Existing accounts
        let accountsLabel = NSTextField(labelWithString: "Saved accounts")
        accountsLabel.font = .boldSystemFont(ofSize: 12)

        let tableScroll = NSScrollView()
        tableScroll.hasVerticalScroller = true
        tableScroll.borderType = .bezelBorder
        tableView.headerView = nil
        tableView.rowSizeStyle = .default
        tableView.usesAlternatingRowBackgroundColors = true
        // The host is listed because it is the whole difference between two accounts
        // that look identical in the table otherwise: same provider, same
        // username label, but only one of them is the one a given repository
        // will actually ask.
        for (title, width) in [("Provider", 130.0), ("Host", 160.0),
                               ("Account", 150.0), ("Token", 80.0)] {
            let column = NSTableColumn(identifier: NSUserInterfaceItemIdentifier(title))
            column.title = title
            column.width = width
            tableView.addTableColumn(column)
        }
        tableView.dataSource = self
        tableView.delegate = self
        tableScroll.documentView = tableView
        tableScroll.translatesAutoresizingMaskIntoConstraints = false

        removeButton.title = "Remove Selected"
        removeButton.bezelStyle = .rounded
        removeButton.keyEquivalent = ""
        removeButton.target = self
        removeButton.action = #selector(removeSelected)
        removeButton.translatesAutoresizingMaskIntoConstraints = false
        testButton.title = "Test Connection"
        testButton.bezelStyle = .rounded
        testButton.keyEquivalent = ""
        testButton.target = self
        testButton.action = #selector(testSelected)
        testButton.translatesAutoresizingMaskIntoConstraints = false

        // New account form
        let newLabel = NSTextField(labelWithString: "Add an account")
        newLabel.font = .boldSystemFont(ofSize: 12)

        providerPopUp.addItems(withTitles: providers.map(\.name))
        providerPopUp.target = self
        providerPopUp.action = #selector(providerChanged)
        providerPopUp.translatesAutoresizingMaskIntoConstraints = false

        usernameField.placeholderString = "username (a label for you)"
        usernameField.translatesAutoresizingMaskIntoConstraints = false

        hostField.placeholderString = "host"
        hostField.delegate = self
        hostField.translatesAutoresizingMaskIntoConstraints = false

        tokenField.placeholderString = "read-only token"
        tokenField.translatesAutoresizingMaskIntoConstraints = false

        statusLabel.font = .systemFont(ofSize: 11)
        statusLabel.textColor = .secondaryLabelColor
        statusLabel.lineBreakMode = .byTruncatingTail

        providerChanged()

        saveButton.title = "Save Token"
        saveButton.bezelStyle = .rounded
        saveButton.keyEquivalent = ""
        saveButton.target = self
        saveButton.action = #selector(saveAccount)
        saveButton.translatesAutoresizingMaskIntoConstraints = false
        for button in [saveButton, testButton] {
            button.setContentHuggingPriority(.required, for: .horizontal)
            button.setContentCompressionResistancePriority(.required, for: .horizontal)
        }
        statusLabel.setContentHuggingPriority(.defaultLow, for: .horizontal)
        statusLabel.setContentCompressionResistancePriority(.defaultLow, for: .horizontal)

        let grid = NSGridView(views: [
            [NSTextField(labelWithString: "Provider"), providerPopUp],
            [NSTextField(labelWithString: "Host"), hostField],
            [NSTextField(labelWithString: "Username"), usernameField],
            [NSTextField(labelWithString: "Token"), tokenField]
        ])
        grid.translatesAutoresizingMaskIntoConstraints = false
        grid.rowSpacing = 8
        grid.columnSpacing = 10
        grid.column(at: 0).xPlacement = .trailing

        // The buttons are stored properties, not locals, so they are added here
        // rather than in the list above: each one is constrained against
        // content or tableScroll, and Auto Layout rejects a constraint whose
        // views share no ancestor.
        for view in [explain, accountsLabel, tableScroll, removeButton, testButton,
                     newLabel, grid, statusLabel, saveButton] as [NSView] {
            view.translatesAutoresizingMaskIntoConstraints = false
            content.addSubview(view)
        }

        NSLayoutConstraint.activate([
            explain.topAnchor.constraint(equalTo: content.topAnchor, constant: 16),
            explain.leadingAnchor.constraint(equalTo: content.leadingAnchor, constant: 16),
            explain.trailingAnchor.constraint(equalTo: content.trailingAnchor, constant: -16),

            accountsLabel.topAnchor.constraint(equalTo: explain.bottomAnchor, constant: 16),
            accountsLabel.leadingAnchor.constraint(equalTo: explain.leadingAnchor),

            tableScroll.topAnchor.constraint(equalTo: accountsLabel.bottomAnchor, constant: 6),
            tableScroll.leadingAnchor.constraint(equalTo: content.leadingAnchor, constant: 16),
            tableScroll.trailingAnchor.constraint(equalTo: content.trailingAnchor, constant: -16),
            tableScroll.heightAnchor.constraint(equalToConstant: 140),

            removeButton.topAnchor.constraint(equalTo: tableScroll.bottomAnchor, constant: 8),
            removeButton.leadingAnchor.constraint(equalTo: content.leadingAnchor, constant: 16),
            testButton.centerYAnchor.constraint(equalTo: removeButton.centerYAnchor),
            testButton.trailingAnchor.constraint(equalTo: content.trailingAnchor, constant: -16),

            newLabel.topAnchor.constraint(equalTo: removeButton.bottomAnchor, constant: 18),
            newLabel.leadingAnchor.constraint(equalTo: content.leadingAnchor, constant: 16),

            grid.topAnchor.constraint(equalTo: newLabel.bottomAnchor, constant: 8),
            grid.leadingAnchor.constraint(equalTo: content.leadingAnchor, constant: 16),
            grid.trailingAnchor.constraint(lessThanOrEqualTo: content.trailingAnchor, constant: -120),

            statusLabel.topAnchor.constraint(equalTo: grid.bottomAnchor, constant: 12),
            statusLabel.leadingAnchor.constraint(equalTo: content.leadingAnchor, constant: 16),
            statusLabel.trailingAnchor.constraint(equalTo: saveButton.leadingAnchor, constant: -8),

            saveButton.centerYAnchor.constraint(equalTo: statusLabel.centerYAnchor),
            saveButton.trailingAnchor.constraint(equalTo: content.trailingAnchor, constant: -16),
            saveButton.bottomAnchor.constraint(lessThanOrEqualTo: content.bottomAnchor, constant: -16),

            // As in the repositories dialog: the buttons hug their titles so the
            // status message keeps the rest of the row instead of being
            // collapsed to a few points wide.
            saveButton.widthAnchor.constraint(greaterThanOrEqualToConstant: 90),
            testButton.widthAnchor.constraint(greaterThanOrEqualToConstant: 90),
            statusLabel.widthAnchor.constraint(greaterThanOrEqualToConstant: 160)
        ])
    }

    // MARK: - Data

    private func reload() {
        rows = store.accounts
        tableView.reloadData()
    }

    private func selectedAccount() -> PRAccount? {
        let row = tableView.selectedRow
        guard row >= 0, row < rows.count else { return nil }
        return rows[row]
    }

    /// Keychain identity for the account being saved, as
    /// `provider|host|username`.
    ///
    /// Accounts saved by an earlier build used `provider|username`;
    /// `migratedIdentity` repairs those on load and moves the Keychain entry
    /// across, so no saved token is lost. Both halves come from
    /// `resolvedProvider()`/`currentHost()`, which is what keeps this string
    /// and the stored provider from disagreeing.
    private func currentIdentity() -> String? {
        let provider = resolvedProvider()
        let username = usernameField.stringValue.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !username.isEmpty else { return nil }
        // The host is in the identity, so the same username on github.com and on
        // a GitHub Enterprise install are two accounts rather than one overwriting
        // the other. `saveAccount` runs the same derivation, so whatever this
        // returns stays consistent with the stored key.
        let host = currentHost()
        return "\(provider)|\(host)|\(username)"
    }

    // MARK: - Actions

    @objc private func providerChanged() {
        let provider = providers[providerPopUp.indexOfSelectedItem].id
        // Bitbucket calls its read-only credential an app password, and Gitea
        // tokens differ from GitHub's only in scope, so the hint adapts.
        switch provider {
        case "bitbucket":
            tokenField.placeholderString = "app password (read-only)"
        case "gitea":
            tokenField.placeholderString = "token (read-only)"
        default:
            tokenField.placeholderString = "read-only token"
        }

        // Gitea has no single public host, so it is the only one where the host
        // has to be typed. For the others the host is implied, except Bitbucket,
        // which is Cloud-only and so has exactly one valid value.
        switch provider {
        case "bitbucket":
            hostField.isEnabled = false
            hostField.placeholderString = "bitbucket.org (Cloud only)"
        case "gitea":
            hostField.isEnabled = true
            hostField.placeholderString = "host, e.g. codeberg.org"
        default:
            hostField.isEnabled = true
            hostField.placeholderString = "host, e.g. gitlab.com"
        }
    }

    /// The provider this account belongs to.
    ///
    /// The typed host is authoritative over the popup. A known public host names
    /// its own forge, and a popup left on the wrong entry used to save a GitLab
    /// token as a *GitHub* account pointing at gitlab.com/api/v3, which then
    /// matched no repository for the rest of its life and reported itself as
    /// valid when tested on its own. Deriving the provider here, in one place,
    /// is what keeps the stored provider and the identity string in step.
    private func resolvedProvider() -> String {
        let chosen = providers[providerPopUp.indexOfSelectedItem].id
        guard hostField.isEnabled else { return chosen }
        let typed = PRHost.bare(hostField.stringValue)
        guard !typed.isEmpty else { return chosen }
        return ForgeDetector.provider(forHost: typed) ?? chosen
    }

    /// The host to save, taken from the field when the provider needs one and
    /// from the provider's known host otherwise.
    ///
    /// Whatever was typed is reduced to a bare host first: the field says
    /// "host" but the obvious thing to paste into it is the URL from the
    /// browser, and a URL saved as a host produces a base URL with the scheme
    /// doubled on the front.
    private func currentHost() -> String {
        let provider = providers[providerPopUp.indexOfSelectedItem].id
        let typed = PRHost.bare(hostField.stringValue)
        if !typed.isEmpty, hostField.isEnabled { return typed }
        return ForgeDetector.defaultHost(for: provider)
    }

    /// Moves the provider popup to match a host that names a known forge.
    ///
    /// Deliberately silent: it corrects the popup rather than printing what it
    /// worked out, because the dialog is already dense with fields and an extra
    /// readout is more noise than the mistake it would explain.
    func controlTextDidChange(_ obj: Notification) {
        guard let field = obj.object as? NSTextField, field === hostField,
              hostField.isEnabled else { return }
        guard let detected = ForgeDetector.provider(forHost: field.stringValue),
              let index = providers.firstIndex(where: { $0.id == detected }),
              index != providerPopUp.indexOfSelectedItem else { return }
        providerPopUp.selectItem(at: index)
    }

    @objc private func saveAccount() {
        guard let identity = currentIdentity() else {
            statusLabel.stringValue = "Enter a username to identify this account."
            statusLabel.textColor = .systemRed
            return
        }
        let token = tokenField.stringValue.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !token.isEmpty else {
            statusLabel.stringValue = "Paste a token to save."
            statusLabel.textColor = .systemRed
            return
        }
        let provider = resolvedProvider()
        // A host with no API root is a provider this build cannot reach, and
        // saving it would leave an account that silently matches nothing.
        guard let baseURL = ForgeDetector.apiBaseURL(provider: provider,
                                                     host: currentHost()) else {
            statusLabel.stringValue = "That provider does not support that host."
            statusLabel.textColor = .systemRed
            return
        }
        let account = PRAccount(identity: identity,
                                provider: provider,
                                username: usernameField.stringValue,
                                baseURL: baseURL)

        do {
            try store.saveAccount(account, token: token)
            tokenField.stringValue = ""
            statusLabel.stringValue = "Saved \(account.username) for \(account.providerName)."
            statusLabel.textColor = .secondaryLabelColor
            reload()
        } catch {
            statusLabel.stringValue = error.localizedDescription
            statusLabel.textColor = .systemRed
        }
    }

    @objc private func testSelected() {
        guard let account = selectedAccount() else {
            statusLabel.stringValue = "Select an account to test."
            statusLabel.textColor = .systemRed
            return
        }
        guard let token = PRCredentialStore.token(identity: account.identity) else {
            statusLabel.stringValue = "\(account.username): no token in the Keychain — re-enter and save it."
            statusLabel.textColor = .systemRed
            return
        }
        statusLabel.stringValue = "Testing \(account.username)…"
        DispatchQueue.global(qos: .userInitiated).async {
            let result = ForgeRegistry.verifyToken(provider: account.provider,
                                                   baseURL: account.baseURL,
                                                   token: token,
                                                   username: account.username)
            DispatchQueue.main.async {
                switch result {
                case .success(let name):
                    self.statusLabel.stringValue = "\(account.username): connected as \(name)."
                    self.statusLabel.textColor = .secondaryLabelColor
                case .failure(let message):
                    self.statusLabel.stringValue = "\(account.username): \(message)"
                    self.statusLabel.textColor = .systemRed
                }
            }
        }
    }

    @objc private func removeSelected() {
        guard let account = selectedAccount() else { return }
        let alert = NSAlert()
        alert.messageText = "Remove \(account.username)?"
        alert.informativeText = "The stored token will be deleted from your Keychain."
        alert.addButton(withTitle: "Remove")
        alert.addButton(withTitle: "Cancel")
        if alert.runModal() == .alertFirstButtonReturn {
            do {
                try store.removeAccount(account)
                statusLabel.stringValue = "Removed \(account.username)."
                statusLabel.textColor = .secondaryLabelColor
                reload()
            } catch {
                statusLabel.stringValue = error.localizedDescription
                statusLabel.textColor = .systemRed
            }
        }
    }

    }

extension AccountsWindowController: NSTableViewDataSource, NSTableViewDelegate {
    func numberOfRows(in tableView: NSTableView) -> Int { rows.count }

    func tableView(_ tableView: NSTableView, viewFor tableColumn: NSTableColumn?, row: Int) -> NSView? {
        guard row < rows.count, let column = tableColumn else { return nil }
        let account = rows[row]
        let text: String
        switch column.identifier.rawValue {
        case "Provider": text = account.providerName
        case "Host": text = account.normalizedAPIHost ?? "—"
        case "Account": text = account.username
        case "Token": text = Self.tokenStatus(for: account)
        default: text = ""
        }
        return NSTextField(labelWithString: text)
    }

    /// What the Token column shows for an account.
    ///
    /// Reading the Keychain to fill in one cell would put an unlock prompt in
    /// front of the user just for opening this window, so it reports what is
    /// already known and says "not checked" when nothing is cached yet. "Test"
    /// or saving the account resolves it, and the row is reloaded afterwards.
    private static func tokenStatus(for account: PRAccount) -> String {
        let state = PRCredentialStore.cachedState(identity: account.identity)
        guard state.isCached else { return "not checked" }
        return state.token == nil ? "missing" : "stored"
    }
}
// by cipher.org.uk
import AppKit

/// Small dialog for adding and editing watched repositories.
///
/// The privacy decision is explicit and per repository: a new repository starts
/// as public with no credentials, and only ticking "Private repository" makes
/// Karma Pro look for a token. That ordering is the point of this screen — a
/// user watching a public repo never causes credentials to be requested or
/// sent anywhere.
final class MonitoredReposWindowController: NSWindowController {
    /// Called when the watched-repository set changes, so the monitor can
    /// re-poll.
    var onChange: (() -> Void)?
    /// Set when a repository is added, so new subscriptions can start quiet.
    var onRepoAdded: ((String) -> Void)?
    /// Reports macOS notification authorization so the user can see why nothing appears.

    private let store = PRStore.shared

    private let tableView = NSTableView()
    private let urlField = NSTextField()
    private let localPathField = NSTextField()
    private let privateCheckbox = NSButton()
    private let depthPopUp = NSPopUpButton()
    private let branchesField = NSTextField()
    /// Picks which saved account authenticates this repository. Shown only when
    /// the repository is private, and only when more than one saved account can
    /// actually serve it — with one account there is no choice to make, and with
    /// none the status line already says so.
    private let accountPopUp = NSPopUpButton()
    private let accountLabel = NSTextField(labelWithString: "Account")
    /// The add-repository form. Held so the account row can be inserted into and
    /// removed from it; a local would not survive past buildUI.
    private let grid = NSGridView()
    /// Index of the account row in `grid`, or nil when it is not shown.
    private var accountRowIndex: Int?
    /// Identity of the account selected for the repository being edited, kept so
    /// the choice survives the form being reset between additions.
    private var selectedAccountIdentity: String?
    private let statusLabel = NSTextField(labelWithString: "")
    private let removeButton = NSButton()
    private let addButton = NSButton()
    private let testButton = NSButton()
    /// Multi-line on purpose. A `labelWithString` field is single-line, and
    /// giving one a word-wrap line break and a 3-line maximum does not make it
    /// wrap: it keeps one line of height while drawing the text through the row
    /// below, which is how this hint ended up printed across "Base branches".
    private let depthHint = NSTextField(wrappingLabelWithString: "")
    private let cacheLabel = NSTextField(labelWithString: "")
    private let clearCacheButton = NSButton()

    /// True while a review checkout is open. Clearing the cache then would delete
    /// the files the main window is showing, so the dialog refuses instead.
    var isReviewActive: (() -> Bool)?
    private let tableScroll = NSScrollView()
    private let pollErrorLabel = NSTextField(wrappingLabelWithString: "")
    private let notifyStatusLabel = NSTextField(wrappingLabelWithString: "")

    private var rows: [MonitoredRepo] = []

    convenience init() {
        // Same as the rest of the app's popups: ESC closes it.
        let window = EscClosableWindow(contentRect: NSRect(x: 0, y: 0, width: 660, height: 500),
                              styleMask: [.titled, .closable, .miniaturizable],
                              backing: .buffered,
                              defer: false)
        window.title = "Watched Repositories"
        window.center()
        self.init(window: window)
        buildUI()
        reload()
    }

    // MARK: - Layout

    private func buildUI() {
        guard let window = window, let content = window.contentView else { return }

        let listLabel = NSTextField(labelWithString: "Watched repositories")
        listLabel.font = .boldSystemFont(ofSize: 12)

        tableScroll.hasVerticalScroller = true
        tableScroll.borderType = .bezelBorder
        tableView.headerView = nil
        tableView.rowSizeStyle = .default
        tableView.usesAlternatingRowBackgroundColors = true
        for (title, width) in [("Watching", 80.0), ("Repository", 170.0), ("Type", 90.0),
                               ("Account", 120.0), ("Depth", 130.0), ("Source", 110.0)] {
            let column = NSTableColumn(identifier: NSUserInterfaceItemIdentifier(title))
            column.title = title
            column.width = width
            tableView.addTableColumn(column)
        }
        tableView.dataSource = self
        tableView.delegate = self
        tableView.target = self
        tableView.doubleAction = #selector(rowDoubleClicked)
        // The table is the scroll view's document view directly, sized in
        // `reload()`. Wrapping it in a further view and constraining that
        // wrapper left the document height ambiguous, so the table drew nothing
        // even with rows to show.
        tableView.autoresizingMask = [.width]
        tableScroll.documentView = tableView
        tableScroll.contentView.postsBoundsChangedNotifications = true
        tableScroll.translatesAutoresizingMaskIntoConstraints = false

        removeButton.title = "Remove"
        removeButton.bezelStyle = .rounded
        removeButton.target = self
        removeButton.action = #selector(removeSelected)
        removeButton.translatesAutoresizingMaskIntoConstraints = false

        let addLabel = NSTextField(labelWithString: "Add a repository")
        addLabel.font = .boldSystemFont(ofSize: 12)

        urlField.placeholderString = "https://github.com/owner/name (or a git remote URL)"
        urlField.target = self
        urlField.action = #selector(urlFieldChanged)
        urlField.translatesAutoresizingMaskIntoConstraints = false

        localPathField.placeholderString = "optional: use an existing local clone instead of downloading"
        localPathField.translatesAutoresizingMaskIntoConstraints = false

        accountPopUp.target = self
        accountPopUp.action = #selector(accountChanged)
        accountPopUp.translatesAutoresizingMaskIntoConstraints = false

        privateCheckbox.setButtonType(.switch)
        privateCheckbox.title = "Private repository (requires a read-only token)"
        privateCheckbox.target = self
        privateCheckbox.action = #selector(privateToggled)
        privateCheckbox.translatesAutoresizingMaskIntoConstraints = false

        depthPopUp.addItems(withTitles: PRKind.Depth.allCases.map(\.title))
        depthPopUp.translatesAutoresizingMaskIntoConstraints = false
        // Start on the depth the status menu is already using, so the two never
        // disagree about what a newly added repository will be scanned at.
        if let index = PRKind.Depth.allCases.firstIndex(of: store.defaultDepth) {
            depthPopUp.selectItem(at: index)
        }

        branchesField.placeholderString = "optional: base branches to watch, e.g. main, release"
        branchesField.translatesAutoresizingMaskIntoConstraints = false

        depthHint.font = .systemFont(ofSize: 10)
        depthHint.textColor = .secondaryLabelColor
        // A wrapping label needs a width before it can decide its height, and
        // the one it is given here is the dialog's own content width less the
        // margins, so the wrapped height matches what will actually be drawn.
        // Left unset it measured as one very long line, so the row it sat in
        // was one line tall and the text ran over "Base branches" below it.
        depthHint.lineBreakMode = .byWordWrapping
        depthHint.maximumNumberOfLines = 0
        depthHint.preferredMaxLayoutWidth = 420
        // A hint is supplementary, so it is the first thing allowed to lose
        // width when the dialog is narrowed rather than the field above it.
        depthHint.setContentHuggingPriority(.defaultLow, for: .horizontal)
        depthHint.setContentCompressionResistancePriority(.defaultLow, for: .horizontal)
        depthPopUp.target = self
        depthPopUp.action = #selector(depthChanged)

        addButton.title = "Add Repository"
        addButton.bezelStyle = .rounded
        addButton.keyEquivalent = "\r"
        addButton.target = self
        addButton.action = #selector(addRepo)
        addButton.translatesAutoresizingMaskIntoConstraints = false

        testButton.title = "Test Connection"
        testButton.bezelStyle = .rounded
        testButton.target = self
        testButton.action = #selector(testConnection)
        testButton.translatesAutoresizingMaskIntoConstraints = false

        pollErrorLabel.font = .systemFont(ofSize: 10)
        pollErrorLabel.textColor = .systemRed
        pollErrorLabel.isHidden = true

        // Notification authorization is the one setting the app cannot fix on the
        // user's behalf, so it is stated here rather than left to be discovered
        // by noticing that nothing ever appears.
        notifyStatusLabel.font = .systemFont(ofSize: 10)
        notifyStatusLabel.textColor = .secondaryLabelColor
        notifyStatusLabel.isHidden = true

        statusLabel.font = .systemFont(ofSize: 11)
        statusLabel.textColor = .secondaryLabelColor
        statusLabel.lineBreakMode = .byTruncatingTail
        for button in [addButton, testButton] {
            button.setContentHuggingPriority(.required, for: .horizontal)
            button.setContentCompressionResistancePriority(.required, for: .horizontal)
        }
        statusLabel.setContentHuggingPriority(.defaultLow, for: .horizontal)
        statusLabel.setContentCompressionResistancePriority(.defaultLow, for: .horizontal)

        grid.addRow(with: [NSTextField(labelWithString: "Repository"), urlField])
        grid.addRow(with: [NSTextField(labelWithString: "Local clone"), localPathField])
        grid.addRow(with: [NSTextField(labelWithString: "Scan depth"), depthPopUp])
        // The hint is the Scan depth row's own explanation, so it stays directly
        // under the dropdown, in the control column where its width is bounded by
        // the same trailing edge as every other field.
        //
        // It deliberately does NOT share a merged row. NSGridView takes a merged
        // row's height from its FIRST cell, which here is the empty label in the
        // label column, so the row came out one line tall and the two lines of
        // hint text hung down over "Base branches" below it. An unmerged row is
        // sized from the tallest of its two cells, which is the hint itself.
        grid.addRow(with: [NSTextField(labelWithString: ""), depthHint])
        grid.addRow(with: [NSTextField(labelWithString: "Base branches"), branchesField])
        grid.translatesAutoresizingMaskIntoConstraints = false
        grid.rowSpacing = 8
        grid.columnSpacing = 10
        grid.column(at: 0).xPlacement = .trailing
        // The account row is inserted above "Local clone" (index 1) once a
        // private repository has more than one usable account, so it appears
        // directly under the URL it applies to.
        updateAccountPicker()
        depthChanged()

        // removeButton is a stored property rather than a local, so it has to be
        // added explicitly: it is constrained against tableScroll and content,
        // and a constraint between a view and its anchor's container is only
        // valid once the view is in that hierarchy.
        cacheLabel.font = .systemFont(ofSize: 11)
        cacheLabel.textColor = .secondaryLabelColor
        cacheLabel.lineBreakMode = .byTruncatingTail
        cacheLabel.setContentCompressionResistancePriority(.defaultLow, for: .horizontal)
        clearCacheButton.title = "Clear Cache"
        clearCacheButton.bezelStyle = .rounded
        clearCacheButton.target = self
        clearCacheButton.action = #selector(clearCache)

        for view in [listLabel, tableScroll, pollErrorLabel, notifyStatusLabel,
                     removeButton, cacheLabel, clearCacheButton, addLabel, grid,
                     privateCheckbox, statusLabel, testButton, addButton] as [NSView] {
            view.translatesAutoresizingMaskIntoConstraints = false
            content.addSubview(view)
        }

        NSLayoutConstraint.activate([
            listLabel.topAnchor.constraint(equalTo: content.topAnchor, constant: 16),
            listLabel.leadingAnchor.constraint(equalTo: content.leadingAnchor, constant: 16),

            tableScroll.topAnchor.constraint(equalTo: listLabel.bottomAnchor, constant: 6),
            tableScroll.leadingAnchor.constraint(equalTo: content.leadingAnchor, constant: 16),
            tableScroll.trailingAnchor.constraint(equalTo: content.trailingAnchor, constant: -16),
            tableScroll.heightAnchor.constraint(equalToConstant: 160),

            pollErrorLabel.topAnchor.constraint(equalTo: tableScroll.bottomAnchor, constant: 6),
            pollErrorLabel.leadingAnchor.constraint(equalTo: content.leadingAnchor, constant: 16),
            pollErrorLabel.trailingAnchor.constraint(equalTo: content.trailingAnchor, constant: -16),

            removeButton.topAnchor.constraint(equalTo: pollErrorLabel.bottomAnchor, constant: 8),
            removeButton.leadingAnchor.constraint(equalTo: content.leadingAnchor, constant: 16),

            // The on-disk review checkouts. Every reviewed pull request leaves a
            // real Git clone behind, so this is stated with a figure and a way to
            // remove it rather than left to accumulate unseen in the caches
            // directory.
            cacheLabel.topAnchor.constraint(equalTo: removeButton.bottomAnchor, constant: 10),
            cacheLabel.leadingAnchor.constraint(equalTo: content.leadingAnchor, constant: 16),
            cacheLabel.centerYAnchor.constraint(equalTo: clearCacheButton.centerYAnchor),

            clearCacheButton.topAnchor.constraint(equalTo: removeButton.bottomAnchor, constant: 4),
            clearCacheButton.trailingAnchor.constraint(equalTo: content.trailingAnchor, constant: -16),
            clearCacheButton.widthAnchor.constraint(greaterThanOrEqualToConstant: 100),

            addLabel.topAnchor.constraint(equalTo: clearCacheButton.bottomAnchor, constant: 18),
            addLabel.leadingAnchor.constraint(equalTo: content.leadingAnchor, constant: 16),

            grid.topAnchor.constraint(equalTo: addLabel.bottomAnchor, constant: 8),
            grid.leadingAnchor.constraint(equalTo: content.leadingAnchor, constant: 16),
            grid.trailingAnchor.constraint(equalTo: content.trailingAnchor, constant: -16),

            privateCheckbox.topAnchor.constraint(equalTo: grid.bottomAnchor, constant: 12),
            privateCheckbox.leadingAnchor.constraint(equalTo: content.leadingAnchor, constant: 16),

            statusLabel.topAnchor.constraint(equalTo: privateCheckbox.bottomAnchor, constant: 12),
            statusLabel.leadingAnchor.constraint(equalTo: content.leadingAnchor, constant: 16),
            statusLabel.trailingAnchor.constraint(equalTo: testButton.leadingAnchor, constant: -8),

            testButton.centerYAnchor.constraint(equalTo: statusLabel.centerYAnchor),
            testButton.trailingAnchor.constraint(equalTo: addButton.leadingAnchor, constant: -8),

            addButton.centerYAnchor.constraint(equalTo: statusLabel.centerYAnchor),
            addButton.trailingAnchor.constraint(equalTo: content.trailingAnchor, constant: -16),
            addButton.bottomAnchor.constraint(lessThanOrEqualTo: content.bottomAnchor, constant: -16),

            testButton.widthAnchor.constraint(greaterThanOrEqualToConstant: 110),
            addButton.widthAnchor.constraint(greaterThanOrEqualToConstant: 110),
            statusLabel.widthAnchor.constraint(greaterThanOrEqualToConstant: 140)
        ])
    }

    // MARK: - Data

    private func reload() {
        rows = store.repos
        tableView.reloadData()
        updateCacheRow()

        // Size the document view to the rows. The table is the document view
        // directly, so AppKit has no intrinsic height to work from and the rows
        // have to be given a frame.
        let headerHeight = tableView.headerView?.frame.height ?? 0
        let needed = CGFloat(tableView.numberOfRows) * tableView.rowHeight + headerHeight
        let visible = tableScroll.contentView.bounds.height
        var frame = tableScroll.documentView?.frame ?? .zero
        frame.origin.x = 0
        frame.size.height = max(needed, visible)
        tableScroll.documentView?.frame = frame
        tableView.frame.size.height = max(needed, visible)
    }

    /// Full poll detail, shown here rather than in the status menu: this is the
    /// only surface wide enough to read a provider error on.
    func setPollError(_ message: String?) {
        let trimmed = message?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
        pollErrorLabel.stringValue = trimmed
        pollErrorLabel.isHidden = trimmed.isEmpty
    }

    /// Reports a notification problem, and stays out of the way when there is not
    /// one.
    ///
    /// Only a state the user can actually fix is shown. "Authorised" is the
    /// normal case and reporting it said nothing except restating a debug log
    /// line, which made the window look like it had failed. A denied app still
    /// runs, still polls and still writes its log, so silence from the status
    /// menu is otherwise untraceable -- that case is the one worth words.
    func setNotificationStatus(_ status: String, _ note: String) {
        let denied = status == "denied"
        let unknown = status == "not requested" || status == "unknown"
        guard denied || unknown else {
            notifyStatusLabel.isHidden = true
            return
        }
        notifyStatusLabel.stringValue = denied
            ? "macOS notifications are turned off for Karma Pro. Turn them on in "
              + "System Settings > Notifications, then wait for the next new pull request."
            : "Karma Pro has not asked macOS for permission to post notifications yet."
        notifyStatusLabel.textColor = denied ? .systemRed : .secondaryLabelColor
        notifyStatusLabel.isHidden = false
    }

    // MARK: - Actions

    /// Keeps the explanation under Scan depth in step with the chosen depth.
    /// The two modes differ in what cross-file analysis can do, so a stale
    /// sentence here would misdescribe what the user just selected.
    @objc private func depthChanged() {
        let index = depthPopUp.indexOfSelectedItem
        guard PRKind.Depth.allCases.indices.contains(index) else { return }
        let depth = PRKind.Depth.allCases[index]
        depthHint.stringValue = depth.explanation
        depthHint.toolTip = depth.explanation
    }

    @objc private func urlFieldChanged() {
        updateDetection()
        updatePrivacyHint()
    }

    @objc private func privateToggled() {
        updateAccountPicker()
        updatePrivacyHint()
    }

    @objc private func accountChanged() {
        let index = accountPopUp.indexOfSelectedItem
        let identities = accountPopUpIdentifiers
        guard index >= 0, index < identities.count else { return }
        selectedAccountIdentity = identities[index]
        updatePrivacyHint()
    }

    /// Identities matching the popup's current items, so the selection survives
    /// the list being rebuilt.
    private var accountPopUpIdentifiers: [String] = []

    /// The accounts that could authenticate the URL currently in the field.
    private func usableAccounts() -> [PRAccount] {
        guard let endpoint = detectedEndpoint(), privateCheckbox.state == .on else { return [] }
        let probe = MonitoredRepo(provider: endpoint.provider,
                                  baseURL: endpoint.apiBaseURL,
                                  webURL: endpoint.webURL,
                                  repoSlug: endpoint.repoSlug,
                                  visibility: .privateRepo)
        return store.accounts(for: probe)
    }

    /// Shows the account picker when, and only when, there is a choice to make.
    ///
    /// One usable account means the choice is made for the user and the picker
    /// would only be noise; zero means the status line already says to add one.
    /// Both still record `selectedAccountIdentity`, so switching from two
    /// accounts back to one keeps the repository pointed at a real account
    /// instead of an identity that has since been deleted.
    private func updateAccountPicker() {
        let accounts = usableAccounts()

        if let index = accountRowIndex {
            grid.removeRow(at: index)
            accountRowIndex = nil
        }
        accountPopUp.removeAllItems()
        accountPopUpIdentifiers = []

        guard let first = accounts.first else {
            selectedAccountIdentity = nil
            return
        }

        // Keep pointing at an account that still exists, otherwise take the first.
        if let current = selectedAccountIdentity,
           accounts.contains(where: { $0.identity == current }) {
            selectedAccountIdentity = current
            selectInPopUp(accounts)
            return
        }
        selectedAccountIdentity = first.identity
        selectInPopUp(accounts)

        guard accounts.count > 1 else { return }
        grid.insertRow(at: 1, with: [accountLabel, accountPopUp])
        accountRowIndex = 1
    }

    private func selectInPopUp(_ accounts: [PRAccount]) {
        accountPopUp.removeAllItems()
        for account in accounts {
            let host = account.normalizedAPIHost ?? account.baseURL
            accountPopUp.addItem(withTitle: "\(account.username) (\(host))")
        }
        accountPopUpIdentifiers = accounts.map(\.identity)
        if let index = accountPopUpIdentifiers.firstIndex(of: selectedAccountIdentity ?? "") {
            accountPopUp.selectItem(at: index)
        }
    }

    /// Reads the URL as the user types it, to drive the private/account hints.
    ///
    /// There is deliberately no "Detected gitlab · https://…" echo of the parse
    /// on this window. It was a merged grid row whose height came from the
    /// label column's cell, so the text hung over "Base branches" underneath,
    /// and it said nothing the account and privacy hints below do not already
    /// say. A URL that cannot be parsed still reports, through the status line.
    private func updateDetection() {
        let text = urlField.stringValue.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !text.isEmpty else { return }
        guard let endpoint = ForgeDetector.detect(from: text) else {
            statusLabel.stringValue = "Could not read that as a repository URL."
            statusLabel.textColor = .systemRed
            return
        }
        // Auto-tick the private box for self-hosted forges, which are
        // overwhelmingly internal and private; leave SaaS defaults untouched.
        if endpoint.provider == "gitea" || endpoint.visibility == .privateRepo {
            privateCheckbox.state = .on
        }
        // The provider can change as the URL is edited, so the list of accounts
        // that could serve this repository changes with it.
        updateAccountPicker()
        updatePrivacyHint()
    }

    private func updatePrivacyHint() {
        guard privateCheckbox.state == .on else {
            statusLabel.stringValue = "Public repository: no credentials are used or sent."
            statusLabel.textColor = .secondaryLabelColor
            return
        }
        // Names the account that will actually be used, rather than asserting
        // that "a" token will be sent: with several saved for one provider the
        // old wording named none of them and the choice was invisible.
        let accounts = usableAccounts()
        if accounts.isEmpty {
            statusLabel.stringValue = "Private repository: no saved account can reach \(detectedForgeName()). Add one in Accounts… first."
            statusLabel.textColor = .systemOrange
        } else if let chosen = accounts.first(where: { $0.identity == selectedAccountIdentity }) {
            statusLabel.stringValue = "Private repository: uses account \"\(chosen.username)\" on \(chosen.normalizedAPIHost ?? chosen.baseURL)."
            statusLabel.textColor = .secondaryLabelColor
        } else {
            statusLabel.stringValue = "Private repository: \(accounts.count) accounts can reach \(detectedForgeName()). Choose one with Account."
            statusLabel.textColor = .secondaryLabelColor
        }
    }

    /// The provider id the URL in the field resolves to, or nil if it cannot be
    /// read. Returns the raw id so callers format it exactly once.
    private func detectedProvider() -> String? {
        detectedEndpoint()?.provider
    }

    /// The forge named by the URL in the field, formatted once, for a URL that
    /// cannot be read yet there is no forge to name.
    private func detectedForgeName() -> String {
        guard let provider = detectedProvider() else { return "the forge" }
        return providerName(provider)
    }

    /// The forge the URL currently in the field resolves to, if any.
    private func detectedEndpoint() -> ForgeDetector.Endpoint? {
        ForgeDetector.detect(from: urlField.stringValue)
    }

    /// The display name for a provider id.
    ///
    /// Every id is spelled out, including GitHub, and the fallback names nothing
    /// in particular. It used to fall through to "GitHub" for anything
    /// unrecognised, which printed "GitHub" for a GitLab repository: the caller
    /// handed this function the *already formatted* name from
    /// `detectedProvider()`, "GitLab" matched no case, and the default spoke for
    /// the wrong forge. Passing a name in is now the mistake that cannot happen,
    /// and an unknown id reads as "that provider" rather than blaming GitHub.
    private func providerName(_ id: String) -> String {
        switch id {
        case "github": return "GitHub"
        case "gitlab": return "GitLab"
        case "bitbucket": return "Bitbucket"
        case "gitea": return "the forge"
        default: return "that provider"
        }
    }

    /// Pauses or resumes one repository without removing it.
    @objc private func toggleEnabled(_ sender: NSButton) {
        let row = sender.tag
        guard row >= 0, row < rows.count else { return }
        let enabled = sender.state == .on
        var repo = rows[row]
        repo.enabled = enabled
        rows[row] = repo
        store.updateRepo(repo)
        tableView.reloadData()
        onChange?()
    }

    /// Confirms the provider is reachable and readable before the repository is
    /// watched, so a bad URL or a missing token is reported here rather than as
    /// a failure in the menu bar on the next poll.
    @objc private func testConnection() {
        let text = urlField.stringValue.trimmingCharacters(in: .whitespacesAndNewlines)
        guard let endpoint = ForgeDetector.detect(from: text) else {
            showMessage("Enter a full repository URL, for example https://github.com/owner/name.", isError: true)
            return
        }
        let isPrivate = privateCheckbox.state == .on
        let visibility: PRKind.Visibility = isPrivate ? .privateRepo : .publicRepo
        let candidate = MonitoredRepo(provider: endpoint.provider,
                                      baseURL: endpoint.apiBaseURL,
                                      webURL: endpoint.webURL,
                                      repoSlug: endpoint.repoSlug,
                                      localPath: localPathField.stringValue
                                        .trimmingCharacters(in: .whitespacesAndNewlines).nilIfEmpty,
                                      visibility: visibility,
                                      accountIdentity: selectedAccountIdentity)
        // Testing with no usable account cannot succeed, and the auth error it
        // produces reads like bad credentials rather than a missing account.
        // Pressing Test is an explicit request, so this may ask for the Keychain.
        if visibility.needsCredentials, store.accountStatus(for: candidate, prompt: true).hasToken == false {
            testButton.isEnabled = true
            showMessage("No saved account can reach \(endpoint.webURL). Add one in Accounts… first.", isError: true)
            return
        }
        testButton.isEnabled = false
        showMessage("Testing connection to \(endpoint.webURL)…", isError: false)
        DispatchQueue.global(qos: .userInitiated).async {
            let result = ForgeRegistry.adapter(for: candidate.provider,
                                              token: self.store.token(for: candidate))
                .testConnection(for: candidate)
            DispatchQueue.main.async {
                self.testButton.isEnabled = true
                switch result {
                case .success:
                    self.showMessage("Connection to \(endpoint.webURL) works.",
                                     isError: false)
                case .failure(let error):
                    self.showMessage(error.message, isError: true)
                }
                PRLog.write("connection test \(endpoint.webURL): \(result)")
            }
        }
    }

    private func showMessage(_ text: String, isError: Bool) {
        statusLabel.stringValue = text
        statusLabel.textColor = isError ? .systemRed : .secondaryLabelColor
    }

    @objc private func addRepo() {
        let text = urlField.stringValue.trimmingCharacters(in: .whitespacesAndNewlines)
        guard let endpoint = ForgeDetector.detect(from: text) else {
            statusLabel.stringValue = "Enter a full repository URL, for example https://github.com/owner/name."
            statusLabel.textColor = .systemRed
            return
        }

        let isPrivate = privateCheckbox.state == .on
        let visibility: PRKind.Visibility = isPrivate ? .privateRepo : .publicRepo
        // Adding a private repo with no usable account would produce a 401 on every
        // poll, so it is refused with a pointer to the fix. This checks the
        // account the picker actually selected, not merely that one exists.
        let credentialCheck = MonitoredRepo(provider: endpoint.provider,
                                            baseURL: endpoint.apiBaseURL,
                                            webURL: endpoint.webURL,
                                            repoSlug: endpoint.repoSlug,
                                            visibility: visibility,
                                            accountIdentity: selectedAccountIdentity)
        if isPrivate, !store.hasUsableToken(for: credentialCheck) {
            let alert = NSAlert()
            alert.messageText = "No usable account for this repository"
            alert.informativeText = "No saved account on \(endpoint.webURL.replacingOccurrences(of: "/\(endpoint.repoSlug)", with: "")) can reach this private \(providerName(endpoint.provider)) repository. Add a read-only token in Accounts… first."
            alert.addButton(withTitle: "OK")
            alert.runModal()
            return
        }

        let depth: PRKind.Depth = PRKind.Depth.allCases.indices.contains(depthPopUp.indexOfSelectedItem)
            ? PRKind.Depth.allCases[depthPopUp.indexOfSelectedItem]
            : .changedOnly
        let branches = branchesField.stringValue
            .split(separator: ",")
            .map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
            .filter { !$0.isEmpty }

        let repo = MonitoredRepo(provider: endpoint.provider,
                                 baseURL: endpoint.apiBaseURL,
                                 webURL: endpoint.webURL,
                                 repoSlug: endpoint.repoSlug,
                                 localPath: localPathField.stringValue
                                    .trimmingCharacters(in: .whitespacesAndNewlines).nilIfEmpty,
                                 visibility: visibility,
                                 depth: depth,
                                 baseBranches: branches,
                                 accountIdentity: selectedAccountIdentity)

        store.addRepo(repo)
        urlField.stringValue = ""
        localPathField.stringValue = ""
        branchesField.stringValue = ""
        privateCheckbox.state = .off
        // The chosen account belonged to the repository just added, so it must
        // not carry over to the next one the user types.
        selectedAccountIdentity = nil
        updateAccountPicker()
        // Deliberately no confirmation here: the repository appearing in the
        // list above is the confirmation, and repeating its URL next to the
        // button read as if the URL were part of the form.
        statusLabel.stringValue = ""
        statusLabel.textColor = .secondaryLabelColor
        reload()
        onRepoAdded?(repo.id)
        onChange?()
    }

    @objc private func removeSelected() {
        let row = tableView.selectedRow
        guard row >= 0, row < rows.count else { return }
        let repo = rows[row]
        let alert = NSAlert()
        alert.messageText = "Stop watching \(repo.repoSlug)?"
        alert.informativeText = "Any temporary checkout created for its pull requests stays on disk."
        alert.addButton(withTitle: "Remove")
        alert.addButton(withTitle: "Cancel")
        if alert.runModal() == .alertFirstButtonReturn {
            store.removeRepo(repo)
            reload()
            onChange?()
        }
    }

    /// Removes every temporary checkout, after confirming, and only when no
    /// review is open -- clearing the cache under an open review would delete
    /// the files the file tree and source viewer are reading.
    @objc private func clearCache() {
        if isReviewActive?() == true {
            presentSheet(title: "Close the open review first",
                         message: "The pull request you are reviewing is being read from this "
                                + "folder. Close that review, then clear the cache.")
            return
        }
        let size = PRMonitor.cacheSize()
        guard size > 0 else {
            showMessage("The review cache is already empty.", isError: false)
            return
        }
        let alert = NSAlert()
        alert.messageText = "Free \(PRMonitor.formattedSize(size)) of review checkouts?"
        alert.informativeText = "Removes every temporary pull request checkout. "
            + "Watching and credentials are untouched. A review that is reopened will be "
            + "downloaded again."
        alert.addButton(withTitle: "Clear Cache")
        alert.addButton(withTitle: "Cancel")
        if alert.runModal() == .alertFirstButtonReturn {
            do {
                let freed = try PRMonitor.clearCache()
                showMessage("Cleared \(PRMonitor.formattedSize(freed)) of review checkouts.",
                            isError: false)
            } catch {
                presentSheet(title: "Could not clear the cache", message: error.localizedDescription)
            }
            updateCacheRow()
        }
    }

    /// Shows the current size, refreshed whenever the dialog is opened or a
    /// repository is added or removed.
    private func updateCacheRow() {
        let size = PRMonitor.cacheSize()
        cacheLabel.stringValue = size == 0
            ? "No review checkouts on disk"
            : "Review checkouts on disk: \(PRMonitor.formattedSize(size))"
        cacheLabel.toolTip = PRMonitor.cacheRoot.path
    }

    private func presentSheet(title: String, message: String) {
        let alert = NSAlert()
        alert.messageText = title
        alert.informativeText = message
        alert.addButton(withTitle: "OK")
        alert.runModal()
    }

    @objc private func rowDoubleClicked() {
        let row = tableView.selectedRow
        guard row >= 0, row < rows.count else { return }
        let repo = rows[row]
        guard let url = URL(string: repo.webURL) else { return }
        NSWorkspace.shared.open(url)
    }
}

extension MonitoredReposWindowController: NSTableViewDataSource, NSTableViewDelegate {
    func numberOfRows(in tableView: NSTableView) -> Int { rows.count }

    func tableView(_ tableView: NSTableView, viewFor tableColumn: NSTableColumn?, row: Int) -> NSView? {
        guard row < rows.count, let column = tableColumn else { return nil }
        let repo = rows[row]

        if column.identifier.rawValue == "Watching" {
            // Untick to pause this repository without deleting it, so polling
            // can be switched back on from this list later.
            let check = NSButton(checkboxWithTitle: "", target: self,
                                 action: #selector(toggleEnabled(_:)))
            check.state = repo.enabled ? .on : .off
            check.tag = row
            check.toolTip = repo.enabled ? "Watching this repository"
                                         : "Not being watched \u{2014} click to resume"
            return check
        }

        let text: String
        switch column.identifier.rawValue {
        case "Repository": text = repo.repoSlug
        case "Type": text = repo.visibility.needsCredentials ? "Private" : "Public"
        // Which of the saved accounts this repository polls with. Two private
        // repositories on one provider can sit on different accounts, so the
        // list has to say which is which or the choice is invisible.
        case "Account":
            if !repo.visibility.needsCredentials {
                text = "—"
            } else if let identity = repo.accountIdentity,
                      let account = store.accounts.first(where: { $0.identity == identity }) {
                text = account.username
            } else {
                text = store.accountStatus(for: repo).account?.username ?? "none"
            }
        case "Depth": text = repo.depth.title
        case "Source": text = repo.localPath == nil ? "Remote" : "Local clone"
        default: text = ""
        }
        let label = NSTextField(labelWithString: text)
        label.lineBreakMode = .byTruncatingMiddle
        label.toolTip = repo.webURL
        return label
    }
}

extension String {
    /// Empty and whitespace-only strings become nil, used to keep optional form
    /// fields out of the persisted model.
    var nilIfEmpty: String? {
        let trimmed = trimmingCharacters(in: .whitespacesAndNewlines)
        return trimmed.isEmpty ? nil : trimmed
    }
}
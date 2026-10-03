// by cipher.org.uk
import Foundation

/// Result of preparing a pull request for review on disk.
struct PreparedCheckout {
    /// Root the app should index and review as an ordinary folder.
    let workspace: URL
    /// Files the PR added or modified, with hunk locations.
    let changedFiles: [ChangedFile]
    /// Refs used to produce the diff, needed for per-file rendering later.
    let baseRef: String
    let headRef: String
    /// Set when a local clone was used, so cleanup can prune the worktree.
    let sourceClone: URL?

    var reviewableFiles: [ChangedFile] { changedFiles.filter(\.isReviewable) }
}

/// Git transport for materialising a pull request on disk.
///
/// This shells out to the `git` binary rather than linking libgit2, because
/// the project builds with a plain `swiftc` invocation and no package manager
/// (see `build.sh`); adding SwiftPM would mean restructuring how the whole app
/// is compiled, signed and shipped. Since macOS does not always have a working
/// `git`, callers check `isAvailable` first and the UI turns a missing binary
/// into an actionable message instead of a silent failure.
///
/// Transport auth for the git operations a review needs.
///
/// The forge token saved in Accounts is the same credential the REST API uses,
/// and git needs it too: cloning a private repository over HTTPS without it
/// makes git try to open a terminal and ask for a username. This process has no
/// terminal, so that attempt fails with "could not read Username ... Device not
/// configured", which says nothing about what to do about it.
///
/// Rather than let git prompt — or embed the token in the remote URL, where it
/// would be written into .git/config and could be printed by any command that
/// echoes the remote — the token is passed per-invocation as an HTTP header, and
/// never touches disk.
///
/// Repositories with no saved token get no header at all, so the user's
/// existing SSH agent or credential helper continues to be what authenticates
/// them. Where a local clone is used its own remote is left exactly as it was.
struct GitAuth {
    let provider: String
    let token: String

    /// The username half of HTTP Basic that each forge expects beside its token.
    ///
    /// These are conventional placeholders rather than real accounts: GitHub,
    /// GitLab and Gitea all accept any non-empty username with the token as the
    /// password, and `x-access-token` is the widely used convention among them.
    /// Bitbucket is the exception and rejects anything else for app passwords.
    private var basicUsername: String {
        provider == "bitbucket" ? "x-token-auth" : "x-access-token"
    }

    /// The header git is asked to send with every HTTP request.
    var extraHeader: String {
        let pair = "\(basicUsername):\(token)"
        let encoded = Data(pair.utf8).base64EncodedString()
        return "Authorization: Basic \(encoded)"
    }

    /// Applied to the git process as configuration rather than as a `-c`
    /// argument.
    ///
    /// The token is deliberately kept out of the command line. Arguments are
    /// world-readable to any process running as the same user, so a `-c` option
    /// would put the credential in `ps` output and in Activity Monitor, where it
    /// would outlive the fetch. Git's `GIT_CONFIG_COUNT` environment variables
    /// set the identical option with the value in the environment instead, which
    /// ordinary process listings do not show. Nothing is written to the
    /// repository's .git/config either way, so the credential is not persisted
    /// for later commands to pick up.
    func apply(to environment: inout [String: String]) {
        environment["GIT_CONFIG_COUNT"] = "1"
        environment["GIT_CONFIG_KEY_0"] = "http.extraHeader"
        environment["GIT_CONFIG_VALUE_0"] = extraHeader
    }
}

enum GitRunner {
    struct GitError: LocalizedError {
        let message: String
        var errorDescription: String? { message }
    }

    /// git is only usable if it runs, which distinguishes "not installed" from
    /// "installed but the Xcode command line tools are missing".
    static func isAvailable() -> Bool {
        (try? run(["--version"])) != nil
    }

    static var unavailableMessage: String {
        "Git is not available on this Mac. Install the Xcode Command Line Tools (xcode-select --install) if you want pull request monitoring support (optional) - everything else in Karma Pro works without it."
    }

    @discardableResult
    static func run(_ arguments: [String], cwd: URL? = nil, auth: GitAuth? = nil) throws -> String {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/env")
        // Auth is set through the environment inside `run` rather than here.
        process.arguments = ["git"] + arguments
        if let cwd = cwd { process.currentDirectoryURL = cwd }

        var environment = ProcessInfo.processInfo.environment
        // Git must never try to prompt. This process is launched by a windowed
        // app with no controlling terminal, so an interactive prompt does not
        // fail politely — it dies with "Device not configured", which mentions
        // neither credentials nor the repository. With prompting disabled git
        // instead reports that it could not read the username and, with an auth
        // header supplied, simply works.
        environment["GIT_TERMINAL_PROMPT"] = "0"
        auth?.apply(to: &environment)
        process.environment = environment

        let out = Pipe()
        let err = Pipe()
        process.standardOutput = out
        process.standardError = err

        try process.run()
        // Drain both pipes before waiting: a git that writes a lot to stderr
        // would otherwise fill the pipe buffer and deadlock.
        let outData = out.fileHandleForReading.readDataToEndOfFile()
        let errData = err.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()

        let outText = String(data: outData, encoding: .utf8) ?? ""
        let errText = String(data: errData, encoding: .utf8) ?? ""

        guard process.terminationStatus == 0 else {
            let detail = errText.trimmingCharacters(in: .whitespacesAndNewlines)
            let useful = detail.isEmpty ? outText.trimmingCharacters(in: .whitespacesAndNewlines) : detail
            throw GitError(message: friendlyMessage(useful, auth: auth))
        }
        return outText
    }

    /// Rewrites git's transport errors into something that names the cause.
    ///
    /// Git's own wording for a failed authenticated fetch is about a terminal or
    /// a username, which sends the reader looking for a tty problem rather than a
    /// token one. Since prompting is now disabled these messages are the usual
    /// symptom of a missing or wrong credential, so they are restated as that.
    private static func friendlyMessage(_ detail: String, auth: GitAuth?) -> String {
        let lowered = detail.lowercased()
        let asksForCredentials = lowered.contains("could not read username")
            || lowered.contains("could not read password")
            || lowered.contains("authentication failed")
            || lowered.contains("terminal prompts disabled")
        guard asksForCredentials else {
            return detail.isEmpty
                ? "git failed (no output)"
                : detail
        }
        if auth != nil {
            return "The saved token for this repository was rejected by the forge. Open Accounts… and check that the token is still valid and has read access."
        }
        return "This repository needs a credential. If it is private, add a read-only token in Accounts…; if you are using a local clone, make sure it can reach the remote (SSH agent or credential helper)."
    }

    /// The remote URL of a local checkout, used when a monitored repo points at
    /// a clone that already exists on this Mac.
    static func remoteURL(ofLocalPath path: URL) -> String? {
        guard let out = try? run(["config", "--get", "remote.origin.url"], cwd: path) else { return nil }
        let trimmed = out.trimmingCharacters(in: .whitespacesAndNewlines)
        return trimmed.isEmpty ? nil : trimmed
    }

    /// The ref a forge publishes for a pull request's head commit.
    ///
    /// GitHub and the GitHub-compatible forges publish every PR as
    /// `refs/pull/<n>/head`, which also resolves PRs raised from forks. GitLab
    /// uses `refs/merge-requests/<iid>/head`. Bitbucket publishes nothing
    /// canonical, so the caller falls back to fetching the head branch by name.
    static func headRefSpec(provider: String, number: Int) -> String? {
        switch provider {
        case "gitlab": return "refs/merge-requests/\(number)/head"
        case "bitbucket": return nil
        default: return "refs/pull/\(number)/head"
        }
    }

    // MARK: - Preparing a review

    /// Materialises a pull request into `workspace`.
    ///
    /// - Parameter localPath: an existing clone on this Mac. When supplied a
    ///   git worktree is created from it and nothing is downloaded; when nil a
    ///   blobless partial clone is made from the remote.
    /// How much history the first fetch asks for. Almost every pull request
    /// finds its merge base inside this, and the deeper fetches below are only
    /// reached for the long-lived branches and stale forks that need them.
    private static let initialFetchDepth = 32

    /// The deepest shallow fetch before falling back to full history. 32k
    /// commits covers essentially every repository still in active use.
    private static let maxShallowDepth = 32_768

    static func prepare(repo: MonitoredRepo,
                        pr: PullRequest,
                        workspace: URL,
                        depth: PRKind.Depth,
                        localPath: URL?,
                        auth: GitAuth?,
                        progress: ((String, Double) -> Void)? = nil) throws -> PreparedCheckout {
        let fm = FileManager.default
        progress?("Preparing a workspace", 0.02)
        if fm.fileExists(atPath: workspace.path) {
            cleanup(workspace, localPath: localPath)
            try fm.createDirectory(at: workspace, withIntermediateDirectories: true)
        } else {
            try fm.createDirectory(at: workspace, withIntermediateDirectories: true)
        }

        if let localPath = localPath, isGitRepo(localPath) {
            return try prepareFromLocalClone(repo: repo, pr: pr, workspace: workspace,
                                            depth: depth, localPath: localPath,
                                            auth: auth, progress: progress)
        }
        return try prepareFromRemote(repo: repo, pr: pr, workspace: workspace,
                                     depth: depth, auth: auth, progress: progress)
    }

    private static func isGitRepo(_ url: URL) -> Bool {
        FileManager.default.fileExists(atPath: url.appendingPathComponent(".git").path)
    }

    /// Worktree from an existing clone. No network beyond fetching the PR's own
    /// commits, and the user's own working tree is never touched.
    private static func prepareFromLocalClone(repo: MonitoredRepo,
                                             pr: PullRequest,
                                             workspace: URL,
                                             depth: PRKind.Depth,
                                             localPath: URL,
                                             auth: GitAuth?,
                                             progress: ((String, Double) -> Void)?) throws -> PreparedCheckout {
        let baseName = "refs/karma/base"
        let headName = "refs/karma/head"

        progress?("Fetching the base branch from your clone", 0.15)
        _ = try? run(["fetch", "--quiet", "origin", pr.baseBranch], cwd: localPath, auth: auth)
        guard (try? run(["update-ref", baseName, "refs/remotes/origin/\(pr.baseBranch)"], cwd: localPath)) != nil else {
            throw GitError(message: "Could not resolve base branch '\(pr.baseBranch)' in \(localPath.lastPathComponent). Check the branch exists locally or fetch it first.")
        }

        progress?("Fetching the pull request", 0.4)
        let headSpec = headRefSpec(provider: repo.provider, number: pr.number)
        if let headSpec = headSpec {
            _ = try? run(["fetch", "--quiet", "origin", "\(headSpec):\(headName)"], cwd: localPath, auth: auth)
        }
        // Fall back to the branch name, which is the only option for Bitbucket
        // and also the fallback when a fork's PR ref is unavailable.
        if !refExists(headName, cwd: localPath) {
            do {
                _ = try run(["fetch", "--quiet", "origin", "\(pr.headBranch):\(headName)"], cwd: localPath, auth: auth)
            } catch {
                throw GitError(message: "Could not fetch the pull request head into \(localPath.lastPathComponent). If this came from a fork, fetch it into your clone first, then try again.")
            }
        }

        // Diff before checkout so a changed-files-only review can prune the
        // tree before any blob is written to disk.
        progress?("Listing the changed files", 0.7)
        let changed = try changedFiles(baseRef: baseName, headRef: headName, cwd: localPath, auth: auth)

        progress?("Checking out the changed files", 0.85)
        try run(["worktree", "add", "--quiet", "--detach", workspace.path, headName], cwd: localPath, auth: auth)
        if depth == .changedOnly {
            try applySparseCheckout(patterns: changed.map(\.path), workspace: workspace)
        }
        progress?("Ready", 1.0)
        return PreparedCheckout(workspace: workspace, changedFiles: changed,
                                baseRef: baseName, headRef: headName, sourceClone: localPath)
    }

    /// Fresh clone from the remote, using a blobless partial clone so only the
    /// blobs for files that are actually checked out are downloaded.
    private static func prepareFromRemote(repo: MonitoredRepo,
                                          pr: PullRequest,
                                          workspace: URL,
                                          depth: PRKind.Depth,
                                          auth: GitAuth?,
                                          progress: ((String, Double) -> Void)?) throws -> PreparedCheckout {
        let remote = "https://\(hostFromBaseURL(repo.baseURL))/\(repo.repoSlug).git"
        let baseName = "refs/karma/base"
        let headName = "refs/karma/head"

        try run(["init", "--quiet"], cwd: workspace)
        try run(["remote", "add", "origin", remote], cwd: workspace)
        // Blobs are then fetched on demand; trees and commits come over cheaply.
        try run(["config", "remote.origin.promisor", "true"], cwd: workspace)
        try run(["config", "remote.origin.partialclonefilter", "blob:none"], cwd: workspace)
        // Local identity so a checkout never trips a global "no committer"
        // config, and no signing or hooks from the user's setup are consulted.
        _ = try? run(["config", "user.email", "karma-pro@localhost"], cwd: workspace)
        _ = try? run(["config", "user.name", "Karma Pro"], cwd: workspace)
        _ = try? run(["config", "commit.gpgsign", "false"], cwd: workspace)

        // Shallow, but not depth 1. A depth-1 fetch leaves base and head with
        // no common ancestor and the three-dot diff fails with "no merge base",
        // while a full-history fetch of a large repository is slow enough to
        // look like a hang. So the history is deepened on demand: start at a
        // depth almost every pull request resolves within, and only reach for
        // more when the merge base is genuinely further back.
        //
        // The partial clone means this stays cheap throughout, because only
        // blobs are skipped -- commits and trees, which is all a merge-base
        // search reads, arrive in every fetch.
        let fetch = ["fetch", "--quiet", "--filter=blob:none", "--no-tags"]
        let headSpec = headRefSpec(provider: repo.provider, number: pr.number) ?? pr.headBranch

        progress?("Connecting to \(hostFromBaseURL(repo.baseURL))", 0.1)
        try run(fetch + ["--depth=\(initialFetchDepth)", "origin", pr.baseBranch], cwd: workspace, auth: auth)
        try run(["update-ref", baseName, "FETCH_HEAD"], cwd: workspace)

        progress?("Downloading the pull request changes", 0.2)
        try run(fetch + ["--depth=\(initialFetchDepth)", "origin", headSpec], cwd: workspace, auth: auth)
        try run(["update-ref", headName, "FETCH_HEAD"], cwd: workspace)

        try fetchCommonHistory(baseSpec: pr.baseBranch, headSpec: headSpec,
                               baseName: baseName, headName: headName,
                               fetch: fetch, workspace: workspace, auth: auth,
                               progress: progress)

        progress?("Listing the changed files", 0.85)
        let changed = try changedFiles(baseRef: baseName, headRef: headName, cwd: workspace, auth: auth)

        if depth == .changedOnly {
            progress?("Pruning to the changed files", 0.9)
            try applySparseCheckout(patterns: changed.map(\.path), workspace: workspace)
        }
        progress?("Checking out the changed files", 0.95)
        try run(["checkout", "--quiet", "--force", headName], cwd: workspace, auth: auth)
        // Re-checkout the tree now that sparse patterns are active so only the
        // wanted blobs are materialised.
        _ = try? run(["read-tree", "-mu", "HEAD"], cwd: workspace, auth: auth)

        progress?("Ready", 1.0)
        return PreparedCheckout(workspace: workspace, changedFiles: changed,
                                baseRef: baseName, headRef: headName, sourceClone: nil)
    }

    /// Deepens both refs until git can find a merge base for them.
    ///
    /// Each step is incremental, so the cost is only paid when the previous,
    /// shallower fetch came up short -- the overwhelmingly common case never
    /// leaves the first small fetch.
    private static func fetchCommonHistory(baseSpec: String,
                                           headSpec: String,
                                           baseName: String,
                                           headName: String,
                                           fetch: [String],
                                           workspace: URL,
                                           auth: GitAuth?,
                                           progress: ((String, Double) -> Void)?) throws {
        guard !hasMergeBase(baseName, headName, cwd: workspace, auth: auth) else { return }

        var step = initialFetchDepth
        var fraction = 0.4
        while step < maxShallowDepth {
            step = min(step * 4, maxShallowDepth)
            fraction = min(fraction + 0.1, 0.8)
            progress?("Looking for the common history (\(step) commits back)",
                      fraction)
            try run(fetch + ["--deepen=\(step)", "origin", baseSpec], cwd: workspace, auth: auth)
            try run(["update-ref", baseName, "FETCH_HEAD"], cwd: workspace)
            try run(fetch + ["--deepen=\(step)", "origin", headSpec], cwd: workspace, auth: auth)
            try run(["update-ref", headName, "FETCH_HEAD"], cwd: workspace)
            if hasMergeBase(baseName, headName, cwd: workspace, auth: auth) { return }
        }

        // Reached only for a base branch that is years of commits ahead of the
        // pull request. Correctness wins over the time it takes.
        progress?("Downloading the full commit history", 0.82)
        try run(fetch + ["--unshallow", "origin", baseSpec], cwd: workspace, auth: auth)
        try run(["update-ref", baseName, "FETCH_HEAD"], cwd: workspace)
        try run(fetch + ["--unshallow", "origin", headSpec], cwd: workspace, auth: auth)
        try run(["update-ref", headName, "FETCH_HEAD"], cwd: workspace)
    }

    /// Whether the two refs share any history. `git merge-base` exits non-zero
    /// when they do not, which is the condition a depth-limited fetch creates.
    private static func hasMergeBase(_ base: String, _ head: String, cwd: URL, auth: GitAuth? = nil) -> Bool {
        (try? run(["merge-base", base, head], cwd: cwd, auth: auth)) != nil
    }

    private static func refExists(_ ref: String, cwd: URL) -> Bool {
        (try? run(["rev-parse", "--verify", "--quiet", ref], cwd: cwd)) != nil
    }

    /// Keeps exactly the given repository-relative paths and prunes the rest.
    ///
    /// The pattern file is written directly rather than shelling to
    /// `git sparse-checkout set`, which is absent from older git versions that
    /// macOS still ships.
    private static func applySparseCheckout(patterns: [String], workspace: URL) throws {
        let infoDir = workspace.appendingPathComponent(".git/info", isDirectory: true)
        try FileManager.default.createDirectory(at: infoDir, withIntermediateDirectories: true)
        let wanted = Set(patterns.filter { !$0.isEmpty })
        let contents = wanted.isEmpty ? "\n" : wanted.sorted().joined(separator: "\n") + "\n"
        try contents.write(to: infoDir.appendingPathComponent("sparse-checkout"), atomically: true, encoding: .utf8)
        try run(["config", "core.sparseCheckout", "true"], cwd: workspace)
    }

    private static func hostFromBaseURL(_ baseURL: String) -> String {
        guard let url = URL(string: baseURL), let host = url.host else { return "github.com" }
        // Bitbucket's API and its git remotes are on different hosts: cloning
        // api.bitbucket.org fails with "repository not found", which is why a
        // Bitbucket repository could never be fetched at all.
        if host == "api.bitbucket.org" { return "bitbucket.org" }
        if host == "api.github.com" { return "github.com" }
        return host
    }

    // MARK: - Diffing

    /// Name-status plus per-file hunks between base and head.
    ///
    /// The three-dot form is deliberate: it diffs the merge base against the
    /// head, so unrelated commits landing on the base branch meanwhile are not
    /// reported as if this PR had changed those lines.
    static func changedFiles(baseRef: String, headRef: String, cwd: URL, auth: GitAuth? = nil) throws -> [ChangedFile] {
        let range = "\(baseRef)...\(headRef)"
        // The diffs below look like pure local work, but in a blobless partial
        // clone the context lines they need are not on disk yet, so git fetches
        // them from the promisor remote while producing the output. That is a
        // network call in disguise and needs the same credential as the fetch
        // that set the clone up -- without it a private review fails here,
        // after the fetch has already succeeded, and looks like a missing token.
        let nameStatus = try run(["diff", "--name-status", "-M", range], cwd: cwd, auth: auth)
        let hunksByPath = try parseHunks(unified: run(["diff", "--unified=0", "-M", range], cwd: cwd, auth: auth))
        // Three lines of context so the reviewer can see the surrounding code
        // and judge a change in context, rather than a bare list of +/- lines.
        let patchesByPath = try parsePatches(unified: run(["diff", "--unified=3", "-M", range], cwd: cwd, auth: auth))

        var results: [ChangedFile] = []
        for row in nameStatus.split(separator: "\n") {
            let fields = row.split(separator: "\t", omittingEmptySubsequences: false).map(String.init)
            guard let statusField = fields.first, fields.count >= 2 else { continue }
            let statusLetter = statusField.prefix(1)
            // Rename rows carry the old path in the second field.
            if statusLetter == "R", fields.count >= 3 {
                let oldPath = fields[1]
                let newPath = fields[2]
                results.append(ChangedFile(path: newPath, oldPath: oldPath, kind: .renamed,
                                           hunks: hunksByPath[newPath] ?? [],
                                           patch: patchesByPath[newPath] ?? ""))
                continue
            }
            let path = fields[1]
            let kind: ChangedFile.ChangeKind
            switch statusLetter {
            case "A": kind = .added
            case "M": kind = .modified
            case "D": kind = .deleted
            default: kind = .modified
            }
            results.append(ChangedFile(path: path, oldPath: nil, kind: kind,
                                       hunks: hunksByPath[path] ?? [],
                                       patch: patchesByPath[path] ?? ""))
        }
        return results
    }

    /// Walks a unified diff with zero context, turning each `@@` header plus the
    /// changed lines that follow it into an exact head-side line range.
    /// Splits a multi-file unified diff into the patch body belonging to each
    /// path, with the `---`/`+++` file headers removed.
    private static func parsePatches(unified: String) throws -> [String: String] {
        var patches: [String: String] = [:]
        var currentPath: String?
        var body: [String] = []

        func flush() {
            guard let path = currentPath else { return }
            let text = body.joined(separator: "\n").trimmingCharacters(in: .whitespacesAndNewlines)
            if !text.isEmpty { patches[path] = text }
        }

        for line in unified.split(separator: "\n", omittingEmptySubsequences: false) {
            let text = String(line)
            if text.hasPrefix("diff --git") || text.hasPrefix("index ")
                || text.hasPrefix("new file mode") || text.hasPrefix("deleted file mode")
                || text.hasPrefix("similarity index") || text.hasPrefix("rename ")
                || text.hasPrefix("old mode") || text.hasPrefix("new mode") {
                continue
            }
            if text.hasPrefix("--- ") {
                flush()
                body = []
                let target = String(text.dropFirst(4))
                currentPath = target == "/dev/null" ? nil : String(target.dropFirst(2))
                continue
            }
            if text.hasPrefix("+++ ") {
                let target = String(text.dropFirst(4))
                if target != "/dev/null" { currentPath = String(target.dropFirst(2)) }
                continue
            }
            if text.hasPrefix("\\ No newline") { continue }
            body.append(text)
        }
        flush()
        return patches
    }

    private static func parseHunks(unified: String) throws -> [String: [DiffHunk]] {
        var hunksByPath: [String: [DiffHunk]] = [:]
        var currentPath: String?
        var pending: (head: Int, base: Int)?
        var headLine = 0
        var baseLine = 0

        func flush() {
            guard let path = currentPath, let start = pending else { return }
            hunksByPath[path, default: []].append(DiffHunk(headStart: start.head,
                                                          headEnd: max(start.head, headLine + 1),
                                                          baseStart: start.base >= 0 ? start.base : nil,
                                                          baseEnd: baseLine >= 0 ? baseLine + 1 : nil))
        }

        for line in unified.split(separator: "\n", omittingEmptySubsequences: false) {
            let text = String(line)
            if text.hasPrefix("+++ ") {
                flush()
                pending = nil
                let target = String(text.dropFirst(4))
                currentPath = target == "/dev/null" ? nil : String(target.dropFirst(2))
                continue
            }
            if text.hasPrefix("@@") {
                flush()
                headLine = parseHunkStart(text, prefix: "+")
                baseLine = parseHunkStart(text, prefix: "-")
                pending = (head: headLine, base: baseLine)
                continue
            }
            if text.hasPrefix("+") && !text.hasPrefix("+++") {
                headLine += 1
            } else if text.hasPrefix("-") && !text.hasPrefix("---") {
                baseLine += 1
            }
        }
        flush()
        return hunksByPath
    }

    /// Extracts a line number from a unified hunk header.
    /// `@@ -12,7 +14,9 @@ context` yields 14 for "+" and 12 for "-".
    private static func parseHunkStart(_ header: String, prefix: String) -> Int {
        guard let range = header.range(of: prefix) else { return -1 }
        let digits = header[range.upperBound...].prefix { $0.isNumber }
        return Int(digits) ?? -1
    }

    /// The unified diff text for one already-checked-out file.
    static func diffForFile(path: String, checkout: PreparedCheckout) -> String {
        (try? run(["diff", "--unified=3", "-M",
                   "\(checkout.baseRef)...\(checkout.headRef)", "--", path],
                  cwd: checkout.workspace)) ?? ""
    }

    /// Removes a temporary review workspace.
    ///
    /// A worktree created from a clone must be pruned through git, otherwise the
    /// clone is left holding a dangling worktree registration.
    static func cleanup(_ workspace: URL, localPath: URL?) {
        if let localPath = localPath, isGitRepo(localPath) {
            _ = try? run(["worktree", "remove", "--force", workspace.path], cwd: localPath)
            _ = try? run(["worktree", "prune"], cwd: localPath)
        }
        try? FileManager.default.removeItem(at: workspace)
    }
}
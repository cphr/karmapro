// by cipher.org.uk
import Foundation

/// Turns a pull request into something the existing Karma Pro UI can review.
///
/// The session owns the temporary checkout, runs the scans needed to tell new
/// problems from inherited ones, and classifies the result. It deliberately
/// runs the *cheap local* scanner on the base commit and the *full* scan
/// (local + AI) on the head: that is what makes diff-aware classification
/// possible without paying for two AI passes per pull request.
final class PRReviewSession {
    let context: PRReviewContext
    let checkout: PreparedCheckout

    /// Findings from the PR head, classified against the diff.
    private(set) var findings: [DiffAwareFinding] = []
    /// True once a head scan has completed, so the UI can distinguish
    /// "not scanned yet" from "scanned and clean".
    private(set) var didScan = false

    /// Cancellable token shared by both scan passes.
    private var scanCancelled = false

    init(repo: MonitoredRepo, pr: PullRequest, checkout: PreparedCheckout) {
        self.checkout = checkout
        self.context = PRReviewContext(repo: repo,
                                       pr: pr,
                                       changedFiles: checkout.changedFiles,
                                       workspace: checkout.workspace,
                                       baseFindings: [])
    }

    /// Root to hand to the normal file tree and scanner.
    var workspace: URL { checkout.workspace }

    /// Paths the PR added or modified, for the "changed files only" filter.
    var reviewablePaths: Set<String> { context.reviewablePaths }

    /// The changed files with their diffs, for the changes window.
    var changedFiles: [ChangedFile] { checkout.changedFiles }

    var title: String { context.title }

    var badgeText: String { context.badgeText }

    /// Whether a given repo-relative path is part of this PR.
    func isChanged(_ repoRelativePath: String) -> Bool {
        reviewablePaths.contains { DiffAwareClassifier.normalizedPath($0) == DiffAwareClassifier.normalizedPath(repoRelativePath) }
    }

    /// Runs both scan passes off the main thread.
    ///
    /// - Parameter wantsAI: when true the head side gets the AI pass.
    /// - Parameter wantsAIBase: when true the base side gets it too. This is a
    ///   separate consent because it is a second bill for a comparison the
    ///   local base scan can already make in most cases; a head-only AI pass
    ///   is the useful default and base-side AI is for callers who want the
    ///   inherited code examined by the same detector that judged the new code.
    func scan(wantsAI: Bool,
              wantsAIBase: Bool = false,
              progress: @escaping (String) -> Void,
              completion: @escaping (Bool) -> Void) {
        scanCancelled = false
        let changed = checkout.changedFiles


        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            guard let self = self else { return }

            // Base pass: checkout the merge base into a scratch clone so the
            // inherited-code comparison runs against real files rather than a
            // diff-only guess.
            progress("Comparing against \(self.checkout.baseRefShort)…")
            let baseFindings = self.scanBase(wantsAI: wantsAIBase, progress: progress)
            if self.scanCancelled { completion(false); return }

            progress("Scanning the pull request…")
            let headFindings = self.scanHead(wantsAI: wantsAI, progress: progress)
            if self.scanCancelled { completion(false); return }

            // Base findings are re-pointed at the head workspace before they are
            // compared. The two scans read different directories, so the same
            // finding carries two different absolute paths and never matches;
            // and the base worktree is deleted as soon as the pass ends, so a
            // row left pointing into it cannot be opened and reports "Could not
            // read file:". Rebasing to the head root fixes both, and the file
            // still exists there because a fixed finding is by definition in a
            // file the PR modified.
            let rebasedBase = self.rebase(baseFindings, onto: self.checkout.workspace)

            var classified = DiffAwareClassifier.classify(headFindings: headFindings,
                                                          baseFindings: rebasedBase,
                                                          changedFiles: changed,
                                                          root: self.checkout.workspace)
            classified = DiffAwareClassifier.downgradeShiftedFindings(classified,
                                                                     baseFindings: rebasedBase,
                                                                     root: self.checkout.workspace)

            DispatchQueue.main.async {
                self.findings = classified
                self.didScan = true
                completion(true)
            }
        }
    }

    func cancelScan() {
        scanCancelled = true
    }

    // MARK: - Scanning

    /// Scans the PR head: local detectors, then the AI pass if requested.
    private func scanHead(wantsAI: Bool, progress: (String) -> Void) -> [ScanFinding] {
        let headRoot = checkout.workspace
        let heuristic = VulnerabilityScanner.scan(projectRoot: headRoot,
                                                  isCancelled: { self.scanCancelled })
        guard wantsAI, !scanCancelled else { return heuristic }
        return heuristic + aiPass(projectRoot: headRoot,
                                  existing: heuristic,
                                  label: "the pull request",
                                  progress: progress)
    }

    /// The AI pass for one side of the comparison.
    ///
    /// Blocking wait is unavoidable here: `runAI` delivers its completion on the
    /// main queue, and this runs on a background worker, so the two must not
    /// race. Cancellation is checked on every iteration so closing the review
    /// window does not leave the worker parked on the semaphore.
    private func aiPass(projectRoot: URL,
                        existing: [ScanFinding],
                        label: String,
                        progress: (String) -> Void) -> [ScanFinding] {
        progress("AI pass on \(label)…")
        let semaphore = DispatchSemaphore(value: 0)
        var aiFindings: [ScanFinding] = []
        AISecurityScanner.runAI(projectRoot: projectRoot,
                                existingFindings: existing,
                                progress: { _ in },
                                isCancelled: { self.scanCancelled },
                                completion: { result in
            aiFindings = AISecurityScanner.dedupe(result.findings, against: existing)
            semaphore.signal()
        },
                                onPhase: { _ in })
        while semaphore.wait(timeout: .now() + 0.05) == .timedOut {
            if scanCancelled { return [] }
        }
        return aiFindings
    }

    /// Re-points findings scanned in one checkout at another root.
    ///
    /// The path *relative* to the root is preserved, so a base finding about
    /// `internal/gitaly/repository.go` becomes the head checkout's copy of that
    /// same file. A file the PR deleted is left alone: there is nothing to point
    /// at, and such a finding is not reported as fixed anyway.
    private func rebase(_ findings: [ScanFinding], onto root: URL) -> [ScanFinding] {
        findings.map { finding in
            let relative = DiffAwareClassifier.repoRelativePath(finding.fileURL, root: baseRoot)
            guard !relative.isEmpty, !relative.hasPrefix("/") else { return finding }
            var moved = finding
            moved.fileURL = root.appendingPathComponent(relative)
            return moved
        }
    }

    /// The scratch worktree the base pass reads, needed to interpret the
    /// absolute URLs that pass produces.
    private var baseRoot: URL {
        checkout.workspace
            .deletingLastPathComponent()
            .appendingPathComponent("base-\(checkout.headRef.hashValue)", isDirectory: true)
    }

    /// Scans the base commit.
    ///
    /// A second worktree of the merge base is created inside the session's own
    /// scratch directory so the base code is scanned with the same detectors as
    /// the head. When the base cannot be checked out the pass is skipped and
    /// classification falls back to the hunk test alone, which is weaker but
    /// still safe: it can only produce `contextual` instead of a confident
    /// `pre-existing`.
    ///
    /// With `wantsAI` the base is also handed to the AI scanner, so inherited
    /// code is judged by the same detector that judged the new code. That costs
    /// a second AI pass.
    private func scanBase(wantsAI: Bool, progress: (String) -> Void) -> [ScanFinding] {
        // The same value `baseRoot` reports, so the rebase that runs afterwards
        // cannot drift from the directory that was actually scanned.
        let scratch = baseRoot

        // A worktree can only be added from a git repo: the user's own clone
        // when there is one, otherwise the workspace this session cloned.
        let anchor = checkout.sourceClone ?? checkout.workspace
        let didCheckout = (try? GitRunner.run(["worktree", "add", "--quiet", "--detach", scratch.path,
                                               checkout.baseRef], cwd: anchor)) != nil
        guard didCheckout else { return [] }
        defer { GitRunner.cleanup(scratch, localPath: checkout.sourceClone) }

        // Only base-side versions of files the PR touches can tell us whether
        // a finding is inherited; scanning the whole base tree would cost a
        // full project scan for almost no extra signal.
        let patterns = checkout.changedFiles.filter(\.isReviewable).map(\.path)
        if !patterns.isEmpty {
            let infoDir = scratch.appendingPathComponent(".git/info", isDirectory: true)
            if (try? FileManager.default.createDirectory(at: infoDir, withIntermediateDirectories: true)) != nil {
                try? (patterns.sorted().joined(separator: "\n") + "\n")
                    .write(to: infoDir.appendingPathComponent("sparse-checkout"), atomically: true, encoding: .utf8)
                _ = try? GitRunner.run(["config", "core.sparseCheckout", "true"], cwd: scratch)
            }
        }

        let heuristic = VulnerabilityScanner.scan(projectRoot: scratch,
                                                   isCancelled: { self.scanCancelled })
        guard wantsAI, !scanCancelled else { return heuristic }
        return heuristic + aiPass(projectRoot: scratch,
                                  existing: heuristic,
                                  label: "the base commit",
                                  progress: progress)
    }

    /// Removes the checkout. Called when the user closes the review.
    func tearDown() {
        cancelScan()
        GitRunner.cleanup(checkout.workspace, localPath: checkout.sourceClone)
    }
}

extension PreparedCheckout {
    /// User-readable short form of the base ref for progress text.
    var baseRefShort: String {
        baseRef.split(separator: "/").last.map(String.init) ?? "base"
    }
}
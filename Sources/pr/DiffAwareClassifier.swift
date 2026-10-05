// by cipher.org.uk
import Foundation

/// Decides whether a finding belongs to the pull request.
///
/// The classifier is intentionally conservative and asymmetric:
///
/// - A finding inside a hunk the PR added is *introduced*. This is the only
///   verdict that changes a review outcome, and it is only claimed when the
///   location is unambiguous.
/// - A finding that also exists at the same location in the base scan is
///   *pre-existing*, no matter what the diff says. An inherited problem the PR
///   happens to touch is still not the PR's fault, and calling it new would be
///   the most damaging mistake this feature could make.
/// - A base finding whose location no longer exists on the head side, or whose
///   sink lines are now gone, is *fixed*.
/// - Anything the PR touched but that matches neither cleanly is
///   *contextual*, so a user glances at it instead of trusting a guess.
///
/// Findings from files the PR never touched are pre-existing by definition,
/// which is why cross-file taint findings are not attributed to a PR.
enum DiffAwareClassifier {
    /// - Parameters:
    ///   - headFindings: findings from scanning the PR head.
    ///   - baseFindings: findings from scanning the merge base, same detectors.
    ///   - changedFiles: the PR's diff, used to decide whether a location was
    ///     touched and how.
    ///   - root: the repository root both sides are made relative to. Required,
    ///     because head and base findings carry absolute paths from two
    ///     different directories and `changedFiles` carries git-relative ones.
    static func classify(headFindings: [ScanFinding],
                         baseFindings: [ScanFinding],
                         changedFiles: [ChangedFile],
                         root: URL) -> [DiffAwareFinding] {
        // Built by hand rather than with Dictionary(grouping:) because a
        // repository cannot list the same path twice in one diff, and the
        // single-value lookup below is what the verdicts are keyed on.
        var changedByPath: [String: ChangedFile] = [:]
        for file in changedFiles { changedByPath[normalizedPath(file.path)] = file }
        let baseByLocation = baseKeyedByLocation(baseFindings, root: root)

        var headKeysSeen = Set<String>()
        // Keyed by symbol rather than line, so a finding that merely moved when
        // the PR edited above it is still recognised as surviving. Without this
        // the exact-line fixed rule below reports it as both pre-existing (from
        // the head pass) and fixed (from the base pass).
        var headSurvivors = Set<String>()
        var results: [DiffAwareFinding] = []
        results.reserveCapacity(headFindings.count)

        for finding in headFindings {
            let path = repoRelativePath(finding.fileURL, root: root)
            let key = locationKey(path: path, line: finding.line, function: finding.function)
            headKeysSeen.insert(key)
            headSurvivors.insert(survivorKey(path: path, function: finding.function,
                                              category: finding.category))

            guard let changed = changedByPath[path] else {
                // Untouched file: inherited by definition. This is the branch
                // that keeps cross-file taint from being blamed on a PR.
                results.append(DiffAwareFinding(finding: finding, awareness: .preExisting))
                continue
            }

            // A brand-new file cannot have pre-existing problems in it.
            if changed.kind == .added {
                results.append(DiffAwareFinding(finding: finding, awareness: .introduced))
                continue
            }

            // The exact same finding already present at base: inherited even
            // though the PR touched the file.
            if baseByLocation[key] != nil {
                results.append(DiffAwareFinding(finding: finding, awareness: .preExisting))
                continue
            }

            if changed.hunks.contains(where: { $0.containsHeadLine(finding.line) }) {
                results.append(DiffAwareFinding(finding: finding, awareness: .introduced))
                continue
            }

            if changed.kind == .renamed, let oldPath = changed.oldPath {
                // A rename keeps the blame of the original file: a problem that
                // existed in the old file is not new code.
                if baseByLocation[locationKey(path: normalizedPath(oldPath), line: finding.line, function: finding.function)] != nil {
                    results.append(DiffAwareFinding(finding: finding, awareness: .preExisting))
                    continue
                }
            }

            results.append(DiffAwareFinding(finding: finding, awareness: .contextual))
        }

        // Anything present at base and gone from the head was fixed by the PR.
        // Only claim this when the base file is one the PR actually modified,
        // so a finding in an untouched file that simply stopped being reported
        // is not reported as a fix.
        for finding in baseFindings {
            let path = repoRelativePath(finding.fileURL, root: root)
            let key = locationKey(path: path, line: finding.line, function: finding.function)
            guard !headKeysSeen.contains(key) else { continue }
            guard let changed = changedByPath[path] else { continue }
            guard changed.kind != .added else { continue }
            // The line moved but the same problem is still reported at head: the
            // PR shifted the code, it did not fix it. Reinstating an identical
            // finding elsewhere in the file is exactly what this looks like, and
            // the exact-line check above cannot tell the two apart. Matching on
            // symbol and category keeps a genuine fix claimable -- removing an
            // NPD while a leak survives in the same function still counts --
            // while giving up the claim whenever the finding is merely displaced.
            let survives = headSurvivors.contains(survivorKey(path: path,
                                                              function: finding.function,
                                                              category: finding.category))
            guard !survives else { continue }
            results.append(DiffAwareFinding(finding: finding, awareness: .fixed))
        }

        return results
    }

    /// Headlines for the report, preferring introduced findings.
    static func introduced(_ findings: [DiffAwareFinding]) -> [DiffAwareFinding] {
        findings.filter { $0.awareness == .introduced }
    }

    static func preExisting(_ findings: [DiffAwareFinding]) -> [DiffAwareFinding] {
        findings.filter { $0.awareness == .preExisting }
    }

    static func fixed(_ findings: [DiffAwareFinding]) -> [DiffAwareFinding] {
        findings.filter { $0.awareness == .fixed }
    }

    static func contextual(_ findings: [DiffAwareFinding]) -> [DiffAwareFinding] {
        findings.filter { $0.awareness == .contextual }
    }

    /// Case- and separator-insensitive repo-relative path.
    ///
    /// Scanners report absolute URLs whose separator style can differ from
    /// git's forward-slash paths, and on a case-insensitive volume the casing
    /// can differ too, so both are normalised before comparing.
    static func normalizedPath(_ path: String) -> String {
        path.replacingOccurrences(of: "\\", with: "/")
            .trimmingCharacters(in: CharacterSet(charactersIn: "/"))
            .lowercased()
    }

    /// The path of `url` relative to the repository root, in the same form as
    /// `normalizedPath(_: String)`.
    ///
    /// This is the single place the two path spaces are bridged, and it is not
    /// optional. A finding carries the absolute URL the scanner walked
    /// (`<checkout>/internal/foo.go`) while a `ChangedFile` carries git's
    /// repo-relative path (`internal/foo.go`). Comparing one against the other
    /// directly never matches, and when that happens `classify` falls through
    /// to its first branch and reports every finding as pre-existing. The same
    /// applies to head against base, because the two are scanned in *different*
    /// directories: the head workspace and a scratch worktree at the merge base,
    /// so even the identical finding has two different absolute paths.
    ///
    /// A URL outside `root` keeps its own normalized form, which cannot match a
    /// git path and is therefore safely treated as untouched.
    static func repoRelativePath(_ url: URL, root: URL) -> String {
        let absolute = url.standardizedFileURL.resolvingSymlinksInPath().path
        let base = root.standardizedFileURL.resolvingSymlinksInPath().path
        if absolute == base { return "" }
        let prefix = base.hasSuffix("/") ? base : base + "/"
        if absolute.hasPrefix(prefix) {
            return normalizedPath(String(absolute.dropFirst(prefix.count)))
        }
        return normalizedPath(absolute)
    }

    /// Matching key for a finding: exact path plus line first, then a looser
    /// path-plus-symbol key so a finding that merely shifted lines when the PR
    /// edited above it is still recognised as pre-existing rather than new.
    private static func locationKey(path: String, line: Int, function: String) -> String {
        "\(path.lowercased())#L\(line)"
    }

    /// Looser key, used to rescue findings that shifted because the PR inserted
    /// lines above them.
    static func symbolKey(path: String, function: String) -> String {
        "\(path.lowercased())#\(function.lowercased())"
    }

    /// Key for deciding whether a base finding still exists at head after a line
    /// shift: symbol plus vulnerability type, so the same category of problem in
    /// the same function is matched while a different problem there is not.
    private static func survivorKey(path: String, function: String, category: String) -> String {
        "\(path.lowercased())#\(function.lowercased())#\(category.lowercased())"
    }

    private static func baseKeyedByLocation(_ findings: [ScanFinding],
                                            root: URL) -> [String: ScanFinding] {
        var map: [String: ScanFinding] = [:]
        for finding in findings {
            map[locationKey(path: repoRelativePath(finding.fileURL, root: root),
                            line: finding.line,
                            function: finding.function)] = finding
        }
        return map
    }

    /// Re-checks head findings against base ones using the looser symbol key,
    /// to catch a finding whose line number moved because the PR inserted code
    /// above it. Anything matched this way is pre-existing, not new.
    static func downgradeShiftedFindings(_ classified: [DiffAwareFinding],
                                         baseFindings: [ScanFinding],
                                         root: URL) -> [DiffAwareFinding] {
        var baseSymbols: [String: [ScanFinding]] = [:]
        for finding in baseFindings {
            let key = symbolKey(path: repoRelativePath(finding.fileURL, root: root),
                                function: finding.function)
            baseSymbols[key, default: []].append(finding)
        }

        return classified.map { item in
            guard item.awareness == .introduced else { return item }
            let key = symbolKey(path: repoRelativePath(item.finding.fileURL, root: root),
                                function: item.finding.function)
            guard let candidates = baseSymbols[key], !candidates.isEmpty else { return item }
            // Same symbol in the base scan means the pattern was already there.
            // Claiming "new" here would blame the PR for pre-existing code, so
            // it is downgraded to contextual for a user to confirm.
            return DiffAwareFinding(finding: item.finding, awareness: .contextual)
        }
    }
}
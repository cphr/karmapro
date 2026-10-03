// by cipher.org.uk
import Foundation

/// Host normalisation shared by the account dialog, forge detection and the
/// credential store's account-to-repository pairing.

enum PRHost {

    static func bare(_ raw: String) -> String {
        var text = raw.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        while let range = text.range(of: "://") {
            text.removeSubrange(text.startIndex..<range.upperBound)
        }
        if let stop = text.firstIndex(where: { $0 == "/" || $0 == "?" || $0 == "#" }) {
            text = String(text[text.startIndex..<stop])
        }
        while text.hasSuffix(":") { text.removeLast() }
        return text
    }

    /// The forge host an API root belongs to, or nil when there is none.
    ///
    /// Both a saved account and a saved repository reduce their API root to the
    /// same host here, and matching pairs them by that value. They used to carry
    /// a copy of this logic each, which is exactly the arrangement that let the
    /// two drift apart: changing one left Bitbucket — whose API root ends in
    /// `/2.0` — reducing to `api.bitbucket.org/2.0` on one side and
    /// `api.bitbucket.org` on the other, so a Bitbucket account matched no
    /// Bitbucket repository at all.
    static func apiHost(_ raw: String) -> String? {
        let value = bare(raw)
        guard !value.isEmpty else { return nil }
        if value.hasPrefix("api.github.com") { return "github.com" }
        return value
    }

    /// The forge that owns a host, when the host names one we recognise.
    ///
    /// Self-hosted forges run on arbitrary hostnames that no table can predict,
    /// so only the four public SaaS hosts are claimed here and everything else
    /// keeps whatever the user chose. Being wrong here is what makes an account
    /// match no repository, so the mapping is kept next to `bare` rather than
    /// being rebuilt per call site.
    static func provider(ofHost raw: String) -> String? {
        switch bare(raw) {
        case "github.com": return "github"
        case "gitlab.com": return "gitlab"
        case "bitbucket.org": return "bitbucket"
        case "codeberg.org": return "gitea"
        default: return nil
        }
    }
}

/// Value types shared by the whole pull-request review feature.
enum PRKind {
    /// Whether a repository is public (no credentials needed) or private
    /// (the user must supply an API token). Public is the default so watching
    /// a public repo requires zero setup and nothing is ever sent anywhere
    /// that the user did not explicitly opt into.
    enum Visibility: String, Codable {
        case publicRepo
        case privateRepo

        var needsCredentials: Bool { self == .privateRepo }
    }

    /// How much of the project to materialise on disk for a review.
    ///
    /// `changedOnly` checks out only the files the PR touches — the fastest
    /// and cheapest option (AI scans bill far fewer tokens) but it cannot
    /// follow taint across files it never fetched. `fullProject` downloads the
    /// complete tree. Both are honest trade-offs the user picks knowingly.
    enum Depth: String, Codable, CaseIterable {
        case changedOnly
        case fullProject

        var title: String {
            switch self {
            case .changedOnly: return "Changed files only"
            case .fullProject: return "Full project"
            }
        }

        var explanation: String {
            switch self {
            case .changedOnly:
                return "Fetches only the files this PR adds or modifies. Fastest and cheapest to scan, but cross-file analysis cannot follow taint into files it never fetched."
            case .fullProject:
                return "Fetches the whole project at the PR's head commit. Slower and larger, but cross-file taint analysis and reachability work normally."
            }
        }
    }

    /// How the user wants to be told about a new pull request.
    enum NotifyStyle: String, Codable, CaseIterable {
        case off
        case banner
        case bannerAndSound

        var title: String {
            switch self {
            case .off: return "Off"
            case .banner: return "Notification"
            case .bannerAndSound: return "Notification + Sound"
            }
        }
    }
}

/// A pull request (GitHub) / merge request (GitLab) as reported by a forge.
struct PullRequest {
    /// Provider-assigned id. Unique per repository, which is what we key on so
    /// two PRs sharing a number on different remotes never collide.
    let id: Int
    let number: Int
    let title: String
    let author: String
    let headBranch: String
    let baseBranch: String
    /// Repository slug as the forge knows it, e.g. "owner/name" or
    /// "group/project". Needed to build API URLs and review links.
    let repoSlug: String
    let webURL: String
    /// Short commit SHA of the PR head, shown in the report for traceability.
    let headSHA: String
    let updatedAt: Date?

    /// Stable identity across polls: the forge id plus the head SHA, so a PR
    /// that is force-pushed to look identical is still recognised as an update.
    func fingerprint(remoteKey: String) -> String {
        "\(remoteKey)#\(id)@\(headSHA.prefix(12))"
    }
}

/// A repository the user has asked Karma Pro to watch.
struct MonitoredRepo: Codable {
    var id: String { "\(provider)|\(baseURL)|\(repoSlug)" }

    let provider: String
    /// API root, e.g. "https://api.github.com" or a self-hosted GitLab URL.
    let baseURL: String
    /// Web root used to build user-facing review links.
    let webURL: String
    let repoSlug: String
    /// Local checkout path, when the repo already exists on this Mac. Nil means
    /// the app will create a temporary workspace.
    var localPath: String?
    var visibility: PRKind.Visibility
    var depth: PRKind.Depth
    /// Base branches the user wants alerts for. Empty means "every branch",
    /// which is the friendlier default for someone who has just added one repo.
    var baseBranches: [String]
    var enabled: Bool
    /// The account the user chose for this repository, as an account identity.
    var accountIdentity: String?

    /// The provider host this repository lives on, used to pair it with a saved
    /// account. Deriving it the same way an account derives its own host is what
    /// lets a private self-hosted repository find its token at all.
    var normalizedAPIHost: String? { PRHost.apiHost(baseURL) }

    init(provider: String,
         baseURL: String,
         webURL: String,
         repoSlug: String,
         localPath: String? = nil,
         visibility: PRKind.Visibility = .publicRepo,
         depth: PRKind.Depth = .changedOnly,
         baseBranches: [String] = [],
         enabled: Bool = true,
         accountIdentity: String? = nil) {
        self.provider = provider
        self.baseURL = baseURL
        self.webURL = webURL
        self.repoSlug = repoSlug
        self.localPath = localPath
        self.visibility = visibility
        self.depth = depth
        self.baseBranches = baseBranches
        self.enabled = enabled
        self.accountIdentity = accountIdentity
    }

    /// True when this PR targets a branch the user asked to hear about.
    func wantsAlert(for pr: PullRequest) -> Bool {
        guard enabled else { return false }
        guard !baseBranches.isEmpty else { return true }
        return baseBranches.contains { $0.compare(pr.baseBranch, options: .caseInsensitive) == .orderedSame }
    }
}

/// What happened to one file between the PR's base and its head.
struct ChangedFile {
    enum ChangeKind: String {
        case added = "A"
        case modified = "M"
        case deleted = "D"
        case renamed = "R"

        var badge: String {
            switch self {
            case .added: return "A"
            case .modified: return "M"
            case .deleted: return "D"
            case .renamed: return "R"
            }
        }
    }

    /// Path relative to the repository root, as git reports it (forward slashes).
    let path: String
    let oldPath: String?
    let kind: ChangeKind
    /// Hunks changed in this file, used to decide whether a finding sits inside
    /// the region the PR actually touched.
    let hunks: [DiffHunk]
    /// The unified diff for this file, header stripped. The hunk ranges drive
    /// the classifier; this is what the user reads, because a change kind and
    /// a line range say nothing about whether the new line is a shell command
    /// or an interpolated SQL string.
    let patch: String

    /// Lines added and removed, which is the part a security review turns on.
    var addedLines: [String] {
        patch.split(separator: "\n", omittingEmptySubsequences: false)
            .filter { $0.hasPrefix("+") && !$0.hasPrefix("+++") }
            .map { String($0.dropFirst()) }
    }

    var removedLines: [String] {
        patch.split(separator: "\n", omittingEmptySubsequences: false)
            .filter { $0.hasPrefix("-") && !$0.hasPrefix("---") }
            .map { String($0.dropFirst()) }
    }

    /// Should this file appear in the "PR changes only" tree? Deletions have
    /// no content to review, so they are excluded.
    var isReviewable: Bool { kind != .deleted }
}

/// One contiguous region of changed lines within a file.
struct DiffHunk {
    /// First changed line on the head side (1-based).
    let headStart: Int
    /// One past the last changed line on the head side.
    let headEnd: Int
    /// First changed line on the base side, nil when the file is brand new.
    let baseStart: Int?
    let baseEnd: Int?

    func containsHeadLine(_ line: Int) -> Bool {
        line >= headStart && line < headEnd
    }
}

/// Everything the UI needs to present one pull request as a folder to review.
struct PRReviewContext {
    let repo: MonitoredRepo
    let pr: PullRequest
    /// Files added/modified by the PR, which is what the filtered tree shows.
    let changedFiles: [ChangedFile]
    /// Root of the checkout the app materialised for this review.
    let workspace: URL
    /// Base-side findings, when a base scan was run. Needed to tell an
    /// introduced problem apart from one the PR merely inherited.
    let baseFindings: [ScanFinding]

    /// Repository-relative paths the PR touched, for filtering the tree.
    var reviewablePaths: Set<String> {
        Set(changedFiles.filter(\.isReviewable).map(\.path))
    }

    var title: String {
        "PR #\(pr.number) \(pr.title)"
    }

    /// Short line shown on the main window badge so the user always knows why
    /// they are looking at a filtered tree.
    var badgeText: String {
        "Reviewing PR #\(pr.number) · \(repo.repoSlug) · \(changedFiles.filter(\.isReviewable).count) files"
    }
}

/// Whether a finding is the pull request's fault. Reported in the scan window's
/// "In PR?" column and used to section the Markdown report.
enum DiffAwareness {
    case introduced
    case preExisting
    case fixed
    /// Touched by the PR but the finding is neither clearly introduced nor
    /// clearly inherited — surfaced for a user glance, never used to block.
    case contextual

    var label: String {
        switch self {
        case .introduced: return "New"
        case .preExisting: return "Pre-existing"
        case .fixed: return "Fixed"
        case .contextual: return "Touched"
        }
    }
}

/// A scan finding paired with its pull-request classification.
struct DiffAwareFinding {
    let finding: ScanFinding
    let awareness: DiffAwareness
}
// by cipher.org.uk
//
// The shared forge every adapter is built on: the error type they
// return, the `ForgeAdapter` protocol they satisfy, provider detection from a
// URL, the HTTP client, the registry that maps a provider name to an adapter,
// and the list envelope decoder that copes with the two shapes forges use.
//
// The four concrete adapters (GitHub, GitLab, Bitbucket, Gitea) live in
// ForgeAdapters.swift. This file holds what they share; that one holds what
// makes them different.
import Foundation

/// Wraps a user-readable message as an `Error` so failures can travel through
/// `Result` without inventing a case for every reason a token might fail.
struct PRMessageError: LocalizedError {
    let message: String
    init(_ message: String) { self.message = message }
    var errorDescription: String? { message }
}

/// One forge integration. Every implementation is read-only: Karma Pro asks a
/// forge "what pull requests are open?" and nothing else. It never approves,
/// comments, labels or merges, so it never needs write scopes, and the token
/// the user supplies can be a read-only credential.
protocol ForgeAdapter {
    /// Stable identifier persisted with a monitored repo.
    var identifier: String { get }
    var displayName: String { get }
    /// Open pull/merge requests, newest activity first.
    func openPullRequests(for repo: MonitoredRepo) throws -> [PullRequest]
    /// Checks the credentials reach the API, returning a user-readable
    /// problem instead of throwing when they simply do not work yet.
    func testConnection(for repo: MonitoredRepo) -> Result<Void, PRMessageError>
}

/// Which forge a URL belongs to, plus the pieces needed to talk to it.
///
/// Detection is by URL rather than by "which adapter did the user pick" so
/// adding a repo is a two-field form (URL + slug) instead of a dropdown plus a
/// URL plus a slug.
enum ForgeDetector {
    struct Endpoint {
        let provider: String
        /// API root used for REST calls.
        let apiBaseURL: String
        /// Web root used to build links the user can click.
        let webURL: String
        let repoSlug: String
        let visibility: PRKind.Visibility
    }

    /// The API root for a provider on a given host.
    ///
    /// One function, used by both detection and the account dialog, so a saved
    /// account and a detected repository always agree on the string that pairs
    /// them. When these two were built separately the account for a self-hosted
    /// forge was saved as a bare host ("codeberg.org") while the repository was
    /// detected as "https://codeberg.org/api/v1", the pair never compared equal,
    /// and no private self-hosted repository could ever find its token.
    static func apiBaseURL(provider: String, host: String) -> String? {
        let clean = PRHost.bare(host)
        guard !clean.isEmpty else { return nil }
        switch provider {
        case "github":
            // github.com is the one SaaS host whose API is not on the same host.
            return clean == "github.com"
                ? "https://api.github.com"
                : "https://\(clean)/api/v3"
        case "gitlab":
            return "https://\(clean)/api/v4"
        case "bitbucket":
            // Only Bitbucket Cloud has an adapter. Bitbucket Server is a
            // different API on a different path and is deliberately not claimed.
            guard clean == "bitbucket.org" else { return nil }
            return "https://api.bitbucket.org/2.0"
        case "gitea":
            return "https://\(clean)/api/v1"
        default:
            return nil
        }
    }

    /// The provider a host belongs to, when the host names one we recognise.
    ///
    /// Self-hosted forges run on arbitrary hostnames, so only the four public
    /// SaaS hosts are claimed here; anything else keeps whatever provider the
    /// user picked in the dialog. Detection exists because typing a GitLab URL
    /// into the host field while the popup still said GitHub saved a GitHub
    /// account that could never match a GitLab repository.
    static func provider(forHost host: String) -> String? {
        PRHost.provider(ofHost: host)
    }

    /// The public host for a provider, used to prefill the account dialog.
    static func defaultHost(for provider: String) -> String {
        switch provider {
        case "github": return "github.com"
        case "gitlab": return "gitlab.com"
        case "bitbucket": return "bitbucket.org"
        default: return "codeberg.org"
        }
    }

    /// Parses `https://github.com/owner/name`, an `origin` git remote
    /// (`git@github.com:owner/name.git`), or a full API root such as
    /// `https://gitlab.example.com/group/project`.
    ///
    /// Returns nil when the host is not one Karma Pro knows how to talk to;
    /// self-hosted GitLab and GitHub-compatible forges are recognised by path
    /// shape rather than hostname so an internal instance works too.
    static func detect(from input: String, defaultVisibility: PRKind.Visibility = .publicRepo) -> Endpoint? {
        var text = input.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !text.isEmpty else { return nil }

        // Strip a trailing .git and any trailing slash.
        if text.hasSuffix(".git") { text = String(text.dropLast(4)) }
        while text.hasSuffix("/") { text = String(text.dropLast()) }

        // Normalise scp-style remotes (git@host:owner/name.git) to a URL.
        if let atIndex = text.firstIndex(of: "@"), !text.contains("://") {
            let afterAt = text[text.index(after: atIndex)...]
            if let colon = afterAt.firstIndex(of: ":") {
                let host = String(afterAt[..<colon])
                let path = String(afterAt[afterAt.index(after: colon)...])
                text = "https://\(host)/\(path)"
            }
        }
        guard let url = URL(string: text), let host = url.host?.lowercased(), let scheme = url.scheme else {
            return nil
        }
        guard scheme == "https" || scheme == "http" else { return nil }

        var components = url.path
            .split(separator: "/", omittingEmptySubsequences: true)
            .map(String.init)

        // Users paste whatever link they have open, which for a forge's merge
        // request list is the *web* URL including its UI-only tail. GitLab marks
        // the boundary with a literal /-/ segment and GitHub with a known
        // trailing resource name, and neither is part of the project path, so
        // the tail has to come off before the slug is built. Without this,
        // https://gitlab.com/gitlab-org/gitaly/-/merge_requests is treated as the
        // project "gitlab-org/gitaly/-/merge_requests" and the API answers
        // "Repository not found" for a repository that plainly exists.
        //
        // The API form is exempt because /api/v4/projects/<id>/merge_requests
        // is a real API path, handled by the branches below before this runs on
        // the host-specific shapes.
        components = trimmedToProjectPath(components, host: host)

        guard components.count >= 2 else { return nil }
        let slug = components.joined(separator: "/")

        // GitHub API moved to /api/v3 for enterprise installs; SaaS uses the
        // bare host. Detect the enterprise shape by an explicit /api/v3 path.
        if host == "github.com" {
            return Endpoint(provider: "github",
                            apiBaseURL: apiBaseURL(provider: "github", host: host)!,
                            webURL: "https://github.com/\(slug)",
                            repoSlug: slug,
                            visibility: .publicRepo)
        }
        if components.first == "api" && components.count >= 4 && components[1] == "v3" {
            let webSlug = components.dropFirst(2).joined(separator: "/")
            return Endpoint(provider: "github",
                            apiBaseURL: apiBaseURL(provider: "github", host: host)!,
                            webURL: "https://\(host)/\(webSlug)",
                            repoSlug: webSlug,
                            visibility: .privateRepo)
        }

        // GitLab.com, plus self-hosted GitLab. The self-hosted form is the
        // common enterprise case, so it is recognised by asking whether the
        // API v4 path is already present in the user's input.
        if host == "gitlab.com" || components.first == "api" && components.count >= 3 && components[1] == "v4" {
            // Tests the *leading* api/v4 prefix rather than searching the whole
            // path for the word "api", which would mangle a real project whose
            // group is literally called "api".
            //
            // An API path is /api/v4/projects/<id-or-path>/<sub-resource>, so the
            // project is the single segment after "projects". Taking the rest of
            // the path instead produced a slug like "projects/1234/merge_requests"
            // and a "Repository not found" for the same reason a pasted web URL
            // used to.
            let isAPIPath = components.first == "api" && components.count >= 3 && components[1] == "v4"
            let webSlug: String
            if isAPIPath, components.count >= 4, components[2] == "projects" {
                webSlug = normalizedAPISlug(components[3])
            } else {
                webSlug = slug
            }
            return Endpoint(provider: "gitlab",
                            apiBaseURL: apiBaseURL(provider: "gitlab", host: host)!,
                            webURL: "https://\(host)/\(webSlug)",
                            repoSlug: webSlug,
                            visibility: host == "gitlab.com" ? defaultVisibility : .privateRepo)
        }

        if host == "bitbucket.org" {
            return Endpoint(provider: "bitbucket",
                            apiBaseURL: apiBaseURL(provider: "bitbucket", host: host)!,
                            webURL: "https://bitbucket.org/\(slug)",
                            repoSlug: slug,
                            visibility: .publicRepo)
        }

        // GitHub-compatible forges (Gitea, Forgejo, Codeberg and the many
        // internal installs that imitate the GitHub API). Trying the GitHub
        // adapter against an unknown host is harmless: a host that does not
        // speak the API simply fails the connection test with a clear message.
        return Endpoint(provider: "gitea",
                        apiBaseURL: apiBaseURL(provider: "gitea", host: host)!,
                        webURL: "https://\(host)/\(slug)",
                        repoSlug: slug,
                        visibility: .privateRepo)
    }

    /// The identifier as GitLab's API accepts it: a URL-encoded `owner/project`
    /// for the path form, a bare number for the numeric one.
    private static func normalizedAPISlug(_ segment: String) -> String {
        if !segment.contains("/") { return segment }
        // Already-encoded from a full path slug; the adapter encodes again, so
        // the inner slashes become %2F.
        return segment
    }

    /// Drops the UI-only tail from a pasted forge URL, leaving the project path.
    ///
    /// Two shapes matter, and both are unambiguous because the tail is either
    /// flagged or drawn from a closed set of reserved names:
    ///
    /// - GitLab writes the boundary explicitly: everything after a literal `/-`
    ///   is UI (`/-/merge_requests`, `/-/issues/42`, `/-/tree/main`). Nested
    ///   groups mean the owner and project are the two segments before `/-`.
    /// - GitHub, Bitbucket and the Gitea family have no marker, so a small
    ///   reserved-word list is used: `pull`, `pulls`, `issues`, `merge_requests`,
    ///   `tree`, `blob`, `commit`, `releases`, `compare`, `branches`, `tags`,
    ///   `wiki`, `settings` and `graphs`. The first match ends the path.
    ///
    /// API paths are returned untouched, since `/api/v4/...` and `/api/v1/...`
    /// are handled as endpoints in their own right by the caller.
    private static func trimmedToProjectPath(_ input: [String], host: String) -> [String] {
        if input.first == "api" { return input }

        var components = input
        if let dashIndex = components.firstIndex(of: "-") {
            // A leading "/-/" means the host was given a bare custom domain and
            // there is no owner/project before it, so there is nothing to keep.
            guard dashIndex >= 2 else { return components }
            components = Array(components[..<dashIndex])
        }

        let reserved: Set<String> = [
            "pull", "pulls", "pull-requests", "merge-requests", "merge_requests",
            "issues", "issue", "tree", "blob", "src", "raw", "blame", "commit",
            "commits", "releases", "compare", "branches", "tags", "wiki", "graphs",
            "settings", "network", "dependabot", "actions", "security", "milestones",
            "search", "find", "-",
        ]
        if let tail = components.dropFirst(2).firstIndex(where: { reserved.contains($0.lowercased()) }) {
            components = Array(components[..<tail])
        }
        return components
    }
}

/// Shared REST plumbing: base URL, token injection, status handling, and the
/// two date formats the forges use.
final class ForgeHTTPClient {
    private let token: String?
    private let timeout: TimeInterval

    init(token: String?, timeout: TimeInterval = 20) {
        self.token = token
        self.timeout = timeout
    }

    enum HTTPFailure: LocalizedError {
        case unauthorized
        case forbidden(String)
        case notFound
        case rateLimited
        case server(Int, String)
        case transport(String)
        case malformed(String)

        var errorDescription: String? {
            switch self {
            case .unauthorized:
                return "The access token was rejected. Check it in Accounts…"
            case .forbidden(let detail):
                return "The token is missing a required permission. \(detail)"
            case .notFound:
                return "Repository not found. If it is private, make sure the repo is marked private and a token with read access is saved."
            case .rateLimited:
                return "The provider is rate-limiting this token. Try again in a few minutes."
            case .server(let code, let body):
                return "The provider returned HTTP \(code). \(body.prefix(200))"
            case .transport(let message):
                return "Could not reach the provider: \(message)"
            case .malformed(let detail):
                return "Unexpected response from the provider: \(detail)"
            }
        }
    }

    /// Performs a GET and decodes JSON. `accept` lets the Gitea-compatible
    /// adapter ask for the plain JSON shape when the vendor media type is not
    /// understood by an older server.
    func get<T: Decodable>(_ path: String,
                           accept: String = "application/json",
                           as type: T.Type) throws -> T {
        var request = URLRequest(url: try url(for: path))
        request.httpMethod = "GET"
        request.timeoutInterval = timeout
        request.setValue(accept, forHTTPHeaderField: "Accept")
        if let token = token, !token.isEmpty {
            request.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        }

        let (data, response): (Data, URLResponse)
        do {
            (data, response) = try performSync(request)
        } catch {
            throw HTTPFailure.transport(error.localizedDescription)
        }
        guard let http = response as? HTTPURLResponse else {
            throw HTTPFailure.transport("no HTTP response")
        }
        switch http.statusCode {
        case 200..<300:
            break
        case 401:
            throw HTTPFailure.unauthorized
        case 403:
            let body = String(data: data, encoding: .utf8) ?? ""
            if body.lowercased().contains("rate limit") || http.value(forHTTPHeaderField: "Retry-After") != nil {
                throw HTTPFailure.rateLimited
            }
            throw HTTPFailure.forbidden(body)
        case 404:
            throw HTTPFailure.notFound
        case 429:
            throw HTTPFailure.rateLimited
        default:
            throw HTTPFailure.server(http.statusCode, String(data: data, encoding: .utf8) ?? "")
        }
        do {
            return try JSONDecoder().decode(type, from: data)
        } catch let DecodingError.dataCorrupted(context) {
            // Only the decoder's own explanation is kept: the raw body can be
            // megabytes of JSON, and it was ending up verbatim in the menu bar.
            throw HTTPFailure.malformed(context.debugDescription)
        } catch {
            throw HTTPFailure.malformed("the response did not match what this provider returns")
        }
    }

    /// Bridges the completion-handler API so the forges can stay synchronous.
    ///
    /// The adapter protocol is synchronous because it is called from background
    /// polling code and from the command-line style verification path; using the
    /// async API here would force both to become `async` for no benefit.
    private func performSync(_ request: URLRequest) throws -> (Data, URLResponse) {
        let semaphore = DispatchSemaphore(value: 0)
        var result: Result<(Data, URLResponse), Error> = .failure(URLError(.unknown))

        let task = URLSession.shared.dataTask(with: request) { data, response, error in
            if let error = error {
                result = .failure(error)
            } else if let data = data, let response = response {
                result = .success((data, response))
            } else {
                result = .failure(URLError(.badServerResponse))
            }
            semaphore.signal()
        }
        task.resume()

        if semaphore.wait(timeout: .now() + timeout) == .timedOut {
            task.cancel()
            throw HTTPFailure.transport("the request timed out after \(Int(timeout))s")
        }
        return try result.get()
    }

    private func url(for path: String) throws -> URL {
        guard let url = URL(string: path) else {
            throw HTTPFailure.malformed("bad URL \(path)")
        }
        return url
    }

    /// GitHub sends RFC 3339 with fractional seconds; GitLab omits them.
    static func parseDate(_ raw: String?) -> Date? {
        guard let raw = raw else { return nil }
        let withFraction = ISO8601DateFormatter()
        withFraction.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        if let date = withFraction.date(from: raw) { return date }
        let plain = ISO8601DateFormatter()
        plain.formatOptions = [.withInternetDateTime]
        return plain.date(from: raw)
    }
}

/// Chooses the adapter that matches a monitored repo's provider.
enum ForgeRegistry {
    static func adapter(for provider: String, token: String?) -> ForgeAdapter {
        switch provider {
        case "gitlab":
            return GitLabAdapter(token: token)
        case "bitbucket":
            return BitbucketAdapter(token: token)
        case "gitea":
            return GiteaAdapter(token: token)
        default:
            return GitHubAdapter(token: token)
        }
    }

    /// Verifies a token by asking the provider who it belongs to.
    ///
    /// Every forge in scope exposes a `/user` endpoint, so this confirms the
    /// token is live and reveals the account name without needing a repository
    /// to be added first. A 401 is reported as an auth problem; a 403 as a
    /// scope problem, which is what a user with a write token saved by mistake
    /// will actually hit.
    static func verifyToken(provider: String,
                            baseURL: String,
                            token: String,
                            username: String = "") -> Result<String, PRMessageError> {
        struct Identity: Decodable {
            let login: String?
            let username: String?
            let nickname: String?
            let display_name: String?
            let full_name: String?
        }
        struct RepoList: Decodable { let values: [Identity]? }

        // Bitbucket answers 403 "This API is not accessible by this authentication
        // mechanism" on /2.0/user for an Atlassian API token, even though that
        // same token reads repositories and clones over https perfectly well. So
        // verify against a workspace instead: 401 there means the token is bad,
        // 404 means it authenticated but the label is not a workspace.
        let path: String
        switch provider {
        case "gitlab": path = "\(baseURL)/user"
        case "bitbucket": path = "\(baseURL)/repositories/\(username)"
        case "gitea":
            // A bare host was stored for self-hosted forges; derive the API root.
            let root = baseURL.contains("://") ? baseURL : "https://\(baseURL)"
            path = baseURL.contains("/api/") ? "\(root)/user" : "\(root)/api/v1/user"
        default:
            path = baseURL.hasSuffix("/api/v3")
                ? "\(baseURL)/user"
                : "\(baseURL)/user"
        }

        do {
            if provider == "bitbucket" {
                do {
                    let list: RepoList = try ForgeHTTPClient(token: token).get(path, as: RepoList.self)
                    return .success(list.values?.first?.nickname ?? username)
                } catch let failure as ForgeHTTPClient.HTTPFailure {
                    if case .notFound = failure { return .success(username) }
                    if case .unauthorized = failure {
                        return .failure(PRMessageError("The token was rejected. Check that it was copied in full and has not been revoked."))
                    }
                    throw failure
                }
            }
            let identity: Identity = try ForgeHTTPClient(token: token).get(path, as: Identity.self)
            let name = identity.login ?? identity.username ?? identity.nickname
                ?? identity.display_name ?? identity.full_name ?? "authenticated account"
            return .success(name)
        } catch let failure as ForgeHTTPClient.HTTPFailure {
            switch failure {
            case .unauthorized:
                return .failure(PRMessageError("The token was rejected. Check that it was copied in full and has not been revoked."))
            case .forbidden(let detail):
                if detail.lowercased().contains("authentication mechanism") {
                    return .failure(PRMessageError("The provider rejected this authentication method, not the token's permissions. \(detail)"))
                }
                return .failure(PRMessageError("The token was accepted but lacks permission. \(detail)"))
            case .notFound:
                return .failure(PRMessageError("The API endpoint was not found. Check the provider host is right."))
            default:
                return .failure(PRMessageError(failure.errorDescription ?? "Connection failed."))
            }
        } catch {
            return .failure(PRMessageError(error.localizedDescription))
        }
    }
}

/// A list response, tolerant of the two envelope shapes the forges use.
///
/// GitHub, GitLab and Gitea return a bare JSON array from their list
/// endpoints, while Bitbucket wraps the same content in `values`. Decoding
/// both here is what keeps the adapters from each assuming an envelope
/// nobody actually sends.
struct ForgeList<Element: Decodable>: Decodable {
    private struct Envelope: Decodable { let values: [Element]? }

    let items: [Element]

    init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()
        if let array = try? container.decode([Element].self) {
            items = array
        } else if let envelope = try? container.decode(Envelope.self), let values = envelope.values {
            items = values
        } else {
            throw DecodingError.dataCorruptedError(in: container, debugDescription: "expected a JSON array or an object with a \"values\" array")
        }
    }
}

extension PRMessageError: CustomStringConvertible {
    var description: String { message }
}

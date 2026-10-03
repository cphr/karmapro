// by cipher.org.uk
import Foundation

/// GitHub (and GitHub Enterprise). Unauthenticated calls work for public
/// repos, which is why `token` is optional and a public repo never needs one.
struct GitHubAdapter: ForgeAdapter {
    let identifier = "github"
    let displayName = "GitHub"
    let token: String?

    private struct Payload: Decodable {
        struct Item: Decodable {
            struct User: Decodable { let login: String }
            struct Head: Decodable {
                let ref: String
                let sha: String
                struct Repo: Decodable { let full_name: String }
            }
            struct Base: Decodable {
                let ref: String
                let repo: Repo
                struct Repo: Decodable { let full_name: String }
            }
            let number: Int
            let title: String
            let html_url: String
            let updated_at: String?
            let user: User?
            let head: Head
            let base: Base
        }
    }
    private typealias ListResponse = ForgeList<Payload.Item>

    func openPullRequests(for repo: MonitoredRepo) throws -> [PullRequest] {
        let path = "\(repo.baseURL)/repos/\(repo.repoSlug)/pulls?state=open&per_page=100&sort=updated&direction=desc"
        let response: ListResponse = try ForgeHTTPClient(token: token).get(path, as: ListResponse.self)
        return response.items.map { item in
            PullRequest(id: item.number,
                        number: item.number,
                        title: item.title,
                        author: item.user?.login ?? "unknown",
                        headBranch: item.head.ref,
                        baseBranch: item.base.ref,
                        repoSlug: item.base.repo.full_name,
                        webURL: item.html_url,
                        headSHA: item.head.sha,
                        updatedAt: ForgeHTTPClient.parseDate(item.updated_at))
        }
    }

    func testConnection(for repo: MonitoredRepo) -> Result<Void, PRMessageError> {
        do {
            _ = try openPullRequests(for: repo)
            return .success(())
        } catch let failure as ForgeHTTPClient.HTTPFailure {
            return .failure(PRMessageError(failure.errorDescription ?? "connection failed"))
        } catch {
            return .failure(PRMessageError(error.localizedDescription))
        }
    }
}

/// GitLab (SaaS and self-hosted). The MR list endpoint returns every MR in the
/// project; it is filtered to open ones here because the endpoint has no
/// server-side state filter worth relying on across GitLab versions.
struct GitLabAdapter: ForgeAdapter {
    let identifier = "gitlab"
    let displayName = "GitLab"
    let token: String?

    /// Percent-encodes a `group/project` slug into the single path segment
    /// GitLab's `/projects/<id>` route expects.
    ///
    /// Two things have to be right here. The slash between the namespace and the
    /// project must become `%2F`, because a real slash makes GitLab read the
    /// extra segment as a subgroup and answer 404. And nothing else may be
    /// encoded: the set below leaves `-`, `_` and `.` alone, and encoding them
    /// as `%2D` and friends also produces 404, because GitLab does not decode
    /// the project id before matching it. A bare numeric project id passes
    /// through unchanged, which is the other form the route accepts.
    static func encodeSlug(_ slug: String) -> String {
        if !slug.contains("/") { return slug }
        // Sub-delimiters that appear in real project names and must stay
        // literal, everything else escaped.
        let literal = CharacterSet(charactersIn:
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_.")
        return slug.addingPercentEncoding(withAllowedCharacters: literal) ?? slug
    }

    private struct Payload: Decodable {
        struct Item: Decodable {
            struct Author: Decodable { let username: String }
            struct References: Decodable {
                struct Ref: Decodable { let name: String; let sha: String }
                let base: Ref?
                let head: Ref?
            }
            let iid: Int
            let id: Int
            let title: String
            let web_url: String
            let updated_at: String?
            let author: Author?
            let references: References?
            /// The head commit of the source branch, on the merge request itself.
            /// The older shape kept it in `references.head.sha`, and both are
            /// decoded because `references` is optional here.
            let sha: String?
            let source_branch: String?
            let target_branch: String?
        }
    }
    private typealias ListResponse = ForgeList<Payload.Item>

    func openPullRequests(for repo: MonitoredRepo) throws -> [PullRequest] {
        // The slug has to reach GitLab as ONE path segment. `urlPathAllowed`
        // contains "/", so percent-encoding a "group/project" slug with it
        // leaves the slash alone and the request arrives as
        // /projects/group/project/merge_requests, which GitLab reads as a
        // nested group and answers 404 for. The slash is encoded explicitly
        // below, which is what makes the request path work for every project
        // outside the top level.
        let encoded = GitLabAdapter.encodeSlug(repo.repoSlug)
        let path = "\(repo.baseURL)/projects/\(encoded)/merge_requests?state=opened&per_page=100&order_by=updated_at&sort=desc"
        let response: ListResponse = try ForgeHTTPClient(token: token).get(path, as: ListResponse.self)
        return response.items.map { item in
            // The head SHA is what makes a force-push recognisable as an update
            // rather than the same pull request seen again. GitLab returns it as
            // the merge request's own `sha`; `references` is a cross-reference
            // string like "!259139" and holds no commit, so reading the head SHA
            // from there left every GitLab pull request with an empty one and the
            // fingerprint reduced to just the id.
            let sha = item.sha ?? item.references?.head?.sha ?? ""
            return PullRequest(id: item.id,
                               number: item.iid,
                               title: item.title,
                               author: item.author?.username ?? "unknown",
                               headBranch: item.source_branch ?? item.references?.head?.name ?? "",
                               baseBranch: item.target_branch ?? item.references?.base?.name ?? "",
                               repoSlug: repo.repoSlug,
                               webURL: item.web_url,
                               headSHA: sha,
                               updatedAt: ForgeHTTPClient.parseDate(item.updated_at))
        }
    }

    func testConnection(for repo: MonitoredRepo) -> Result<Void, PRMessageError> {
        do {
            _ = try openPullRequests(for: repo)
            return .success(())
        } catch let failure as ForgeHTTPClient.HTTPFailure {
            return .failure(PRMessageError(failure.errorDescription ?? "connection failed"))
        } catch {
            return .failure(PRMessageError(error.localizedDescription))
        }
    }
}

/// Bitbucket Cloud. Uses app passwords rather than PATs: Bitbucket's equivalent
/// read-only credential is called an "app password" in its UI.
struct BitbucketAdapter: ForgeAdapter {
    let identifier = "bitbucket"
    let displayName = "Bitbucket"
    let token: String?

    private struct Payload: Decodable {
        struct Item: Decodable {
            struct Author: Decodable { let nickname: String?; let display_name: String? }
            struct Branch: Decodable { let name: String? }
            struct Commit: Decodable { let hash: String? }
            struct Source: Decodable {
                let branch: Branch
                let commit: Commit?
            }
            struct Destination: Decodable { let branch: Branch }
            let id: Int
            let title: String
            let links: Links
            let author: Author?
            let source: Source
            let destination: Destination
            let updated_on: String?
        }
        struct Links: Decodable { struct Href: Decodable { let href: String? }; let html: Href }
    }
    private typealias ListResponse = ForgeList<Payload.Item>

    func openPullRequests(for repo: MonitoredRepo) throws -> [PullRequest] {
        // pagelen is capped at 50 by the API; 100 is answered with
        // HTTP 400 "Invalid pagelen" rather than being clamped, so the request
        // has to ask for a value the server accepts.
        let path = "\(repo.baseURL)/repositories/\(repo.repoSlug)/pullrequests?state=OPEN&pagelen=50&sort=-updated_on"
        let response: ListResponse = try ForgeHTTPClient(token: token).get(path, as: ListResponse.self)
        return response.items.map { item in
            PullRequest(id: item.id,
                        number: item.id,
                        title: item.title,
                        author: item.author?.nickname ?? item.author?.display_name ?? "unknown",
                        headBranch: item.source.branch.name ?? "",
                        baseBranch: item.destination.branch.name ?? "",
                        repoSlug: repo.repoSlug,
                        webURL: item.links.html.href ?? "",
                        // The list payload does carry the head commit under
                        // source.commit.hash. Without it the fingerprint reduces
                        // to the pull request id alone, so a force-push that
                        // leaves the same branches would never be noticed as an
                        // update to an already-announced pull request.
                        headSHA: item.source.commit?.hash ?? "",
                        updatedAt: ForgeHTTPClient.parseDate(item.updated_on))
        }
    }

    func testConnection(for repo: MonitoredRepo) -> Result<Void, PRMessageError> {
        do {
            _ = try openPullRequests(for: repo)
            return .success(())
        } catch let failure as ForgeHTTPClient.HTTPFailure {
            return .failure(PRMessageError(failure.errorDescription ?? "connection failed"))
        } catch {
            return .failure(PRMessageError(error.localizedDescription))
        }
    }
}

/// Gitea / Forgejo / Codeberg. These speak the GitHub REST API closely enough
/// that the GitHub shapes decode directly once the path and media type match.
struct GiteaAdapter: ForgeAdapter {
    let identifier = "gitea"
    let displayName = "Gitea / Forgejo / Codeberg"
    let token: String?

    private struct Payload: Decodable {
        struct Item: Decodable {
            struct User: Decodable { let login: String? }
            struct Ref: Decodable { let ref: String?; let sha: String? }
            let id: Int
            let number: Int
            let title: String
            let html_url: String
            let updated_at: String?
            let user: User?
            let head: Ref?
            let base: Ref?
        }
    }
    private typealias ListResponse = ForgeList<Payload.Item>

    func openPullRequests(for repo: MonitoredRepo) throws -> [PullRequest] {
        let path = "\(repo.baseURL)/repos/\(repo.repoSlug)/pulls?state=open&limit=50"
        let response: ListResponse = try ForgeHTTPClient(token: token).get(path, as: ListResponse.self)
        return response.items.map { item in
            PullRequest(id: item.id,
                        number: item.number,
                        title: item.title,
                        author: item.user?.login ?? "unknown",
                        headBranch: item.head?.ref ?? "",
                        baseBranch: item.base?.ref ?? "",
                        repoSlug: repo.repoSlug,
                        webURL: item.html_url,
                        headSHA: item.head?.sha ?? "",
                        updatedAt: ForgeHTTPClient.parseDate(item.updated_at))
        }
    }

    func testConnection(for repo: MonitoredRepo) -> Result<Void, PRMessageError> {
        do {
            _ = try openPullRequests(for: repo)
            return .success(())
        } catch let failure as ForgeHTTPClient.HTTPFailure {
            return .failure(PRMessageError(failure.errorDescription ?? "connection failed"))
        } catch {
            return .failure(PRMessageError(error.localizedDescription))
        }
    }
}
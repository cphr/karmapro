// by cipher.org.uk
import Foundation

/// Asks GitHub for the newest production release of Karma Pro.
///
/// Three outcomes and nothing else: up to date, a newer release, or a failure.
///
/// Every way the request can go wrong — no network, a blocked or
/// authentication-demanding proxy, a timeout, an untrusted certificate, a rate
/// limit, a server error, a missing repository, malformed JSON, an unreadable
/// tag — collapses into the same `.failed`. Telling those apart reliably is the
/// expensive part of this feature and of no use to the reader, who can only act
/// on "try again later" regardless of which one it was.
///
/// The check also never writes a user preference. Nothing here can turn the
/// daily check off, or change any other setting, on its own.
enum UpdateChecker {

    enum Outcome {
        case upToDate(current: String)
        case updateAvailable(Release)
        case failed
    }

    struct Release {
        let version: String
        let publishedAt: Date?
        /// Always the release's own page, so Download goes to the exact release
        /// rather than to a list the user then has to search.
        let pageURL: URL
    }

    /// The newest non-draft, non-prerelease release. GitHub's `latest` already
    /// applies both exclusions, so this needs no second filter of its own.
    static let endpoint = URL(string: "https://api.github.com/repos/cphr/karmapro/releases/latest")!

    /// Used only when the payload carries no `html_url`.
    static let fallbackPage = URL(string: "https://github.com/cphr/karmapro/releases/latest")!

    /// Long enough for a slow connection, short enough that a request the
    /// network silently swallows cannot leave the menu item disabled forever.
    static let timeout: TimeInterval = 15

    /// GitHub rejects API requests that arrive without one.
    private static let userAgent = "KarmaPro/\(currentVersion) (macOS; update check)"

    /// The running version, read from the bundle so it can never disagree with
    /// what actually shipped. Same source as the splash label.
    static var currentVersion: String {
        let version = Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String
        return (version?.isEmpty == false) ? version! : "0"
    }

    private struct Payload: Decodable {
        let tagName: String
        let publishedAt: Date?
        let htmlURL: URL?

        enum CodingKeys: String, CodingKey {
            case tagName = "tag_name"
            case publishedAt = "published_at"
            case htmlURL = "html_url"
        }
    }

    /// Performs one check. `completion` is always delivered on the main queue.
    static func check(completion: @escaping (Outcome) -> Void) {
        var request = URLRequest(url: endpoint)
        request.timeoutInterval = timeout
        request.setValue(userAgent, forHTTPHeaderField: "User-Agent")
        request.setValue("application/vnd.github+json", forHTTPHeaderField: "Accept")

        let task = URLSession.shared.dataTask(with: request) { data, response, _ in
            let outcome = interpret(data: data, response: response)
            DispatchQueue.main.async { completion(outcome) }
        }
        task.resume()
    }

    /// Turns whatever came back into one of the three outcomes.
    static func interpret(data: Data?, response: URLResponse?) -> Outcome {
        guard let http = response as? HTTPURLResponse,
              (200..<300).contains(http.statusCode),
              let data,
              let payload = try? decoder().decode(Payload.self, from: data),
              VersionComparator.components(of: payload.tagName) != nil else {
            return .failed
        }

        let version = VersionComparator.normalised(payload.tagName)
        guard VersionComparator.isNewer(tag: version, than: currentVersion) else {
            return .upToDate(current: currentVersion)
        }
        return .updateAvailable(Release(version: version,
                                        publishedAt: payload.publishedAt,
                                        pageURL: payload.htmlURL ?? fallbackPage))
    }

    /// GitHub sends `published_at` as an ISO 8601 timestamp, which is not what
    /// `JSONDecoder` expects by default.
    private static func decoder() -> JSONDecoder {
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        return decoder
    }

    /// How long ago a release appeared, phrased for the update alert:
    /// "today", "yesterday", "3 days ago", "2 months ago", or a plain date once
    /// it is old enough that counting days stops being useful.
    static func agePhrase(since date: Date?, now: Date = Date()) -> String {
        guard let date else { return "" }
        let days = Calendar.current.dateComponents([.day], from: date, to: now).day ?? 0
        if days <= 0 { return "today" }
        if days == 1 { return "yesterday" }
        if days < 30 { return "\(days) days ago" }
        if days < 365 {
            let months = max(1, days / 30)
            return months == 1 ? "a month ago" : "\(months) months ago"
        }
        let formatter = DateFormatter()
        formatter.dateFormat = "yyyy-MM-dd"
        return formatter.string(from: date)
    }
}

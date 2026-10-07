// by cipher.org.uk
import Foundation

struct OSVVulnerability: Decodable {
    let id: String
    let summary: String?
    let details: String?
    let aliases: [String]?
    let severity: [OSVSeverityEntry]?
    let databaseSpecific: OSVDatabaseSpecific?

    struct OSVSeverityEntry: Decodable {
        let type: String?
        let score: String?
    }

    struct OSVDatabaseSpecific: Decodable {
        let severity: String?
    }

    enum CodingKeys: String, CodingKey {
        case id, summary, details, aliases, severity
        case databaseSpecific = "database_specific"
    }
}

enum OSVSeverityLevel: String {
    case critical, high, medium, low
}

enum OSVClient {
    static let defaultEndpoint = URL(string: "https://api.osv.dev/v1/querybatch")!
    static let maxBatchSize = 1000
    static let detailConcurrency = 8

    enum Progress {
        case querying(done: Int, total: Int)
        case fetchingDetails(done: Int, total: Int)
    }

    struct QueryPackage: Encodable {
        let name: String
        let ecosystem: String
    }

    struct Query: Encodable {
        let package: QueryPackage
        let version: String
    }

    struct QueryBatch: Encodable {
        let queries: [Query]
    }

    struct BatchResult: Decodable {
        let vulns: [OSVVulnerability]?
    }

    struct BatchResponse: Decodable {
        let results: [BatchResult]
    }

    static func queryKey(ecosystem: String, name: String, version: String) -> String {
        "\(ecosystem)\u{0}\(name)\u{0}\(version)"
    }

    static func vulnerabilities(for dependencies: [PackageDependency],
                                endpoint: URL,
                                progress: @escaping (Progress) -> Void) throws -> [String: [OSVVulnerability]] {
        var order: [String] = []
        var queryByKey: [String: Query] = [:]
        for dependency in dependencies {
            let key = queryKey(ecosystem: dependency.ecosystem,
                               name: dependency.name,
                               version: dependency.version)
            if queryByKey[key] == nil {
                queryByKey[key] = Query(package: QueryPackage(name: dependency.name,
                                                              ecosystem: dependency.ecosystem),
                                        version: dependency.version)
                order.append(key)
            }
        }

        var stubsByKey: [String: [OSVVulnerability]] = [:]
        let total = order.count
        progress(.querying(done: 0, total: total))
        var index = 0
        let encoder = JSONEncoder()
        while index < order.count {
            let end = min(index + maxBatchSize, order.count)
            let keys = Array(order[index..<end])
            let batch = QueryBatch(queries: keys.compactMap { queryByKey[$0] })
            let payload = try encoder.encode(batch)
            let data = try perform(request: jsonRequest(body: payload, endpoint: endpoint))
            let decoded = try JSONDecoder().decode(BatchResponse.self, from: data)
            guard decoded.results.count == keys.count else {
                throw NSError(domain: "OSVClient", code: 1, userInfo: [
                    NSLocalizedDescriptionKey: "OSV returned \(decoded.results.count) results for \(keys.count) queries.",
                ])
            }
            for (key, result) in zip(keys, decoded.results) {
                stubsByKey[key] = result.vulns ?? []
            }
            index = end
            progress(.querying(done: index, total: total))
        }

        var uniqueIDs: [String] = []
        var seenIDs = Set<String>()
        for key in order {
            for stub in stubsByKey[key] ?? [] where seenIDs.insert(stub.id).inserted {
                uniqueIDs.append(stub.id)
            }
        }
        let details = fetchDetails(ids: uniqueIDs, endpoint: endpoint, progress: progress)

        var outcome: [String: [OSVVulnerability]] = [:]
        for (key, stubs) in stubsByKey {
            outcome[key] = stubs.map { details[$0.id] ?? $0 }
        }
        return outcome
    }

    private static func fetchDetails(ids: [String],
                                     endpoint: URL,
                                     progress: @escaping (Progress) -> Void) -> [String: OSVVulnerability] {
        guard !ids.isEmpty else { return [:] }
        let base = endpoint.deletingLastPathComponent().appendingPathComponent("vulns")
        let queue = OperationQueue()
        queue.maxConcurrentOperationCount = detailConcurrency
        let lock = NSLock()
        var records: [String: OSVVulnerability] = [:]
        var completed = 0

        for id in ids {
            queue.addOperation {
                if let record = try? fetchDetail(id: id, base: base) {
                    lock.lock()
                    records[id] = record
                    lock.unlock()
                }
                lock.lock()
                completed += 1
                let done = completed
                lock.unlock()
                progress(.fetchingDetails(done: done, total: ids.count))
            }
        }
        queue.waitUntilAllOperationsAreFinished()
        return records
    }

    private static func fetchDetail(id: String, base: URL) throws -> OSVVulnerability {
        let url = base.appendingPathComponent(id)
        var request = URLRequest(url: url)
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        request.timeoutInterval = 30
        let data = try perform(request: request)
        return try JSONDecoder().decode(OSVVulnerability.self, from: data)
    }

    private static func jsonRequest(body: Data, endpoint: URL) -> URLRequest {
        var request = URLRequest(url: endpoint)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        request.httpBody = body
        request.timeoutInterval = 60
        return request
    }

    private static func perform(request: URLRequest) throws -> Data {
        let semaphore = DispatchSemaphore(value: 0)
        var dataResult: Data?
        var responseResult: URLResponse?
        var errorResult: Error?
        URLSession.shared.dataTask(with: request) { data, response, error in
            dataResult = data
            responseResult = response
            errorResult = error
            semaphore.signal()
        }.resume()
        semaphore.wait()

        if let error = errorResult { throw error }
        guard let http = responseResult as? HTTPURLResponse else {
            throw NSError(domain: "OSVClient", code: 2, userInfo: [
                NSLocalizedDescriptionKey: "No HTTP response from the vulnerability service.",
            ])
        }
        guard http.statusCode == 200 else {
            let snippet = dataResult.flatMap { String(data: $0.prefix(300), encoding: .utf8) } ?? ""
            throw NSError(domain: "OSVClient", code: http.statusCode, userInfo: [
                NSLocalizedDescriptionKey: "Vulnerability service returned HTTP \(http.statusCode). \(snippet)",
            ])
        }
        guard let data = dataResult else {
            throw NSError(domain: "OSVClient", code: 3, userInfo: [
                NSLocalizedDescriptionKey: "Empty response from the vulnerability service.",
            ])
        }
        return data
    }

    static func severity(of vulnerability: OSVVulnerability) -> OSVSeverityLevel {
        if let raw = vulnerability.databaseSpecific?.severity?.uppercased() {
            switch raw {
            case "CRITICAL": return .critical
            case "HIGH": return .high
            case "MODERATE", "MEDIUM": return .medium
            case "LOW": return .low
            default: break
            }
        }
        if let entries = vulnerability.severity {
            for entry in entries {
                guard let score = entry.score else { continue }
                if let value = Double(score) {
                    return bucket(value)
                }
                let isV3 = entry.type?.uppercased().contains("V3") == true
                if (isV3 || score.hasPrefix("CVSS:3")), let value = cvss3BaseScore(score) {
                    return bucket(value)
                }
            }
        }
        return .medium
    }

    static func bucket(_ score: Double) -> OSVSeverityLevel {
        if score >= 9.0 { return .critical }
        if score >= 7.0 { return .high }
        if score >= 4.0 { return .medium }
        return .low
    }

    static func cvss3BaseScore(_ vector: String) -> Double? {
        var metrics: [String: String] = [:]
        for part in vector.split(separator: "/") {
            let pair = part.split(separator: ":", maxSplits: 1)
            guard pair.count == 2 else { continue }
            metrics[String(pair[0])] = String(pair[1])
        }
        guard let avValue = metrics["AV"], let acValue = metrics["AC"],
              let prValue = metrics["PR"], let uiValue = metrics["UI"],
              let scopeValue = metrics["S"], let cValue = metrics["C"],
              let iValue = metrics["I"], let aValue = metrics["A"] else { return nil }

        let scopeChanged = scopeValue == "C"
        guard let av = ["N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20][avValue],
              let ac = ["L": 0.77, "M": 0.44, "H": 0.20][acValue],
              let ui = ["N": 0.85, "R": 0.62][uiValue],
              let pr = scopeChanged
                  ? ["N": 0.85, "U": 0.27, "C": 0.50][prValue]
                  : ["N": 0.85, "U": 0.62, "C": 0.68][prValue],
              let confidentiality = ["N": 0.0, "L": 0.22, "H": 0.56][cValue],
              let integrity = ["N": 0.0, "L": 0.22, "H": 0.56][iValue],
              let availability = ["N": 0.0, "L": 0.22, "H": 0.56][aValue] else { return nil }

        let iss = 1 - (1 - confidentiality) * (1 - integrity) * (1 - availability)
        let exploitability = 8.22 * av * ac * pr * ui
        guard iss > 0 else { return roundup(exploitability) }

        func raised(_ base: Double, _ exponent: Int) -> Double {
            var result = 1.0
            for _ in 0..<exponent { result *= base }
            return result
        }

        let impact: Double
        if scopeChanged {
            impact = 7.52 * (iss - 0.029) - 3.25 * raised(iss * 0.9731 - 0.02, 13)
        } else {
            impact = 7.52 * (iss - 0.029) - 3.25 * raised(iss - 0.02, 13)
        }
        guard impact > 0 else { return roundup(exploitability) }
        let base = scopeChanged
            ? min(1.08 * (exploitability + impact), 10)
            : min(exploitability + impact, 10)
        return roundup(base)
    }

    private static func roundup(_ value: Double) -> Double {
        let rounded = (value * 10).rounded(.up) / 10
        return min(max(rounded, 0), 10)
    }
}

// by cipher.org.uk
import Foundation

/// Serialises scan results as a SARIF 2.1.0 log, so the findings can be
/// imported by GitHub code scanning, the SARIF Viewer extension, and other
/// SARIF consumers.
///
/// Paths are written absolute, matching the paths the scanner reports and the
/// ones the table shows. `runs[].tool.driver.rules` holds one rule per unique
/// finding category; each result carries `ruleId` and `ruleIndex` so consumers
/// that only read the rules array can still label the row.
enum SARIFExport {

    /// Encodes `findings` — the rows currently visible in the scan table — as
    /// pretty-printed SARIF 2.1.0 JSON.
    static func data(from findings: [ScanFinding]) throws -> Data {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes]
        return try encoder.encode(makeLog(from: findings))
    }

    // MARK: - Log assembly

    private static func makeLog(from findings: [ScanFinding]) -> Log {
        var rules: [Rule] = []
        var ruleIndexOf: [String: Int] = [:]
        var takenIDs = Set<String>()
        var artifacts: [Artifact] = []
        var artifactIndexOf: [String: Int] = [:]
        var results: [SARIFResult] = []

        for finding in findings {
            let ruleIndex: Int
            if let existing = ruleIndexOf[finding.category] {
                ruleIndex = existing
            } else {
                ruleIndex = rules.count
                ruleIndexOf[finding.category] = ruleIndex
                rules.append(Rule(id: uniqueID(for: finding.category, taken: &takenIDs),
                                  name: pascalCase(finding.category),
                                  shortDescription: Text(text: finding.category)))
            }

            let path = finding.fileURL.path
            let artifactIndex: Int
            if let existing = artifactIndexOf[path] {
                artifactIndex = existing
            } else {
                artifactIndex = artifacts.count
                artifactIndexOf[path] = artifactIndex
                artifacts.append(Artifact(location: Location(uri: path)))
            }

            results.append(SARIFResult(ruleId: rules[ruleIndex].id,
                                       ruleIndex: ruleIndex,
                                       level: level(for: finding.severity),
                                       message: Text(text: finding.message),
                                       locations: [ResultLocation(physicalLocation:
                                            PhysicalLocation(artifactLocation: Location(uri: path,
                                                                                        index: artifactIndex),
                                                             region: Region(startLine: max(1, finding.line))))],
                                       properties: properties(for: finding)))
        }

        let driver = Driver(name: "Karma Pro", version: toolVersion, rules: rules)
        return Log(version: "2.1.0",
                   runs: [Run(tool: Tool(driver: driver),
                              artifacts: artifacts,
                              results: results)])
    }

    /// SARIF has four levels; the scanner's four severities map onto three of
    /// them (`none` means "explicitly not a problem", so nothing maps there).
    private static func level(for severity: ScanFinding.Severity) -> String {
        switch severity {
        case .critical, .high: return "error"
        case .medium:          return "warning"
        case .low:             return "note"
        }
    }

    /// Fields SARIF has no standard slot for, kept as `result.properties` so
    /// the export does not silently drop the evidence behind a finding.
    private static func properties(for finding: ScanFinding) -> [String: String] {
        var props: [String: String] = [
            "severity": finding.severity.label,
            "exploitability": finding.exploitability.label,
            "function": finding.function,
            "engine": finding.scanningSource,
            "reachable": finding.reachable ? "true" : "false",
            "crossFile": finding.crossFile ? "true" : "false"
        ]
        if let taint = finding.taint, !taint.isEmpty { props["taint"] = taint }
        if let packageName = finding.packageName { props["package"] = packageName }
        return props
    }

    private static var toolVersion: String {
        (Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String) ?? "unknown"
    }

    // MARK: - Identifiers

    /// A `ruleId` for `category`: lowercased, non-alphanumerics collapsed to a
    /// single '-', with `-2`, `-3`… appended when two categories reduce to the
    /// same slug so no result can point at the wrong rule.
    private static func uniqueID(for category: String, taken: inout Set<String>) -> String {
        let root = slug(category).isEmpty ? "rule" : slug(category)
        var candidate = root
        var suffix = 2
        while !taken.insert(candidate).inserted {
            candidate = "\(root)-\(suffix)"
            suffix += 1
        }
        return candidate
    }

    private static func slug(_ text: String) -> String {
        var out = ""
        for ch in text.lowercased() {
            if ch.isLetter || ch.isNumber {
                out.append(ch)
            } else if !out.isEmpty && !out.hasSuffix("-") {
                out.append("-")
            }
        }
        if out.hasSuffix("-") { out.removeLast() }
        return out
    }

    /// SARIF's `rule.name` must be an identifier with no spaces, so the
    /// category is also rendered PascalCase for display in consumers that
    /// prefer `name` over `shortDescription`.
    private static func pascalCase(_ text: String) -> String {
        let parts = text.split(whereSeparator: { !$0.isLetter && !$0.isNumber })
        let joined = parts.map { $0.prefix(1).uppercased() + $0.dropFirst().lowercased() }.joined()
        return joined.isEmpty ? "Rule" : joined
    }

    // MARK: - SARIF 2.1.0 shape

    private struct Log: Encodable {
        let version: String
        let runs: [Run]
    }

    private struct Run: Encodable {
        let tool: Tool
        let artifacts: [Artifact]
        let results: [SARIFResult]
    }

    private struct Tool: Encodable {
        let driver: Driver
    }

    private struct Driver: Encodable {
        let name: String
        let version: String
        let rules: [Rule]
    }

    private struct Rule: Encodable {
        let id: String
        let name: String
        let shortDescription: Text
    }

    private struct Artifact: Encodable {
        let location: Location
    }

    private struct Location: Encodable {
        let uri: String
        var index: Int?
    }

    private struct SARIFResult: Encodable {
        let ruleId: String
        let ruleIndex: Int
        let level: String
        let message: Text
        let locations: [ResultLocation]
        let properties: [String: String]
    }

    private struct ResultLocation: Encodable {
        let physicalLocation: PhysicalLocation
    }

    private struct PhysicalLocation: Encodable {
        let artifactLocation: Location
        let region: Region
    }

    private struct Region: Encodable {
        let startLine: Int
    }

    private struct Text: Encodable {
        let text: String
    }
}

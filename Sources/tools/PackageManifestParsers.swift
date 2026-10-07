// by cipher.org.uk
import Foundation

extension PackageDetector {

    static func parsePackageJsonManifest(text: String, url: URL, ecosystem: String) -> [PackageDependency] {
        guard let root = jsonDict(text) else { return [] }
        let locator = PackageLineLocator(text)
        var out: [PackageDependency] = []
        for section in ["dependencies", "devDependencies", "optionalDependencies", "peerDependencies"] {
            guard let entries = root[section] as? [String: String] else { continue }
            for name in entries.keys.sorted() {
                guard let version = entries[name], isExactVersion(version) else { continue }
                out.append(makeDependency(name: name, version: version, ecosystem: ecosystem,
                                          url: url, line: locator.line(ofName: name)))
            }
        }
        return out
    }

    static func parsePyproject(text: String, url: URL, ecosystem: String) -> [PackageDependency] {
        let lines = text.components(separatedBy: "\n")
        var out: [PackageDependency] = []
        var seen = Set<String>()
        var section = ""
        var inArray = false

        func add(name: String, version: String, line: Int) {
            guard isExactVersion(version), !seen.contains(name + "@" + version) else { return }
            seen.insert(name + "@" + version)
            out.append(makeDependency(name: name, version: version, ecosystem: ecosystem,
                                      url: url, line: line))
        }

        for (index, raw) in lines.enumerated() {
            let trimmed = raw.trimmingCharacters(in: .whitespaces)
            if trimmed.hasPrefix("["), trimmed.hasSuffix("]") {
                section = trimmed
                inArray = false
                continue
            }
            if inArray || trimmed.range(of: #"^\s*dependencies\s*=\s*\["#, options: .regularExpression) != nil {
                if trimmed.contains("]") { inArray = false } else { inArray = true }
                for quoted in regexGroups(#""([^"]+)""#, in: trimmed).map({ $0[1] }) {
                    guard let separator = quoted.range(of: "==") else { continue }
                    let name = String(quoted[..<separator.lowerBound]).trimmingCharacters(in: .whitespaces)
                    var version = String(quoted[separator.upperBound...]).trimmingCharacters(in: .whitespaces)
                    if let marker = version.firstIndex(of: ";") {
                        version = String(version[..<marker]).trimmingCharacters(in: .whitespaces)
                    }
                    guard name.range(of: #"^[A-Za-z0-9][A-Za-z0-9._-]*$"#,
                                     options: .regularExpression) != nil else { continue }
                    add(name: name, version: version, line: index + 1)
                }
                continue
            }
            guard section.contains("poetry"), section.contains("dependencies") else { continue }
            guard let equals = trimmed.range(of: " = ") else { continue }
            let name = String(trimmed[..<equals.lowerBound])
            guard name.range(of: #"^[A-Za-z0-9][A-Za-z0-9._-]*$"#,
                             options: .regularExpression) != nil else { continue }
            let value = String(trimmed[equals.upperBound...])
            if let version = quotedValue(value) {
                add(name: name, version: version, line: index + 1)
            } else if let inner = regexGroups(#"version\s*=\s*"([^"]+)""#, in: value).first {
                add(name: name, version: inner[1], line: index + 1)
            }
        }
        return out
    }

    static func parseCargoToml(text: String, url: URL, ecosystem: String) -> [PackageDependency] {
        let lines = text.components(separatedBy: "\n")
        var out: [PackageDependency] = []
        var seen = Set<String>()
        var section = ""

        for (index, raw) in lines.enumerated() {
            let trimmed = raw.trimmingCharacters(in: .whitespaces)
            if trimmed.hasPrefix("["), trimmed.hasSuffix("]") {
                section = trimmed.lowercased()
                continue
            }
            let isDependencies = section.contains(".dependencies]")
            guard isDependencies, let equals = trimmed.range(of: " = ") else { continue }
            let name = String(trimmed[..<equals.lowerBound])
            guard name.range(of: #"^[A-Za-z0-9][A-Za-z0-9_-]*$"#,
                             options: .regularExpression) != nil else { continue }
            let value = String(trimmed[equals.upperBound...])
            var version: String?
            if let quoted = quotedValue(value) {
                version = quoted
            } else {
                version = regexGroups(#"version\s*=\s*"([^"]+)""#, in: value).first?[1]
            }
            guard let resolved = version, isExactVersion(resolved),
                  !seen.contains(name + "@" + resolved) else { continue }
            seen.insert(name + "@" + resolved)
            out.append(makeDependency(name: name, version: resolved, ecosystem: ecosystem,
                                      url: url, line: index + 1))
        }
        return out
    }

    static func parseComposerJson(text: String, url: URL, ecosystem: String) -> [PackageDependency] {
        guard let root = jsonDict(text) else { return [] }
        let locator = PackageLineLocator(text)
        var out: [PackageDependency] = []
        var seen = Set<String>()
        for section in ["require", "require-dev"] {
            guard let entries = root[section] as? [String: String] else { continue }
            for name in entries.keys.sorted() {
                guard var version = entries[name] else { continue }
                if version.hasPrefix("v") { version.removeFirst() }
                guard isExactVersion(version), !seen.contains(name + "@" + version) else { continue }
                seen.insert(name + "@" + version)
                out.append(makeDependency(name: name, version: version, ecosystem: ecosystem,
                                          url: url, line: locator.line(ofName: name)))
            }
        }
        return out
    }

    static func parseGemfile(text: String, url: URL, ecosystem: String) -> [PackageDependency] {
        var out: [PackageDependency] = []
        var seen = Set<String>()
        let lines = text.components(separatedBy: "\n")
        for (index, raw) in lines.enumerated() {
            guard let match = regexGroups(#"^\s*gem\s+["']([^"']+)["']\s*,\s*["']([^"']+)["']"#,
                                          in: raw).first else { continue }
            let name = match[1]
            let version = match[2]
            guard isExactVersion(version), !seen.contains(name + "@" + version) else { continue }
            seen.insert(name + "@" + version)
            out.append(makeDependency(name: name, version: version, ecosystem: ecosystem,
                                      url: url, line: index + 1))
        }
        return out
    }

    static func parsePom(text: String, url: URL, ecosystem: String) -> [PackageDependency] {
        let locator = PackageLineLocator(text)
        var out: [PackageDependency] = []
        var seen = Set<String>()
        let chunks = text.components(separatedBy: "<dependency>")
        for chunk in chunks.dropFirst() {
            guard let end = chunk.range(of: "</dependency>") else { continue }
            let block = String(chunk[..<end.lowerBound])
            guard let group = regexGroups(#"<groupId>([^<]+)</groupId>"#, in: block).first,
                  let artifact = regexGroups(#"<artifactId>([^<]+)</artifactId>"#, in: block).first,
                  let version = regexGroups(#"<version>([^<]+)</version>"#, in: block).first
            else { continue }
            let name = "\(group[1]):\(artifact[1])"
            let resolved = version[1].trimmingCharacters(in: .whitespacesAndNewlines)
            guard !resolved.contains("${"), isExactVersion(resolved),
                  !seen.contains(name + "@" + resolved) else { continue }
            seen.insert(name + "@" + resolved)
            out.append(makeDependency(name: name, version: resolved, ecosystem: ecosystem,
                                      url: url,
                                      line: locator.line(of: "<artifactId>\(artifact[1])</artifactId>")))
        }
        return out
    }

    static func parseGradleBuild(text: String, url: URL, ecosystem: String) -> [PackageDependency] {
        var out: [PackageDependency] = []
        var seen = Set<String>()
        let configurations = #"(implementation|api|compile|compileOnly|runtimeOnly|testImplementation|testApi|debugImplementation|releaseImplementation|androidTestImplementation|kapt|ksp|annotationProcessor|testCompile)\b"#
        let lines = text.components(separatedBy: "\n")
        for (index, raw) in lines.enumerated() {
            if raw.contains("classpath") || raw.contains("platform(") || raw.contains("enforcedPlatform(") {
                continue
            }
            guard raw.range(of: configurations, options: .regularExpression) != nil else { continue }
            for match in regexGroups(#"['"]([\w.\-]+:[\w.\-]+:[^'"\s]+)['"]"#, in: raw) {
                let parts = match[1].split(separator: ":", maxSplits: 2)
                guard parts.count == 3 else { continue }
                let name = "\(parts[0]):\(parts[1])"
                let version = String(parts[2])
                guard isExactVersion(version), !seen.contains(name + "@" + version) else { continue }
                seen.insert(name + "@" + version)
                out.append(makeDependency(name: name, version: version, ecosystem: ecosystem,
                                          url: url, line: index + 1))
            }
        }
        return out
    }

    static func parseCsproj(text: String, url: URL, ecosystem: String) -> [PackageDependency] {
        let locator = PackageLineLocator(text)
        var out: [PackageDependency] = []
        var seen = Set<String>()

        func add(name: String, version: String, line: Int) {
            let resolved = version.trimmingCharacters(in: .whitespacesAndNewlines)
            guard !resolved.contains("$"), isExactVersion(resolved),
                  !seen.contains(name + "@" + resolved) else { return }
            seen.insert(name + "@" + resolved)
            out.append(makeDependency(name: name, version: resolved, ecosystem: ecosystem,
                                      url: url, line: line))
        }

        for match in regexGroups(#"<PackageReference[^>]*\bInclude="([^"]+)"[^>]*\bVersion="([^"]+)""#,
                                 in: text) {
            add(name: match[1], version: match[2],
                line: locator.line(of: "Include=\"\(match[1])\""))
        }
        for match in regexGroups(#"<PackageReference[^>]*\bInclude="([^"]+)"[^>]*>(.*?)</PackageReference>"#,
                                 in: text) {
            guard let version = regexGroups(#"<Version>([^<]+)</Version>"#, in: match[2]).first else {
                continue
            }
            add(name: match[1], version: version[1],
                line: locator.line(of: "Include=\"\(match[1])\""))
        }
        return out
    }
}

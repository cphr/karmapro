// by cipher.org.uk
import Foundation

extension PackageDetector {

    static func parseNpmLock(text: String, url: URL, ecosystem: String) -> [PackageDependency] {
        guard let root = jsonDict(text) else { return [] }
        let locator = PackageLineLocator(text)
        var out: [PackageDependency] = []
        var seen = Set<String>()

        func add(name: String, version: String) {
            let value = version.trimmingCharacters(in: .whitespaces)
            guard isExactVersion(value), !seen.contains(name + "@" + value) else { return }
            seen.insert(name + "@" + value)
            out.append(makeDependency(name: name, version: value, ecosystem: ecosystem,
                                      url: url, line: locator.line(ofName: name)))
        }

        if let packages = root["packages"] as? [String: Any] {
            for key in packages.keys.sorted() {
                guard key != "", let entry = packages[key] as? [String: Any],
                      (entry["link"] as? Bool) != true,
                      let version = entry["version"] as? String else { continue }
                var name = entry["name"] as? String
                if name == nil && key.contains("node_modules/") {
                    name = key.components(separatedBy: "node_modules/").last
                }
                guard let resolved = name, !resolved.isEmpty else { continue }
                add(name: resolved, version: version)
            }
        } else if let dependencies = root["dependencies"] as? [String: Any] {
            func walk(_ dict: [String: Any]) {
                for key in dict.keys.sorted() {
                    guard let entry = dict[key] as? [String: Any] else { continue }
                    if let version = entry["version"] as? String {
                        add(name: key, version: version)
                    }
                    if let nested = entry["dependencies"] as? [String: Any] {
                        walk(nested)
                    }
                }
            }
            walk(dependencies)
        }
        return out
    }

    static func yarnSelectorName(_ selector: String) -> String? {
        var value = selector.trimmingCharacters(in: .whitespaces)
        value = value.trimmingCharacters(in: CharacterSet(charactersIn: "\""))
        guard !value.isEmpty else { return nil }
        for marker in ["workspace:", "file:", "link:", "portal:", "patch:", "exec:"] {
            if value.contains(marker) { return nil }
        }
        if let range = value.range(of: "@npm:") {
            let name = String(value[..<range.lowerBound])
            return name.isEmpty ? nil : name
        }
        guard let at = value.lastIndex(of: "@"), at > value.startIndex else { return nil }
        let name = String(value[..<at])
        return name.isEmpty ? nil : name
    }

    static func parseYarnLock(text: String, url: URL, ecosystem: String) -> [PackageDependency] {
        let lines = text.components(separatedBy: "\n")
        var out: [PackageDependency] = []
        var seen = Set<String>()
        var names: [String] = []
        var version: String?
        var headerLine = 1

        func flush() {
            defer { names = []; version = nil }
            guard let resolved = version, isExactVersion(resolved) else { return }
            for name in names where !seen.contains(name + "@" + resolved) {
                seen.insert(name + "@" + resolved)
                out.append(makeDependency(name: name, version: resolved, ecosystem: ecosystem,
                                          url: url, line: headerLine))
            }
        }

        for (index, raw) in lines.enumerated() {
            if raw.isEmpty {
                flush()
                continue
            }
            if !raw.hasPrefix(" "), raw.hasSuffix(":") {
                flush()
                headerLine = index + 1
                let header = String(raw.dropLast())
                names = header.split(separator: ",").compactMap { yarnSelectorName(String($0)) }
                continue
            }
            let trimmed = raw.trimmingCharacters(in: .whitespaces)
            guard trimmed.hasPrefix("version") else { continue }
            if let quoted = trimmed.range(of: "\"([^\"]+)\"", options: .regularExpression) {
                let inner = trimmed[quoted]
                version = String(inner.dropFirst().dropLast())
            } else if let colon = trimmed.range(of: "version:") {
                let rest = String(trimmed[colon.upperBound...]).trimmingCharacters(in: .whitespaces)
                if !rest.isEmpty { version = rest }
            }
        }
        flush()
        return out
    }

    static func parsePnpmLock(text: String, url: URL, ecosystem: String) -> [PackageDependency] {
        let lines = text.components(separatedBy: "\n")
        var out: [PackageDependency] = []
        var seen = Set<String>()
        var inPackages = false

        func add(key: String, line: Int) {
            var body = key
            if body.hasPrefix("/") { body = String(body.dropFirst()) }
            guard !body.isEmpty else { return }
            var name: String?
            var version: String?
            if let slash = body.lastIndex(of: "/"),
               body[body.index(after: slash)...].first?.isNumber == true {
                name = String(body[..<slash])
                version = String(body[body.index(after: slash)...])
            } else if let at = body.lastIndex(of: "@"),
                      body[body.index(after: at)...].first?.isNumber == true {
                name = String(body[..<at])
                version = String(body[body.index(after: at)...])
            }
            guard let resolvedName = name, var resolvedVersion = version,
                  !resolvedName.isEmpty else { return }
            if let underscore = resolvedVersion.firstIndex(of: "_") {
                resolvedVersion = String(resolvedVersion[..<underscore])
            }
            if let paren = resolvedVersion.firstIndex(of: "(") {
                resolvedVersion = String(resolvedVersion[..<paren])
            }
            guard isExactVersion(resolvedVersion),
                  !seen.contains(resolvedName + "@" + resolvedVersion) else { return }
            seen.insert(resolvedName + "@" + resolvedVersion)
            out.append(makeDependency(name: resolvedName, version: resolvedVersion,
                                      ecosystem: ecosystem, url: url, line: line))
        }

        for (index, raw) in lines.enumerated() {
            if raw == "packages:" {
                inPackages = true
                continue
            }
            guard inPackages else { continue }
            if raw.isEmpty { continue }
            if !raw.hasPrefix(" ") {
                inPackages = false
                continue
            }
            guard raw.hasPrefix("  "), !raw.hasPrefix("    ") else { continue }
            let trimmed = raw.trimmingCharacters(in: .whitespaces)
            guard trimmed.hasSuffix(":") else { continue }
            var key = String(trimmed.dropLast())
            key = key.trimmingCharacters(in: CharacterSet(charactersIn: "'\""))
            if let paren = key.firstIndex(of: "(") {
                key = String(key[..<paren])
            }
            add(key: key, line: index + 1)
        }
        return out
    }

    static func parseTOMLPackageBlocks(text: String, url: URL, ecosystem: String) -> [PackageDependency] {
        let lines = text.components(separatedBy: "\n")
        var out: [PackageDependency] = []
        var name: String?
        var version: String?
        var blockStart = 1

        func flush() {
            defer { name = nil; version = nil }
            guard let resolvedName = name, let resolvedVersion = version,
                  isExactVersion(resolvedVersion) else { return }
            out.append(makeDependency(name: resolvedName, version: resolvedVersion,
                                      ecosystem: ecosystem, url: url, line: blockStart))
        }

        for (index, raw) in lines.enumerated() {
            let trimmed = raw.trimmingCharacters(in: .whitespaces)
            if trimmed == "[[package]]" {
                flush()
                blockStart = index + 1
            } else if trimmed.hasPrefix("name = ") {
                name = quotedValue(trimmed)
            } else if trimmed.hasPrefix("version = ") {
                version = quotedValue(trimmed)
            }
        }
        flush()
        return out
    }

    static func parsePipfileLock(text: String, url: URL, ecosystem: String) -> [PackageDependency] {
        guard let root = jsonDict(text) else { return [] }
        let locator = PackageLineLocator(text)
        var out: [PackageDependency] = []
        for section in ["default", "develop"] {
            guard let entries = root[section] as? [String: Any] else { continue }
            for name in entries.keys.sorted() {
                guard let entry = entries[name] as? [String: Any],
                      let raw = entry["version"] as? String else { continue }
                var version = raw
                while version.hasPrefix("=") { version.removeFirst() }
                guard isExactVersion(version) else { continue }
                out.append(makeDependency(name: name, version: version, ecosystem: ecosystem,
                                          url: url, line: locator.line(ofName: name)))
            }
        }
        return out
    }

    static func parseRequirements(text: String, url: URL, ecosystem: String) -> [PackageDependency] {
        var out: [PackageDependency] = []
        var seen = Set<String>()
        let lines = text.components(separatedBy: "\n")
        for (index, raw) in lines.enumerated() {
            var line = raw.trimmingCharacters(in: .whitespaces)
            if line.isEmpty || line.hasPrefix("#") || line.hasPrefix("-") || line.hasPrefix("//") {
                continue
            }
            if let hash = line.range(of: " #") {
                line = String(line[..<hash.lowerBound]).trimmingCharacters(in: .whitespaces)
            }
            if let semi = line.firstIndex(of: ";") {
                line = String(line[..<semi]).trimmingCharacters(in: .whitespaces)
            }
            guard let split = line.range(of: "==") else { continue }
            var name = String(line[..<split.lowerBound])
            let version = String(line[split.upperBound...]).trimmingCharacters(in: .whitespaces)
            if let bracket = name.firstIndex(of: "[") {
                name = String(name[..<bracket])
            }
            guard name.range(of: #"^[A-Za-z0-9][A-Za-z0-9._-]*$"#, options: .regularExpression) != nil,
                  isExactVersion(version),
                  !seen.contains(name.lowercased() + "@" + version) else { continue }
            seen.insert(name.lowercased() + "@" + version)
            out.append(makeDependency(name: name, version: version, ecosystem: ecosystem,
                                      url: url, line: index + 1))
        }
        return out
    }

    static func parseCargoLock(text: String, url: URL, ecosystem: String) -> [PackageDependency] {
        let lines = text.components(separatedBy: "\n")
        var out: [PackageDependency] = []
        var name: String?
        var version: String?
        var source: String?
        var blockStart = 1

        func flush() {
            defer { name = nil; version = nil; source = nil }
            guard let resolvedName = name, let resolvedVersion = version,
                  let resolvedSource = source,
                  resolvedSource.hasPrefix("registry+"),
                  isExactVersion(resolvedVersion) else { return }
            out.append(makeDependency(name: resolvedName, version: resolvedVersion,
                                      ecosystem: ecosystem, url: url, line: blockStart))
        }

        for (index, raw) in lines.enumerated() {
            let trimmed = raw.trimmingCharacters(in: .whitespaces)
            if trimmed == "[[package]]" {
                flush()
                blockStart = index + 1
            } else if trimmed.hasPrefix("name = ") {
                name = quotedValue(trimmed)
            } else if trimmed.hasPrefix("version = ") {
                version = quotedValue(trimmed)
            } else if trimmed.hasPrefix("source = ") {
                source = quotedValue(trimmed)
            }
        }
        flush()
        return out
    }

    static func parseComposerLock(text: String, url: URL, ecosystem: String) -> [PackageDependency] {
        guard let root = jsonDict(text) else { return [] }
        let locator = PackageLineLocator(text)
        var out: [PackageDependency] = []
        var seen = Set<String>()
        for section in ["packages", "packages-dev"] {
            guard let entries = root[section] as? [[String: Any]] else { continue }
            for entry in entries {
                guard let name = entry["name"] as? String,
                      var version = entry["version"] as? String else { continue }
                if version.hasPrefix("v") { version.removeFirst() }
                guard isExactVersion(version), !seen.contains(name + "@" + version) else { continue }
                seen.insert(name + "@" + version)
                out.append(makeDependency(name: name, version: version, ecosystem: ecosystem,
                                          url: url, line: locator.line(ofName: name)))
            }
        }
        return out
    }

    static func parseGoMod(text: String, url: URL, ecosystem: String) -> [PackageDependency] {
        let lines = text.components(separatedBy: "\n")
        var out: [PackageDependency] = []
        var seen = Set<String>()
        var inRequireBlock = false

        func add(_ statement: String, line: Int) {
            var value = statement
            if let comment = value.range(of: "//") {
                value = String(value[..<comment.lowerBound])
            }
            let tokens = value.split(whereSeparator: { $0 == " " || $0 == "\t" })
            guard tokens.count >= 2 else { return }
            let name = String(tokens[0])
            let version = String(tokens[1])
            guard version.range(of: #"^v[0-9]+(\.[0-9]+)+([-+][0-9A-Za-z.\-+]+)?$"#,
                                options: .regularExpression) != nil,
                  !seen.contains(name + "@" + version) else { return }
            seen.insert(name + "@" + version)
            out.append(makeDependency(name: name, version: version, ecosystem: ecosystem,
                                      url: url, line: line))
        }

        for (index, raw) in lines.enumerated() {
            let trimmed = raw.trimmingCharacters(in: .whitespaces)
            if inRequireBlock {
                if trimmed == ")" {
                    inRequireBlock = false
                    continue
                }
                add(trimmed, line: index + 1)
                continue
            }
            if trimmed.hasPrefix("require (") {
                inRequireBlock = true
            } else if trimmed.hasPrefix("require ") {
                add(String(trimmed.dropFirst("require ".count)), line: index + 1)
            }
        }
        return out
    }

    static func parseGemfileLock(text: String, url: URL, ecosystem: String) -> [PackageDependency] {
        let lines = text.components(separatedBy: "\n")
        var out: [PackageDependency] = []
        var seen = Set<String>()
        var section = ""
        var inSpecs = false

        for (index, raw) in lines.enumerated() {
            if !raw.hasPrefix(" ") {
                section = raw.trimmingCharacters(in: .whitespaces)
                inSpecs = false
                continue
            }
            guard section == "GEM" else { continue }
            let trimmed = raw.trimmingCharacters(in: .whitespaces)
            if trimmed == "specs:" {
                inSpecs = true
                continue
            }
            guard inSpecs, raw.hasPrefix("    "), !raw.hasPrefix("     ") else { continue }
            guard let open = trimmed.range(of: " ("),
                  let close = trimmed.range(of: ")", range: open.upperBound..<trimmed.endIndex)
            else { continue }
            let name = String(trimmed[..<open.lowerBound])
            let version = String(trimmed[open.upperBound..<close.lowerBound])
            guard !name.isEmpty, isExactVersion(version),
                  !seen.contains(name + "@" + version) else { continue }
            seen.insert(name + "@" + version)
            out.append(makeDependency(name: name, version: version, ecosystem: ecosystem,
                                      url: url, line: index + 1))
        }
        return out
    }

    static func parsePackagesLockJson(text: String, url: URL, ecosystem: String) -> [PackageDependency] {
        guard let root = jsonDict(text),
              let dependencies = root["dependencies"] as? [String: Any] else { return [] }
        let locator = PackageLineLocator(text)
        var out: [PackageDependency] = []
        var seen = Set<String>()
        for framework in dependencies.keys.sorted() {
            guard let entries = dependencies[framework] as? [String: Any] else { continue }
            for name in entries.keys.sorted() {
                guard let entry = entries[name] as? [String: Any],
                      let version = entry["resolved"] as? String,
                      isExactVersion(version),
                      !seen.contains(name + "@" + version) else { continue }
                seen.insert(name + "@" + version)
                out.append(makeDependency(name: name, version: version, ecosystem: ecosystem,
                                          url: url, line: locator.line(ofName: name)))
            }
        }
        return out
    }

    static func normalizedRepositoryURL(_ raw: String) -> String? {
        var value = raw.trimmingCharacters(in: .whitespaces)
        if value.hasPrefix("git@") {
            let rest = String(value.dropFirst("git@".count))
            if let colon = rest.firstIndex(of: ":") {
                let host = String(rest[..<colon])
                let path = String(rest[rest.index(after: colon)...])
                value = "https://\(host)/\(path)"
            }
        }
        guard value.hasPrefix("http://") || value.hasPrefix("https://") else { return nil }
        if value.hasSuffix(".git") { value = String(value.dropLast(4)) }
        while value.hasSuffix("/") { value.removeLast() }
        return value
    }

    static func parsePackageResolved(text: String, url: URL, ecosystem: String) -> [PackageDependency] {
        guard let root = jsonDict(text) else { return [] }
        let locator = PackageLineLocator(text)
        var entries: [[String: Any]] = []
        if let objects = root["objects"] as? [[String: Any]] {
            entries.append(contentsOf: objects)
        }
        if let pins = root["pins"] as? [[String: Any]] {
            entries.append(contentsOf: pins)
        }
        var out: [PackageDependency] = []
        var seen = Set<String>()
        for entry in entries {
            let repository = (entry["location"] as? String) ?? (entry["repositoryURL"] as? String)
            let state = entry["state"] as? [String: Any]
            guard let repositoryURL = repository,
                  let version = state?["version"] as? String,
                  let name = normalizedRepositoryURL(repositoryURL),
                  isExactVersion(version),
                  !seen.contains(name + "@" + version) else { continue }
            seen.insert(name + "@" + version)
            let identity = (entry["identity"] as? String) ?? (entry["package"] as? String) ?? name
            out.append(makeDependency(name: name, version: version, ecosystem: ecosystem,
                                      url: url, line: locator.line(ofName: identity)))
        }
        return out
    }

    static func parseGradleLockfile(text: String, url: URL, ecosystem: String) -> [PackageDependency] {
        var out: [PackageDependency] = []
        var seen = Set<String>()
        let lines = text.components(separatedBy: "\n")
        for (index, raw) in lines.enumerated() {
            let trimmed = raw.trimmingCharacters(in: .whitespaces)
            if trimmed.isEmpty || trimmed.hasPrefix("#") { continue }
            let left = trimmed.split(separator: "=", maxSplits: 1).first.map(String.init) ?? trimmed
            let parts = left.split(separator: ":")
            guard parts.count == 3 else { continue }
            let name = "\(parts[0]):\(parts[1])"
            let version = String(parts[2])
            guard isExactVersion(version), !seen.contains(name + "@" + version) else { continue }
            seen.insert(name + "@" + version)
            out.append(makeDependency(name: name, version: version, ecosystem: ecosystem,
                                      url: url, line: index + 1))
        }
        return out
    }

    static func parseVersionCatalog(text: String, url: URL, ecosystem: String) -> [PackageDependency] {
        let lines = text.components(separatedBy: "\n")
        var versions: [String: String] = [:]
        var section = ""
        for raw in lines {
            let trimmed = raw.trimmingCharacters(in: .whitespaces)
            if trimmed.hasPrefix("["), trimmed.hasSuffix("]") {
                section = trimmed
                continue
            }
            guard section == "[versions]", let equals = trimmed.range(of: " = ") else { continue }
            let key = String(trimmed[..<equals.lowerBound])
            guard let value = quotedValue(String(trimmed[equals.upperBound...])) else { continue }
            versions[key] = value
        }

        var out: [PackageDependency] = []
        var seen = Set<String>()
        section = ""
        for (index, raw) in lines.enumerated() {
            let trimmed = raw.trimmingCharacters(in: .whitespaces)
            if trimmed.hasPrefix("["), trimmed.hasSuffix("]") {
                section = trimmed
                continue
            }
            guard section == "[libraries]" else { continue }
            guard let module = regexGroups(#"module\s*=\s*"([^"]+)""#, in: trimmed).first else {
                continue
            }
            let parts = module[1].split(separator: ":")
            guard parts.count == 2 else { continue }
            let name = module[1]
            var version: String?
            if let direct = regexGroups(#"version\s*=\s*"([^"]+)""#, in: trimmed).first {
                version = direct[1]
            } else if let ref = regexGroups(#"version\.ref\s*=\s*"([^"]+)""#, in: trimmed).first {
                version = versions[ref[1]]
            }
            guard let resolved = version, isExactVersion(resolved),
                  !seen.contains(name + "@" + resolved) else { continue }
            seen.insert(name + "@" + resolved)
            out.append(makeDependency(name: name, version: resolved, ecosystem: ecosystem,
                                      url: url, line: index + 1))
        }
        return out
    }
}

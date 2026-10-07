// by cipher.org.uk
import Foundation

struct PackageDependency {
    let name: String
    let version: String
    let ecosystem: String
    let fileURL: URL
    let line: Int
}

struct PackageDetection {
    struct DetectedFile {
        let url: URL
        let relativePath: String
        let language: String
        let ecosystem: String
        let isLockfile: Bool
    }
    let files: [DetectedFile]
    let dependencies: [PackageDependency]
}

enum PackageDetector {
    typealias FileSpec = (language: String, ecosystem: String)

    static let lockFileSpecs: [String: FileSpec] = [
        "package-lock.json": ("JavaScript", "npm"),
        "npm-shrinkwrap.json": ("JavaScript", "npm"),
        "yarn.lock": ("JavaScript", "npm"),
        "pnpm-lock.yaml": ("JavaScript", "npm"),
        "poetry.lock": ("Python", "PyPI"),
        "Pipfile.lock": ("Python", "PyPI"),
        "uv.lock": ("Python", "PyPI"),
        "requirements.txt": ("Python", "PyPI"),
        "Cargo.lock": ("Rust", "crates.io"),
        "composer.lock": ("PHP", "Packagist"),
        "go.mod": ("Go", "Go"),
        "Gemfile.lock": ("Ruby", "RubyGems"),
        "packages.lock.json": (".NET", "NuGet"),
        "Package.resolved": ("Swift", "SwiftURL"),
        "gradle.lockfile": ("Java", "Maven"),
        "libs.versions.toml": ("Java", "Maven"),
    ]

    static let manifestFileSpecs: [String: FileSpec] = [
        "package.json": ("JavaScript", "npm"),
        "pyproject.toml": ("Python", "PyPI"),
        "Cargo.toml": ("Rust", "crates.io"),
        "composer.json": ("PHP", "Packagist"),
        "Gemfile": ("Ruby", "RubyGems"),
        "pom.xml": ("Java", "Maven"),
        "build.gradle": ("Java", "Maven"),
        "build.gradle.kts": ("Java", "Maven"),
    ]

    private static let skippedDirectoryNames: Set<String> = [
        "node_modules", "vendor", "Pods", "Carthage", "build", "Build", "BUILD",
        "dist", "Dist", "out", "target", "bin", "obj", "packages", "DerivedData",
        "__pycache__", "bower_components", "coverage", "tmp", "venv", "Godeps",
    ]

    static func detect(root: URL) -> PackageDetection {
        let fm = FileManager.default
        let rootPath = root.standardizedFileURL.path
        var locks: [(url: URL, spec: FileSpec)] = []
        var manifests: [(url: URL, spec: FileSpec)] = []

        let resourceKeys: [URLResourceKey] = [.isDirectoryKey]
        guard let enumerator = fm.enumerator(at: root,
                                             includingPropertiesForKeys: resourceKeys,
                                             options: [.skipsHiddenFiles]) else {
            return PackageDetection(files: [], dependencies: [])
        }

        for case let url as URL in enumerator {
            let values = try? url.resourceValues(forKeys: Set(resourceKeys))
            if values?.isDirectory == true {
                if skippedDirectoryNames.contains(url.lastPathComponent) {
                    enumerator.skipDescendants()
                }
                continue
            }
            if relativePath(of: url, rootPath: rootPath).split(separator: "/").count > 10 {
                continue
            }
            let name = url.lastPathComponent
            if let spec = lockFileSpecs[name] {
                locks.append((url, spec))
            } else if let spec = manifestFileSpecs[name] {
                manifests.append((url, spec))
            } else if url.pathExtension.lowercased() == "csproj" {
                manifests.append((url, (language: ".NET", ecosystem: "NuGet")))
            }
        }

        let languagesWithLocks = Set(locks.map { $0.spec.language })
        var kept: [(url: URL, spec: FileSpec, isLockfile: Bool)] = []
        kept.append(contentsOf: locks.map { ($0.url, $0.spec, true) })
        kept.append(contentsOf: manifests
            .filter { !languagesWithLocks.contains($0.spec.language) }
            .map { ($0.url, $0.spec, false) })

        var files: [PackageDetection.DetectedFile] = []
        var dependencies: [PackageDependency] = []
        for entry in kept {
            files.append(PackageDetection.DetectedFile(
                url: entry.url,
                relativePath: relativePath(of: entry.url, rootPath: rootPath),
                language: entry.spec.language,
                ecosystem: entry.spec.ecosystem,
                isLockfile: entry.isLockfile))
            guard let text = try? String(contentsOf: entry.url, encoding: .utf8) else { continue }
            dependencies.append(contentsOf: parse(text: text,
                                                  url: entry.url,
                                                  ecosystem: entry.spec.ecosystem))
        }

        files.sort { $0.relativePath < $1.relativePath }
        dependencies.sort {
            if $0.fileURL.path != $1.fileURL.path { return $0.fileURL.path < $1.fileURL.path }
            if $0.line != $1.line { return $0.line < $1.line }
            return $0.name < $1.name
        }
        return PackageDetection(files: files, dependencies: dependencies)
    }

    private static func relativePath(of url: URL, rootPath: String) -> String {
        if url.path.hasPrefix(rootPath + "/") {
            return String(url.path.dropFirst(rootPath.count + 1))
        }
        return url.lastPathComponent
    }

    static func parse(text: String, url: URL, ecosystem: String) -> [PackageDependency] {
        switch url.lastPathComponent {
        case "package-lock.json", "npm-shrinkwrap.json":
            return parseNpmLock(text: text, url: url, ecosystem: ecosystem)
        case "yarn.lock":
            return parseYarnLock(text: text, url: url, ecosystem: ecosystem)
        case "pnpm-lock.yaml":
            return parsePnpmLock(text: text, url: url, ecosystem: ecosystem)
        case "package.json":
            return parsePackageJsonManifest(text: text, url: url, ecosystem: ecosystem)
        case "poetry.lock", "uv.lock":
            return parseTOMLPackageBlocks(text: text, url: url, ecosystem: ecosystem)
        case "pyproject.toml":
            return parsePyproject(text: text, url: url, ecosystem: ecosystem)
        case "Pipfile.lock":
            return parsePipfileLock(text: text, url: url, ecosystem: ecosystem)
        case "requirements.txt":
            return parseRequirements(text: text, url: url, ecosystem: ecosystem)
        case "Cargo.lock":
            return parseCargoLock(text: text, url: url, ecosystem: ecosystem)
        case "Cargo.toml":
            return parseCargoToml(text: text, url: url, ecosystem: ecosystem)
        case "composer.lock":
            return parseComposerLock(text: text, url: url, ecosystem: ecosystem)
        case "composer.json":
            return parseComposerJson(text: text, url: url, ecosystem: ecosystem)
        case "go.mod":
            return parseGoMod(text: text, url: url, ecosystem: ecosystem)
        case "Gemfile.lock":
            return parseGemfileLock(text: text, url: url, ecosystem: ecosystem)
        case "Gemfile":
            return parseGemfile(text: text, url: url, ecosystem: ecosystem)
        case "packages.lock.json":
            return parsePackagesLockJson(text: text, url: url, ecosystem: ecosystem)
        case "Package.resolved":
            return parsePackageResolved(text: text, url: url, ecosystem: ecosystem)
        case "gradle.lockfile":
            return parseGradleLockfile(text: text, url: url, ecosystem: ecosystem)
        case "libs.versions.toml":
            return parseVersionCatalog(text: text, url: url, ecosystem: ecosystem)
        case "pom.xml":
            return parsePom(text: text, url: url, ecosystem: ecosystem)
        case "build.gradle", "build.gradle.kts":
            return parseGradleBuild(text: text, url: url, ecosystem: ecosystem)
        default:
            if url.pathExtension.lowercased() == "csproj" {
                return parseCsproj(text: text, url: url, ecosystem: ecosystem)
            }
            return []
        }
    }

    static func isExactVersion(_ raw: String) -> Bool {
        let value = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !value.isEmpty else { return false }
        if value.contains("://") || value.hasPrefix("git") || value.hasPrefix("file:")
            || value.hasPrefix("http") || value.hasPrefix("workspace:") || value.hasPrefix("link:") {
            return false
        }
        return value.range(of: #"^[0-9]+(\.[0-9]+)+([-+][0-9A-Za-z.\-+]+)?$"#,
                           options: .regularExpression) != nil
    }

    static func jsonDict(_ text: String) -> [String: Any]? {
        guard let data = text.data(using: .utf8),
              let object = try? JSONSerialization.jsonObject(with: data),
              let dict = object as? [String: Any] else { return nil }
        return dict
    }

    static func quotedValue(_ line: String) -> String? {
        guard let first = line.firstIndex(of: "\""),
              let last = line.lastIndex(of: "\""),
              first < last else { return nil }
        return String(line[line.index(after: first)..<last])
    }

    static func regexGroups(_ pattern: String, in text: String) -> [[String]] {
        guard let regex = try? NSRegularExpression(pattern: pattern) else { return [] }
        let full = NSRange(text.startIndex..<text.endIndex, in: text)
        return regex.matches(in: text, range: full).map { match in
            (0..<match.numberOfRanges).map { index in
                guard let range = Range(match.range(at: index), in: text) else { return "" }
                return String(text[range])
            }
        }
    }

    static func makeDependency(name: String, version: String, ecosystem: String,
                               url: URL, line: Int) -> PackageDependency {
        PackageDependency(name: name,
                          version: version,
                          ecosystem: ecosystem,
                          fileURL: url,
                          line: line)
    }
}

final class PackageLineLocator {
    private let text: NSString
    private let starts: [Int]
    private var hint = 0

    init(_ string: String) {
        text = string as NSString
        let length = text.length
        var offsets = [0]
        if length > 0 {
            var buffer = [UniChar](repeating: 0, count: length)
            text.getCharacters(&buffer, range: NSRange(location: 0, length: length))
            for index in 0..<length where buffer[index] == 10 {
                offsets.append(index + 1)
            }
        }
        starts = offsets
    }

    func line(of needle: String) -> Int {
        guard let range = find(needle) else { return 1 }
        return lineNumber(at: range.location)
    }

    func line(ofName name: String) -> Int {
        if let range = find("\"\(name)\"") {
            return lineNumber(at: range.location)
        }
        if let range = find(name) {
            return lineNumber(at: range.location)
        }
        return 1
    }

    private func find(_ needle: String) -> NSRange? {
        guard !needle.isEmpty, text.length > 0 else { return nil }
        let length = text.length
        let from = min(hint, length)
        var found = text.range(of: needle, options: [],
                               range: NSRange(location: from, length: length - from))
        if found.location == NSNotFound && hint > 0 {
            found = text.range(of: needle, options: [],
                               range: NSRange(location: 0, length: length))
        }
        guard found.location != NSNotFound else { return nil }
        hint = found.location + max(found.length, 1)
        return found
    }

    private func lineNumber(at location: Int) -> Int {
        var low = 0
        var high = starts.count - 1
        var answer = 0
        while low <= high {
            let mid = (low + high) / 2
            if starts[mid] <= location {
                answer = mid
                low = mid + 1
            } else {
                high = mid - 1
            }
        }
        return answer + 1
    }
}

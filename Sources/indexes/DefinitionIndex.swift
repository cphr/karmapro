// by cipher.org.uk
import Foundation

/// One location where a function/method is defined within the project.
struct DefinitionLocation: Equatable {
    let fileURL: URL
    /// Offset of the *name* in the defining file's source.
    let nameOffset: Int
    /// File extension (used to re-derive the language when building the popup).
    let ext: String
}

/// A project-wide map of function/method name → definition locations, used to
/// resolve a *call site* to the source definition of the called symbol.
///
/// This is a thin, derived view over a `ProjectSourceIndex`: the name-based
/// map is computed from the definitions the shared index already parsed, so no
/// source file is walked or read a second time. Name-based (not
/// scope/signature aware) by design — a call site resolves to a matching
/// definition of the same name.
struct DefinitionIndex {
    private let definitions: [String: [DefinitionLocation]]

    private init(definitions: [String: [DefinitionLocation]]) {
        self.definitions = definitions
    }

    /// Derives the call-site index from the already-built project source index.
    static func build(sourceIndex: ProjectSourceIndex) -> DefinitionIndex {
        var map: [String: [DefinitionLocation]] = [:]
        for (url, entry) in sourceIndex.entries {
            let ext = url.pathExtension.lowercased()
            for def in entry.funcs {
                guard def.nameRange.location != NSNotFound, def.nameRange.length > 0 else { continue }
                let loc = DefinitionLocation(fileURL: url,
                                             nameOffset: def.nameRange.location,
                                             ext: ext)
                map[def.name, default: []].append(loc)
            }
        }
        // Deterministic ordering doesn't matter for name-based lookup; keep insertion.
        return DefinitionIndex(definitions: map)
    }

    /// True iff `name` names at least one definition inside the project.
    func contains(name: String) -> Bool {
        definitions[name] != nil
    }

    /// All definitions of `name`. Prefers one inside `preferredFileURL` when the
    /// caller is browsing that file (same-file definitions take precedence), but
    /// returns the first definition if none match.
    func lookUp(name: String, preferredFileURL: URL? = nil) -> DefinitionLocation? {
        guard let locs = definitions[name], !locs.isEmpty else { return nil }
        if let preferred = preferredFileURL {
            if let sameFile = locs.first(where: { $0.fileURL.standardizedFileURL == preferred.standardizedFileURL }) {
                return sameFile
            }
        }
        return locs[0]
    }
}
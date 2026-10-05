// by cipher.org.uk
import Foundation

/// Orders two version strings.
///
/// Both sides are reduced to integer components: an optional leading `v` is
/// dropped, the rest is split on `.`, and a missing component counts as zero, so
/// `0.13`, `v0.13` and `0.13.0` are all the same version. Components are
/// compared **numerically, never lexically**, because `0.10` is a later release
/// than `0.9` and plain string ordering gets that backwards.
///
/// Kept free of AppKit and the network so it can be exercised directly.
enum VersionComparator {
    enum Ordering {
        case older, same, newer
    }

    /// Ordered comparison of two versions or release tags.
    static func compare(_ lhs: String, _ rhs: String) -> Ordering {
        guard let left = components(of: lhs), let right = components(of: rhs) else {
            // An unreadable side is treated as the older one so the caller can
            // decide; `UpdateChecker` rejects it before it ever gets here.
            return .older
        }
        for index in 0..<max(left.count, right.count) {
            let l = index < left.count ? left[index] : 0
            let r = index < right.count ? right[index] : 0
            if l != r { return l < r ? .older : .newer }
        }
        return .same
    }

    /// True when `tag` names a strictly newer version than `current`.
    static func isNewer(tag: String, than current: String) -> Bool {
        compare(tag, current) == .newer
    }

    /// Drops a leading `v` and returns the bare version, e.g. `v0.14` → `0.14`.
    static func normalised(_ version: String) -> String {
        var text = version.trimmingCharacters(in: .whitespacesAndNewlines)
        if text.hasPrefix("v") || text.hasPrefix("V") { text.removeFirst() }
        return text
    }

    /// Splits a version or tag into its integer components, or nil when it
    /// carries no version this can read.
    ///
    /// Every component must be digits. `0.14` and `v0.14` are accepted;
    /// `0.14-beta` and an empty tag are not. Nothing is guessed at, because a
    /// wrong guess here would either hide a real release or offer one that does
    /// not exist — `UpdateChecker` turns a nil into its generic failure instead.
    static func components(of version: String) -> [Int]? {
        let text = normalised(version)
        guard !text.isEmpty else { return nil }
        let parts = text.split(separator: ".", omittingEmptySubsequences: false)
        var result: [Int] = []
        for part in parts {
            guard !part.isEmpty,
                  part.allSatisfy({ $0.isASCII && $0.isNumber }),
                  let value = Int(part) else { return nil }
            result.append(value)
        }
        return result
    }
}

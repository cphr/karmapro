// by cipher.org.uk
import Foundation

/// A tokenized Naive Bayes classifier for source code lines.
///
/// A line of source is treated as a "bag of tokens". The classifier learns
/// P(token | good) and P(token | bad) from training patches, then, for an
/// unclassified line, computes the probability that the line belongs to the
/// "bad" (vulnerable/removed) class using Bayes' rule with add-one (Laplace)
/// smoothing.
final class BayesianClassifier: Codable {
    var name: String
    var goodTokens: [String: Int]   // token -> count observed in "+" lines
    var badTokens: [String: Int]    // token -> count observed in "-" lines
    var goodExamples: Int
    var badExamples: Int

    init(name: String) {
        self.name = name
        self.goodTokens = [:]
        self.badTokens = [:]
        self.goodExamples = 0
        self.badExamples = 0
    }

    // MARK: - Vocabulary / tokenization

    /// Tokenizes a single source line into lowercase word tokens and symbols.
    static func tokenize(_ line: String) -> [String] {
        // Lowercase, then split on anything that is not a letter/digit/underscore.
        let lowered = line.lowercased()
        var tokens: [String] = []
        var current = ""
        for ch in lowered {
            if ch.isLetter || ch.isNumber || ch == "_" {
                current.append(ch)
            } else {
                if !current.isEmpty {
                    tokens.append(current)
                    current = ""
                } else if !ch.isWhitespace {
                    // Keep meaningful single-character symbols (operators) as tokens.
                    tokens.append(String(ch))
                }
            }
        }
        if !current.isEmpty { tokens.append(current) }
        return tokens
    }

    /// Tokens that carry real signal (longer identifiers, or a curated symbol set).
    static func signalTokens(_ tokens: [String]) -> Set<String> {
        var set: Set<String> = []
        let symbolSignals: Set<Character> = ["*", "%", "=", "<", ">", "!", "&", "|", "+", "-"]
        for t in tokens {
            if t.count >= 3 {
                set.insert(t)
            } else if t.count == 1, let first = t.first, symbolSignals.contains(first) {
                set.insert(t)
            }
        }
        return set
    }

    // MARK: - Training

    /// Trains on one labeled line. `isBad == true` means "+" (added/fixed/good),
    /// actually: in a patch, "+" denotes the good (added) side and "-" the bad
    /// (removed) side. We therefore label "+" as good and "-" as bad.
    func train(line: String, isBad: Bool) {
        let tokens = BayesianClassifier.tokenize(line)
        let keep = BayesianClassifier.signalTokens(tokens)
        if isBad {
            badExamples += 1
            for t in keep { badTokens[t, default: 0] += 1 }
        } else {
            goodExamples += 1
            for t in keep { goodTokens[t, default: 0] += 1 }
        }
    }

    // MARK: - Classification

    private var _vocabSizeCache: Int?

    private func vocabSize() -> Int {
        if let v = _vocabSizeCache { return v }
        var keys = Set(goodTokens.keys)
        keys.formUnion(badTokens.keys)
        let v = keys.count
        _vocabSizeCache = v
        return v
    }

    /// Returns the probability (0...1) that a line is "bad" (vulnerable), using
    /// a Naive Bayes model with Laplace smoothing.
    func probabilityBad(line: String) -> Double {
        let tokens = BayesianClassifier.tokenize(line)
        let keep = BayesianClassifier.signalTokens(tokens)
        guard !keep.isEmpty else { return 0.5 }

        let totalExamples = Double(goodExamples + badExamples)
        guard totalExamples > 0 else { return 0.5 }
        let priorBad = Double(badExamples) / totalExamples
        let priorGood = 1.0 - priorBad

        let V = Double(vocabSize())
        let alpha = 1.0

        var logBad = log(priorBad)
        var logGood = log(priorGood)
        for t in keep {
            let b = Double(badTokens[t] ?? 0) + alpha
            let g = Double(goodTokens[t] ?? 0) + alpha
            let denomBad = Double(badExamples) + V * alpha
            let denomGood = Double(goodExamples) + V * alpha
            logBad += log(b / denomBad)
            logGood += log(g / denomGood)
        }

        // Numerically-stable sigmoid of the log-odds difference.
        let diff = logBad - logGood
        let probBad = 1.0 / (1.0 + exp(-diff))
        return min(max(probBad, 0.0), 1.0)
    }

    // MARK: - Persistence helpers

    func jsonData() throws -> Data {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        return try encoder.encode(self)
    }

    static func from(data: Data) throws -> BayesianClassifier {
        return try JSONDecoder().decode(BayesianClassifier.self, from: data)
    }
}

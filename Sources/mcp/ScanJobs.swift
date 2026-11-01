// by cipher.org.uk
import Foundation

enum ScanEngine: String {
    case staticScan = "static"
    case ai
    case both

    var usesAI: Bool { self != .staticScan }
}

struct ScanSummary {
    let findings: Int
    let critical: Int
    let high: Int
    let medium: Int
    let low: Int
    let engines: [String: Int]

    init(_ findings: [ScanFinding]) {
        var engines: [String: Int] = [:]
        var critical = 0, high = 0, medium = 0, low = 0
        for f in findings {
            engines[f.scanningSource, default: 0] += 1
            switch f.severity {
            case .critical: critical += 1
            case .high: high += 1
            case .medium: medium += 1
            case .low: low += 1
            }
        }
        self.findings = findings.count
        self.critical = critical
        self.high = high
        self.medium = medium
        self.low = low
        self.engines = engines
    }

    var json: [String: Any] {
        ["findings": findings, "critical": critical, "high": high,
         "medium": medium, "low": low, "engines": engines]
    }
}

final class ScanJob {
    enum Status: String {
        case queued, running, completed, failed, cancelled
    }

    let id: String
    let path: String
    let engine: ScanEngine
    let model: String?
    let createdAt = Date()

    fileprivate var status: Status = .queued
    fileprivate var stage = "queued"
    fileprivate var progress: Double = 0
    fileprivate var summary: ScanSummary?
    fileprivate var sarif: String?
    fileprivate var error: String?
    fileprivate var finishedAt: Date?
    fileprivate var cancelRequested = false

    init(id: String, path: String, engine: ScanEngine, model: String?) {
        self.id = id
        self.path = path
        self.engine = engine
        self.model = model
    }

    var isFinished: Bool { status == .completed || status == .failed || status == .cancelled }

    /// Read on the runner queue when broadcasting a progress notification.
    var progressInfo: (status: String, stage: String, progress: Double) {
        (status.rawValue, stage, progress)
    }

    /// `inlineSARIF` keeps the document out of the poll response when it is huge.
    func json(inlineSARIF: Bool) -> [String: Any] {
        var out: [String: Any] = [
            "job_id": id,
            "status": status.rawValue,
            "engine": engine.rawValue,
            "path": path,
            "stage": stage,
            "progress": (progress * 1000).rounded() / 1000,
            "created_at": ISO8601DateFormatter().string(from: createdAt)
        ]
        if let model { out["model"] = model }
        if let summary { out["summary"] = summary.json }
        if let error { out["error"] = error }
        if let sarif {
            if inlineSARIF {
                out["sarif"] = sarif
            } else {
                out["sarif_resource"] = "sarif://job/\(id)"
                out["sarif_bytes"] = sarif.utf8.count
            }
        }
        return out
    }
}

/// Runs one scan at a time, reusing the app's own engines: the built-in
/// scanner on a background queue and the AI pass through AISecurityScanner,
/// which keeps its provider worker pool (1 for local, 3 for keyed endpoints).
final class ScanJobRunner {
    static let shared = ScanJobRunner()

    /// Called whenever a job's state changes. Fires on the runner's queue.
    var onUpdate: ((ScanJob) -> Void)?

    private let queue = DispatchQueue(label: "app.karmapro.mcp.jobs")
    private var pending: [ScanJob] = []
    private var running: ScanJob?
    private var finished: [ScanJob] = []
    private var lastPublish = Date.distantPast

    // MARK: - Submission

    func submit(path: String, engine: ScanEngine, model: String?) -> ScanJob {
        let job = ScanJob(id: Self.makeID(), path: path, engine: engine, model: model)
        // Synchronous so the job is queryable the moment this returns; no
        // callback here re-enters the runner.
        queue.sync {
            self.pending.append(job)
            self.publish(job, force: true)
            self.startNextLocked()
        }
        return job
    }

    func job(id: String) -> ScanJob? {
        queue.sync { jobLocked(id) }
    }

    private func jobLocked(_ id: String) -> ScanJob? {
        if let running, running.id == id { return running }
        return pending.first { $0.id == id } ?? finished.first { $0.id == id }
    }

    /// A consistent copy of a job's state, safe to read off the runner queue.
    func snapshot(id: String, inlineSARIF: Bool = false) -> [String: Any]? {
        queue.sync { jobLocked(id)?.json(inlineSARIF: inlineSARIF) }
    }

    func sarifText(id: String) -> String? {
        queue.sync { jobLocked(id)?.sarif }
    }

    /// Every completed report, for `resources/list`.
    func documents() -> [(id: String, bytes: Int)] {
        queue.sync {
            finished.compactMap { job in
                guard let sarif = job.sarif else { return nil }
                return (job.id, sarif.utf8.count)
            }
        }
    }

    @discardableResult
    func cancel(id: String) -> ScanJob? {
        queue.sync {
            if let running, running.id == id {
                running.cancelRequested = true
                running.stage = "cancelling"
                return running
            }
            if let index = pending.firstIndex(where: { $0.id == id }) {
                let job = pending.remove(at: index)
                job.status = .cancelled
                job.stage = "cancelled"
                job.finishedAt = Date()
                self.finished.append(job)
                self.publish(job, force: true)
                return job
            }
            return finished.first { $0.id == id }
        }
    }

    func retained() -> [ScanJob] {
        queue.sync { finished.filter { $0.sarif != nil } }
    }

    // MARK: - Execution

    private func startNextLocked() {
        guard running == nil, !pending.isEmpty else { return }
        let job = pending.removeFirst()
        running = job
        job.status = .running
        job.stage = "static scan"
        publish(job, force: true)
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            self?.execute(job)
        }
    }

    /// `ai` skips the built-in pass entirely; `both` uses it as the baseline the
    /// AI findings are merged against, exactly as the Security Scan window does.
    private func execute(_ job: ScanJob) {
        if job.engine == .ai {
            runAI(job, baseline: [])
            return
        }
        let findings = VulnerabilityScanner.scan(
            projectRoot: URL(fileURLWithPath: job.path),
            progress: { [weak self] done, total in
                guard let self else { return }
                let fraction = total > 0 ? Double(done) / Double(total) : 0
                self.update(job) {
                    $0.stage = "static scan \(done)/\(total)"
                    $0.progress = $0.engine == .both ? fraction * 0.4 : fraction
                }
            },
            isCancelled: { job.cancelRequested }
        )

        if job.cancelRequested {
            finish(job, .cancelled, findings: findings)
            return
        }
        guard job.engine == .both else {
            finish(job, .completed, findings: findings)
            return
        }
        runAI(job, baseline: findings)
    }

    private func runAI(_ job: ScanJob, baseline: [ScanFinding]) {
        let client = OpenRouterClient.shared
        if client.requiresAPIKey,
           client.apiKey.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
            finish(job, .failed, findings: baseline,
                   error: "AI scan needs an API key. Connect \(client.provider.name) in the AI Assistant window first.")
            return
        }

        update(job) {
            $0.stage = "AI scan"
            $0.progress = $0.engine == .both ? 0.4 : 0
        }

        AISecurityScanner.runAI(
            projectRoot: URL(fileURLWithPath: job.path),
            existingFindings: baseline,
            progress: { [weak self] fraction in
                self?.update(job) {
                    let scaled = $0.engine == .both ? 0.4 + 0.6 * min(max(fraction, 0), 1)
                                                   : min(max(fraction, 0), 1)
                    $0.progress = min(scaled, 1)
                    $0.stage = "AI scan"
                }
            },
            isCancelled: { job.cancelRequested },
            completion: { [weak self] result in
                guard let self else { return }
                if job.cancelRequested {
                    self.finish(job, .cancelled, findings: result.findings)
                } else {
                    self.finish(job, .completed, findings: result.findings)
                }
            },
            onPhase: { [weak self] phase in
                self?.update(job) {
                    $0.stage = phase == .thinking ? "AI thinking" : "AI answering"
                }
            },
            modelOverride: job.model)
    }

    private func finish(_ job: ScanJob, _ status: ScanJob.Status,
                        findings: [ScanFinding] = [], error: String? = nil) {
        var sarif: String?
        if status == .completed || !findings.isEmpty {
            if let data = try? SARIFExport.data(from: findings) {
                sarif = String(data: data, encoding: .utf8)
            }
        }
        queue.async {
            job.status = status
            job.stage = status == .completed ? "done" : status.rawValue
            job.error = error
            job.summary = ScanSummary(findings)
            job.sarif = sarif
            job.progress = 1
            job.finishedAt = Date()
            if let running = self.running, running === job { self.running = nil }
            self.finished.append(job)
            self.prune()
            self.publish(job, force: true)
            self.startNextLocked()
        }
    }

    private func update(_ job: ScanJob, _ body: @escaping (ScanJob) -> Void) {
        queue.async {
            body(job)
            self.publish(job, force: false)
        }
    }

    /// Progress fires often (once per file); throttle so notifications stay sane.
    private func publish(_ job: ScanJob, force: Bool) {
        let now = Date()
        guard force || now.timeIntervalSince(lastPublish) > 0.4 else { return }
        lastPublish = now
        onUpdate?(job)
    }

    private func prune() {
        let cutoff = Date().addingTimeInterval(-2 * 60 * 60)
        finished.removeAll { ($0.finishedAt ?? Date()) < cutoff }
        if finished.count > 50 { finished.removeFirst(finished.count - 50) }
    }

    private static func makeID() -> String {
        UUID().uuidString.replacingOccurrences(of: "-", with: "").lowercased()
    }
}

// by cipher.org.uk
import AppKit

/// Window that plots the cyclomatic complexity of every function in a project
/// as a scatter chart (one colour-coded point per function, labelled with its
/// complexity value). Opened from the source viewer's context menu.
final class ComplexityScatterWindowController: NSWindowController {
    private let scatterView = ComplexityScatterView()
    private let summaryLabel = NSTextField(labelWithString: "")
    private let hoverLabel = NSTextField(labelWithString: "")
    /// Big, centered "Analyzing complexity distribution…" block shown while the
    /// background scan runs; the previous small header spinner was easy to miss.
    private let analyzingView = NSView()
    private let analyzingSpinner = NSProgressIndicator()
    private let analyzingLabel = NSTextField(labelWithString: "Analyzing complexity distribution…")

    /// Fired when the user clicks a point in the chart. Passes file + 1-based line.
    var onOpenFile: ((URL, Int) -> Void)?

    private var fileURL: URL?

    /// Bumped on every load so a slow background analysis can never clobber a
    /// newer one that started while it was still running.
    private var loadGeneration = 0

    /// Cooperative stop flag for the running project analysis. Set when the
    /// window closes (or a new load supersedes the current one) so the
    /// background worker exits early instead of finishing the whole scan.
    private var analysisCancellation: VariableFlowCancellation?

    convenience init() {
        let window = EscClosableWindow(
            contentRect: NSRect(x: 0, y: 0, width: 760, height: 520),
            styleMask: [.titled, .closable, .resizable],
            backing: .buffered,
            defer: false
        )
        window.title = "Complexity distribution"
        window.minSize = NSSize(width: 480, height: 320)
        self.init(window: window)
        window.delegate = self
        buildContent()
    }

    /// Centers the window on screen every time it is shown.
    override func showWindow(_ sender: Any?) {
        window?.center()
        super.showWindow(sender)
    }

    private func buildContent() {
        guard let content = window?.contentView else { return }

        summaryLabel.font = NSFont.systemFont(ofSize: 13, weight: .semibold)
        summaryLabel.textColor = .labelColor
        summaryLabel.translatesAutoresizingMaskIntoConstraints = false
        content.addSubview(summaryLabel)

        analyzingSpinner.style = .spinning
        analyzingSpinner.isIndeterminate = true
        analyzingSpinner.controlSize = .regular
        analyzingSpinner.translatesAutoresizingMaskIntoConstraints = false
        analyzingView.addSubview(analyzingSpinner)

        analyzingLabel.font = NSFont.systemFont(ofSize: 14)
        analyzingLabel.textColor = .secondaryLabelColor
        analyzingLabel.alignment = .center
        analyzingLabel.translatesAutoresizingMaskIntoConstraints = false
        analyzingView.addSubview(analyzingLabel)

        analyzingView.translatesAutoresizingMaskIntoConstraints = false
        analyzingView.isHidden = true
        content.addSubview(analyzingView)

        hoverLabel.font = NSFont.systemFont(ofSize: 11)
        hoverLabel.textColor = .secondaryLabelColor
        hoverLabel.lineBreakMode = .byTruncatingMiddle
        hoverLabel.translatesAutoresizingMaskIntoConstraints = false
        content.addSubview(hoverLabel)

        scatterView.translatesAutoresizingMaskIntoConstraints = false
        content.addSubview(scatterView)

        // The analyzing block must float above the scatter view, which covers the
        // whole plot area with an opaque fill; otherwise it renders underneath it.
        content.addSubview(analyzingView, positioned: .above, relativeTo: scatterView)

        NSLayoutConstraint.activate([
            summaryLabel.topAnchor.constraint(equalTo: content.topAnchor, constant: 14),
            summaryLabel.leadingAnchor.constraint(equalTo: content.leadingAnchor, constant: 16),
            summaryLabel.trailingAnchor.constraint(lessThanOrEqualTo: content.trailingAnchor, constant: -16),
            hoverLabel.topAnchor.constraint(equalTo: summaryLabel.bottomAnchor, constant: 4),
            hoverLabel.leadingAnchor.constraint(equalTo: content.leadingAnchor, constant: 16),
            hoverLabel.trailingAnchor.constraint(lessThanOrEqualTo: content.trailingAnchor, constant: -16),
            scatterView.topAnchor.constraint(equalTo: hoverLabel.bottomAnchor, constant: 8),
            scatterView.bottomAnchor.constraint(equalTo: content.bottomAnchor),
            scatterView.leadingAnchor.constraint(equalTo: content.leadingAnchor),
            scatterView.trailingAnchor.constraint(equalTo: content.trailingAnchor),
            analyzingView.centerXAnchor.constraint(equalTo: content.centerXAnchor),
            analyzingView.centerYAnchor.constraint(equalTo: content.centerYAnchor, constant: -16),
            analyzingSpinner.topAnchor.constraint(equalTo: analyzingView.topAnchor),
            analyzingSpinner.centerXAnchor.constraint(equalTo: analyzingView.centerXAnchor),
            analyzingSpinner.widthAnchor.constraint(equalToConstant: 40),
            analyzingSpinner.heightAnchor.constraint(equalToConstant: 40),
            analyzingLabel.topAnchor.constraint(equalTo: analyzingSpinner.bottomAnchor, constant: 12),
            analyzingLabel.leadingAnchor.constraint(equalTo: analyzingView.leadingAnchor),
            analyzingLabel.trailingAnchor.constraint(equalTo: analyzingView.trailingAnchor),
            analyzingLabel.bottomAnchor.constraint(equalTo: analyzingView.bottomAnchor)
        ])

        scatterView.onHover = { [weak self] point in
            guard let self = self else { return }
            if let p = point {
                var prefix = ""
                if let file = p.file {
                    prefix = "\(file.lastPathComponent) · "
                }
                self.hoverLabel.stringValue = "\(prefix)\(p.name) — line \(p.line) · complexity \(p.complexity)"
            } else {
                self.hoverLabel.stringValue = ""
            }
        }
        scatterView.onSelect = { [weak self] point in
            guard let self = self else { return }
            let url = point.file ?? self.fileURL
            guard let url = url else { return }
            self.onOpenFile?(url, point.line)
        }
    }

    /// Plots every function in every source file under `root` (skipping the
    /// same build/vendor/node_modules/.git directories as the rest of the app).
    /// The analysis runs off the main thread so large projects never freeze the
    /// UI while the chart is being produced; a spinner shows until it finishes,
    /// and closing the window cancels the remaining work.
    func loadProject(root: URL) {
        analysisCancellation?.cancel()
        let cancellation = VariableFlowCancellation()
        analysisCancellation = cancellation
        let gen = loadGeneration + 1
        loadGeneration = gen
        let root = root.standardizedFileURL
        let files = SourceTree.enumerate(extensions: ProjectSourceIndex.viewerExtensions, in: root)
            .sorted { $0.path < $1.path }
        summaryLabel.stringValue = "Analyzing complexity distribution…"
        scatterView.points = []
        scatterView.placeholderText = ""
        window?.title = "Complexity distribution — \(root.lastPathComponent)"
        analyzingView.isHidden = false
        analyzingSpinner.startAnimation(nil)
        let startedAt = Date()

        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            var project: [ComplexityScatterView.Point] = []
            var busyFiles = 0
            for url in files {
                if cancellation.isCancelled { break }
                guard let source = try? String(contentsOf: url, encoding: .utf8),
                      source.count <= ProjectSourceIndex.maxChars else { continue }
                for entry in ControlFlowParser.analyzeAll(source: source, ext: url.pathExtension) {
                    project.append(.init(name: entry.name, complexity: entry.complexity,
                                         line: entry.line, file: url))
                }
                busyFiles += 1
            }
            DispatchQueue.main.async {
                guard let self = self, self.loadGeneration == gen, !cancellation.isCancelled else { return }
                self.analyzingSpinner.stopAnimation(nil)
                self.analyzingView.isHidden = true
                let count = project.count
                if count == 0 {
                    self.summaryLabel.stringValue = "No functions found across \(files.count) files"
                    self.scatterView.placeholderText = "No functions found in this project"
                } else {
                    let complexities = project.map { $0.complexity }
                    let mean = complexities.reduce(0, +) / count
                    let maxC = complexities.max() ?? 0
                    let seenFiles = Set(project.compactMap { $0.file?.path }).count
                    let elapsed = String(format: "%.1f", Date().timeIntervalSince(startedAt))
                    self.summaryLabel.stringValue =
                        "\(root.lastPathComponent) — \(count) functions in \(seenFiles)/\(busyFiles) files · mean complexity \(mean) · max \(maxC) · \(elapsed)s"
                }
                self.scatterView.points = project
            }
        }
    }

    /// Reads the file, computes per-function complexity, and plots it.
    func load(fileURL: URL) {
        analysisCancellation?.cancel()
        loadGeneration += 1
        self.fileURL = fileURL
        scatterView.placeholderText = "No functions found in this file"
        guard let source = try? String(contentsOf: fileURL, encoding: .utf8) else {
            summaryLabel.stringValue = "Unable to read \(fileURL.lastPathComponent)"
            scatterView.points = []
            return
        }
        let entries = ControlFlowParser.analyzeAll(source: source, ext: fileURL.pathExtension)
        let complexities = entries.map { $0.complexity }
        let count = entries.count
        if count == 0 {
            summaryLabel.stringValue = "\(fileURL.lastPathComponent) — no functions found"
        } else {
            let mean = complexities.reduce(0, +) / count
            let maxC = complexities.max() ?? 0
            summaryLabel.stringValue =
                "\(fileURL.lastPathComponent) — \(count) functions · mean complexity \(mean) · max \(maxC)"
        }
        scatterView.points = entries.map {
            .init(name: $0.name, complexity: $0.complexity, line: $0.line, file: fileURL)
        }
        window?.title = "Complexity distribution — \(fileURL.lastPathComponent)"
    }
}

extension ComplexityScatterWindowController: NSWindowDelegate {
    /// Closing the window stops the background analysis so it does not keep
    /// chewing through the project once the user has dismissed the chart.
    func windowWillClose(_ notification: Notification) {
        analysisCancellation?.cancel()
        analyzingSpinner.stopAnimation(nil)
        analyzingView.isHidden = true
    }
}
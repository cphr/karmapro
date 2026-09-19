// by cipher.org.uk
import AppKit

/// Window where the user pastes a stacktrace/backtrace, clicks Analyse and gets
/// a clickable left-to-right frame diagram. Clicking a node opens the source
/// file at the referenced line in the main source browser.
///
/// Files referenced by the stacktrace are resolved relative to the currently
/// open project; frames that cannot be resolved are shown in red and the user
/// is told the backtrace must come from the open project's source.
final class BacktraceAnalyserWindowController: NSWindowController {

    private let textView = NSTextView()
    private let textScroll = NSScrollView()
    private let analyseButton = NSButton(title: "Analyse", target: nil, action: nil)
    private let diagramView = BacktraceDiagramView()
    private let statusLabel = NSTextField(labelWithString: "")

    private let projectRoot: URL
    private var sourceNavigator: ((URL, Int) -> Void)?

    init(projectRoot: URL, sourceNavigator: @escaping (URL, Int) -> Void) {
        self.projectRoot = projectRoot
        self.sourceNavigator = sourceNavigator
        let window = EscClosableWindow(
            contentRect: NSRect(x: 0, y: 0, width: 1000, height: 560),
            styleMask: [.titled, .closable, .resizable],
            backing: .buffered,
            defer: false
        )
        window.title = "Backtrace Analyser"
        window.minSize = NSSize(width: 660, height: 380)
        super.init(window: window)
        window.center()
        buildContent()
    }

    required init?(coder: NSCoder) {
        fatalError("init(coder:) has not been implemented")
    }

    private func buildContent() {
        guard let content = window?.contentView else { return }

        // Paste area
        textView.font = NSFont.monospacedSystemFont(ofSize: 12, weight: .regular)
        textView.textColor = .labelColor
        textView.backgroundColor = .textBackgroundColor
        textView.isEditable = true
        textView.isSelectable = true
        textView.isRichText = false
        textView.isVerticallyResizable = true
        textView.minSize = NSSize(width: 0, height: 0)
        textView.maxSize = NSSize(width: CGFloat.greatestFiniteMagnitude, height: CGFloat.greatestFiniteMagnitude)
        textView.autoresizingMask = [.width]
        textView.textContainer?.widthTracksTextView = true
        textScroll.documentView = textView
        textScroll.hasVerticalScroller = true
        textScroll.autohidesScrollers = true
        textScroll.borderType = .lineBorder
        textScroll.translatesAutoresizingMaskIntoConstraints = false
        content.addSubview(textScroll)

        // Analyse button
        analyseButton.target = self
        analyseButton.action = #selector(analyse(_:))
        analyseButton.bezelStyle = .rounded
        analyseButton.font = NSFont.systemFont(ofSize: 13, weight: .semibold)
        analyseButton.isEnabled = true
        analyseButton.translatesAutoresizingMaskIntoConstraints = false
        content.addSubview(analyseButton)

        // Frame diagram
        diagramView.translatesAutoresizingMaskIntoConstraints = false
        content.addSubview(diagramView)

        // Status label
        statusLabel.font = NSFont.systemFont(ofSize: 11)
        statusLabel.textColor = .secondaryLabelColor
        statusLabel.lineBreakMode = .byTruncatingTail
        statusLabel.translatesAutoresizingMaskIntoConstraints = false
        content.addSubview(statusLabel)

        NSLayoutConstraint.activate([
            textScroll.topAnchor.constraint(equalTo: content.topAnchor, constant: 12),
            textScroll.leadingAnchor.constraint(equalTo: content.leadingAnchor, constant: 12),
            textScroll.trailingAnchor.constraint(equalTo: content.trailingAnchor, constant: -12),
            textScroll.heightAnchor.constraint(equalToConstant: 170),

            analyseButton.topAnchor.constraint(equalTo: textScroll.bottomAnchor, constant: 8),
            analyseButton.leadingAnchor.constraint(equalTo: content.leadingAnchor, constant: 12),
            analyseButton.widthAnchor.constraint(equalToConstant: 120),
            analyseButton.heightAnchor.constraint(equalToConstant: 34),

            statusLabel.leadingAnchor.constraint(equalTo: analyseButton.trailingAnchor, constant: 12),
            statusLabel.trailingAnchor.constraint(equalTo: content.trailingAnchor, constant: -12),
            statusLabel.centerYAnchor.constraint(equalTo: analyseButton.centerYAnchor),

            diagramView.topAnchor.constraint(equalTo: analyseButton.bottomAnchor, constant: 8),
            diagramView.leadingAnchor.constraint(equalTo: content.leadingAnchor),
            diagramView.trailingAnchor.constraint(equalTo: content.trailingAnchor),
            diagramView.bottomAnchor.constraint(equalTo: content.bottomAnchor)
        ])

        diagramView.onNodeClick = { [weak self] url, line in
            guard let self = self else { return }
            if let url = url {
                self.sourceNavigator?(url, line)
            } else {
                let alert = NSAlert()
                alert.messageText = "File not found in the open project"
                alert.informativeText = "This frame references a source file that is not part of the currently open project. Open the matching project and try again."
                alert.addButton(withTitle: "OK")
                alert.runModal()
            }
        }
    }

    @objc func analyse(_ sender: Any?) {
        let text = textView.string
        guard !text.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
            statusLabel.stringValue = "Paste a stacktrace first."
            return
        }

        let frames = BacktraceParser().parse(text)
        guard !frames.isEmpty else {
            statusLabel.stringValue = "No stacktrace frames could be parsed. Check the format."
            return
        }

        var nodes: [BacktraceDiagramView.FrameNode] = []
        var unresolvedCount = 0
        for frame in frames {
            let resolvedURL = resolveFilePath(frame.fileHint)
            if resolvedURL == nil { unresolvedCount += 1 }
            nodes.append(BacktraceDiagramView.FrameNode(
                functionName: frame.functionName,
                fileHint: frame.fileHint,
                fileURL: resolvedURL,
                line: frame.line
            ))
        }

        diagramView.display(frames: nodes)

        if unresolvedCount > 0 {
            statusLabel.stringValue = "Parsed \(nodes.count) frame(s) — \(unresolvedCount) not found in the open project. The backtrace must come from the open project's source."
            let alert = NSAlert()
            alert.messageText = "Some files were not found in the open project"
            alert.informativeText = "\(unresolvedCount) of \(nodes.count) frame(s) reference source files that do not exist in the currently open project. The backtrace must come from the source code of the open project."
            alert.addButton(withTitle: "OK")
            alert.runModal()
        } else {
            statusLabel.stringValue = "Parsed \(nodes.count) frame(s) — all files resolved. Click a frame to jump to its source."
        }
    }

    private func resolveFilePath(_ hint: String) -> URL? {
        // Already an absolute path that exists: use it directly.
        if hint.hasPrefix("/") {
            let absolute = URL(fileURLWithPath: hint)
            if FileManager.default.fileExists(atPath: absolute.path) {
                return absolute
            }
        }
        let candidates = [
            projectRoot.appendingPathComponent(hint),
            projectRoot.appendingPathComponent((hint as NSString).lastPathComponent)
        ]
        for url in candidates {
            if FileManager.default.fileExists(atPath: url.path) {
                return url
            }
        }
        return nil
    }
}
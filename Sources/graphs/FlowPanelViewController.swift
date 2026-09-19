// by cipher.org.uk
import AppKit

/// Right-hand panel showing the cyclomatic complexity and the logic flowchart
/// of the currently selected/clicked function.
final class FlowPanelViewController: NSViewController {
    private let chartView = FlowChartView()
    private let functionLabel = NSTextField(labelWithString: "No function selected")
    private let complexityBadge = NSTextField(labelWithString: "")
    private let linesLabel = NSTextField(labelWithString: "")
    private let callsLabel = NSTextField(wrappingLabelWithString: "")
    private let placeholder = NSTextField(wrappingLabelWithString: "Click a function name in the source to see its cyclomatic complexity and logic flowchart.")
    private let centerButton = NSButton(title: "Center", target: nil, action: nil)

    private var currentSource: String?
    private var currentFunction: String?

    override func loadView() {
        let container = NSView()

        functionLabel.font = NSFont.systemFont(ofSize: 13, weight: .semibold)
        functionLabel.textColor = .labelColor
        functionLabel.lineBreakMode = .byTruncatingMiddle
        functionLabel.translatesAutoresizingMaskIntoConstraints = false
        container.addSubview(functionLabel)

        centerButton.bezelStyle = .rounded
        centerButton.controlSize = .small
        centerButton.target = self
        centerButton.action = #selector(centerChart(_:))
        centerButton.toolTip = "Center the flowchart in the panel"
        centerButton.translatesAutoresizingMaskIntoConstraints = false
        container.addSubview(centerButton)

        // Reliability: render complexity as colored bold text (no fragile background layer).
        complexityBadge.font = NSFont.systemFont(ofSize: 13, weight: .bold)
        complexityBadge.textColor = .secondaryLabelColor
        complexityBadge.alignment = .left
        complexityBadge.lineBreakMode = .byTruncatingTail
        complexityBadge.setContentHuggingPriority(.defaultLow, for: .horizontal)
        complexityBadge.translatesAutoresizingMaskIntoConstraints = false
        container.addSubview(complexityBadge)

        linesLabel.font = NSFont.systemFont(ofSize: 12)
        linesLabel.textColor = .secondaryLabelColor
        linesLabel.translatesAutoresizingMaskIntoConstraints = false
        container.addSubview(linesLabel)

        callsLabel.font = NSFont.systemFont(ofSize: 12)
        callsLabel.textColor = .secondaryLabelColor
        callsLabel.translatesAutoresizingMaskIntoConstraints = false
        container.addSubview(callsLabel)

        placeholder.font = NSFont.systemFont(ofSize: 12)
        placeholder.textColor = .secondaryLabelColor
        placeholder.translatesAutoresizingMaskIntoConstraints = false
        container.addSubview(placeholder)

        chartView.translatesAutoresizingMaskIntoConstraints = false
        container.addSubview(chartView)

        let top = container.safeAreaLayoutGuide.topAnchor

        NSLayoutConstraint.activate([
            functionLabel.topAnchor.constraint(equalTo: top, constant: 10),
            functionLabel.leadingAnchor.constraint(equalTo: container.leadingAnchor, constant: 14),
            functionLabel.trailingAnchor.constraint(lessThanOrEqualTo: centerButton.leadingAnchor, constant: -8),

            centerButton.topAnchor.constraint(equalTo: top, constant: 8),
            centerButton.trailingAnchor.constraint(equalTo: container.trailingAnchor, constant: -14),

            complexityBadge.topAnchor.constraint(equalTo: functionLabel.bottomAnchor, constant: 8),
            complexityBadge.leadingAnchor.constraint(equalTo: container.leadingAnchor, constant: 14),
            complexityBadge.trailingAnchor.constraint(lessThanOrEqualTo: container.trailingAnchor, constant: -14),
            complexityBadge.heightAnchor.constraint(equalToConstant: 20),

            linesLabel.topAnchor.constraint(equalTo: complexityBadge.bottomAnchor, constant: 6),
            linesLabel.leadingAnchor.constraint(equalTo: container.leadingAnchor, constant: 14),
            linesLabel.trailingAnchor.constraint(lessThanOrEqualTo: container.trailingAnchor, constant: -14),

            callsLabel.topAnchor.constraint(equalTo: linesLabel.bottomAnchor, constant: 6),
            callsLabel.leadingAnchor.constraint(equalTo: container.leadingAnchor, constant: 14),
            callsLabel.trailingAnchor.constraint(lessThanOrEqualTo: container.trailingAnchor, constant: -14),

            placeholder.centerXAnchor.constraint(equalTo: container.centerXAnchor),
            placeholder.centerYAnchor.constraint(equalTo: container.centerYAnchor),
            placeholder.leadingAnchor.constraint(greaterThanOrEqualTo: container.leadingAnchor, constant: 14),
            placeholder.trailingAnchor.constraint(lessThanOrEqualTo: container.trailingAnchor, constant: -14),

            chartView.topAnchor.constraint(equalTo: callsLabel.bottomAnchor, constant: 8),
            chartView.bottomAnchor.constraint(equalTo: container.bottomAnchor),
            chartView.leadingAnchor.constraint(equalTo: container.leadingAnchor),
            chartView.trailingAnchor.constraint(equalTo: container.trailingAnchor)
        ])

        self.view = container
        placeholder.isHidden = false
    }

    override func viewWillAppear() {
        super.viewWillAppear()
        // The flowchart view is flipped AND layer-backed. On recent macOS the
        // AppKit layer sync has been observed to composite its backing store
        // with a vertical offset that paints the chart over this pane's header
        // (function name / cyclomatic complexity / lines / calls) exactly when a
        // flowchart is produced. Explicit z-ordering keeps the header above the
        // chart layer no matter what the sync does.
        functionLabel.layer?.zPosition = 100
        centerButton.layer?.zPosition = 100
        complexityBadge.layer?.zPosition = 100
        linesLabel.layer?.zPosition = 100
        callsLabel.layer?.zPosition = 100
        chartView.layer?.zPosition = -1
    }

    private func enforceHeaderZOrder() {
        guard view.layer != nil else { return }
        functionLabel.layer?.zPosition = 100
        centerButton.layer?.zPosition = 100
        complexityBadge.layer?.zPosition = 100
        linesLabel.layer?.zPosition = 100
        callsLabel.layer?.zPosition = 100
        chartView.layer?.zPosition = -1
    }

    // MARK: - Data

    /// Shows the flowchart + complexity for `functionName` in `source`.
    func show(functionName: String, source: String, fileExtension: String = "") {
        enforceHeaderZOrder()
        currentSource = source
        currentFunction = functionName
        functionLabel.stringValue = functionName
        placeholder.isHidden = true

        // Use the C/C++/Java/C# control-flow parser for all supported languages.
        guard let flow = ControlFlowParser.analyze(source: source, ext: fileExtension, functionName: functionName) else {
            complexityBadge.stringValue = "Cyclomatic complexity: —"
            complexityBadge.textColor = .secondaryLabelColor
            return
        }

        let c = flow.complexity
        complexityBadge.stringValue = "Cyclomatic complexity: \(c)"
        complexityBadge.textColor = complexityColor(c)

        linesLabel.stringValue = "Lines: \(source.components(separatedBy: "\n").count)"

        let callees: [String] = {
            let graph = diagramCallGraph(source: source,
                                          definitions: diagramDefinitions(source: source, ext: fileExtension))
            return graph.calls.filter { $0.from == functionName }.map { $0.to }
        }()
        if callees.isEmpty {
            callsLabel.stringValue = "Functions called: none"
        } else {
            callsLabel.stringValue = "Functions called (\(callees.count)): \(callees.joined(separator: ", "))"
        }

        chartView.show(flow)
    }

    func clear() {
        enforceHeaderZOrder()
        currentSource = nil
        currentFunction = nil
        functionLabel.stringValue = "No function selected"
        complexityBadge.stringValue = ""
        linesLabel.stringValue = ""
        callsLabel.stringValue = ""
        chartView.clear()
        placeholder.isHidden = false
    }

    @objc private func centerChart(_ sender: Any?) {
        chartView.center()
    }

    private func complexityColor(_ c: Int) -> NSColor {
        switch c {
        case ..<5:  return NSColor.systemGreen
        case ..<10: return NSColor.systemOrange
        case ..<20: return NSColor.systemRed
        default:    return NSColor(calibratedRed: 0.45, green: 0.20, blue: 0.20, alpha: 1.0)
        }
    }
}
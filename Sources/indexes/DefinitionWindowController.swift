// by cipher.org.uk
import AppKit

/// A small window that shows the source of a function/method's definition,
/// opened when the user clicks a call site in the source viewer. The definition
/// line is scrolled into view and briefly highlighted.
final class DefinitionWindowController: NSWindowController {
    private let textView = NSTextView()
    private let locationLabel = NSTextField(labelWithString: "")
    private let highlighter = SyntaxHighlighter()
    /// Character range of the definition line within the loaded source, used to
    /// scroll it into view and highlight it once the window is on screen.
    private var definitionLineRange: NSRange?
    /// Offset of the definition name, used as a fallback target for scrolling.
    private var fallbackOffset = 0
    private var scrollObservers: [NSObjectProtocol] = []

    convenience init(location: DefinitionLocation) {
        let window = EscClosableWindow(
            contentRect: NSRect(x: 0, y: 0, width: 640, height: 400),
            styleMask: [.titled, .closable, .resizable],
            backing: .buffered,
            defer: false
        )
        window.title = "Definition — \(location.fileURL.lastPathComponent)"
        window.minSize = NSSize(width: 420, height: 240)
        self.init(window: window)
        buildContent()
        load(location: location)
        // Center the popup on the screen, then scroll to the definition as soon
        // as the window is actually on screen and laid out. Multiple triggers
        // guarantee the scroll applies regardless of when layout first happens.
        window.center()
        scrollObservers.append(NotificationCenter.default.addObserver(
            forName: NSWindow.didBecomeKeyNotification, object: window, queue: .main
        ) { [weak self] _ in
            self?.scrollDefinitionLineToCenter()
        })
        scrollObservers.append(NotificationCenter.default.addObserver(
            forName: NSView.frameDidChangeNotification, object: window.contentView, queue: .main
        ) { [weak self] _ in
            self?.scrollDefinitionLineToCenter()
        })
        DispatchQueue.main.async { [weak self] in
            self?.scrollDefinitionLineToCenter()
        }
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.15) { [weak self] in
            self?.scrollDefinitionLineToCenter()
        }
    }

    deinit {
        for token in scrollObservers {
            NotificationCenter.default.removeObserver(token)
        }
    }

    private func buildContent() {
        guard let content = window?.contentView else { return }

        locationLabel.font = NSFont.systemFont(ofSize: 11)
        locationLabel.textColor = .secondaryLabelColor
        locationLabel.lineBreakMode = .byTruncatingMiddle
        locationLabel.translatesAutoresizingMaskIntoConstraints = false
        content.addSubview(locationLabel)

        let scroll = NSScrollView()
        scroll.hasVerticalScroller = true
        scroll.hasHorizontalScroller = true
        scroll.autohidesScrollers = true
        scroll.borderType = .noBorder
        scroll.translatesAutoresizingMaskIntoConstraints = false
        content.addSubview(scroll)

        textView.isEditable = false
        textView.isSelectable = true
        textView.isRichText = false
        textView.font = NSFont.monospacedSystemFont(ofSize: 12, weight: .regular)
        textView.textColor = .labelColor
        textView.backgroundColor = .textBackgroundColor
        textView.isVerticallyResizable = true
        textView.isHorizontallyResizable = false
        textView.autoresizingMask = [.width]
        textView.textContainerInset = NSSize(width: 8, height: 4)
        let tc = textView.textContainer!
        tc.widthTracksTextView = true
        tc.containerSize = NSSize(width: CGFloat.greatestFiniteMagnitude, height: CGFloat.greatestFiniteMagnitude)
        scroll.documentView = textView

        NSLayoutConstraint.activate([
            locationLabel.topAnchor.constraint(equalTo: content.topAnchor, constant: 12),
            locationLabel.leadingAnchor.constraint(equalTo: content.leadingAnchor, constant: 16),
            locationLabel.trailingAnchor.constraint(equalTo: content.trailingAnchor, constant: -16),
            scroll.topAnchor.constraint(equalTo: locationLabel.bottomAnchor, constant: 8),
            scroll.bottomAnchor.constraint(equalTo: content.bottomAnchor),
            scroll.leadingAnchor.constraint(equalTo: content.leadingAnchor),
            scroll.trailingAnchor.constraint(equalTo: content.trailingAnchor)
        ])
    }

    private func load(location: DefinitionLocation) {
        guard let source = try? String(contentsOf: location.fileURL, encoding: .utf8) else {
            locationLabel.stringValue = location.fileURL.path
            textView.string = "Unable to read the definition file."
            return
        }
        let attributed = highlighter.highlight(source, for: location.ext)
        textView.textStorage?.setAttributedString(attributed ?? NSAttributedString(string: source))

        // Line number (1-based) of the definition name.
        let ns = source as NSString
        let clampedOffset = min(max(location.nameOffset, 0), ns.length)
        fallbackOffset = clampedOffset
        let line = ns.substring(to: clampedOffset).components(separatedBy: "\n").count

        locationLabel.stringValue = "\(location.fileURL.path) — line \(line)"

        definitionLineRange = lineRange(in: ns, line: line)
        if let range = definitionLineRange {
            highlightLine(range: range)
        }

        // Initial best-effort scroll; refined by scrollDefinitionLineToCenter once
        // the window is visible.
        let charRange = NSRange(location: clampedOffset, length: 0)
        textView.scrollRangeToVisible(charRange)
    }

    /// Returns the character range covering the whole line `line` (1-based), or
    /// nil if the line is out of bounds.
    private func lineRange(in ns: NSString, line: Int) -> NSRange? {
        let count = ns.components(separatedBy: "\n").count
        guard line >= 1, line <= count else { return nil }
        var location = 0
        for _ in 1..<line {
            location = ns.range(of: "\n", options: [], range: NSRange(location: location, length: ns.length - location)).location
            if location == NSNotFound { return nil }
            location += 1
        }
        var end = ns.range(of: "\n", options: [], range: NSRange(location: location, length: ns.length - location)).location
        if end == NSNotFound { end = ns.length }
        return NSRange(location: location, length: max(0, end - location))
    }

    /// Scrolls the text view so the definition line sits vertically centered.
    private func scrollDefinitionLineToCenter() {
        // Primary: scroll the definition line into view through AppKit's own
        // handling, then fine-tune so it is vertically centered.
        if let range = definitionLineRange, range.length > 0 {
            textView.setSelectedRange(range)
            textView.scrollRangeToVisible(range)
        } else if fallbackOffset >= 0 {
            let r = NSRange(location: fallbackOffset, length: 0)
            textView.scrollRangeToVisible(r)
        }

        guard let range = definitionLineRange,
              range.length > 0,
              let lm = textView.layoutManager,
              let tc = textView.textContainer else { return }
        lm.ensureLayout(for: tc)

        guard let clip = textView.enclosingScrollView?.contentView else { return }
        let rect = lm.boundingRect(forGlyphRange: range, in: tc)
        let visibleHeight = clip.bounds.height

        // Set the clip view's origin so the definition line's vertical center
        // lands in the middle of the visible area.
        let scrollY = max(0, rect.midY - visibleHeight / 2)
        clip.scroll(to: NSPoint(x: 0, y: scrollY))
        textView.enclosingScrollView?.reflectScrolledClipView(clip)
    }

    /// Applies a transient yellow highlight to the definition line, then fades
    /// it out after a short delay.
    private func highlightLine(range: NSRange) {
        guard range.length > 0 else { return }
        let highlight = NSColor(calibratedRed: 1.0, green: 0.9, blue: 0.3, alpha: 0.45)
        let attr: [NSAttributedString.Key: Any] = [.backgroundColor: highlight]
        textView.layoutManager?.addTemporaryAttributes(attr, forCharacterRange: range)

        DispatchQueue.main.asyncAfter(deadline: .now() + 2.5) { [weak self] in
            self?.textView.layoutManager?.removeTemporaryAttribute(.backgroundColor, forCharacterRange: range)
        }
    }
}

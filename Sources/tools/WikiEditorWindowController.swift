// by cipher.org.uk
import AppKit

/// Text view that follows wiki links on a plain click even while editable.
/// In a normal editable `NSTextView`, AppKit only activates `NSLinkAttributeName`
/// with a Command-click; here a click landing on a `wiki://` link is routed to
/// `onLinkClick` instead, so links in a page are single-click targets (which
/// is what "click to create the page that doesn't exist yet" requires).
final class WikiLinkTextView: NSTextView {
    var onLinkClick: ((URL) -> Void)?

    override func mouseDown(with event: NSEvent) {
        let point = convert(event.locationInWindow, from: nil)
        let index = characterIndex(for: point)
        if let url = linkURL(at: index) {
            onLinkClick?(url)
            return
        }
        // characterIndex(for:) can round a click near the right edge of a link
        // onto the following character; nudge one index back as a fallback.
        if let url = linkURL(at: index - 1) {
            onLinkClick?(url)
            return
        }
        super.mouseDown(with: event)
    }

    private func linkURL(at index: Int) -> URL? {
        guard index != NSNotFound, index >= 0, index < (textStorage?.length ?? 0) else { return nil }
        return textStorage?.attribute(.link, at: index, effectiveRange: nil) as? URL
    }
}

/// Rich-text page editor for the private wiki. A title field at the top, a
/// small formatting bar (bold/italic/underline/code/heading/body), and a
/// white-buffered `NSTextView` for the page body.
///
/// Links come in two forms:
///  - `Insert Link…` attaches an attributed `wiki://` link to the selection;
///  - typing `[[Any Page Name]]` auto-styles the inner text as a link.
/// Both resolve on click. If the target page does not exist yet it is created
/// (by `WikiWindowController`) and opened — the second click workflow that
/// grows a wiki out of dead links.
final class WikiEditorWindowController: NSWindowController, NSTextViewDelegate, NSWindowDelegate {
    private let store = WikiStore.shared

    private let titleField = NSTextField()
    private let textView = WikiLinkTextView()
    private let statusLabel = NSTextField(wrappingLabelWithString: "")
    private let formatBar = NSStackView()
    private var saveButton: NSButton!

    /// The slug of the page being edited. Always set (pages are created by the
    /// list controller before the editor opens).
    private var slug = ""
    var pageSlug: String { slug }

    private var isDirty = false
    private var isApplyingLinks = false

    /// Called with a link target name when the user clicks a `wiki://` link.
    /// The owner is expected to open the page, creating it if needed.
    var onNavigate: ((String) -> Void)?

    /// Called once after the window closes so the owner can refresh lists.
    var onClose: (() -> Void)?

    convenience init(slug: String) {
        let window = EscClosableWindow(
            contentRect: NSRect(x: 0, y: 0, width: 820, height: 620),
            styleMask: [.titled, .closable, .resizable],
            backing: .buffered,
            defer: false
        )
        window.title = "Wiki Page"
        window.minSize = NSSize(width: 520, height: 360)
        self.init(window: window)
        self.slug = slug
        buildContent()
        loadPage()
        centerWindowOnScreen()
    }

    private func buildContent() {
        guard let content = window?.contentView else { return }
        window?.delegate = self

        titleField.font = NSFont.systemFont(ofSize: 20, weight: .bold)
        titleField.textColor = .labelColor
        titleField.isBordered = false
        titleField.drawsBackground = false
        titleField.focusRingType = .none
        titleField.placeholderString = "Page Title"
        titleField.translatesAutoresizingMaskIntoConstraints = false
        titleField.target = self
        titleField.action = #selector(titleChanged)

        let rule = NSBox()
        rule.boxType = .separator
        rule.translatesAutoresizingMaskIntoConstraints = false

        formatBar.orientation = .horizontal
        formatBar.alignment = .centerY
        formatBar.spacing = 6
        formatBar.translatesAutoresizingMaskIntoConstraints = false
        formatBar.addArrangedSubview(makeFormatButton("B", #selector(boldClicked), toolTip: "Bold"))
        formatBar.addArrangedSubview(makeFormatButton("I", #selector(italicClicked), toolTip: "Italic"))
        formatBar.addArrangedSubview(makeFormatButton("U", #selector(underlineClicked), toolTip: "Underline"))
        formatBar.addArrangedSubview(makeFormatButton("Code", #selector(codeClicked), toolTip: "Monospace code"))
        formatBar.addArrangedSubview(makeFormatButton("Heading", #selector(headingClicked), toolTip: "Heading style"))
        formatBar.addArrangedSubview(makeFormatButton("Body", #selector(bodyClicked), toolTip: "Body text style"))
        formatBar.addArrangedSubview(makeFormatButton("Link…", #selector(insertLinkClicked), toolTip: "Insert a link to another wiki page"))

        let scrollView = NSScrollView()
        scrollView.hasVerticalScroller = true
        scrollView.autohidesScrollers = true
        scrollView.borderType = .bezelBorder
        scrollView.translatesAutoresizingMaskIntoConstraints = false

        textView.isRichText = true
        textView.allowsUndo = true
        textView.isVerticallyResizable = true
        textView.isHorizontallyResizable = false
        textView.autoresizingMask = [.width]
        textView.textContainer?.widthTracksTextView = true
        textView.drawsBackground = true
        textView.backgroundColor = .white
        textView.textColor = .black
        textView.font = NSFont.systemFont(ofSize: 14)
        textView.textContainerInset = NSSize(width: 12, height: 12)
        textView.delegate = self
        textView.onLinkClick = { [weak self] url in
            self?.navigate(to: url)
        }
        scrollView.documentView = textView

        statusLabel.font = NSFont.systemFont(ofSize: 11)
        statusLabel.textColor = .secondaryLabelColor
        statusLabel.translatesAutoresizingMaskIntoConstraints = false

        saveButton = NSButton(title: "Save", target: self, action: #selector(saveClicked))
        saveButton.bezelStyle = .rounded
        saveButton.keyEquivalent = "s"
        saveButton.keyEquivalentModifierMask = [.command]

        let bottomRow = NSStackView(views: [statusLabel, saveButton])
        bottomRow.orientation = .horizontal
        bottomRow.alignment = .centerY
        bottomRow.spacing = 10
        bottomRow.translatesAutoresizingMaskIntoConstraints = false
        content.addSubview(bottomRow)

        content.addSubview(titleField)
        content.addSubview(rule)
        content.addSubview(formatBar)
        content.addSubview(scrollView)

        NSLayoutConstraint.activate([
            titleField.topAnchor.constraint(equalTo: content.topAnchor, constant: 16),
            titleField.leadingAnchor.constraint(equalTo: content.leadingAnchor, constant: 16),
            titleField.trailingAnchor.constraint(equalTo: content.trailingAnchor, constant: -16),

            rule.topAnchor.constraint(equalTo: titleField.bottomAnchor, constant: 8),
            rule.leadingAnchor.constraint(equalTo: content.leadingAnchor, constant: 16),
            rule.trailingAnchor.constraint(equalTo: content.trailingAnchor, constant: -16),

            formatBar.topAnchor.constraint(equalTo: rule.bottomAnchor, constant: 8),
            formatBar.leadingAnchor.constraint(equalTo: content.leadingAnchor, constant: 16),

            scrollView.topAnchor.constraint(equalTo: formatBar.bottomAnchor, constant: 10),
            scrollView.leadingAnchor.constraint(equalTo: content.leadingAnchor, constant: 16),
            scrollView.trailingAnchor.constraint(equalTo: content.trailingAnchor, constant: -16),

            bottomRow.topAnchor.constraint(equalTo: scrollView.bottomAnchor, constant: 10),
            bottomRow.leadingAnchor.constraint(equalTo: content.leadingAnchor, constant: 16),
            bottomRow.trailingAnchor.constraint(equalTo: content.trailingAnchor, constant: -16),
            bottomRow.bottomAnchor.constraint(equalTo: content.bottomAnchor, constant: -12)
        ])
    }

    private func makeFormatButton(_ title: String, _ action: Selector, toolTip: String) -> NSButton {
        let button = NSButton(title: title, target: self, action: action)
        button.bezelStyle = .rounded
        button.controlSize = .small
        button.toolTip = toolTip
        return button
    }

    private func centerWindowOnScreen() {
        guard let window = window, let screen = window.screen else { return }
        let frame = screen.visibleFrame
        let origin = NSPoint(x: frame.midX - window.frame.width / 2,
                             y: frame.midY - window.frame.height / 2)
        window.setFrameOrigin(origin)
    }

    // MARK: - Loading / saving

    private func loadPage() {
        guard let info = store.pageInfo(slug: slug) else {
            titleField.stringValue = "Untitled"
            close()
            return
        }
        window?.title = info.title
        titleField.stringValue = info.title
        if let body = store.body(slug: slug), body.length > 0 {
            textView.textStorage?.setAttributedString(body)
        }
        textView.setSelectedRange(NSRange(location: 0, length: 0))
        textView.font = NSFont.systemFont(ofSize: 14)
        applyWikiLinks()
        isDirty = false
        updateStatus()
        window?.makeFirstResponder(textView)
    }

    func saveNow() {
        guard !slug.isEmpty else { return }
        let body = textView.textStorage?.copy() as? NSAttributedString
            ?? NSAttributedString(string: textView.string)
        let saved = store.savePage(slug: slug, title: titleField.stringValue, body: body)
        if saved {
            isDirty = false
            updateStatus()
        }
    }

    @objc private func saveClicked() {
        saveNow()
    }

    @objc private func titleChanged() {
        isDirty = true
        updateStatus()
    }

    func windowShouldClose(_ sender: NSWindow) -> Bool {
        true
    }

    /// Always persists the page when its window goes away — whether the user
    /// pressed ⌘W, the red close button, Esc, or the app terminated — so an
    /// unsaved edit is never lost by closing the editor.
    func windowWillClose(_ notification: Notification) {
        if isDirty { saveNow() }
        onClose?()
    }

    // MARK: - Status

    private func updateStatus() {
        let title = slug.isEmpty ? "Untitled" : titleField.stringValue
        let count = textView.string.count
        statusLabel.stringValue = isDirty
            ? "Edited — \(title) · \(count) characters"
            : "Saved — \(title) · \(count) characters"
    }

    // MARK: - Formatting actions

    private func selectedRange() -> NSRange {
        textView.selectedRange()
    }

    private func setTypingFont(_ font: NSFont) {
        var attrs = textView.typingAttributes
        attrs[.font] = font
        textView.typingAttributes = attrs
    }

    private func applyFont(over range: NSRange, _ builder: (NSFont?) -> NSFont) {
        if range.length > 0 {
            textView.textStorage?.beginEditing()
            textView.textStorage?.enumerateAttribute(.font, in: range, options: []) { value, r, _ in
                let font = builder(value as? NSFont)
                textView.textStorage?.addAttribute(.font, value: font, range: r)
            }
            textView.textStorage?.endEditing()
        } else {
            setTypingFont(builder(textView.typingAttributes[.font] as? NSFont))
        }
    }

    private func currentFont() -> NSFont {
        let range = textView.selectedRange()
        if range.length > 0,
           let font = textView.textStorage?.attribute(.font, at: range.location, effectiveRange: nil) as? NSFont {
            return font
        }
        return textView.typingAttributes[.font] as? NSFont ?? NSFont.systemFont(ofSize: 14)
    }

    private func font(_ font: NSFont, with trait: NSFontDescriptor.SymbolicTraits, on: Bool) -> NSFont {
        let current = font.fontDescriptor.symbolicTraits
        let combined = on ? current.union(trait) : current.subtracting(trait)
        return NSFont(descriptor: font.fontDescriptor.withSymbolicTraits(combined), size: font.pointSize) ?? font
    }

    private func toggleTrait(_ trait: NSFontDescriptor.SymbolicTraits) {
        let range = textView.selectedRange()
        if range.length > 0 {
            textView.textStorage?.beginEditing()
            textView.textStorage?.enumerateAttribute(.font, in: range, options: []) { value, r, _ in
                let font = value as? NSFont ?? NSFont.systemFont(ofSize: 14)
                let on = font.fontDescriptor.symbolicTraits.contains(trait)
                textView.textStorage?.addAttribute(.font, value: self.font(font, with: trait, on: !on), range: r)
            }
            textView.textStorage?.endEditing()
        } else {
            let font = currentFont()
            let on = font.fontDescriptor.symbolicTraits.contains(trait)
            var attrs = textView.typingAttributes
            attrs[.font] = self.font(font, with: trait, on: !on)
            textView.typingAttributes = attrs
        }
    }

    private func toggleUnderline() {
        let range = textView.selectedRange()
        let value: Int
        if range.length > 0 {
            value = (textView.textStorage?.attribute(.underlineStyle, at: range.location, effectiveRange: nil) as? Int) ?? 0
        } else {
            value = (textView.typingAttributes[.underlineStyle] as? Int) ?? 0
        }
        let newValue = value != 0 ? 0 : NSUnderlineStyle.single.rawValue
        if range.length > 0 {
            textView.textStorage?.addAttribute(.underlineStyle, value: newValue, range: range)
        } else {
            var attrs = textView.typingAttributes
            attrs[.underlineStyle] = newValue
            textView.typingAttributes = attrs
        }
    }

    @objc private func boldClicked() {
        toggleTrait(.bold)
    }

    @objc private func italicClicked() {
        toggleTrait(.italic)
    }

    @objc private func underlineClicked() {
        toggleUnderline()
    }

    @objc private func codeClicked() {
        let range = selectedRange()
        let size = (textView.typingAttributes[.font] as? NSFont)?.pointSize ?? 14
        applyFont(over: range) { font in
            let pointSize = font?.pointSize ?? size
            return NSFont.monospacedSystemFont(ofSize: pointSize, weight: .regular)
        }
    }

    @objc private func headingClicked() {
        let range = selectedRange()
        applyFont(over: range) { _ in
            NSFont.systemFont(ofSize: 20, weight: .bold)
        }
    }

    @objc private func bodyClicked() {
        let range = selectedRange()
        applyFont(over: range) { _ in
            NSFont.systemFont(ofSize: 14)
        }
    }

    // MARK: - Links

    @objc private func insertLinkClicked() {
        let selection = textView.selectedRange()

        // Casual path: with a selection the button instantly hyperlinks those
        // words (page name = the selected words, created on first click). No
        // dialog needed.
        if selection.length > 0 {
            let selected = (textView.string as NSString).substring(with: selection)
                .trimmingCharacters(in: .whitespacesAndNewlines)
            guard !selected.isEmpty else { return }
            guard let url = wikiURL(for: selected) else { return }
            insertLink(url: url, display: selected, at: selection)
            return
        }

        // Without a selection, ask for the link text and target page name,
        // inserting at the caret. The page name falls back to the link text so
        // confirming never silently does nothing.
        let alert = NSAlert()
        alert.messageText = "Insert Wiki Link"
        alert.informativeText = "With a selection, the Link button hyperlinks it instantly. Here you can set the link text and the page it opens (created if missing)."
        alert.addButton(withTitle: "Insert")
        alert.addButton(withTitle: "Cancel")

        let textLabel = NSTextField(labelWithString: "Link text:")
        let textField = NSTextField(frame: NSRect(x: 0, y: 0, width: 280, height: 24))
        textField.placeholderString = "e.g. Buffer Overflow Notes"
        let pageLabel = NSTextField(labelWithString: "Wiki page:")
        let pageField = NSTextField(frame: NSRect(x: 0, y: 0, width: 280, height: 24))
        pageField.placeholderString = "e.g. Buffer Overflows"

        let grid = NSGridView(views: [
            [textLabel, textField],
            [pageLabel, pageField]
        ])
        grid.rowSpacing = 8
        grid.columnSpacing = 10
        alert.accessoryView = grid
        alert.window.initialFirstResponder = pageField
        NSApp.activate(ignoringOtherApps: true)
        guard alert.runModal() == .alertFirstButtonReturn else { return }

        let display = textField.stringValue.trimmingCharacters(in: .whitespacesAndNewlines)
        let target = pageField.stringValue.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !target.isEmpty || !display.isEmpty else { return }
        let pageName = target.isEmpty ? display : target
        guard let url = wikiURL(for: pageName) else { return }
        insertLink(url: url, display: display.isEmpty ? pageName : display, at: textView.selectedRange())
    }

    private func insertLink(url: URL, display: String, at range: NSRange) {
        var attrs: [NSAttributedString.Key: Any] = [:]
        if let textFont = textView.typingAttributes[.font] as? NSFont {
            attrs[.font] = textFont
        }
        attrs[.link] = url
        attrs[.foregroundColor] = NSColor.linkColor
        attrs[.underlineStyle] = NSUnderlineStyle.single.rawValue

        let linked = NSAttributedString(string: display, attributes: attrs)
        textView.insertText(linked, replacementRange: range)
        isDirty = true
        updateStatus()
    }

    private func wikiURL(for target: String) -> URL? {
        let encoded = target.addingPercentEncoding(withAllowedCharacters: .urlPathAllowed) ?? target
        return URL(string: "wiki://page/\(encoded)")
    }

    /// Styles `[[Page Name]]` occurrences as links. The brackets are dimmed and
    /// the inner text carries the `wiki://` link attribute so a click navigates.
    private func applyWikiLinks() {
        guard !isApplyingLinks else { return }
        isApplyingLinks = true
        defer { isApplyingLinks = false }
        guard let storage = textView.textStorage else { return }

        let pattern = "\\[\\[([^\\[\\]]+)\\]\\]"
        guard let regex = try? NSRegularExpression(pattern: pattern) else { return }
        let full = textView.string as NSString
        let matches = regex.matches(in: textView.string, range: NSRange(location: 0, length: full.length))

        storage.beginEditing()
        for match in matches {
            let bracketStart = match.range
            let inner = NSRange(location: bracketStart.location + 2, length: bracketStart.length - 4)
            guard inner.length > 0 else { continue }
            let target = full.substring(with: inner)
            guard let url = wikiURL(for: target) else { continue }

            let existing = storage.attribute(.link, at: inner.location, effectiveRange: nil) as? URL
            if existing != url {
                var attrs: [NSAttributedString.Key: Any] = [.link: url]
                if let font = storage.attribute(.font, at: inner.location, effectiveRange: nil) as? NSFont {
                    attrs[.font] = font
                }
                storage.addAttributes(attrs, range: inner)
            }
            storage.addAttribute(.foregroundColor, value: NSColor.tertiaryLabelColor, range: NSRange(location: bracketStart.location, length: 2))
            storage.addAttribute(.foregroundColor, value: NSColor.tertiaryLabelColor, range: NSRange(location: inner.location + inner.length, length: 2))
        }
        storage.endEditing()
    }

    func textDidChange(_ notification: Notification) {
        applyWikiLinks()
        isDirty = true
        updateStatus()
    }

    func textView(_ textView: NSTextView, clickedOnLink link: Any, at charIndex: Int) -> Bool {
        guard let url = link as? URL, url.scheme == "wiki" else { return false }
        navigate(to: url)
        return true
    }

    private func navigate(to url: URL) {
        guard url.scheme == "wiki" else { return }
        let target = url.lastPathComponent.removingPercentEncoding ?? ""
        guard !target.isEmpty else { return }
        onNavigate?(target)
    }
}
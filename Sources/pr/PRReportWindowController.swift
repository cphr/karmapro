// by cipher.org.uk
import AppKit

/// Shows the generated Markdown report and lets the user copy or save it.
///
/// The report is never transmitted anywhere. Karma Pro holds no write scope
/// against any forge, so the report exists as text the user places themselves —
/// pasted into a comment, committed to a file, or kept for themselves.
final class PRReportWindowController: NSWindowController, NSTextViewDelegate {
    private let textView = NSTextView()
    private let statusLabel = NSTextField(labelWithString: "")
    private var suggestedName: String

    init() {
        // EscClosableWindow, not NSWindow: Escape did nothing on this window,
        // which is the one place the user most wants to dismiss it after
        // reading a report.
        let window = EscClosableWindow(
            contentRect: NSRect(x: 0, y: 0, width: 760, height: 620),
            styleMask: [.titled, .closable, .miniaturizable, .resizable],
            backing: .buffered,
            defer: false)
        window.title = "Pull Request Review Report"
        window.center()
        self.suggestedName = "PR-review.md"
        super.init(window: window)
        build()
    }

    required init?(coder: NSCoder) {
        suggestedName = "PR-review.md"
        super.init(coder: coder)
    }

    private func build() {
        guard let content = window?.contentView else { return }

        textView.isRichText = false
        textView.font = .monospacedSystemFont(ofSize: 11, weight: .regular)
        textView.isEditable = false
        textView.autoresizingMask = [.width]
        textView.textContainer?.widthTracksTextView = true

        let scroll = NSScrollView()
        scroll.hasVerticalScroller = true
        scroll.borderType = .bezelBorder
        scroll.documentView = textView
        scroll.translatesAutoresizingMaskIntoConstraints = false

        let copyButton = NSButton(title: "Copy Markdown", target: self, action: #selector(copyMarkdown))
        copyButton.bezelStyle = .rounded
        let saveButton = NSButton(title: "Save As…", target: self, action: #selector(save))
        saveButton.bezelStyle = .rounded
        saveButton.keyEquivalent = "\r"

        statusLabel.font = .systemFont(ofSize: 11)
        statusLabel.textColor = .secondaryLabelColor
        statusLabel.stringValue = "Nothing has been sent anywhere. Save or copy this yourself."

        for view in [scroll, copyButton, saveButton, statusLabel] as [NSView] {
            view.translatesAutoresizingMaskIntoConstraints = false
            content.addSubview(view)
        }

        NSLayoutConstraint.activate([
            scroll.topAnchor.constraint(equalTo: content.topAnchor, constant: 12),
            scroll.leadingAnchor.constraint(equalTo: content.leadingAnchor, constant: 12),
            scroll.trailingAnchor.constraint(equalTo: content.trailingAnchor, constant: -12),
            scroll.bottomAnchor.constraint(equalTo: copyButton.topAnchor, constant: -12),

            copyButton.leadingAnchor.constraint(equalTo: content.leadingAnchor, constant: 12),
            copyButton.bottomAnchor.constraint(equalTo: content.bottomAnchor, constant: -12),
            saveButton.leadingAnchor.constraint(equalTo: copyButton.trailingAnchor, constant: 8),
            saveButton.centerYAnchor.constraint(equalTo: copyButton.centerYAnchor),
            statusLabel.leadingAnchor.constraint(equalTo: saveButton.trailingAnchor, constant: 12),
            statusLabel.trailingAnchor.constraint(equalTo: content.trailingAnchor, constant: -12),
            statusLabel.centerYAnchor.constraint(equalTo: copyButton.centerYAnchor)
        ])
    }

    /// Must be called on a controller the caller keeps alive: see the note on
    /// the class's unowned button targets.
    ///
    /// The buttons hold their target unowned, so a controller created as a
    /// temporary and released the moment `showWindow` returned left both buttons
    /// addressing freed memory. "Save As…" did nothing at all because there was
    /// no live receiver to run `save()`.
    func showReport(markdown: String, suggestedName: String) {
        guard window != nil else { return }
        textView.string = markdown
        self.suggestedName = suggestedName
        statusLabel.textColor = .secondaryLabelColor
        statusLabel.stringValue = "Nothing has been sent anywhere. Save or copy this yourself."
        NSApp.activate(ignoringOtherApps: true)
        showWindow(nil)
        window?.center()
        window?.makeKeyAndOrderFront(nil)
    }

    @objc private func copyMarkdown() {
        let pasteboard = NSPasteboard.general
        pasteboard.clearContents()
        pasteboard.setString(textView.string, forType: .string)
        statusLabel.stringValue = "Copied to the clipboard."
    }

    @objc private func save() {
        let panel = NSSavePanel()
        panel.nameFieldStringValue = suggestedName
        panel.allowedContentTypes = [.plainText]
        panel.canCreateDirectories = true
        panel.message = "Save the Markdown review report"

        let write: (URL) -> Void = { [weak self] url in
            guard let self = self else { return }
            do {
                try self.textView.string.write(to: url, atomically: true, encoding: .utf8)
                self.statusLabel.stringValue = "Saved to \(url.lastPathComponent)."
                self.statusLabel.textColor = .secondaryLabelColor
            } catch {
                self.statusLabel.stringValue = "Could not save: \(error.localizedDescription)"
                self.statusLabel.textColor = .systemRed
            }
        }

        // A sheet needs an ordered parent window to attach to. This window is
        // reachable and key whenever Save As… is clickable, but falling back to
        // the app-modal form costs nothing and removes the case where the panel
        // never appears at all.
        if let parent = window, parent.isVisible {
            panel.beginSheetModal(for: parent) { response in
                guard response == .OK, let url = panel.url else { return }
                write(url)
            }
        } else {
            panel.begin { response in
                guard response == .OK, let url = panel.url else { return }
                write(url)
            }
        }
    }
}
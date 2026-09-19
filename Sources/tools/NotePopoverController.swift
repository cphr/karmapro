// by cipher.org.uk
import AppKit

/// A small popover editor for leaving a note on a specific line of a source file.
/// Shows the file name + line number, a multi-line text field, and Save / Remove.
final class NotePopoverController: NSViewController, NSTextViewDelegate {
    private let line: Int
    private let filePath: String
    private var textView = NSTextView()
    private var saveButton: NSButton?
    private var removeButton: NSButton?

    /// Called when the note is saved or removed with the resulting text (nil = removed).
    var onSave: ((String?) -> Void)?

    init(line: Int, filePath: String) {
        self.line = line
        self.filePath = filePath
        super.init(nibName: nil, bundle: nil)
        preferredContentSize = NSSize(width: 280, height: 150)
    }

    required init?(coder: NSCoder) { fatalError("init(coder:) has not been implemented") }

    override func loadView() {
        let container = NSView()
        container.translatesAutoresizingMaskIntoConstraints = false

        let title = NSTextField(labelWithString: "Note — Line \(line)")
        title.font = NSFont.systemFont(ofSize: 12, weight: .semibold)
        title.textColor = .labelColor
        title.translatesAutoresizingMaskIntoConstraints = false

        let fileField = NSTextField(labelWithString: (filePath as NSString).lastPathComponent)
        fileField.font = NSFont.systemFont(ofSize: 10)
        fileField.textColor = .secondaryLabelColor
        fileField.lineBreakMode = .byTruncatingMiddle
        fileField.translatesAutoresizingMaskIntoConstraints = false

        let scroll = NSScrollView()
        scroll.hasVerticalScroller = true
        scroll.autohidesScrollers = true
        scroll.borderType = .bezelBorder
        scroll.translatesAutoresizingMaskIntoConstraints = false

        textView.isRichText = false
        textView.isEditable = true
        textView.font = NSFont.systemFont(ofSize: 12)
        textView.allowsUndo = true
        textView.delegate = self
        textView.isVerticallyResizable = true
        textView.isHorizontallyResizable = false
        textView.autoresizingMask = [.width]
        textView.textContainerInset = NSSize(width: 4, height: 4)
        textView.textContainer?.widthTracksTextView = true
        scroll.documentView = textView

        let save = NSButton(title: "Save", target: self, action: #selector(saveClicked))
        save.bezelStyle = .rounded
        save.keyEquivalent = "\r"

        let remove = NSButton(title: "Remove", target: self, action: #selector(removeClicked))
        remove.bezelStyle = .rounded

        save.translatesAutoresizingMaskIntoConstraints = false
        remove.translatesAutoresizingMaskIntoConstraints = false
        saveButton = save
        removeButton = remove

        container.addSubview(title)
        container.addSubview(fileField)
        container.addSubview(scroll)
        container.addSubview(save)
        container.addSubview(remove)

        NSLayoutConstraint.activate([
            title.topAnchor.constraint(equalTo: container.topAnchor, constant: 10),
            title.leadingAnchor.constraint(equalTo: container.leadingAnchor, constant: 12),
            title.trailingAnchor.constraint(lessThanOrEqualTo: container.trailingAnchor, constant: -12),

            fileField.topAnchor.constraint(equalTo: title.bottomAnchor, constant: 2),
            fileField.leadingAnchor.constraint(equalTo: title.leadingAnchor),
            fileField.trailingAnchor.constraint(lessThanOrEqualTo: container.trailingAnchor, constant: -12),

            scroll.topAnchor.constraint(equalTo: fileField.bottomAnchor, constant: 8),
            scroll.leadingAnchor.constraint(equalTo: container.leadingAnchor, constant: 12),
            scroll.trailingAnchor.constraint(equalTo: container.trailingAnchor, constant: -12),

            save.topAnchor.constraint(equalTo: scroll.bottomAnchor, constant: 8),
            save.trailingAnchor.constraint(equalTo: scroll.trailingAnchor),
            save.bottomAnchor.constraint(equalTo: container.bottomAnchor, constant: -10),

            remove.centerYAnchor.constraint(equalTo: save.centerYAnchor),
            remove.trailingAnchor.constraint(equalTo: save.leadingAnchor, constant: -8),

            scroll.heightAnchor.constraint(greaterThanOrEqualToConstant: 70)
        ])

        self.view = container
    }

    override func viewDidLoad() {
        super.viewDidLoad()
        if let text = NoteStore.shared.note(for: URL(fileURLWithPath: filePath), line: line) {
            textView.string = text
        }
        removeButton?.isHidden = NoteStore.shared.note(for: URL(fileURLWithPath: filePath), line: line) == nil
    }

    override func viewDidAppear() {
        super.viewDidAppear()
        view.window?.makeFirstResponder(textView)
    }

    @objc private func saveClicked() {
        let text = textView.string
        let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
        onSave?(trimmed.isEmpty ? nil : text)
    }

    @objc private func removeClicked() {
        onSave?(nil)
    }
}

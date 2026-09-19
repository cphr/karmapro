// by cipher.org.uk
import AppKit

/// A brief splash screen shown at launch. Displays the bundled image with the
/// "Karma Pro" wordmark overlaid at the top, then closes itself.
final class SplashWindowController: NSWindowController {
    fileprivate static let dark = NSColor(calibratedRed: 0.04, green: 0.06, blue: 0.11, alpha: 1.0)

    private var hideWorkItem: DispatchWorkItem?
    var onFinished: (() -> Void)?

    convenience init() {
        let size = NSSize(width: 480, height: 320)
        let window = EscClosableWindow(
            contentRect: NSRect(origin: .zero, size: size),
            styleMask: [.borderless],
            backing: .buffered,
            defer: false
        )
        window.isMovableByWindowBackground = true
        window.backgroundColor = SplashWindowController.dark
        window.isOpaque = true
        window.level = .floating
        window.hasShadow = true
        window.center()
        self.init(window: window)
        window.contentView = SplashView(frame: NSRect(origin: .zero, size: size))
    }

    func start() {
        showWindow(nil)
        NSApp.activate(ignoringOtherApps: true)
        let work = DispatchWorkItem { [weak self] in
            guard let self = self else { return }
            self.window?.orderOut(nil)
            self.onFinished?()
        }
        hideWorkItem = work
        DispatchQueue.main.asyncAfter(deadline: .now() + 3.0, execute: work)
    }

    deinit {
        hideWorkItem?.cancel()
    }
}

/// Renders the bundled image across the whole window and overlays the "Karma Pro"
/// wordmark at the top, falling back to a plain dark panel if the asset is
/// unavailable.
private final class SplashView: NSView {
    private lazy var splashImage: NSImage? = {
        Bundle.main.url(forResource: "SplashImage", withExtension: "jpg")
            .flatMap { NSImage(contentsOf: $0) }
    }()

    override func draw(_ dirtyRect: NSRect) {
        SplashWindowController.dark.setFill()
        bounds.fill()

        guard let img = splashImage else {
            // Fallback: plain dark panel with the wordmark.
            let titleAttrs: [NSAttributedString.Key: Any] = [
                .font: NSFont.systemFont(ofSize: 44, weight: .heavy),
                .foregroundColor: NSColor.white
            ]
            let title = "Karma Pro" as NSString
            let tsz = title.size(withAttributes: titleAttrs)
            title.draw(at: NSPoint(x: (bounds.width - tsz.width) / 2, y: bounds.height - 14 - tsz.height),
                       withAttributes: titleAttrs)
            return
        }

        NSGraphicsContext.current?.imageInterpolation = .high

        // Cover the window (aspect-fill; square source centered in a wide window).
        // NSImage.draw in this non-flipped context renders the image upright.
        let scale = max(bounds.width / img.size.width, bounds.height / img.size.height)
        let dw = img.size.width * scale
        let dh = img.size.height * scale
        let drawRect = NSRect(x: (bounds.width - dw) / 2, y: (bounds.height - dh) / 2, width: dw, height: dh)
        img.draw(in: drawRect, from: .zero, operation: .sourceOver, fraction: 1.0)

        // Top scrim so the wordmark is legible on any background.
        let scrimHeight = bounds.height * 0.30
        if let scrim = NSGradient(colors: [
            NSColor.black.withAlphaComponent(0.55),
            NSColor.black.withAlphaComponent(0.0)
        ]) {
            scrim.draw(in: NSRect(x: 0, y: bounds.height - scrimHeight,
                                  width: bounds.width, height: scrimHeight), angle: 270)
        }

        // --- "Karma Pro" wordmark at the top ---
        let shadow = NSShadow()
        shadow.shadowBlurRadius = 8
        shadow.shadowOffset = NSSize(width: 0, height: -1)
        shadow.shadowColor = NSColor.black.withAlphaComponent(0.75)
        let titleAttrs: [NSAttributedString.Key: Any] = [
            .font: NSFont.systemFont(ofSize: 38, weight: .heavy),
            .foregroundColor: NSColor.white,
            .shadow: shadow
        ]
        let title = "Karma Pro" as NSString
        let tsz = title.size(withAttributes: titleAttrs)
        title.draw(at: NSPoint(x: (bounds.width - tsz.width) / 2, y: bounds.height - 14 - tsz.height),
                   withAttributes: titleAttrs)

        // --- Footer: smallest of smalls, bottom-left ---
        let footerAttrs: [NSAttributedString.Key: Any] = [
            .font: NSFont.systemFont(ofSize: 10, weight: .regular),
            .foregroundColor: NSColor.white.withAlphaComponent(0.7)
        ]
        let footer = "brought to you by cipher.org.uk" as NSString
        let fsz = footer.size(withAttributes: footerAttrs)
        let footerOrigin = NSPoint(x: 10, y: 8)
        // Black underlay pill so the credit stays legible on any background.
        NSColor.black.withAlphaComponent(0.55).setFill()
        NSBezierPath(roundedRect:
            NSRect(x: footerOrigin.x - 5, y: footerOrigin.y - 3,
                   width: fsz.width + 10, height: fsz.height + 6),
            xRadius: 4, yRadius: 4).fill()
        footer.draw(at: footerOrigin, withAttributes: footerAttrs)
    }

    override func hitTest(_ point: NSPoint) -> NSView? { nil }
}
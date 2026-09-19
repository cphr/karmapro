// by cipher.org.uk
import Foundation
import AppKit

/// A floating magnification lens overlay view that follows the cursor
/// and renders zoomed-in source text underneath it.
final class CodeMagnifyingGlassView: NSView {
    weak var targetTextView: NSTextView?
    private var zoomFactor: CGFloat = 1.5
    private var lensRadius: CGFloat = 220.0

    init(targetTextView: NSTextView) {
        self.targetTextView = targetTextView
        let diameter = lensRadius * 2
        super.init(frame: NSRect(x: 0, y: 0, width: diameter, height: diameter))
        self.wantsLayer = true
        self.layer?.cornerRadius = lensRadius
        self.layer?.masksToBounds = true
        self.layer?.borderColor = NSColor.controlAccentColor.cgColor
        self.layer?.borderWidth = 3.5
        self.layer?.shadowColor = NSColor.black.cgColor
        self.layer?.shadowOpacity = 0.5
        self.layer?.shadowRadius = 10.0
        self.layer?.shadowOffset = CGSize(width: 0, height: -5)
        self.isHidden = true
    }

    required init?(coder: NSCoder) {
        fatalError("init(coder:) has not been implemented")
    }

    override func draw(_ dirtyRect: NSRect) {
        super.draw(dirtyRect)
        guard let tv = targetTextView, let context = NSGraphicsContext.current?.cgContext else {
            NSColor.windowBackgroundColor.setFill()
            dirtyRect.fill()
            return
        }

        // Draw background white/tint
        NSColor.textBackgroundColor.setFill()
        dirtyRect.fill()

        context.saveGState()

        // Flip coordinate system because CoreGraphics / NSView layer rendering
        // coordinates differ from AppKit view coordinate space.
        context.translateBy(x: 0, y: bounds.height)
        context.scaleBy(x: 1.0, y: -1.0)

        // Translate and scale around the center of the lens
        let center = CGPoint(x: bounds.midX, y: bounds.midY)
        context.translateBy(x: center.x, y: center.y)
        context.scaleBy(x: zoomFactor, y: zoomFactor)
        context.translateBy(x: -center.x, y: -center.y)

        // Convert current window mouse location to text view coordinates
        let mouseInWindow = window?.mouseLocationOutsideOfEventStream ?? .zero
        let mouseInTV = tv.convert(mouseInWindow, from: nil)

        // Offset context to center the magnified area around the mouse
        let dx = center.x - mouseInTV.x
        let dy = center.y - mouseInTV.y
        context.translateBy(x: dx, y: dy)

        // Render the target text view into the lens context
        tv.layer?.render(in: context)

        context.restoreGState()

        // Draw outer glass ring reflection
        NSColor.gridColor.setStroke()
        let path = NSBezierPath(ovalIn: bounds.insetBy(dx: 1, dy: 1))
        path.lineWidth = 2.0
        path.stroke()
    }

    func updatePosition(withEvent event: NSEvent) {
        guard superview != nil, targetTextView != nil else { return }
        let locInWindow = event.locationInWindow
        let locInSuperview = superview?.convert(locInWindow, from: nil) ?? locInWindow

        let diameter = lensRadius * 2
        let newOrigin = CGPoint(
            x: locInSuperview.x - lensRadius,
            y: locInSuperview.y - lensRadius
        )
        frame = NSRect(origin: newOrigin, size: CGSize(width: diameter, height: diameter))
        needsDisplay = true
    }
}

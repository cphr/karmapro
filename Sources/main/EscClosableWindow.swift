// by cipher.org.uk
import AppKit

/// A window that closes when the Escape key is pressed.
///
/// AppKit routes an unhandled Escape to `cancelOperation(_:)` on the key
/// window's responder chain, so overriding it here gives every popup/child
/// window standard ESC-to-dismiss behavior. The main window and modal system
/// dialogs deliberately keep their default handling.
final class EscClosableWindow: NSWindow {
    override func cancelOperation(_ sender: Any?) {
        if let sheetParent = sheetParent {
            sheetParent.endSheet(self)
        } else {
            close()
        }
    }
}
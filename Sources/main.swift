// by cipher.org.uk
import AppKit

let app = NSApplication.shared
if let darkAppearance = NSAppearance(named: .darkAqua) {
    app.appearance = darkAppearance
}
// Load the bundle icon so the Dock / Cmd-Tab tile shows the app's magnifying-glass + lock
// icon reliably (independent of macOS icon-cache behavior).
if let bundleIcon = NSImage(named: NSImage.Name("AppIcon")) {
    app.applicationIconImage = bundleIcon
}

// Build a minimal main menu with an About item crediting cipher.org.uk.
// The target is kept alive for the app's lifetime so the menu item stays enabled.
final class AboutMenuItemTarget: NSObject {
    private var splash: SplashWindowController?
    private var hideWorkItem: DispatchWorkItem?

    @objc func showAbout(_ sender: Any?) {
        let splash = SplashWindowController()
        splash.showWindow(nil)
        NSApp.activate(ignoringOtherApps: true)
        self.splash = splash
        hideWorkItem?.cancel()
        let work = DispatchWorkItem { [weak self] in
            self?.splash?.window?.orderOut(nil)
            self?.splash = nil
        }
        hideWorkItem = work
        DispatchQueue.main.asyncAfter(deadline: .now() + 5.0, execute: work)
    }
}

let aboutTarget = AboutMenuItemTarget()

final class HelpMenuTarget: NSObject {
    private var helpController: HelpWindowController?

    @objc func showHelp(_ sender: Any?) {
        if helpController == nil {
            helpController = HelpWindowController()
        }
        helpController?.showWindow(nil)
        helpController?.window?.makeKeyAndOrderFront(nil)
        NSApp.activate(ignoringOtherApps: true)
    }
}

let helpTarget = HelpMenuTarget()

final class LicensingMenuTarget: NSObject {
    private var licensingController: LicensingWindowController?

    @objc func scanProjectLicenses(_ sender: Any?) {
        // Find current project root if available from delegate/windowController
        let rootURL: URL? = (NSApp.delegate as? AppDelegate)?.currentProjectRootURL
        let controller = LicensingWindowController(projectRoot: rootURL)
        controller.showWindow(nil)
        controller.window?.makeKeyAndOrderFront(nil)
        NSApp.activate(ignoringOtherApps: true)
        licensingController = controller
    }
}

let licensingTarget = LicensingMenuTarget()

func makeMainMenu() -> NSMenu {
    let mainMenu = NSMenu()

    let appMenuItem = NSMenuItem()
    mainMenu.addItem(appMenuItem)
    let appMenu = NSMenu()
    let aboutItem = NSMenuItem(title: "About Karma Pro",
                                action: #selector(AboutMenuItemTarget.showAbout(_:)),
                                keyEquivalent: "")
    aboutItem.target = aboutTarget
    appMenu.addItem(aboutItem)
    appMenu.addItem(NSMenuItem.separator())
    appMenu.addItem(NSMenuItem(title: "Quit Karma Pro",
                                action: #selector(NSApplication.terminate(_:)),
                                keyEquivalent: "q"))
    appMenuItem.submenu = appMenu

    // Standard Edit menu: without it, Cut/Copy/Paste/Select All shortcuts
    // (Cmd+X/C/V/A) are never dispatched to text fields, which broke pasting
    // e.g. an OpenRouter API key into the AI window. The nil targets let the
    // actions flow down the responder chain to the focused control.
    let editMenuItem = NSMenuItem()
    mainMenu.addItem(editMenuItem)
    let editMenu = NSMenu(title: "Edit")
    editMenu.addItem(NSMenuItem(title: "Undo", action: #selector(UndoManager.undo), keyEquivalent: "z"))
    editMenu.addItem(NSMenuItem(title: "Redo", action: #selector(UndoManager.redo), keyEquivalent: "Z"))
    editMenu.addItem(NSMenuItem.separator())
    editMenu.addItem(NSMenuItem(title: "Cut", action: #selector(NSText.cut(_:)), keyEquivalent: "x"))
    editMenu.addItem(NSMenuItem(title: "Copy", action: #selector(NSText.copy(_:)), keyEquivalent: "c"))
    editMenu.addItem(NSMenuItem(title: "Paste", action: #selector(NSText.paste(_:)), keyEquivalent: "v"))
    editMenu.addItem(NSMenuItem(title: "Delete", action: #selector(NSText.delete(_:)), keyEquivalent: ""))
    editMenu.addItem(NSMenuItem(title: "Select All", action: #selector(NSText.selectAll(_:)), keyEquivalent: "a"))
    editMenuItem.submenu = editMenu

    let licensingMenuItem = NSMenuItem()
    mainMenu.addItem(licensingMenuItem)
    let licensingMenu = NSMenu(title: "Licensing")
    let scanLicensesItem = NSMenuItem(title: "Scan Licenses",
                                     action: #selector(LicensingMenuTarget.scanProjectLicenses(_:)),
                                     keyEquivalent: "l")
    scanLicensesItem.target = licensingTarget
    licensingMenu.addItem(scanLicensesItem)
    licensingMenuItem.submenu = licensingMenu

    let helpMenuItem = NSMenuItem()
    mainMenu.addItem(helpMenuItem)
    let helpMenu = NSMenu(title: "Help")
    let helpItem = NSMenuItem(title: "Karma Pro Help",
                              action: #selector(HelpMenuTarget.showHelp(_:)),
                              keyEquivalent: "?")
    helpItem.target = helpTarget
    helpMenu.addItem(helpItem)
    helpMenuItem.submenu = helpMenu

    return mainMenu
}

app.mainMenu = makeMainMenu()

let delegate = AppDelegate()
app.delegate = delegate
app.setActivationPolicy(.regular)
app.run()

// by cipher.org.uk
import Foundation
import WebKit
import AppKit

/// Window controller that displays the Karma Pro User Guide & Help document
/// rendered cleanly in a WebKit view, complete with the splash image and formatting.
final class HelpWindowController: NSWindowController {
    private var webView: WKWebView!

    convenience init() {
        let window = EscClosableWindow(
            contentRect: NSRect(x: 0, y: 0, width: 750, height: 600),
            styleMask: [.titled, .closable, .resizable, .miniaturizable],
            backing: .buffered,
            defer: false
        )
        window.title = "Karma Pro Help & User Guide"
        window.center()
        self.init(window: window)
        setupUI()
        loadHelpContent()
    }

    private func setupUI() {
        guard let contentView = window?.contentView else { return }
        
        let config = WKWebViewConfiguration()
        webView = WKWebView(frame: contentView.bounds, configuration: config)
        webView.autoresizingMask = [.width, .height]
        contentView.addSubview(webView)
    }

    private func loadHelpContent() {
        let mdPath = Bundle.main.path(forResource: "HelpContent", ofType: "md")
            ?? "/Users/manos/visual studio/reviewer/Resources_src/HelpContent.md"
        
        guard let mdContent = try? String(contentsOfFile: mdPath, encoding: .utf8) else {
            webView.loadHTMLString("<h3>Help content not found.</h3>", baseURL: nil)
            return
        }

        let html = markdownToHTML(mdContent)
        let baseURL = Bundle.main.resourceURL ?? URL(fileURLWithPath: "/Users/manos/visual studio/reviewer/Resources_src/")
        webView.loadHTMLString(html, baseURL: baseURL)
    }

    private func markdownToHTML(_ md: String) -> String {
        // Basic Markdown to HTML converter with styling
        let escaped = md
            .replacingOccurrences(of: "&", with: "&amp;")
            .replacingOccurrences(of: "<", with: "&lt;")
            .replacingOccurrences(of: ">", with: "&gt;")

        var html = ""
        let lines = escaped.components(separatedBy: "\n")
        var inList = false

        for line in lines {
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            if trimmed.hasPrefix("# ") {
                if inList { html += "</ul>"; inList = false }
                html += "<h1>\(String(trimmed.dropFirst(2)))</h1>\n"
            } else if trimmed.hasPrefix("## ") {
                if inList { html += "</ul>"; inList = false }
                html += "<h2>\(String(trimmed.dropFirst(3)))</h2>\n"
            } else if trimmed.hasPrefix("- ") {
                if !inList { html += "<ul>"; inList = true }
                let item = String(trimmed.dropFirst(2))
                html += "<li>\(formatInline(item))</li>\n"
            } else if trimmed.hasPrefix("1. ") || trimmed.hasPrefix("2. ") || trimmed.hasPrefix("3. ") || trimmed.hasPrefix("4. ") || trimmed.hasPrefix("5. ") || trimmed.hasPrefix("6. ") {
                if inList { html += "</ul>"; inList = false }
                html += "<p><strong>\(trimmed)</strong></p>\n"
            } else if trimmed.hasPrefix("![Karma Pro Splash]") || trimmed.hasPrefix("![") && trimmed.contains("](") {
                if inList { html += "</ul>"; inList = false }
                html += "<div style='text-align:center; margin: 20px 0;'><img src='HelpSplash.jpg' style='max-width:320px; border-radius:8px; box-shadow: 0 4px 12px rgba(0,0,0,0.15);'/></div>\n"
            } else if trimmed.isEmpty {
                if inList { html += "</ul>"; inList = false }
                html += "<br/>\n"
            } else {
                if inList { html += "</ul>"; inList = false }
                html += "<p>\(formatInline(trimmed))</p>\n"
            }
        }
        if inList { html += "</ul>" }

        return """
        <!DOCTYPE html>
        <html>
        <head>
        <meta charset="utf-8">
        <style>
            body {
                font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
                color: #333;
                background-color: #f9f9fb;
                padding: 30px 40px;
                line-height: 1.6;
                font-size: 14px;
            }
            h1 { font-size: 24px; color: #111; border-bottom: 2px solid #eaeaea; padding-bottom: 8px; margin-top: 0; }
            h2 { font-size: 16px; color: #222; margin-top: 25px; border-bottom: 1px solid #eaeaea; padding-bottom: 4px; }
            p { margin: 8px 0; }
            ul { margin: 6px 0 12px 20px; }
            li { margin-bottom: 4px; }
            code { background: #eee; padding: 2px 6px; border-radius: 4px; font-size: 13px; font-family: monospace; }
            strong { color: #111; }
            hr { border: none; border-top: 1px solid #eaeaea; margin: 25px 0; }
        </style>
        </head>
        <body>
        \(html)
        </body>
        </html>
        """
    }

    private func formatInline(_ text: String) -> String {
        // Convert **bold** to <strong>
        var res = text
        while let start = res.range(of: "**"), let end = res.range(of: "**", range: start.upperBound..<res.endIndex) {
            let boldText = res[start.upperBound..<end.lowerBound]
            res.replaceSubrange(start.lowerBound..<end.upperBound, with: "<strong>\(boldText)</strong>")
        }
        return res
    }
}

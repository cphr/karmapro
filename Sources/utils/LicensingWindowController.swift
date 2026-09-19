// by cipher.org.uk
import Foundation
import AppKit

/// Window controller that scans a project directory for license files (LICENSE, LICENSE.md,
/// COPYING, etc.), identifies their license type, and evaluates commercial use permit and
/// required license terms.
final class LicensingWindowController: NSWindowController {
    private var textView: NSTextView!

    convenience init(projectRoot: URL?) {
        let window = EscClosableWindow(
            contentRect: NSRect(x: 0, y: 0, width: 700, height: 500),
            styleMask: [.titled, .closable, .resizable, .miniaturizable],
            backing: .buffered,
            defer: false
        )
        window.title = "Project License & Commercial Use Auditor"
        window.center()
        self.init(window: window)
        setupUI()
        scanLicenses(in: projectRoot)
    }

    private func setupUI() {
        guard let contentView = window?.contentView else { return }

        let scrollView = NSScrollView(frame: contentView.bounds)
        scrollView.hasVerticalScroller = true
        scrollView.autoresizingMask = [.width, .height]

        let tv = NSTextView(frame: scrollView.bounds)
        tv.isEditable = false
        tv.isSelectable = true
        tv.font = NSFont.monospacedSystemFont(ofSize: 13.0, weight: .regular)
        tv.textContainerInset = NSSize(width: 15, height: 15)
        tv.backgroundColor = NSColor.textBackgroundColor

        scrollView.documentView = tv
        contentView.addSubview(scrollView)
        self.textView = tv
    }

    private func scanLicenses(in root: URL?) {
        guard let root = root else {
            textView.string = "No project folder currently open.\nPlease open a project using File > Open... to scan for licenses."
            return
        }

        var report = "=== Project License & Commercial Use Audit ===\n"
        report += "Scanned Root: \(root.path)\n\n"

        let fm = FileManager.default
        let licenseNames = ["license", "licence", "license.md", "licence.md", "copying", "copying.md", "license.txt", "licence.txt"]

        var foundLicenses: [(url: URL, content: String)] = []

        if let enumerator = fm.enumerator(at: root, includingPropertiesForKeys: [.isRegularFileKey], options: [.skipsHiddenFiles]) {
            for case let fileURL as URL in enumerator {
                let lowerName = fileURL.lastPathComponent.lowercased()
                if licenseNames.contains(lowerName) || lowerName.hasPrefix("license") || lowerName.hasPrefix("licence") {
                    if let text = try? String(contentsOf: fileURL, encoding: .utf8) {
                        foundLicenses.append((fileURL, text))
                    }
                }
            }
        }

        if foundLicenses.isEmpty {
            report += "[-] No standard license files (LICENSE, LICENSE.md, COPYING) found in this project directory.\n\n"
            report += "Commercial Use Assessment:\n"
            report += "• Without an explicit open-source license file, standard copyright law applies.\n"
            report += "• You DO NOT have permission to use, copy, modify, or distribute this code commercially unless granted under a separate private agreement or contract with the author."
        } else {
            for lic in foundLicenses {
                report += "--------------------------------------------------\n"
                report += "Found License File: \(lic.url.path.replacingOccurrences(of: root.path + "/", with: ""))\n"
                report += "--------------------------------------------------\n"
                
                let analysis = analyzeLicenseText(lic.content)
                report += "• Detected License Type : \(analysis.name)\n"
                report += "• Commercial Use Permitted? : \(analysis.commercialAllowed ? "YES ✅" : "NO ❌")\n"
                report += "• Required License/Conditions : \(analysis.conditions)\n\n"
                report += "License Snippet / Summary:\n"
                let preview = lic.content.components(separatedBy: "\n").prefix(25).joined(separator: "\n")
                report += preview + (lic.content.components(separatedBy: "\n").count > 25 ? "\n[... truncated ...]\n" : "\n")
            }
        }

        textView.string = report
    }

    private struct LicenseAnalysis {
        let name: String
        let commercialAllowed: Bool
        let conditions: String
    }

    private func analyzeLicenseText(_ text: String) -> LicenseAnalysis {
        let lower = text.lowercased()

        if lower.contains("mit license") || lower.contains("permission is hereby granted, free of charge") {
            return LicenseAnalysis(
                name: "MIT License",
                commercialAllowed: true,
                conditions: "Permitted. Must include the original copyright notice and permission notice in all copies or substantial portions of the software."
            )
        } else if lower.contains("apache license") && lower.contains("version 2.0") {
            return LicenseAnalysis(
                name: "Apache License 2.0",
                commercialAllowed: true,
                conditions: "Permitted. Requires preserving copyright, patent, trademark, and attribution notices, and stating changes made to modified files."
            )
        } else if lower.contains("bsd 3-clause") || (lower.contains("bsd license") && lower.contains("redistribution and use in source and binary forms")) {
            return LicenseAnalysis(
                name: "BSD 3-Clause License",
                commercialAllowed: true,
                conditions: "Permitted. Requires retaining copyright notice, conditions list, disclaimer, and prohibits using the copyright holder's name for endorsement without prior written consent."
            )
        } else if lower.contains("bsd 2-clause") {
            return LicenseAnalysis(
                name: "BSD 2-Clause License",
                commercialAllowed: true,
                conditions: "Permitted. Requires retaining copyright notice, conditions list, and disclaimer."
            )
        } else if lower.contains("gnu general public license") || lower.contains("gpl v3") || lower.contains("gpl-3.0") {
            return LicenseAnalysis(
                name: "GNU General Public License v3.0 (GPLv3)",
                commercialAllowed: true,
                conditions: "Conditionally Permitted. Commercial use is allowed, but **viral copyleft applies**: any commercial distribution of derivative works or binaries requires disclosing corresponding complete source code under the same GPLv3 license."
            )
        } else if lower.contains("gnu lesser general public license") || lower.contains("lgpl") {
            return LicenseAnalysis(
                name: "GNU Lesser General Public License (LGPL)",
                commercialAllowed: true,
                conditions: "Conditionally Permitted. Commercial use allowed. Linking dynamically to LGPL libraries generally does not propagate copyleft to your proprietary code, but modifications to the LGPL library itself must remain open source."
            )
        } else if lower.contains("mozilla public license") || lower.contains("mpl") {
            return LicenseAnalysis(
                name: "Mozilla Public License (MPL 2.0)",
                commercialAllowed: true,
                conditions: "Conditionally Permitted. File-level copyleft: commercial use allowed, but any modified MPL-licensed files must remain open source under MPL."
            )
        } else if lower.contains("isc license") {
            return LicenseAnalysis(
                name: "ISC License",
                commercialAllowed: true,
                conditions: "Permitted. Similar to MIT, very permissive with minimal copyright retention requirements."
            )
        } else if lower.contains("unlicense") || lower.contains("disclaims all copyright") {
            return LicenseAnalysis(
                name: "The Unlicense (Public Domain)",
                commercialAllowed: true,
                conditions: "Fully Permitted without restrictions, attribution, or conditions."
            )
        } else {
            return LicenseAnalysis(
                name: "Custom / Unrecognized Open Source / Proprietary",
                commercialAllowed: false,
                conditions: "Review license text carefully. Unless explicitly granted commercial rights, assume proprietary restrictions apply."
            )
        }
    }
}

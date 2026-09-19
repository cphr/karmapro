// by cipher.org.uk
import AppKit

/// Window used to create a new bug report or edit an existing one. It collects a
/// title, severity, exploitability, description, package name, and version number,
/// then stores the result via `BugStore` and notifies the caller.
final class BugEditorWindowController: NSWindowController {
    private let titleField = NSTextField(frame: .zero)
    private let titleMenu = NSPopUpButton(frame: .zero, pullsDown: false)
    private let severityPopup = NSPopUpButton(frame: .zero, pullsDown: false)
    private let exploitabilityPopup = NSPopUpButton(frame: .zero, pullsDown: false)
    private let packageField = NSTextField(frame: .zero)
    private let versionField = NSTextField(frame: .zero)
    private let statusPopup = NSPopUpButton(frame: .zero, pullsDown: false)
    private let detailTextView = NSTextView(frame: .zero)
    private let errorLabel = NSTextField(wrappingLabelWithString: "")

    private var editingBug: Bug?

    /// Invoked after a bug is created or updated (passes the saved bug).
    var onSaved: ((Bug) -> Void)?

    /// Preset security-vulnerability titles shown in the title dropdown. The first
    /// entry ("Custom title…") lets the user type their own title freely.
    private static let presetTitles: [String] = {
        var arr: [String] = []

        arr.append("SQL Injection")
        arr.append("Blind SQL Injection")
        arr.append("Time-Based SQL Injection")
        arr.append("Boolean-Based Blind SQL Injection")
        arr.append("SQL Injection via User Input")
        arr.append("SQL Injection in Login Query")
        arr.append("SQL Injection in Search Parameter")
        arr.append("Second-Order SQL Injection")
        arr.append("SQL Injection via Stored Procedure")
        arr.append("Stored Cross-Site Scripting (XSS)")
        arr.append("Reflected Cross-Site Scripting (XSS)")
        arr.append("DOM-Based Cross-Site Scripting (XSS)")
        arr.append("XSS via Unsanitized User Input")
        arr.append("Persistent XSS in Comment Field")
        arr.append("Cascading Style Sheets (CSS) Injection")
        arr.append("OS Command Injection")
        arr.append("Command Injection via Shell Metacharacters")
        arr.append("Blind Command Injection")
        arr.append("Code Injection")
        arr.append("Remote Code Execution (RCE)")
        arr.append("Remote Code Execution via Deserialization")
        arr.append("PHP Code Injection")
        arr.append("Server-Side Template Injection (SSTI)")
        arr.append("Unrestricted File Upload Leading to Code Execution")
        arr.append("Broken Authentication")
        arr.append("Session Fixation")
        arr.append("Session Hijacking")
        arr.append("Session Token Leak in URL")
        arr.append("Predictable Session Identifier")
        arr.append("Session Cookie Missing Secure Flag")
        arr.append("Session Cookie Missing HttpOnly Flag")
        arr.append("Session Timeout Not Enforced")
        arr.append("Credential Reuse / Default Credentials")
        arr.append("Weak Password Policy")
        arr.append("Account Enumeration via Login")
        arr.append("Account Lockout Bypass")
        arr.append("Password Stored in Plaintext")
        arr.append("Password in Configuration File")
        arr.append("Privilege Escalation")
        arr.append("Horizontal Privilege Escalation")
        arr.append("Vertical Privilege Escalation")
        arr.append("Insecure Direct Object Reference (IDOR)")
        arr.append("Bypass of Password Change Flow")
        arr.append("Remember-Me Cookie Predictable")
        arr.append("Broken Access Control")
        arr.append("Missing Access Control on API Endpoint")
        arr.append("Authorization Bypass")
        arr.append("Path Traversal")
        arr.append("Directory Traversal")
        arr.append("Local File Inclusion (LFI)")
        arr.append("Remote File Inclusion (RFI)")
        arr.append("Symlink Following / Arbitrary File Read")
        arr.append("Arbitrary File Read")
        arr.append("Arbitrary File Write")
        arr.append("Unrestricted File Upload")
        arr.append("Zip Slip (Path Traversal in Archive)")
        arr.append("Use of Weak Hashing Algorithm (MD5/SHA-1)")
        arr.append("Weak Cryptographic Key")
        arr.append("Insufficient Key Length")
        arr.append("Hardcoded Encryption Key")
        arr.append("Hardcoded Credentials")
        arr.append("Hardcoded API Key")
        arr.append("Hardcoded Password")
        arr.append("Weak Random Number Generator")
        arr.append("Use of Insecure Cipher")
        arr.append("ECB Mode Encryption")
        arr.append("Missing Certificate Validation")
        arr.append("Insecure TLS Configuration")
        arr.append("TLS/SSL Certificate Verification Disabled")
        arr.append("Use of Deprecated Cryptographic Algorithm")
        arr.append("Server-Side Request Forgery (SSRF)")
        arr.append("XML External Entity (XXE) Injection")
        arr.append("XML External Entity (XXE) via File Upload")
        arr.append("Insecure Deserialization")
        arr.append("Unsafe Deserialization of Untrusted Data")
        arr.append("LDAP Injection")
        arr.append("Expression Language (EL) Injection")
        arr.append("Template Injection")
        arr.append("Header Injection")
        arr.append("HTTP Response Splitting")
        arr.append("Email Header Injection")
        arr.append("Log Injection")
        arr.append("Formula Injection (CSV Injection)")
        arr.append("Regex Injection / ReDoS")
        arr.append("Regular Expression Denial of Service (ReDoS)")
        arr.append("Null Byte Injection")
        arr.append("HTTP Request Smuggling")
        arr.append("Cross-Site Request Forgery (CSRF)")
        arr.append("Cross-Site Request Forgery on State-Changing Requests")
        arr.append("Missing CSRF Token")
        arr.append("CORS Misconfiguration")
        arr.append("Sensitive Data Exposure")
        arr.append("Exposure of Personally Identifiable Information (PII)")
        arr.append("Credentials Exposed in Logs")
        arr.append("API Key Exposed in Client-Side Code")
        arr.append("Source Code Disclosure")
        arr.append("Debug Information Exposed in Production")
        arr.append("Verbose Error Messages Leaking Details")
        arr.append("Sensitive Data in URL")
        arr.append("Sensitive Data in Query String")
        arr.append("Clear-Text Transmission of Sensitive Data")
        arr.append("Security Misconfiguration")
        arr.append("Directory Listing Enabled")
        arr.append("Default/Root Credentials Enabled")
        arr.append("Unnecessary Services Enabled")
        arr.append("Outdated Component with Known Vulnerability")
        arr.append("Vulnerable Dependency")
        arr.append("Use of Component with Known Vulnerabilities")
        arr.append("Unsanitized Error Handling")
        arr.append("Missing Security Headers")
        arr.append("Insecure HTTP Usage")
        arr.append("Information Disclosure in Error Messages")
        arr.append("Missing Input Validation")
        arr.append("Improper Error Handling")
        arr.append("Improper Sanitization of User Input")
        arr.append("Data Injection")
        arr.append("Integer Overflow / Underflow")
        arr.append("Buffer Overflow")
        arr.append("Out-of-Bounds Write")
        arr.append("Use-After-Free")
        arr.append("Double Free")
        arr.append("Null Pointer Dereference")
        arr.append("Memory Leak")
        arr.append("Uninitialized Memory Use")
        arr.append("Stack Overflow")
        arr.append("Heap Overflow")
        arr.append("Format String Vulnerability")
        arr.append("Race Condition")
        arr.append("Time-of-Check to Time-of-Use (TOCTOU)")
        arr.append("Insecure Direct Object Reference")
        arr.append("Business Logic Flaw")
        arr.append("Authorization Flaw in Business Logic")
        arr.append("Improper Input Validation")
        arr.append("Mass Assignment Vulnerability")
        arr.append("Clickjacking / UI Redressing")
        arr.append("Open Redirect")
        arr.append("Unvalidated Redirect")
        arr.append("Denial of Service (DoS)")
        arr.append("Distributed Denial of Service (DDoS)")
        arr.append("Resource Exhaustion")
        arr.append("Unbounded Resource Allocation")
        arr.append("Slowloris Attack Vector")
        arr.append("Zip Bomb / Decompression Bomb")
        arr.append("Insufficient Logging and Monitoring")
        arr.append("Security Headers Missing")
        arr.append("Weak TLS Cipher Suites")
        arr.append("Insecure Use of Cryptography")
        arr.append("Trust Boundary Violation")
        arr.append("Unchecked File Permissions")
        arr.append("Permissions on Sensitive File Too Permissive")
        arr.append("Insecure Network Communication")
        arr.append("Man-in-the-Middle (MITM) Vulnerability")
        arr.append("DNS Rebinding")
        arr.append("Host Header Injection")
        arr.append("Cache Poisoning")
        arr.append("Subdomain Takeover")
        arr.append("Clickjacking Protection Missing")
        arr.append("Weak SHA-1 Certificate Signature")
        arr.append("Deprecated Hash Used for Password Storage")
        arr.append("Password Stored with Unkeyed Hash")
        arr.append("Insufficient Password Hashing Iterations")
        arr.append("Salt Reuse Across Passwords")
        arr.append("Hardcoded Salt in Crypto")
        arr.append("Cryptographic Nonce Reuse")
        arr.append("Nonce Reuse in Encryption")
        arr.append("Short Random Seed")
        arr.append("Insecure Randomness in Security Context")
        arr.append("Predictive Random Number Generation")
        arr.append("Use of Math.random for Security")
        arr.append("Weak KDF for Password Storage")
        arr.append("PBKDF2/BCrypt Cost Factor Too Low")
        arr.append("AES Key Stored in Source Code")
        arr.append("Private Key Exposed")
        arr.append("Certificate Private Key Leak")
        arr.append("Insufficient Key Management")
        arr.append("Key Hardcoded in Binary")
        arr.append("Missing Encryption of Sensitive Data")
        arr.append("Transport Layer Encryption Missing")
        arr.append("No Encryption at Rest")
        arr.append("Database Column Not Encrypted")
        arr.append("Cipher in CBC with Predictable IV")
        arr.append("Use of Broken Cipher (RC4/3DES)")
        arr.append("Export-Grade Cipher Enabled")
        arr.append("TLS 1.0/1.1 Enabled")
        arr.append("SSLv3 POODLE Vulnerability")
        arr.append("Heartbleed-Style Vulnerability")
        arr.append("Missing HSTS Header")
        arr.append("Certificate Pinning Absent")
        arr.append("Self-Signed Certificate Trusted")
        arr.append("Hostname Verification Disabled")
        arr.append("SQL Injection in Stored Procedure")
        arr.append("SQL Injection via ORDER BY")
        arr.append("SQL Injection via Error Messages")
        arr.append("SQL Injection via Cookies")
        arr.append("SQL Injection via HTTP Headers")
        arr.append("Union-Based SQL Injection")
        arr.append("Stacked Query SQL Injection")
        arr.append("LDAP Injection via User Input")
        arr.append("XML Injection")
        arr.append("XPath Injection")
        arr.append("XQuery Injection")
        arr.append("SOAP Injection")
        arr.append("HTTP Parameter Pollution")
        arr.append("Content-Type Injection")
        arr.append("MIME Type Confusion")
        arr.append("SVG Injection")
        arr.append("Markdown Injection")
        arr.append("YAML Deserialization / YAML Injection")
        arr.append("Animated GIF / Image Metadata Injection")
        arr.append("Uploaded File Executable")
        arr.append("Double Encoding Bypass")
        arr.append("Null Byte in Filename")
        arr.append("Command Injection via Filename")
        arr.append("Argument Injection")
        arr.append("Option Injection into Executable")
        arr.append("SSRF via URL Parameter")
        arr.append("SSRF through DNS Rebinding")
        arr.append("Blind SSRF")
        arr.append("Full SSRF (Internal Service Access)")
        arr.append("Gopher SSRF")
        arr.append("Insecure Java Deserialization")
        arr.append("Insecure .NET Deserialization")
        arr.append("Insecure PHP Deserialization (unserialize)")
        arr.append("Insecure Python Pickle Deserialization")
        arr.append("Object Injection via Deserialization")
        arr.append("Gadget Chain Deserialization")
        arr.append("Arbitrary File Read via Path Traversal")
        arr.append("Arbitrary File Write via Path Traversal")
        arr.append("Symlink Following (File Read)")
        arr.append("Hard Link Following")
        arr.append("Unrestricted File Upload (Executable)")
        arr.append("Unrestricted File Upload (SVG/XSS)")
        arr.append("Unrestricted File Upload (Archive Bomb)")
        arr.append("File Upload with Insufficient Validation")
        arr.append("Path Traversal in Zip Extraction")
        arr.append("Log File Injection / Poisoning")
        arr.append("File Extension Filter Bypass")
        arr.append("Double Extension Upload")
        arr.append("Temporary File with Insecure Permissions")
        arr.append("Insecure Temporary File Creation")
        arr.append("Insecure Direct Object Reference (IDOR)")
        arr.append("Missing Function-Level Access Control")
        arr.append("Missing Object-Level Authorization")
        arr.append("Privilege Escalation via IDOR")
        arr.append("IDOR on API Endpoints")
        arr.append("IDOR on Download Endpoint")
        arr.append("Insecure Direct Object Reference on Files")
        arr.append("Mass Enumeration via IDOR")
        arr.append("Broken Object Level Authorization (BOLA)")
        arr.append("Broken Function Level Authorization")
        arr.append("Authorization Bypass via Parameter Tampering")
        arr.append("Role-Based Access Control Bypass")
        arr.append("Default Admin Account Enabled")
        arr.append("Weak Session ID")
        arr.append("Session ID in Cookie without Secure Flag")
        arr.append("Session Regeneration Missing on Login")
        arr.append("Session Not Invalidated on Logout")
        arr.append("No Session Expiration")
        arr.append("Concurrent Session Limit Unenforced")
        arr.append("Account Takeover via Session Leak")
        arr.append("Account Takeover via Password Reset Token")
        arr.append("Insecure Password Reset Flow")
        arr.append("Password Reset Token in URL")
        arr.append("Password Reset Link Predictable")
        arr.append("Registration Enabling Arbitrary Account")
        arr.append("Email Verification Bypass")
        arr.append("OTP Brute Force Possible")
        arr.append("Two-Factor Authentication (2FA) Bypass")
        arr.append("2FA Not Enforced")
        arr.append("Credential Stuffing Mitigation Missing")
        arr.append("Rate Limiting Absent on Login")
        arr.append("Brute-Force Protection Missing")
        arr.append("CAPTCHA Bypassable")
        arr.append("Lockout Policy Missing")
        arr.append("Username/Password Timing Side Channel")
        arr.append("JWT Algorithm Confusion")
        arr.append("JWT with 'none' Algorithm")
        arr.append("JWT Secret Guessable")
        arr.append("JWT Not Validating Expiration")
        arr.append("OAuth Token Misconfiguration")
        arr.append("OAuth Redirect URI Manipulation")
        arr.append("OAuth State Parameter Missing")
        arr.append("API Token in Query String")
        arr.append("Bearer Token Missing Expiration")
        arr.append("Stored XSS via SVG Upload")
        arr.append("XSS via JSONP Endpoint")
        arr.append("Blind XSS (Callback Bypass)")
        arr.append("XSS in Error Page")
        arr.append("XSS in 404 Page")
        arr.append("XSS via Link Shortener")
        arr.append("Self-XSS Leading to Stored XSS")
        arr.append("Mutation XSS (mXSS)")
        arr.append("Unsafe InnerHTML Usage")
        arr.append("eval() on Untrusted Input")
        arr.append("Dangerous Function Usage (eval/Function)")
        arr.append("Prototype Pollution")
        arr.append("Client-Side Template Injection")
        arr.append("PostMessage Origin Not Validated")
        arr.append("WebSocket Origin Not Validated")
        arr.append("CSP Allowing Inline Scripts")
        arr.append("CSP Reporting-Only Mode")
        arr.append("Missing X-Content-Type-Options")
        arr.append("Missing X-Frame-Options / CSP frame-ancestors")
        arr.append("Referrer Policy Misconfiguration")
        arr.append("Open Redirect in Login Redirect")
        arr.append("Open Redirect via 'next' Parameter")
        arr.append("Clickjacking via Delay")
        arr.append("Drag-and-Drop Clickjacking (Clickbandit)")
        arr.append("Tabnabbing")
        arr.append("Keylogging via Malicious Extension")
        arr.append("HTTP Parameter Injection")
        arr.append("HTTP Request Splitting")
        arr.append("HTTP Response Splitting (CRLF)")
        arr.append("Request Smuggling (CL.TE)")
        arr.append("Request Smuggling (TE.CL)")
        arr.append("Cache Poisoning via Request Smuggling")
        arr.append("Host Header Poisoning")
        arr.append("Path Confusion (Trailing Slash)")
        arr.append("Unicode Path Bypass")
        arr.append("Directory Traversal Unicode Issues")
        arr.append("Server-Side Path Traversal")
        arr.append("Path Normalization Bypass")
        arr.append("Alias / Symlink Virtual Host Confusion")
        arr.append("Virtual Host Misconfiguration")
        arr.append("Spring Actuator Exposed")
        arr.append("Debug Endpoint Exposed")
        arr.append("Swagger/API Docs Exposed")
        arr.append("GraphQL Introspection Enabled")
        arr.append("GraphQL Field-Level Authorization Bypass")
        arr.append("Batch GraphQL DoS")
        arr.append("WebSocket Message Injection")
        arr.append("Server-Side Request via WebSocket Upgrade")
        arr.append("DNS Rebinding against Internal Services")
        arr.append("Web Cache Deception")
        arr.append("Content Spoofing")
        arr.append("Homograph / IDN Spoofing")
        arr.append("Business Logic Flaw in Pricing")
        arr.append("Price/Currency Manipulation")
        arr.append("Coupon Code Reuse")
        arr.append("Negative Quantity Order")
        arr.append("Integer Overflow in Arithmetic")
        arr.append("Race Condition in Balance Transfer")
        arr.append("Loyalty Points Manipulation")
        arr.append("Transaction Double-Spend")
        arr.append("Order Status Tampering")
        arr.append("Mass Assignment on Profile Fields")
        arr.append("Mass Assignment on Privileged Fields")
        arr.append("Missing Input Sanitization on Numeric Fields")
        arr.append("Unvalidated Numeric Range")
        arr.append("Unvalidated Length/Size")
        arr.append("Unhandled File Size Limit")
        arr.append("Illogical Application State")
        arr.append("Workflow Bypass")
        arr.append("Skipping Mandatory Steps in Workflow")
        arr.append("Authorization Not Checked in Batch Operations")
        arr.append("Timezone/Date Validation Issue")
        arr.append("Unicode Normalization Injection")
        arr.append("Unbounded Memory Allocation")
        arr.append("Unbounded CPU Consumption")
        arr.append("Unbounded Number of Threads")
        arr.append("Connection Pool Exhaustion")
        arr.append("Too Many Open File Descriptors")
        arr.append("Deep Recursion Stack Overflow")
        arr.append("Infinite Loop on Malformed Input")
        arr.append("Huge Payload DoS")
        arr.append("Slow JSON Parsing DoS")
        arr.append("Billion Laughs XML Bomb")
        arr.append("Decompression Bomb (Zip/Gzip)")
        arr.append("Recursive Query / Cyclic Dependency DoS")
        arr.append("Rate Limiting Missing on API")
        arr.append("Pagination Bound Missing")
        arr.append("Unlimited Search Results")
        arr.append("Missing Size Limit on Upload")
        arr.append("Request Body Size Unbounded")
        arr.append("Stack Buffer Overflow")
        arr.append("Heap Buffer Overflow")
        arr.append("Off-by-One Error")
        arr.append("Integer Signedness Bug")
        arr.append("Use of Uninitialized Pointer")
        arr.append("Dangling Pointer")
        arr.append("Wild / Whack Pointer")
        arr.append("Memory Corruption")
        arr.append("Type Confusion")
        arr.append("Object Confusion")
        arr.append("Race Condition on Shared Memory")
        arr.append("Data Race")
        arr.append("Deadlock")
        arr.append("Livelock")
        arr.append("Unsafe Pointer Arithmetic")
        arr.append("Missing Bounds Check")
        arr.append("Array Index Out of Bounds")
        arr.append("Negative Array Index")
        arr.append("String Overrun")
        arr.append("Format String Exploitation")
        arr.append("Importance of ASLR/DEP Disabled")
        arr.append("Stack Canary Missing")
        arr.append("Insecure Platform Network Connection")
        arr.append("Weak Permissions on Android Manifest")
        arr.append("Android Activity Export Without Permission")
        arr.append("iOS Insecure Data Storage")
        arr.append("iOS Keychain Access Group Misuse")
        arr.append("Hardcoded Secrets in Mobile App")
        arr.append("Root/Jailbreak Detection Bypass")
        arr.append("Insecure Local Storage (NSUserDefaults)")
        arr.append("Sensitive Data in Clipboard")
        arr.append("Sensitive Data in Logcat")
        arr.append("Cloud Bucket Misconfiguration")
        arr.append("AWS S3 Bucket Publicly Accessible")
        arr.append("Cloud IAM Role Over-Provisioned")
        arr.append("Unrestricted Cloud Metadata (IMDS) Access")
        arr.append("API Authentication Missing")
        arr.append("API Rate Limit Exceeded Data Leak")
        arr.append("API Endpoint Returned Excessive Data")
        arr.append("Broken API Authentication")
        arr.append("API Key Leak in Public Repo")
        arr.append("Third-Party SDK Data Leak")
        arr.append("Insecure Deep Link Handling")
        arr.append("Universal Link Handling Misconfiguration")
        arr.append("Java Unsafe Reflection")
        arr.append("Java SecurityManager Bypass")
        arr.append("Missing Data Encryption in Transit")
        arr.append("Logging of Sensitive Data")
        arr.append("PII Stored Longer Than Necessary")
        arr.append("Missing Consent for Data Collection")
        arr.append("Unauthorized Data Access")
        arr.append("Excessive Data Exposure")
        arr.append("Improper Restriction of XML External Entities")
        arr.append("Incomplete Cleanup of Sensitive Data")
        arr.append("Sensitive Data in Thumbnails")
        arr.append("Side-Channel (Timing) Information Disclosure")
        arr.append("Cache Timing Attack Vector")
        arr.append("Padding Oracle Vulnerability")
        arr.append("Bleichenbacher Attack Vector")
        arr.append("Length Extension Attack Vector")
        arr.append("Hash Collision Attack Vector")
        arr.append("Birthday Attack on Hash")
        arr.append("Same-Origin Policy Bypass")
        arr.append("Cross-Origin Resource Sharing (CORS) Bypass")
        arr.append("Mixed Content (HTTPS/HTTP)")
        arr.append("Insecure XML Parsing")
        arr.append("Regular Expression Catastrophic Backtracking")
        arr.append("ReDoS via User-Controlled Regex")

        return arr
    }()

    private static let presetDescriptions: [String: String] = {
        var d: [String: String] = [:]

        d["SQL Injection"] = "User-supplied data is concatenated into a SQL statement, letting an attacker alter the query to read, modify, or delete data or bypass authentication. Attacker-controlled input is accepted into a parser or interpreter without validation, enabling data or control-flow tampering."
        d["Blind SQL Injection"] = "User-supplied data is concatenated into a SQL statement, letting an attacker alter the query to read, modify, or delete data or bypass authentication. Attacker-controlled input is accepted into a parser or interpreter without validation, enabling data or control-flow tampering."
        d["Time-Based SQL Injection"] = "User-supplied data is concatenated into a SQL statement, letting an attacker alter the query to read, modify, or delete data or bypass authentication. Attacker-controlled input is accepted into a parser or interpreter without validation, enabling data or control-flow tampering."
        d["Boolean-Based Blind SQL Injection"] = "User-supplied data is concatenated into a SQL statement, letting an attacker alter the query to read, modify, or delete data or bypass authentication. Attacker-controlled input is accepted into a parser or interpreter without validation, enabling data or control-flow tampering."
        d["SQL Injection via User Input"] = "User-supplied data is concatenated into a SQL statement, letting an attacker alter the query to read, modify, or delete data or bypass authentication. Attacker-controlled input is accepted into a parser or interpreter without validation, enabling data or control-flow tampering."
        d["SQL Injection in Login Query"] = "User-supplied data is concatenated into a SQL statement, letting an attacker alter the query to read, modify, or delete data or bypass authentication. Attacker-controlled input is accepted into a parser or interpreter without validation, enabling data or control-flow tampering."
        d["SQL Injection in Search Parameter"] = "User-supplied data is concatenated into a SQL statement, letting an attacker alter the query to read, modify, or delete data or bypass authentication. Attacker-controlled input is accepted into a parser or interpreter without validation, enabling data or control-flow tampering."
        d["Second-Order SQL Injection"] = "User-supplied data is concatenated into a SQL statement, letting an attacker alter the query to read, modify, or delete data or bypass authentication. Attacker-controlled input is accepted into a parser or interpreter without validation, enabling data or control-flow tampering."
        d["SQL Injection via Stored Procedure"] = "User-supplied data is concatenated into a SQL statement, letting an attacker alter the query to read, modify, or delete data or bypass authentication. Attacker-controlled input is accepted into a parser or interpreter without validation, enabling data or control-flow tampering."
        d["Stored Cross-Site Scripting (XSS)"] = "Unsanitized user input is rendered as markup, letting an attacker execute scripts in another user's browser session."
        d["Reflected Cross-Site Scripting (XSS)"] = "Unsanitized user input is rendered as markup, letting an attacker execute scripts in another user's browser session."
        d["DOM-Based Cross-Site Scripting (XSS)"] = "Unsanitized user input is rendered as markup, letting an attacker execute scripts in another user's browser session."
        d["XSS via Unsanitized User Input"] = "Unsanitized user input is rendered as markup, letting an attacker execute scripts in another user's browser session."
        d["Persistent XSS in Comment Field"] = "Unsanitized user input is rendered as markup, letting an attacker execute scripts in another user's browser session."
        d["Cascading Style Sheets (CSS) Injection"] = "Attacker-controlled input is accepted into a parser or interpreter without validation, enabling data or control-flow tampering."
        d["OS Command Injection"] = "Untrusted input reaches an interpreter or shell, allowing arbitrary command or code execution on the host. Attacker-controlled input is accepted into a parser or interpreter without validation, enabling data or control-flow tampering."
        d["Command Injection via Shell Metacharacters"] = "Untrusted input reaches an interpreter or shell, allowing arbitrary command or code execution on the host. Attacker-controlled input is accepted into a parser or interpreter without validation, enabling data or control-flow tampering."
        d["Blind Command Injection"] = "Untrusted input reaches an interpreter or shell, allowing arbitrary command or code execution on the host. Attacker-controlled input is accepted into a parser or interpreter without validation, enabling data or control-flow tampering."
        d["Code Injection"] = "Untrusted input reaches an interpreter or shell, allowing arbitrary command or code execution on the host. Attacker-controlled input is accepted into a parser or interpreter without validation, enabling data or control-flow tampering."
        d["Remote Code Execution (RCE)"] = "Untrusted input reaches an interpreter or shell, allowing arbitrary command or code execution on the host."
        d["Remote Code Execution via Deserialization"] = "Untrusted input reaches an interpreter or shell, allowing arbitrary command or code execution on the host. Attacker-controlled input is accepted into a parser or interpreter without validation, enabling data or control-flow tampering."
        d["PHP Code Injection"] = "Untrusted input reaches an interpreter or shell, allowing arbitrary command or code execution on the host. Attacker-controlled input is accepted into a parser or interpreter without validation, enabling data or control-flow tampering."
        d["Server-Side Template Injection (SSTI)"] = "Attacker-controlled input is accepted into a parser or interpreter without validation, enabling data or control-flow tampering."
        d["Unrestricted File Upload Leading to Code Execution"] = "Unvalidated file paths or uploads allow reading, writing, or executing files outside the intended directory."
        d["Broken Authentication"] = "Authentication, session, or authorization checks are missing or flawed, allowing unauthorized access, impersonation, or privilege escalation."
        d["Session Fixation"] = "Authentication, session, or authorization checks are missing or flawed, allowing unauthorized access, impersonation, or privilege escalation."
        d["Session Hijacking"] = "Authentication, session, or authorization checks are missing or flawed, allowing unauthorized access, impersonation, or privilege escalation."
        d["Session Token Leak in URL"] = "Authentication, session, or authorization checks are missing or flawed, allowing unauthorized access, impersonation, or privilege escalation. Sensitive information or excessive functionality is exposed to unauthorized parties, aiding further attacks."
        d["Predictable Session Identifier"] = "Authentication, session, or authorization checks are missing or flawed, allowing unauthorized access, impersonation, or privilege escalation."
        d["Session Cookie Missing Secure Flag"] = "Authentication, session, or authorization checks are missing or flawed, allowing unauthorized access, impersonation, or privilege escalation."
        d["Session Cookie Missing HttpOnly Flag"] = "Authentication, session, or authorization checks are missing or flawed, allowing unauthorized access, impersonation, or privilege escalation."
        d["Session Timeout Not Enforced"] = "Untrusted input reaches an interpreter or shell, allowing arbitrary command or code execution on the host. Authentication, session, or authorization checks are missing or flawed, allowing unauthorized access, impersonation, or privilege escalation."
        d["Credential Reuse / Default Credentials"] = "Authentication, session, or authorization checks are missing or flawed, allowing unauthorized access, impersonation, or privilege escalation. Sensitive information or excessive functionality is exposed to unauthorized parties, aiding further attacks."
        d["Weak Password Policy"] = "Authentication, session, or authorization checks are missing or flawed, allowing unauthorized access, impersonation, or privilege escalation."
        d["Account Enumeration via Login"] = "Attacker-controlled input is accepted into a parser or interpreter without validation, enabling data or control-flow tampering. Authentication, session, or authorization checks are missing or flawed, allowing unauthorized access, impersonation, or privilege escalation."
        d["Account Lockout Bypass"] = "Authentication, session, or authorization checks are missing or flawed, allowing unauthorized access, impersonation, or privilege escalation."
        d["Password Stored in Plaintext"] = "Authentication, session, or authorization checks are missing or flawed, allowing unauthorized access, impersonation, or privilege escalation."
        d["Password in Configuration File"] = "Unvalidated file paths or uploads allow reading, writing, or executing files outside the intended directory. Authentication, session, or authorization checks are missing or flawed, allowing unauthorized access, impersonation, or privilege escalation."
        d["Privilege Escalation"] = "Authentication, session, or authorization checks are missing or flawed, allowing unauthorized access, impersonation, or privilege escalation."
        d["Horizontal Privilege Escalation"] = "Authentication, session, or authorization checks are missing or flawed, allowing unauthorized access, impersonation, or privilege escalation."
        d["Vertical Privilege Escalation"] = "Authentication, session, or authorization checks are missing or flawed, allowing unauthorized access, impersonation, or privilege escalation."
        d["Insecure Direct Object Reference (IDOR)"] = "Authentication, session, or authorization checks are missing or flawed, allowing unauthorized access, impersonation, or privilege escalation."
        d["Bypass of Password Change Flow"] = "Authentication, session, or authorization checks are missing or flawed, allowing unauthorized access, impersonation, or privilege escalation."
        d["Remember-Me Cookie Predictable"] = "Authentication, session, or authorization checks are missing or flawed, allowing unauthorized access, impersonation, or privilege escalation."
        d["Broken Access Control"] = "Authentication, session, or authorization checks are missing or flawed, allowing unauthorized access, impersonation, or privilege escalation."
        d["Missing Access Control on API Endpoint"] = "Authentication, session, or authorization checks are missing or flawed, allowing unauthorized access, impersonation, or privilege escalation. Sensitive information or excessive functionality is exposed to unauthorized parties, aiding further attacks."
        d["Authorization Bypass"] = "Authentication, session, or authorization checks are missing or flawed, allowing unauthorized access, impersonation, or privilege escalation."
        d["Path Traversal"] = "Unvalidated file paths or uploads allow reading, writing, or executing files outside the intended directory."
        d["Directory Traversal"] = "Unvalidated file paths or uploads allow reading, writing, or executing files outside the intended directory."
        d["Local File Inclusion (LFI)"] = "Unvalidated file paths or uploads allow reading, writing, or executing files outside the intended directory."
        d["Remote File Inclusion (RFI)"] = "Unvalidated file paths or uploads allow reading, writing, or executing files outside the intended directory."
        d["Symlink Following / Arbitrary File Read"] = "Unvalidated file paths or uploads allow reading, writing, or executing files outside the intended directory."
        d["Arbitrary File Read"] = "Unvalidated file paths or uploads allow reading, writing, or executing files outside the intended directory."
        d["Arbitrary File Write"] = "Unvalidated file paths or uploads allow reading, writing, or executing files outside the intended directory."
        d["Unrestricted File Upload"] = "Unvalidated file paths or uploads allow reading, writing, or executing files outside the intended directory."
        d["Zip Slip (Path Traversal in Archive)"] = "Unvalidated file paths or uploads allow reading, writing, or executing files outside the intended directory."
        d["Use of Weak Hashing Algorithm (MD5/SHA-1)"] = "Deprecates or weakens the underlying hash/key-derivation function, allowing offline brute-force or collision attacks against stored values."
        d["Weak Cryptographic Key"] = "Weak or predictable cryptographic material or usage lets an attacker forge, decrypt, or replay protected data."
        d["Insufficient Key Length"] = "Weak or predictable cryptographic material or usage lets an attacker forge, decrypt, or replay protected data."
        d["Hardcoded Encryption Key"] = "Weak or predictable cryptographic material or usage lets an attacker forge, decrypt, or replay protected data."
        d["Hardcoded Credentials"] = "Authentication, session, or authorization checks are missing or flawed, allowing unauthorized access, impersonation, or privilege escalation."
        d["Hardcoded API Key"] = "Weak or predictable cryptographic material or usage lets an attacker forge, decrypt, or replay protected data. Sensitive information or excessive functionality is exposed to unauthorized parties, aiding further attacks."
        d["Hardcoded Password"] = "Authentication, session, or authorization checks are missing or flawed, allowing unauthorized access, impersonation, or privilege escalation."
        d["Weak Random Number Generator"] = "Weak or predictable cryptographic material or usage lets an attacker forge, decrypt, or replay protected data."
        d["Use of Insecure Cipher"] = "Weak or predictable cryptographic material or usage lets an attacker forge, decrypt, or replay protected data."
        d["ECB Mode Encryption"] = "Weak or predictable cryptographic material or usage lets an attacker forge, decrypt, or replay protected data."
        d["Missing Certificate Validation"] = "Insecure or missing transport-layer security exposes data to interception and tampering in transit."
        d["Insecure TLS Configuration"] = "Insecure or missing transport-layer security exposes data to interception and tampering in transit."
        d["TLS/SSL Certificate Verification Disabled"] = "Insecure or missing transport-layer security exposes data to interception and tampering in transit."
        d["Use of Deprecated Cryptographic Algorithm"] = "Weak or predictable cryptographic material or usage lets an attacker forge, decrypt, or replay protected data."
        d["Server-Side Request Forgery (SSRF)"] = "'Server-Side Request Forgery (SSRF)' reflects a security weakness in the application that may allow an attacker to compromise confidentiality, integrity, or availability."
        d["XML External Entity (XXE) Injection"] = "Attacker-controlled input is accepted into a parser or interpreter without validation, enabling data or control-flow tampering."
        d["XML External Entity (XXE) via File Upload"] = "Attacker-controlled input is accepted into a parser or interpreter without validation, enabling data or control-flow tampering. Unvalidated file paths or uploads allow reading, writing, or executing files outside the intended directory."
        d["Insecure Deserialization"] = "Attacker-controlled input is accepted into a parser or interpreter without validation, enabling data or control-flow tampering."
        d["Unsafe Deserialization of Untrusted Data"] = "Attacker-controlled input is accepted into a parser or interpreter without validation, enabling data or control-flow tampering. Sensitive information or excessive functionality is exposed to unauthorized parties, aiding further attacks."
        d["LDAP Injection"] = "Attacker-controlled input is accepted into a parser or interpreter without validation, enabling data or control-flow tampering."
        d["Expression Language (EL) Injection"] = "Attacker-controlled input is accepted into a parser or interpreter without validation, enabling data or control-flow tampering."
        d["Template Injection"] = "Attacker-controlled input is accepted into a parser or interpreter without validation, enabling data or control-flow tampering."
        d["Header Injection"] = "Attacker-controlled input is accepted into a parser or interpreter without validation, enabling data or control-flow tampering."
        d["HTTP Response Splitting"] = "Attacker-controlled input is accepted into a parser or interpreter without validation, enabling data or control-flow tampering."
        d["Email Header Injection"] = "Attacker-controlled input is accepted into a parser or interpreter without validation, enabling data or control-flow tampering."
        d["Log Injection"] = "Attacker-controlled input is accepted into a parser or interpreter without validation, enabling data or control-flow tampering."
        d["Formula Injection (CSV Injection)"] = "Attacker-controlled input is accepted into a parser or interpreter without validation, enabling data or control-flow tampering."
        d["Regex Injection / ReDoS"] = "Attacker-controlled input is accepted into a parser or interpreter without validation, enabling data or control-flow tampering. Insufficient resource limits allow an attacker to exhaust CPU, memory, or connections and deny service to legitimate users."
        d["Regular Expression Denial of Service (ReDoS)"] = "Attacker-controlled input is accepted into a parser or interpreter without validation, enabling data or control-flow tampering. Insufficient resource limits allow an attacker to exhaust CPU, memory, or connections and deny service to legitimate users."
        d["Null Byte Injection"] = "Attacker-controlled input is accepted into a parser or interpreter without validation, enabling data or control-flow tampering."
        d["HTTP Request Smuggling"] = "Attacker-controlled input is accepted into a parser or interpreter without validation, enabling data or control-flow tampering."
        d["Cross-Site Request Forgery (CSRF)"] = "'Cross-Site Request Forgery (CSRF)' reflects a security weakness in the application that may allow an attacker to compromise confidentiality, integrity, or availability."
        d["Cross-Site Request Forgery on State-Changing Requests"] = "'Cross-Site Request Forgery on State-Changing Requests' reflects a security weakness in the application that may allow an attacker to compromise confidentiality, integrity, or availability."
        d["Missing CSRF Token"] = "Authentication, session, or authorization checks are missing or flawed, allowing unauthorized access, impersonation, or privilege escalation."
        d["CORS Misconfiguration"] = "A client-side security control is missing or bypassable, enabling script injection, clickjacking, or data leakage in the browser. Sensitive information or excessive functionality is exposed to unauthorized parties, aiding further attacks."
        d["Sensitive Data Exposure"] = "Sensitive information or excessive functionality is exposed to unauthorized parties, aiding further attacks."
        d["Exposure of Personally Identifiable Information (PII)"] = "Sensitive information or excessive functionality is exposed to unauthorized parties, aiding further attacks."
        d["Credentials Exposed in Logs"] = "Attacker-controlled input is accepted into a parser or interpreter without validation, enabling data or control-flow tampering. Authentication, session, or authorization checks are missing or flawed, allowing unauthorized access, impersonation, or privilege escalation."
        d["API Key Exposed in Client-Side Code"] = "Weak or predictable cryptographic material or usage lets an attacker forge, decrypt, or replay protected data. Sensitive information or excessive functionality is exposed to unauthorized parties, aiding further attacks."
        d["Source Code Disclosure"] = "Untrusted input reaches an interpreter or shell, allowing arbitrary command or code execution on the host. Sensitive information or excessive functionality is exposed to unauthorized parties, aiding further attacks."
        d["Debug Information Exposed in Production"] = "Sensitive information or excessive functionality is exposed to unauthorized parties, aiding further attacks."
        d["Verbose Error Messages Leaking Details"] = "Sensitive information or excessive functionality is exposed to unauthorized parties, aiding further attacks."
        d["Sensitive Data in URL"] = "Sensitive information or excessive functionality is exposed to unauthorized parties, aiding further attacks."
        d["Sensitive Data in Query String"] = "Sensitive information or excessive functionality is exposed to unauthorized parties, aiding further attacks."
        d["Clear-Text Transmission of Sensitive Data"] = "Sensitive information or excessive functionality is exposed to unauthorized parties, aiding further attacks."
        d["Security Misconfiguration"] = "Sensitive information or excessive functionality is exposed to unauthorized parties, aiding further attacks."
        d["Directory Listing Enabled"] = "Unvalidated file paths or uploads allow reading, writing, or executing files outside the intended directory."
        d["Default/Root Credentials Enabled"] = "Authentication, session, or authorization checks are missing or flawed, allowing unauthorized access, impersonation, or privilege escalation. Sensitive information or excessive functionality is exposed to unauthorized parties, aiding further attacks."
        d["Unnecessary Services Enabled"] = "'Unnecessary Services Enabled' reflects a security weakness in the application that may allow an attacker to compromise confidentiality, integrity, or availability."
        d["Outdated Component with Known Vulnerability"] = "'Outdated Component with Known Vulnerability' reflects a security weakness in the application that may allow an attacker to compromise confidentiality, integrity, or availability."
        d["Vulnerable Dependency"] = "'Vulnerable Dependency' reflects a security weakness in the application that may allow an attacker to compromise confidentiality, integrity, or availability."
        d["Use of Component with Known Vulnerabilities"] = "'Use of Component with Known Vulnerabilities' reflects a security weakness in the application that may allow an attacker to compromise confidentiality, integrity, or availability."
        d["Unsanitized Error Handling"] = "'Unsanitized Error Handling' reflects a security weakness in the application that may allow an attacker to compromise confidentiality, integrity, or availability."
        d["Missing Security Headers"] = "Attacker-controlled input is accepted into a parser or interpreter without validation, enabling data or control-flow tampering."
        d["Insecure HTTP Usage"] = "'Insecure HTTP Usage' reflects a security weakness in the application that may allow an attacker to compromise confidentiality, integrity, or availability."
        d["Information Disclosure in Error Messages"] = "Sensitive information or excessive functionality is exposed to unauthorized parties, aiding further attacks."
        d["Missing Input Validation"] = "'Missing Input Validation' reflects a security weakness in the application that may allow an attacker to compromise confidentiality, integrity, or availability."
        d["Improper Error Handling"] = "'Improper Error Handling' reflects a security weakness in the application that may allow an attacker to compromise confidentiality, integrity, or availability."
        d["Improper Sanitization of User Input"] = "'Improper Sanitization of User Input' reflects a security weakness in the application that may allow an attacker to compromise confidentiality, integrity, or availability."
        d["Data Injection"] = "Attacker-controlled input is accepted into a parser or interpreter without validation, enabling data or control-flow tampering. Sensitive information or excessive functionality is exposed to unauthorized parties, aiding further attacks."
        d["Integer Overflow / Underflow"] = "Incorrect memory handling can corrupt state or crash, and may be exploited to hijack program flow."
        d["Buffer Overflow"] = "Incorrect memory handling can corrupt state or crash, and may be exploited to hijack program flow."
        d["Out-of-Bounds Write"] = "Unvalidated file paths or uploads allow reading, writing, or executing files outside the intended directory. Incorrect memory handling can corrupt state or crash, and may be exploited to hijack program flow."
        d["Use-After-Free"] = "Incorrect memory handling can corrupt state or crash, and may be exploited to hijack program flow."
        d["Double Free"] = "Incorrect memory handling can corrupt state or crash, and may be exploited to hijack program flow."
        d["Null Pointer Dereference"] = "Incorrect memory handling can corrupt state or crash, and may be exploited to hijack program flow."
        d["Memory Leak"] = "Insufficient resource limits allow an attacker to exhaust CPU, memory, or connections and deny service to legitimate users. Sensitive information or excessive functionality is exposed to unauthorized parties, aiding further attacks."
        d["Uninitialized Memory Use"] = "Insufficient resource limits allow an attacker to exhaust CPU, memory, or connections and deny service to legitimate users. Incorrect memory handling can corrupt state or crash, and may be exploited to hijack program flow."
        d["Stack Overflow"] = "Incorrect memory handling can corrupt state or crash, and may be exploited to hijack program flow."
        d["Heap Overflow"] = "Incorrect memory handling can corrupt state or crash, and may be exploited to hijack program flow."
        d["Format String Vulnerability"] = "Incorrect memory handling can corrupt state or crash, and may be exploited to hijack program flow."
        d["Race Condition"] = "Incorrect memory handling can corrupt state or crash, and may be exploited to hijack program flow."
        d["Time-of-Check to Time-of-Use (TOCTOU)"] = "'Time-of-Check to Time-of-Use (TOCTOU)' reflects a security weakness in the application that may allow an attacker to compromise confidentiality, integrity, or availability."
        d["Insecure Direct Object Reference"] = "'Insecure Direct Object Reference' reflects a security weakness in the application that may allow an attacker to compromise confidentiality, integrity, or availability."
        d["Business Logic Flaw"] = "Attacker-controlled input is accepted into a parser or interpreter without validation, enabling data or control-flow tampering."
        d["Authorization Flaw in Business Logic"] = "Attacker-controlled input is accepted into a parser or interpreter without validation, enabling data or control-flow tampering. Authentication, session, or authorization checks are missing or flawed, allowing unauthorized access, impersonation, or privilege escalation."
        d["Improper Input Validation"] = "'Improper Input Validation' reflects a security weakness in the application that may allow an attacker to compromise confidentiality, integrity, or availability."
        d["Mass Assignment Vulnerability"] = "'Mass Assignment Vulnerability' reflects a security weakness in the application that may allow an attacker to compromise confidentiality, integrity, or availability."
        d["Clickjacking / UI Redressing"] = "A client-side security control is missing or bypassable, enabling script injection, clickjacking, or data leakage in the browser."
        d["Open Redirect"] = "'Open Redirect' reflects a security weakness in the application that may allow an attacker to compromise confidentiality, integrity, or availability."
        d["Unvalidated Redirect"] = "'Unvalidated Redirect' reflects a security weakness in the application that may allow an attacker to compromise confidentiality, integrity, or availability."
        d["Denial of Service (DoS)"] = "Insufficient resource limits allow an attacker to exhaust CPU, memory, or connections and deny service to legitimate users."
        d["Distributed Denial of Service (DDoS)"] = "Insufficient resource limits allow an attacker to exhaust CPU, memory, or connections and deny service to legitimate users."
        d["Resource Exhaustion"] = "Untrusted input reaches an interpreter or shell, allowing arbitrary command or code execution on the host. Insufficient resource limits allow an attacker to exhaust CPU, memory, or connections and deny service to legitimate users."
        d["Unbounded Resource Allocation"] = "Untrusted input reaches an interpreter or shell, allowing arbitrary command or code execution on the host. Insufficient resource limits allow an attacker to exhaust CPU, memory, or connections and deny service to legitimate users."
        d["Slowloris Attack Vector"] = "Insufficient resource limits allow an attacker to exhaust CPU, memory, or connections and deny service to legitimate users."
        d["Zip Bomb / Decompression Bomb"] = "Unvalidated file paths or uploads allow reading, writing, or executing files outside the intended directory. Insufficient resource limits allow an attacker to exhaust CPU, memory, or connections and deny service to legitimate users."
        d["Insufficient Logging and Monitoring"] = "Attacker-controlled input is accepted into a parser or interpreter without validation, enabling data or control-flow tampering. Sensitive information or excessive functionality is exposed to unauthorized parties, aiding further attacks."
        d["Security Headers Missing"] = "Attacker-controlled input is accepted into a parser or interpreter without validation, enabling data or control-flow tampering."
        d["Weak TLS Cipher Suites"] = "Weak or predictable cryptographic material or usage lets an attacker forge, decrypt, or replay protected data. Insecure or missing transport-layer security exposes data to interception and tampering in transit."
        d["Insecure Use of Cryptography"] = "Weak or predictable cryptographic material or usage lets an attacker forge, decrypt, or replay protected data."
        d["Trust Boundary Violation"] = "'Trust Boundary Violation' reflects a security weakness in the application that may allow an attacker to compromise confidentiality, integrity, or availability."
        d["Unchecked File Permissions"] = "Unvalidated file paths or uploads allow reading, writing, or executing files outside the intended directory. Sensitive information or excessive functionality is exposed to unauthorized parties, aiding further attacks."
        d["Permissions on Sensitive File Too Permissive"] = "Unvalidated file paths or uploads allow reading, writing, or executing files outside the intended directory. Sensitive information or excessive functionality is exposed to unauthorized parties, aiding further attacks."
        d["Insecure Network Communication"] = "'Insecure Network Communication' reflects a security weakness in the application that may allow an attacker to compromise confidentiality, integrity, or availability."
        d["Man-in-the-Middle (MITM) Vulnerability"] = "'Man-in-the-Middle (MITM) Vulnerability' reflects a security weakness in the application that may allow an attacker to compromise confidentiality, integrity, or availability."
        d["DNS Rebinding"] = "'DNS Rebinding' reflects a security weakness in the application that may allow an attacker to compromise confidentiality, integrity, or availability."
        d["Host Header Injection"] = "Attacker-controlled input is accepted into a parser or interpreter without validation, enabling data or control-flow tampering."
        d["Cache Poisoning"] = "'Cache Poisoning' reflects a security weakness in the application that may allow an attacker to compromise confidentiality, integrity, or availability."
        d["Subdomain Takeover"] = "'Subdomain Takeover' reflects a security weakness in the application that may allow an attacker to compromise confidentiality, integrity, or availability."
        d["Clickjacking Protection Missing"] = "A client-side security control is missing or bypassable, enabling script injection, clickjacking, or data leakage in the browser."
        d["Weak SHA-1 Certificate Signature"] = "Deprecates or weakens the underlying hash/key-derivation function, allowing offline brute-force or collision attacks against stored values. Insecure or missing transport-layer security exposes data to interception and tampering in transit."
        d["Deprecated Hash Used for Password Storage"] = "Deprecates or weakens the underlying hash/key-derivation function, allowing offline brute-force or collision attacks against stored values. Authentication, session, or authorization checks are missing or flawed, allowing unauthorized access, impersonation, or privilege escalation."
        d["Password Stored with Unkeyed Hash"] = "Deprecates or weakens the underlying hash/key-derivation function, allowing offline brute-force or collision attacks against stored values. Weak or predictable cryptographic material or usage lets an attacker forge, decrypt, or replay protected data."
        d["Insufficient Password Hashing Iterations"] = "Deprecates or weakens the underlying hash/key-derivation function, allowing offline brute-force or collision attacks against stored values. Authentication, session, or authorization checks are missing or flawed, allowing unauthorized access, impersonation, or privilege escalation."
        d["Salt Reuse Across Passwords"] = "Weak or predictable cryptographic material or usage lets an attacker forge, decrypt, or replay protected data. Authentication, session, or authorization checks are missing or flawed, allowing unauthorized access, impersonation, or privilege escalation."
        d["Hardcoded Salt in Crypto"] = "Weak or predictable cryptographic material or usage lets an attacker forge, decrypt, or replay protected data."
        d["Cryptographic Nonce Reuse"] = "Weak or predictable cryptographic material or usage lets an attacker forge, decrypt, or replay protected data."
        d["Nonce Reuse in Encryption"] = "Weak or predictable cryptographic material or usage lets an attacker forge, decrypt, or replay protected data."
        d["Short Random Seed"] = "Weak or predictable cryptographic material or usage lets an attacker forge, decrypt, or replay protected data."
        d["Insecure Randomness in Security Context"] = "Weak or predictable cryptographic material or usage lets an attacker forge, decrypt, or replay protected data."
        d["Predictive Random Number Generation"] = "Weak or predictable cryptographic material or usage lets an attacker forge, decrypt, or replay protected data."
        d["Use of Math.random for Security"] = "Weak or predictable cryptographic material or usage lets an attacker forge, decrypt, or replay protected data."
        d["Weak KDF for Password Storage"] = "Deprecates or weakens the underlying hash/key-derivation function, allowing offline brute-force or collision attacks against stored values. Authentication, session, or authorization checks are missing or flawed, allowing unauthorized access, impersonation, or privilege escalation."
        d["PBKDF2/BCrypt Cost Factor Too Low"] = "Deprecates or weakens the underlying hash/key-derivation function, allowing offline brute-force or collision attacks against stored values."
        d["AES Key Stored in Source Code"] = "Weak or predictable cryptographic material or usage lets an attacker forge, decrypt, or replay protected data. Untrusted input reaches an interpreter or shell, allowing arbitrary command or code execution on the host."
        d["Private Key Exposed"] = "Weak or predictable cryptographic material or usage lets an attacker forge, decrypt, or replay protected data. Sensitive information or excessive functionality is exposed to unauthorized parties, aiding further attacks."
        d["Certificate Private Key Leak"] = "Weak or predictable cryptographic material or usage lets an attacker forge, decrypt, or replay protected data. Insecure or missing transport-layer security exposes data to interception and tampering in transit."
        d["Insufficient Key Management"] = "Weak or predictable cryptographic material or usage lets an attacker forge, decrypt, or replay protected data."
        d["Key Hardcoded in Binary"] = "Weak or predictable cryptographic material or usage lets an attacker forge, decrypt, or replay protected data."
        d["Missing Encryption of Sensitive Data"] = "Weak or predictable cryptographic material or usage lets an attacker forge, decrypt, or replay protected data. Sensitive information or excessive functionality is exposed to unauthorized parties, aiding further attacks."
        d["Transport Layer Encryption Missing"] = "Weak or predictable cryptographic material or usage lets an attacker forge, decrypt, or replay protected data. Insecure or missing transport-layer security exposes data to interception and tampering in transit."
        d["No Encryption at Rest"] = "Weak or predictable cryptographic material or usage lets an attacker forge, decrypt, or replay protected data."
        d["Database Column Not Encrypted"] = "Weak or predictable cryptographic material or usage lets an attacker forge, decrypt, or replay protected data. Sensitive information or excessive functionality is exposed to unauthorized parties, aiding further attacks."
        d["Cipher in CBC with Predictable IV"] = "Weak or predictable cryptographic material or usage lets an attacker forge, decrypt, or replay protected data."
        d["Use of Broken Cipher (RC4/3DES)"] = "Weak or predictable cryptographic material or usage lets an attacker forge, decrypt, or replay protected data."
        d["Export-Grade Cipher Enabled"] = "Weak or predictable cryptographic material or usage lets an attacker forge, decrypt, or replay protected data."
        d["TLS 1.0/1.1 Enabled"] = "Insecure or missing transport-layer security exposes data to interception and tampering in transit."
        d["SSLv3 POODLE Vulnerability"] = "Insecure or missing transport-layer security exposes data to interception and tampering in transit."
        d["Heartbleed-Style Vulnerability"] = "'Heartbleed-Style Vulnerability' reflects a security weakness in the application that may allow an attacker to compromise confidentiality, integrity, or availability."
        d["Missing HSTS Header"] = "Insecure or missing transport-layer security exposes data to interception and tampering in transit. Attacker-controlled input is accepted into a parser or interpreter without validation, enabling data or control-flow tampering."
        d["Certificate Pinning Absent"] = "Insecure or missing transport-layer security exposes data to interception and tampering in transit."
        d["Self-Signed Certificate Trusted"] = "Insecure or missing transport-layer security exposes data to interception and tampering in transit."
        d["Hostname Verification Disabled"] = "'Hostname Verification Disabled' reflects a security weakness in the application that may allow an attacker to compromise confidentiality, integrity, or availability."
        d["SQL Injection in Stored Procedure"] = "User-supplied data is concatenated into a SQL statement, letting an attacker alter the query to read, modify, or delete data or bypass authentication. Attacker-controlled input is accepted into a parser or interpreter without validation, enabling data or control-flow tampering."
        d["SQL Injection via ORDER BY"] = "User-supplied data is concatenated into a SQL statement, letting an attacker alter the query to read, modify, or delete data or bypass authentication. Attacker-controlled input is accepted into a parser or interpreter without validation, enabling data or control-flow tampering."
        d["SQL Injection via Error Messages"] = "User-supplied data is concatenated into a SQL statement, letting an attacker alter the query to read, modify, or delete data or bypass authentication. Attacker-controlled input is accepted into a parser or interpreter without validation, enabling data or control-flow tampering."
        d["SQL Injection via Cookies"] = "User-supplied data is concatenated into a SQL statement, letting an attacker alter the query to read, modify, or delete data or bypass authentication. Attacker-controlled input is accepted into a parser or interpreter without validation, enabling data or control-flow tampering."
        d["SQL Injection via HTTP Headers"] = "User-supplied data is concatenated into a SQL statement, letting an attacker alter the query to read, modify, or delete data or bypass authentication. Attacker-controlled input is accepted into a parser or interpreter without validation, enabling data or control-flow tampering."
        d["Union-Based SQL Injection"] = "User-supplied data is concatenated into a SQL statement, letting an attacker alter the query to read, modify, or delete data or bypass authentication. Attacker-controlled input is accepted into a parser or interpreter without validation, enabling data or control-flow tampering."
        d["Stacked Query SQL Injection"] = "User-supplied data is concatenated into a SQL statement, letting an attacker alter the query to read, modify, or delete data or bypass authentication. Attacker-controlled input is accepted into a parser or interpreter without validation, enabling data or control-flow tampering."
        d["LDAP Injection via User Input"] = "Attacker-controlled input is accepted into a parser or interpreter without validation, enabling data or control-flow tampering."
        d["XML Injection"] = "Attacker-controlled input is accepted into a parser or interpreter without validation, enabling data or control-flow tampering."
        d["XPath Injection"] = "Attacker-controlled input is accepted into a parser or interpreter without validation, enabling data or control-flow tampering. Unvalidated file paths or uploads allow reading, writing, or executing files outside the intended directory."
        d["XQuery Injection"] = "Attacker-controlled input is accepted into a parser or interpreter without validation, enabling data or control-flow tampering."
        d["SOAP Injection"] = "Attacker-controlled input is accepted into a parser or interpreter without validation, enabling data or control-flow tampering."
        d["HTTP Parameter Pollution"] = "'HTTP Parameter Pollution' reflects a security weakness in the application that may allow an attacker to compromise confidentiality, integrity, or availability."
        d["Content-Type Injection"] = "Attacker-controlled input is accepted into a parser or interpreter without validation, enabling data or control-flow tampering. A client-side security control is missing or bypassable, enabling script injection, clickjacking, or data leakage in the browser."
        d["MIME Type Confusion"] = "'MIME Type Confusion' reflects a security weakness in the application that may allow an attacker to compromise confidentiality, integrity, or availability."
        d["SVG Injection"] = "Attacker-controlled input is accepted into a parser or interpreter without validation, enabling data or control-flow tampering."
        d["Markdown Injection"] = "Attacker-controlled input is accepted into a parser or interpreter without validation, enabling data or control-flow tampering."
        d["YAML Deserialization / YAML Injection"] = "Attacker-controlled input is accepted into a parser or interpreter without validation, enabling data or control-flow tampering."
        d["Animated GIF / Image Metadata Injection"] = "Attacker-controlled input is accepted into a parser or interpreter without validation, enabling data or control-flow tampering. Sensitive information or excessive functionality is exposed to unauthorized parties, aiding further attacks."
        d["Uploaded File Executable"] = "Unvalidated file paths or uploads allow reading, writing, or executing files outside the intended directory."
        d["Double Encoding Bypass"] = "'Double Encoding Bypass' reflects a security weakness in the application that may allow an attacker to compromise confidentiality, integrity, or availability."
        d["Null Byte in Filename"] = "Unvalidated file paths or uploads allow reading, writing, or executing files outside the intended directory."
        d["Command Injection via Filename"] = "Untrusted input reaches an interpreter or shell, allowing arbitrary command or code execution on the host. Attacker-controlled input is accepted into a parser or interpreter without validation, enabling data or control-flow tampering."
        d["Argument Injection"] = "Attacker-controlled input is accepted into a parser or interpreter without validation, enabling data or control-flow tampering."
        d["Option Injection into Executable"] = "Attacker-controlled input is accepted into a parser or interpreter without validation, enabling data or control-flow tampering."
        d["SSRF via URL Parameter"] = "'SSRF via URL Parameter' reflects a security weakness in the application that may allow an attacker to compromise confidentiality, integrity, or availability."
        d["SSRF through DNS Rebinding"] = "'SSRF through DNS Rebinding' reflects a security weakness in the application that may allow an attacker to compromise confidentiality, integrity, or availability."
        d["Blind SSRF"] = "'Blind SSRF' reflects a security weakness in the application that may allow an attacker to compromise confidentiality, integrity, or availability."
        d["Full SSRF (Internal Service Access)"] = "'Full SSRF (Internal Service Access)' reflects a security weakness in the application that may allow an attacker to compromise confidentiality, integrity, or availability."
        d["Gopher SSRF"] = "'Gopher SSRF' reflects a security weakness in the application that may allow an attacker to compromise confidentiality, integrity, or availability."
        d["Insecure Java Deserialization"] = "Attacker-controlled input is accepted into a parser or interpreter without validation, enabling data or control-flow tampering."
        d["Insecure .NET Deserialization"] = "Attacker-controlled input is accepted into a parser or interpreter without validation, enabling data or control-flow tampering."
        d["Insecure PHP Deserialization (unserialize)"] = "Attacker-controlled input is accepted into a parser or interpreter without validation, enabling data or control-flow tampering."
        d["Insecure Python Pickle Deserialization"] = "Attacker-controlled input is accepted into a parser or interpreter without validation, enabling data or control-flow tampering."
        d["Object Injection via Deserialization"] = "Attacker-controlled input is accepted into a parser or interpreter without validation, enabling data or control-flow tampering."
        d["Gadget Chain Deserialization"] = "Attacker-controlled input is accepted into a parser or interpreter without validation, enabling data or control-flow tampering."
        d["Arbitrary File Read via Path Traversal"] = "Unvalidated file paths or uploads allow reading, writing, or executing files outside the intended directory."
        d["Arbitrary File Write via Path Traversal"] = "Unvalidated file paths or uploads allow reading, writing, or executing files outside the intended directory."
        d["Symlink Following (File Read)"] = "Unvalidated file paths or uploads allow reading, writing, or executing files outside the intended directory."
        d["Hard Link Following"] = "'Hard Link Following' reflects a security weakness in the application that may allow an attacker to compromise confidentiality, integrity, or availability."
        d["Unrestricted File Upload (Executable)"] = "Unvalidated file paths or uploads allow reading, writing, or executing files outside the intended directory."
        d["Unrestricted File Upload (SVG/XSS)"] = "Unsanitized user input is rendered as markup, letting an attacker execute scripts in another user's browser session. Unvalidated file paths or uploads allow reading, writing, or executing files outside the intended directory."
        d["Unrestricted File Upload (Archive Bomb)"] = "Unvalidated file paths or uploads allow reading, writing, or executing files outside the intended directory. Insufficient resource limits allow an attacker to exhaust CPU, memory, or connections and deny service to legitimate users."
        d["File Upload with Insufficient Validation"] = "Unvalidated file paths or uploads allow reading, writing, or executing files outside the intended directory."
        d["Path Traversal in Zip Extraction"] = "Unvalidated file paths or uploads allow reading, writing, or executing files outside the intended directory."
        d["Log File Injection / Poisoning"] = "Attacker-controlled input is accepted into a parser or interpreter without validation, enabling data or control-flow tampering. Unvalidated file paths or uploads allow reading, writing, or executing files outside the intended directory."
        d["File Extension Filter Bypass"] = "Unvalidated file paths or uploads allow reading, writing, or executing files outside the intended directory."
        d["Double Extension Upload"] = "Unvalidated file paths or uploads allow reading, writing, or executing files outside the intended directory."
        d["Temporary File with Insecure Permissions"] = "Unvalidated file paths or uploads allow reading, writing, or executing files outside the intended directory. Sensitive information or excessive functionality is exposed to unauthorized parties, aiding further attacks."
        d["Insecure Temporary File Creation"] = "Unvalidated file paths or uploads allow reading, writing, or executing files outside the intended directory."
        d["Missing Function-Level Access Control"] = "Attacker-controlled input is accepted into a parser or interpreter without validation, enabling data or control-flow tampering. Authentication, session, or authorization checks are missing or flawed, allowing unauthorized access, impersonation, or privilege escalation."
        d["Missing Object-Level Authorization"] = "Attacker-controlled input is accepted into a parser or interpreter without validation, enabling data or control-flow tampering. Authentication, session, or authorization checks are missing or flawed, allowing unauthorized access, impersonation, or privilege escalation."
        d["Privilege Escalation via IDOR"] = "Authentication, session, or authorization checks are missing or flawed, allowing unauthorized access, impersonation, or privilege escalation."
        d["IDOR on API Endpoints"] = "Authentication, session, or authorization checks are missing or flawed, allowing unauthorized access, impersonation, or privilege escalation. Sensitive information or excessive functionality is exposed to unauthorized parties, aiding further attacks."
        d["IDOR on Download Endpoint"] = "Authentication, session, or authorization checks are missing or flawed, allowing unauthorized access, impersonation, or privilege escalation. Sensitive information or excessive functionality is exposed to unauthorized parties, aiding further attacks."
        d["Insecure Direct Object Reference on Files"] = "Unvalidated file paths or uploads allow reading, writing, or executing files outside the intended directory."
        d["Mass Enumeration via IDOR"] = "Authentication, session, or authorization checks are missing or flawed, allowing unauthorized access, impersonation, or privilege escalation."
        d["Broken Object Level Authorization (BOLA)"] = "Attacker-controlled input is accepted into a parser or interpreter without validation, enabling data or control-flow tampering. Authentication, session, or authorization checks are missing or flawed, allowing unauthorized access, impersonation, or privilege escalation."
        d["Broken Function Level Authorization"] = "Attacker-controlled input is accepted into a parser or interpreter without validation, enabling data or control-flow tampering. Authentication, session, or authorization checks are missing or flawed, allowing unauthorized access, impersonation, or privilege escalation."
        d["Authorization Bypass via Parameter Tampering"] = "Authentication, session, or authorization checks are missing or flawed, allowing unauthorized access, impersonation, or privilege escalation."
        d["Role-Based Access Control Bypass"] = "Authentication, session, or authorization checks are missing or flawed, allowing unauthorized access, impersonation, or privilege escalation."
        d["Default Admin Account Enabled"] = "Authentication, session, or authorization checks are missing or flawed, allowing unauthorized access, impersonation, or privilege escalation. Sensitive information or excessive functionality is exposed to unauthorized parties, aiding further attacks."
        d["Weak Session ID"] = "Authentication, session, or authorization checks are missing or flawed, allowing unauthorized access, impersonation, or privilege escalation."
        d["Session ID in Cookie without Secure Flag"] = "Authentication, session, or authorization checks are missing or flawed, allowing unauthorized access, impersonation, or privilege escalation."
        d["Session Regeneration Missing on Login"] = "Attacker-controlled input is accepted into a parser or interpreter without validation, enabling data or control-flow tampering. Authentication, session, or authorization checks are missing or flawed, allowing unauthorized access, impersonation, or privilege escalation."
        d["Session Not Invalidated on Logout"] = "Attacker-controlled input is accepted into a parser or interpreter without validation, enabling data or control-flow tampering. Authentication, session, or authorization checks are missing or flawed, allowing unauthorized access, impersonation, or privilege escalation."
        d["No Session Expiration"] = "Authentication, session, or authorization checks are missing or flawed, allowing unauthorized access, impersonation, or privilege escalation."
        d["Concurrent Session Limit Unenforced"] = "Untrusted input reaches an interpreter or shell, allowing arbitrary command or code execution on the host. Authentication, session, or authorization checks are missing or flawed, allowing unauthorized access, impersonation, or privilege escalation."
        d["Account Takeover via Session Leak"] = "Authentication, session, or authorization checks are missing or flawed, allowing unauthorized access, impersonation, or privilege escalation. Sensitive information or excessive functionality is exposed to unauthorized parties, aiding further attacks."
        d["Account Takeover via Password Reset Token"] = "Authentication, session, or authorization checks are missing or flawed, allowing unauthorized access, impersonation, or privilege escalation."
        d["Insecure Password Reset Flow"] = "Authentication, session, or authorization checks are missing or flawed, allowing unauthorized access, impersonation, or privilege escalation."
        d["Password Reset Token in URL"] = "Authentication, session, or authorization checks are missing or flawed, allowing unauthorized access, impersonation, or privilege escalation."
        d["Password Reset Link Predictable"] = "Authentication, session, or authorization checks are missing or flawed, allowing unauthorized access, impersonation, or privilege escalation."
        d["Registration Enabling Arbitrary Account"] = "Authentication, session, or authorization checks are missing or flawed, allowing unauthorized access, impersonation, or privilege escalation."
        d["Email Verification Bypass"] = "'Email Verification Bypass' reflects a security weakness in the application that may allow an attacker to compromise confidentiality, integrity, or availability."
        d["OTP Brute Force Possible"] = "Untrusted input reaches an interpreter or shell, allowing arbitrary command or code execution on the host. Authentication, session, or authorization checks are missing or flawed, allowing unauthorized access, impersonation, or privilege escalation."
        d["Two-Factor Authentication (2FA) Bypass"] = "Authentication, session, or authorization checks are missing or flawed, allowing unauthorized access, impersonation, or privilege escalation."
        d["2FA Not Enforced"] = "Untrusted input reaches an interpreter or shell, allowing arbitrary command or code execution on the host. Authentication, session, or authorization checks are missing or flawed, allowing unauthorized access, impersonation, or privilege escalation."
        d["Credential Stuffing Mitigation Missing"] = "Authentication, session, or authorization checks are missing or flawed, allowing unauthorized access, impersonation, or privilege escalation."
        d["Rate Limiting Absent on Login"] = "Attacker-controlled input is accepted into a parser or interpreter without validation, enabling data or control-flow tampering. Authentication, session, or authorization checks are missing or flawed, allowing unauthorized access, impersonation, or privilege escalation."
        d["Brute-Force Protection Missing"] = "Untrusted input reaches an interpreter or shell, allowing arbitrary command or code execution on the host. Authentication, session, or authorization checks are missing or flawed, allowing unauthorized access, impersonation, or privilege escalation."
        d["CAPTCHA Bypassable"] = "Authentication, session, or authorization checks are missing or flawed, allowing unauthorized access, impersonation, or privilege escalation."
        d["Lockout Policy Missing"] = "Authentication, session, or authorization checks are missing or flawed, allowing unauthorized access, impersonation, or privilege escalation."
        d["Username/Password Timing Side Channel"] = "Authentication, session, or authorization checks are missing or flawed, allowing unauthorized access, impersonation, or privilege escalation."
        d["JWT Algorithm Confusion"] = "Authentication, session, or authorization checks are missing or flawed, allowing unauthorized access, impersonation, or privilege escalation."
        d["JWT with 'none' Algorithm"] = "Authentication, session, or authorization checks are missing or flawed, allowing unauthorized access, impersonation, or privilege escalation."
        d["JWT Secret Guessable"] = "Authentication, session, or authorization checks are missing or flawed, allowing unauthorized access, impersonation, or privilege escalation."
        d["JWT Not Validating Expiration"] = "Authentication, session, or authorization checks are missing or flawed, allowing unauthorized access, impersonation, or privilege escalation."
        d["OAuth Token Misconfiguration"] = "Authentication, session, or authorization checks are missing or flawed, allowing unauthorized access, impersonation, or privilege escalation. Sensitive information or excessive functionality is exposed to unauthorized parties, aiding further attacks."
        d["OAuth Redirect URI Manipulation"] = "Authentication, session, or authorization checks are missing or flawed, allowing unauthorized access, impersonation, or privilege escalation."
        d["OAuth State Parameter Missing"] = "Authentication, session, or authorization checks are missing or flawed, allowing unauthorized access, impersonation, or privilege escalation."
        d["API Token in Query String"] = "Authentication, session, or authorization checks are missing or flawed, allowing unauthorized access, impersonation, or privilege escalation. Sensitive information or excessive functionality is exposed to unauthorized parties, aiding further attacks."
        d["Bearer Token Missing Expiration"] = "Authentication, session, or authorization checks are missing or flawed, allowing unauthorized access, impersonation, or privilege escalation."
        d["Stored XSS via SVG Upload"] = "Unsanitized user input is rendered as markup, letting an attacker execute scripts in another user's browser session. Unvalidated file paths or uploads allow reading, writing, or executing files outside the intended directory."
        d["XSS via JSONP Endpoint"] = "Unsanitized user input is rendered as markup, letting an attacker execute scripts in another user's browser session. Sensitive information or excessive functionality is exposed to unauthorized parties, aiding further attacks."
        d["Blind XSS (Callback Bypass)"] = "Unsanitized user input is rendered as markup, letting an attacker execute scripts in another user's browser session."
        d["XSS in Error Page"] = "Unsanitized user input is rendered as markup, letting an attacker execute scripts in another user's browser session."
        d["XSS in 404 Page"] = "Unsanitized user input is rendered as markup, letting an attacker execute scripts in another user's browser session."
        d["XSS via Link Shortener"] = "Unsanitized user input is rendered as markup, letting an attacker execute scripts in another user's browser session."
        d["Self-XSS Leading to Stored XSS"] = "Unsanitized user input is rendered as markup, letting an attacker execute scripts in another user's browser session."
        d["Mutation XSS (mXSS)"] = "Unsanitized user input is rendered as markup, letting an attacker execute scripts in another user's browser session."
        d["Unsafe InnerHTML Usage"] = "A client-side security control is missing or bypassable, enabling script injection, clickjacking, or data leakage in the browser."
        d["eval() on Untrusted Input"] = "A client-side security control is missing or bypassable, enabling script injection, clickjacking, or data leakage in the browser."
        d["Dangerous Function Usage (eval/Function)"] = "A client-side security control is missing or bypassable, enabling script injection, clickjacking, or data leakage in the browser."
        d["Prototype Pollution"] = "Attacker-controlled input is accepted into a parser or interpreter without validation, enabling data or control-flow tampering. A client-side security control is missing or bypassable, enabling script injection, clickjacking, or data leakage in the browser."
        d["Client-Side Template Injection"] = "Attacker-controlled input is accepted into a parser or interpreter without validation, enabling data or control-flow tampering."
        d["PostMessage Origin Not Validated"] = "A client-side security control is missing or bypassable, enabling script injection, clickjacking, or data leakage in the browser."
        d["WebSocket Origin Not Validated"] = "A client-side security control is missing or bypassable, enabling script injection, clickjacking, or data leakage in the browser. Insufficient resource limits allow an attacker to exhaust CPU, memory, or connections and deny service to legitimate users."
        d["CSP Allowing Inline Scripts"] = "A client-side security control is missing or bypassable, enabling script injection, clickjacking, or data leakage in the browser."
        d["CSP Reporting-Only Mode"] = "A client-side security control is missing or bypassable, enabling script injection, clickjacking, or data leakage in the browser."
        d["Missing X-Content-Type-Options"] = "A client-side security control is missing or bypassable, enabling script injection, clickjacking, or data leakage in the browser."
        d["Missing X-Frame-Options / CSP frame-ancestors"] = "A client-side security control is missing or bypassable, enabling script injection, clickjacking, or data leakage in the browser."
        d["Referrer Policy Misconfiguration"] = "Sensitive information or excessive functionality is exposed to unauthorized parties, aiding further attacks."
        d["Open Redirect in Login Redirect"] = "Attacker-controlled input is accepted into a parser or interpreter without validation, enabling data or control-flow tampering. Authentication, session, or authorization checks are missing or flawed, allowing unauthorized access, impersonation, or privilege escalation."
        d["Open Redirect via 'next' Parameter"] = "'Open Redirect via 'next' Parameter' reflects a security weakness in the application that may allow an attacker to compromise confidentiality, integrity, or availability."
        d["Clickjacking via Delay"] = "A client-side security control is missing or bypassable, enabling script injection, clickjacking, or data leakage in the browser."
        d["Drag-and-Drop Clickjacking (Clickbandit)"] = "A client-side security control is missing or bypassable, enabling script injection, clickjacking, or data leakage in the browser."
        d["Tabnabbing"] = "A client-side security control is missing or bypassable, enabling script injection, clickjacking, or data leakage in the browser."
        d["Keylogging via Malicious Extension"] = "Weak or predictable cryptographic material or usage lets an attacker forge, decrypt, or replay protected data. Attacker-controlled input is accepted into a parser or interpreter without validation, enabling data or control-flow tampering."
        d["HTTP Parameter Injection"] = "Attacker-controlled input is accepted into a parser or interpreter without validation, enabling data or control-flow tampering."
        d["HTTP Request Splitting"] = "'HTTP Request Splitting' reflects a security weakness in the application that may allow an attacker to compromise confidentiality, integrity, or availability."
        d["HTTP Response Splitting (CRLF)"] = "Attacker-controlled input is accepted into a parser or interpreter without validation, enabling data or control-flow tampering."
        d["Request Smuggling (CL.TE)"] = "Attacker-controlled input is accepted into a parser or interpreter without validation, enabling data or control-flow tampering."
        d["Request Smuggling (TE.CL)"] = "Attacker-controlled input is accepted into a parser or interpreter without validation, enabling data or control-flow tampering."
        d["Cache Poisoning via Request Smuggling"] = "Attacker-controlled input is accepted into a parser or interpreter without validation, enabling data or control-flow tampering."
        d["Host Header Poisoning"] = "Attacker-controlled input is accepted into a parser or interpreter without validation, enabling data or control-flow tampering."
        d["Path Confusion (Trailing Slash)"] = "Unvalidated file paths or uploads allow reading, writing, or executing files outside the intended directory."
        d["Unicode Path Bypass"] = "Unvalidated file paths or uploads allow reading, writing, or executing files outside the intended directory."
        d["Directory Traversal Unicode Issues"] = "Unvalidated file paths or uploads allow reading, writing, or executing files outside the intended directory."
        d["Server-Side Path Traversal"] = "Unvalidated file paths or uploads allow reading, writing, or executing files outside the intended directory."
        d["Path Normalization Bypass"] = "Unvalidated file paths or uploads allow reading, writing, or executing files outside the intended directory."
        d["Alias / Symlink Virtual Host Confusion"] = "Unvalidated file paths or uploads allow reading, writing, or executing files outside the intended directory."
        d["Virtual Host Misconfiguration"] = "Sensitive information or excessive functionality is exposed to unauthorized parties, aiding further attacks."
        d["Spring Actuator Exposed"] = "Sensitive information or excessive functionality is exposed to unauthorized parties, aiding further attacks."
        d["Debug Endpoint Exposed"] = "Sensitive information or excessive functionality is exposed to unauthorized parties, aiding further attacks."
        d["Swagger/API Docs Exposed"] = "Sensitive information or excessive functionality is exposed to unauthorized parties, aiding further attacks."
        d["GraphQL Introspection Enabled"] = "Sensitive information or excessive functionality is exposed to unauthorized parties, aiding further attacks."
        d["GraphQL Field-Level Authorization Bypass"] = "Attacker-controlled input is accepted into a parser or interpreter without validation, enabling data or control-flow tampering. Authentication, session, or authorization checks are missing or flawed, allowing unauthorized access, impersonation, or privilege escalation."
        d["Batch GraphQL DoS"] = "Insufficient resource limits allow an attacker to exhaust CPU, memory, or connections and deny service to legitimate users. Sensitive information or excessive functionality is exposed to unauthorized parties, aiding further attacks."
        d["WebSocket Message Injection"] = "Attacker-controlled input is accepted into a parser or interpreter without validation, enabling data or control-flow tampering. Insufficient resource limits allow an attacker to exhaust CPU, memory, or connections and deny service to legitimate users."
        d["Server-Side Request via WebSocket Upgrade"] = "Insufficient resource limits allow an attacker to exhaust CPU, memory, or connections and deny service to legitimate users."
        d["DNS Rebinding against Internal Services"] = "'DNS Rebinding against Internal Services' reflects a security weakness in the application that may allow an attacker to compromise confidentiality, integrity, or availability."
        d["Web Cache Deception"] = "'Web Cache Deception' reflects a security weakness in the application that may allow an attacker to compromise confidentiality, integrity, or availability."
        d["Content Spoofing"] = "'Content Spoofing' reflects a security weakness in the application that may allow an attacker to compromise confidentiality, integrity, or availability."
        d["Homograph / IDN Spoofing"] = "'Homograph / IDN Spoofing' reflects a security weakness in the application that may allow an attacker to compromise confidentiality, integrity, or availability."
        d["Business Logic Flaw in Pricing"] = "Attacker-controlled input is accepted into a parser or interpreter without validation, enabling data or control-flow tampering."
        d["Price/Currency Manipulation"] = "'Price/Currency Manipulation' reflects a security weakness in the application that may allow an attacker to compromise confidentiality, integrity, or availability."
        d["Coupon Code Reuse"] = "'Coupon Code Reuse' reflects a security weakness in the application that may allow an attacker to compromise confidentiality, integrity, or availability."
        d["Negative Quantity Order"] = "'Negative Quantity Order' reflects a security weakness in the application that may allow an attacker to compromise confidentiality, integrity, or availability."
        d["Integer Overflow in Arithmetic"] = "Incorrect memory handling can corrupt state or crash, and may be exploited to hijack program flow."
        d["Race Condition in Balance Transfer"] = "Incorrect memory handling can corrupt state or crash, and may be exploited to hijack program flow."
        d["Loyalty Points Manipulation"] = "'Loyalty Points Manipulation' reflects a security weakness in the application that may allow an attacker to compromise confidentiality, integrity, or availability."
        d["Transaction Double-Spend"] = "'Transaction Double-Spend' reflects a security weakness in the application that may allow an attacker to compromise confidentiality, integrity, or availability."
        d["Order Status Tampering"] = "'Order Status Tampering' reflects a security weakness in the application that may allow an attacker to compromise confidentiality, integrity, or availability."
        d["Mass Assignment on Profile Fields"] = "Unvalidated file paths or uploads allow reading, writing, or executing files outside the intended directory."
        d["Mass Assignment on Privileged Fields"] = "Authentication, session, or authorization checks are missing or flawed, allowing unauthorized access, impersonation, or privilege escalation."
        d["Missing Input Sanitization on Numeric Fields"] = "'Missing Input Sanitization on Numeric Fields' reflects a security weakness in the application that may allow an attacker to compromise confidentiality, integrity, or availability."
        d["Unvalidated Numeric Range"] = "'Unvalidated Numeric Range' reflects a security weakness in the application that may allow an attacker to compromise confidentiality, integrity, or availability."
        d["Unvalidated Length/Size"] = "'Unvalidated Length/Size' reflects a security weakness in the application that may allow an attacker to compromise confidentiality, integrity, or availability."
        d["Unhandled File Size Limit"] = "Unvalidated file paths or uploads allow reading, writing, or executing files outside the intended directory."
        d["Illogical Application State"] = "Attacker-controlled input is accepted into a parser or interpreter without validation, enabling data or control-flow tampering."
        d["Workflow Bypass"] = "'Workflow Bypass' reflects a security weakness in the application that may allow an attacker to compromise confidentiality, integrity, or availability."
        d["Skipping Mandatory Steps in Workflow"] = "'Skipping Mandatory Steps in Workflow' reflects a security weakness in the application that may allow an attacker to compromise confidentiality, integrity, or availability."
        d["Authorization Not Checked in Batch Operations"] = "Authentication, session, or authorization checks are missing or flawed, allowing unauthorized access, impersonation, or privilege escalation."
        d["Timezone/Date Validation Issue"] = "'Timezone/Date Validation Issue' reflects a security weakness in the application that may allow an attacker to compromise confidentiality, integrity, or availability."
        d["Unicode Normalization Injection"] = "Attacker-controlled input is accepted into a parser or interpreter without validation, enabling data or control-flow tampering."
        d["Unbounded Memory Allocation"] = "Insufficient resource limits allow an attacker to exhaust CPU, memory, or connections and deny service to legitimate users."
        d["Unbounded CPU Consumption"] = "Insufficient resource limits allow an attacker to exhaust CPU, memory, or connections and deny service to legitimate users."
        d["Unbounded Number of Threads"] = "Unvalidated file paths or uploads allow reading, writing, or executing files outside the intended directory. Insufficient resource limits allow an attacker to exhaust CPU, memory, or connections and deny service to legitimate users."
        d["Connection Pool Exhaustion"] = "Insufficient resource limits allow an attacker to exhaust CPU, memory, or connections and deny service to legitimate users."
        d["Too Many Open File Descriptors"] = "Unvalidated file paths or uploads allow reading, writing, or executing files outside the intended directory."
        d["Deep Recursion Stack Overflow"] = "Insufficient resource limits allow an attacker to exhaust CPU, memory, or connections and deny service to legitimate users. Incorrect memory handling can corrupt state or crash, and may be exploited to hijack program flow."
        d["Infinite Loop on Malformed Input"] = "Insufficient resource limits allow an attacker to exhaust CPU, memory, or connections and deny service to legitimate users."
        d["Huge Payload DoS"] = "Insufficient resource limits allow an attacker to exhaust CPU, memory, or connections and deny service to legitimate users."
        d["Slow JSON Parsing DoS"] = "Insufficient resource limits allow an attacker to exhaust CPU, memory, or connections and deny service to legitimate users."
        d["Billion Laughs XML Bomb"] = "Attacker-controlled input is accepted into a parser or interpreter without validation, enabling data or control-flow tampering. Insufficient resource limits allow an attacker to exhaust CPU, memory, or connections and deny service to legitimate users."
        d["Decompression Bomb (Zip/Gzip)"] = "Unvalidated file paths or uploads allow reading, writing, or executing files outside the intended directory. Insufficient resource limits allow an attacker to exhaust CPU, memory, or connections and deny service to legitimate users."
        d["Recursive Query / Cyclic Dependency DoS"] = "Insufficient resource limits allow an attacker to exhaust CPU, memory, or connections and deny service to legitimate users."
        d["Rate Limiting Missing on API"] = "Authentication, session, or authorization checks are missing or flawed, allowing unauthorized access, impersonation, or privilege escalation. Insufficient resource limits allow an attacker to exhaust CPU, memory, or connections and deny service to legitimate users."
        d["Pagination Bound Missing"] = "'Pagination Bound Missing' reflects a security weakness in the application that may allow an attacker to compromise confidentiality, integrity, or availability."
        d["Unlimited Search Results"] = "'Unlimited Search Results' reflects a security weakness in the application that may allow an attacker to compromise confidentiality, integrity, or availability."
        d["Missing Size Limit on Upload"] = "Unvalidated file paths or uploads allow reading, writing, or executing files outside the intended directory."
        d["Request Body Size Unbounded"] = "Insufficient resource limits allow an attacker to exhaust CPU, memory, or connections and deny service to legitimate users."
        d["Stack Buffer Overflow"] = "Incorrect memory handling can corrupt state or crash, and may be exploited to hijack program flow."
        d["Heap Buffer Overflow"] = "Incorrect memory handling can corrupt state or crash, and may be exploited to hijack program flow."
        d["Off-by-One Error"] = "Incorrect memory handling can corrupt state or crash, and may be exploited to hijack program flow."
        d["Integer Signedness Bug"] = "'Integer Signedness Bug' reflects a security weakness in the application that may allow an attacker to compromise confidentiality, integrity, or availability."
        d["Use of Uninitialized Pointer"] = "Incorrect memory handling can corrupt state or crash, and may be exploited to hijack program flow."
        d["Dangling Pointer"] = "Incorrect memory handling can corrupt state or crash, and may be exploited to hijack program flow."
        d["Wild / Whack Pointer"] = "Incorrect memory handling can corrupt state or crash, and may be exploited to hijack program flow."
        d["Memory Corruption"] = "Insufficient resource limits allow an attacker to exhaust CPU, memory, or connections and deny service to legitimate users. Incorrect memory handling can corrupt state or crash, and may be exploited to hijack program flow."
        d["Type Confusion"] = "'Type Confusion' reflects a security weakness in the application that may allow an attacker to compromise confidentiality, integrity, or availability."
        d["Object Confusion"] = "'Object Confusion' reflects a security weakness in the application that may allow an attacker to compromise confidentiality, integrity, or availability."
        d["Race Condition on Shared Memory"] = "Deprecates or weakens the underlying hash/key-derivation function, allowing offline brute-force or collision attacks against stored values. Insufficient resource limits allow an attacker to exhaust CPU, memory, or connections and deny service to legitimate users."
        d["Data Race"] = "Incorrect memory handling can corrupt state or crash, and may be exploited to hijack program flow. Sensitive information or excessive functionality is exposed to unauthorized parties, aiding further attacks."
        d["Deadlock"] = "Incorrect memory handling can corrupt state or crash, and may be exploited to hijack program flow."
        d["Livelock"] = "'Livelock' reflects a security weakness in the application that may allow an attacker to compromise confidentiality, integrity, or availability."
        d["Unsafe Pointer Arithmetic"] = "Incorrect memory handling can corrupt state or crash, and may be exploited to hijack program flow."
        d["Missing Bounds Check"] = "'Missing Bounds Check' reflects a security weakness in the application that may allow an attacker to compromise confidentiality, integrity, or availability."
        d["Array Index Out of Bounds"] = "Incorrect memory handling can corrupt state or crash, and may be exploited to hijack program flow."
        d["Negative Array Index"] = "'Negative Array Index' reflects a security weakness in the application that may allow an attacker to compromise confidentiality, integrity, or availability."
        d["String Overrun"] = "'String Overrun' reflects a security weakness in the application that may allow an attacker to compromise confidentiality, integrity, or availability."
        d["Format String Exploitation"] = "Incorrect memory handling can corrupt state or crash, and may be exploited to hijack program flow."
        d["Importance of ASLR/DEP Disabled"] = "'Importance of ASLR/DEP Disabled' reflects a security weakness in the application that may allow an attacker to compromise confidentiality, integrity, or availability."
        d["Stack Canary Missing"] = "Incorrect memory handling can corrupt state or crash, and may be exploited to hijack program flow."
        d["Insecure Platform Network Connection"] = "'Insecure Platform Network Connection' reflects a security weakness in the application that may allow an attacker to compromise confidentiality, integrity, or availability."
        d["Weak Permissions on Android Manifest"] = "Sensitive information or excessive functionality is exposed to unauthorized parties, aiding further attacks."
        d["Android Activity Export Without Permission"] = "Sensitive information or excessive functionality is exposed to unauthorized parties, aiding further attacks."
        d["iOS Insecure Data Storage"] = "Sensitive information or excessive functionality is exposed to unauthorized parties, aiding further attacks."
        d["iOS Keychain Access Group Misuse"] = "Weak or predictable cryptographic material or usage lets an attacker forge, decrypt, or replay protected data."
        d["Hardcoded Secrets in Mobile App"] = "'Hardcoded Secrets in Mobile App' reflects a security weakness in the application that may allow an attacker to compromise confidentiality, integrity, or availability."
        d["Root/Jailbreak Detection Bypass"] = "'Root/Jailbreak Detection Bypass' reflects a security weakness in the application that may allow an attacker to compromise confidentiality, integrity, or availability."
        d["Insecure Local Storage (NSUserDefaults)"] = "Authentication, session, or authorization checks are missing or flawed, allowing unauthorized access, impersonation, or privilege escalation. Sensitive information or excessive functionality is exposed to unauthorized parties, aiding further attacks."
        d["Sensitive Data in Clipboard"] = "Sensitive information or excessive functionality is exposed to unauthorized parties, aiding further attacks."
        d["Sensitive Data in Logcat"] = "Attacker-controlled input is accepted into a parser or interpreter without validation, enabling data or control-flow tampering. Sensitive information or excessive functionality is exposed to unauthorized parties, aiding further attacks."
        d["Cloud Bucket Misconfiguration"] = "Sensitive information or excessive functionality is exposed to unauthorized parties, aiding further attacks."
        d["AWS S3 Bucket Publicly Accessible"] = "Sensitive information or excessive functionality is exposed to unauthorized parties, aiding further attacks."
        d["Cloud IAM Role Over-Provisioned"] = "Sensitive information or excessive functionality is exposed to unauthorized parties, aiding further attacks."
        d["Unrestricted Cloud Metadata (IMDS) Access"] = "Sensitive information or excessive functionality is exposed to unauthorized parties, aiding further attacks."
        d["API Authentication Missing"] = "Authentication, session, or authorization checks are missing or flawed, allowing unauthorized access, impersonation, or privilege escalation. Sensitive information or excessive functionality is exposed to unauthorized parties, aiding further attacks."
        d["API Rate Limit Exceeded Data Leak"] = "Authentication, session, or authorization checks are missing or flawed, allowing unauthorized access, impersonation, or privilege escalation. Insufficient resource limits allow an attacker to exhaust CPU, memory, or connections and deny service to legitimate users."
        d["API Endpoint Returned Excessive Data"] = "Sensitive information or excessive functionality is exposed to unauthorized parties, aiding further attacks."
        d["Broken API Authentication"] = "Authentication, session, or authorization checks are missing or flawed, allowing unauthorized access, impersonation, or privilege escalation. Sensitive information or excessive functionality is exposed to unauthorized parties, aiding further attacks."
        d["API Key Leak in Public Repo"] = "Weak or predictable cryptographic material or usage lets an attacker forge, decrypt, or replay protected data. Sensitive information or excessive functionality is exposed to unauthorized parties, aiding further attacks."
        d["Third-Party SDK Data Leak"] = "Sensitive information or excessive functionality is exposed to unauthorized parties, aiding further attacks."
        d["Insecure Deep Link Handling"] = "'Insecure Deep Link Handling' reflects a security weakness in the application that may allow an attacker to compromise confidentiality, integrity, or availability."
        d["Universal Link Handling Misconfiguration"] = "Sensitive information or excessive functionality is exposed to unauthorized parties, aiding further attacks."
        d["Java Unsafe Reflection"] = "'Java Unsafe Reflection' reflects a security weakness in the application that may allow an attacker to compromise confidentiality, integrity, or availability."
        d["Java SecurityManager Bypass"] = "'Java SecurityManager Bypass' reflects a security weakness in the application that may allow an attacker to compromise confidentiality, integrity, or availability."
        d["Missing Data Encryption in Transit"] = "Weak or predictable cryptographic material or usage lets an attacker forge, decrypt, or replay protected data. Sensitive information or excessive functionality is exposed to unauthorized parties, aiding further attacks."
        d["Logging of Sensitive Data"] = "Attacker-controlled input is accepted into a parser or interpreter without validation, enabling data or control-flow tampering. Sensitive information or excessive functionality is exposed to unauthorized parties, aiding further attacks."
        d["PII Stored Longer Than Necessary"] = "Sensitive information or excessive functionality is exposed to unauthorized parties, aiding further attacks."
        d["Missing Consent for Data Collection"] = "Sensitive information or excessive functionality is exposed to unauthorized parties, aiding further attacks."
        d["Unauthorized Data Access"] = "Authentication, session, or authorization checks are missing or flawed, allowing unauthorized access, impersonation, or privilege escalation. Sensitive information or excessive functionality is exposed to unauthorized parties, aiding further attacks."
        d["Excessive Data Exposure"] = "Sensitive information or excessive functionality is exposed to unauthorized parties, aiding further attacks."
        d["Improper Restriction of XML External Entities"] = "Attacker-controlled input is accepted into a parser or interpreter without validation, enabling data or control-flow tampering."
        d["Incomplete Cleanup of Sensitive Data"] = "Sensitive information or excessive functionality is exposed to unauthorized parties, aiding further attacks."
        d["Sensitive Data in Thumbnails"] = "Sensitive information or excessive functionality is exposed to unauthorized parties, aiding further attacks."
        d["Side-Channel (Timing) Information Disclosure"] = "Attacker-controlled input is accepted into a parser or interpreter without validation, enabling data or control-flow tampering. Sensitive information or excessive functionality is exposed to unauthorized parties, aiding further attacks."
        d["Cache Timing Attack Vector"] = "'Cache Timing Attack Vector' reflects a security weakness in the application that may allow an attacker to compromise confidentiality, integrity, or availability."
        d["Padding Oracle Vulnerability"] = "'Padding Oracle Vulnerability' reflects a security weakness in the application that may allow an attacker to compromise confidentiality, integrity, or availability."
        d["Bleichenbacher Attack Vector"] = "'Bleichenbacher Attack Vector' reflects a security weakness in the application that may allow an attacker to compromise confidentiality, integrity, or availability."
        d["Length Extension Attack Vector"] = "'Length Extension Attack Vector' reflects a security weakness in the application that may allow an attacker to compromise confidentiality, integrity, or availability."
        d["Hash Collision Attack Vector"] = "Deprecates or weakens the underlying hash/key-derivation function, allowing offline brute-force or collision attacks against stored values."
        d["Birthday Attack on Hash"] = "Deprecates or weakens the underlying hash/key-derivation function, allowing offline brute-force or collision attacks against stored values."
        d["Same-Origin Policy Bypass"] = "A client-side security control is missing or bypassable, enabling script injection, clickjacking, or data leakage in the browser."
        d["Cross-Origin Resource Sharing (CORS) Bypass"] = "Deprecates or weakens the underlying hash/key-derivation function, allowing offline brute-force or collision attacks against stored values. Untrusted input reaches an interpreter or shell, allowing arbitrary command or code execution on the host."
        d["Mixed Content (HTTPS/HTTP)"] = "Insecure or missing transport-layer security exposes data to interception and tampering in transit. A client-side security control is missing or bypassable, enabling script injection, clickjacking, or data leakage in the browser."
        d["Insecure XML Parsing"] = "Attacker-controlled input is accepted into a parser or interpreter without validation, enabling data or control-flow tampering."
        d["Regular Expression Catastrophic Backtracking"] = "Attacker-controlled input is accepted into a parser or interpreter without validation, enabling data or control-flow tampering."
        d["ReDoS via User-Controlled Regex"] = "Attacker-controlled input is accepted into a parser or interpreter without validation, enabling data or control-flow tampering. Insufficient resource limits allow an attacker to exhaust CPU, memory, or connections and deny service to legitimate users."

        return d
    }()
    convenience init(bug: Bug?) {
        let window = EscClosableWindow(
            contentRect: NSRect(x: 0, y: 0, width: 560, height: 600),
            styleMask: [.titled, .closable],
            backing: .buffered,
            defer: false
        )
        window.title = bug == nil ? "New Bug Report" : "Edit Bug Report"
        self.init(window: window)
        self.editingBug = bug
        buildContent()
        if let bug = bug { populate(with: bug) }
    }

    override func showWindow(_ sender: Any?) {
        window?.center()
        window?.makeKeyAndOrderFront(nil)
        NSApp.activate(ignoringOtherApps: true)
        super.showWindow(sender)
        DispatchQueue.main.async { [weak self] in
            self?.window?.makeFirstResponder(self?.titleField)
        }
    }

    private func buildContent() {
        guard let content = window?.contentView else { return }

        let left: CGFloat = 20
        let labelWidth: CGFloat = 110
        let fieldX: CGFloat = left + labelWidth + 8
        let fieldWidth: CGFloat = 560 - 20 - fieldX - 8

        func label(_ text: String, y: CGFloat) -> NSTextField {
            let l = NSTextField(labelWithString: text)
            l.font = NSFont.systemFont(ofSize: 13, weight: .medium)
            l.alignment = .right
            l.frame = NSRect(x: left, y: y, width: labelWidth, height: 20)
            return l
        }

        titleField.placeholderString = "Short summary of the issue"
        titleField.frame = NSRect(x: fieldX, y: 540, width: fieldWidth, height: 24)
        content.addSubview(titleField)
        content.addSubview(label("Title:", y: 542))

        // Dropdown of preset security-vulnerability titles (only when creating a
        // new report). "Custom title…" (first entry) leaves the editable title field
        // for the user to type their own. When editing an existing report the
        // dropdown is omitted so the title/description are not overwritten.
        if editingBug == nil {
            titleMenu.addItems(withTitles: ["Custom title…"] + Self.presetTitles)
            titleMenu.target = self
            titleMenu.action = #selector(titleMenuItemSelected(_:))
            titleMenu.frame = NSRect(x: fieldX, y: 574, width: fieldWidth, height: 26)
            content.addSubview(titleMenu)
            content.addSubview(label("Use preset title:", y: 577))
        }

        severityPopup.addItems(withTitles: ["info", "low", "medium", "high", "critical"])
        severityPopup.frame = NSRect(x: fieldX, y: 500, width: fieldWidth, height: 26)
        content.addSubview(severityPopup)
        content.addSubview(label("Severity:", y: 503))

        exploitabilityPopup.addItems(withTitles: ["info", "low", "medium", "high", "critical"])
        exploitabilityPopup.frame = NSRect(x: fieldX, y: 460, width: fieldWidth, height: 26)
        content.addSubview(exploitabilityPopup)
        content.addSubview(label("Exploitability:", y: 463))

        packageField.placeholderString = "e.g. com.example.app"
        packageField.frame = NSRect(x: fieldX, y: 420, width: fieldWidth, height: 24)
        content.addSubview(packageField)
        content.addSubview(label("Package:", y: 422))

        versionField.placeholderString = "e.g. 1.0.3"
        versionField.frame = NSRect(x: fieldX, y: 380, width: fieldWidth, height: 24)
        content.addSubview(versionField)
        content.addSubview(label("Version:", y: 382))

        statusPopup.addItems(withTitles: Bug.statuses)
        statusPopup.frame = NSRect(x: fieldX, y: 340, width: fieldWidth, height: 26)
        content.addSubview(statusPopup)
        content.addSubview(label("Status:", y: 343))

        content.addSubview(label("Description:", y: 295))

        let detailScroll = NSScrollView(frame: NSRect(x: fieldX, y: 70, width: fieldWidth, height: 220))
        detailScroll.hasVerticalScroller = true
        detailScroll.autohidesScrollers = true
        detailScroll.borderType = .bezelBorder
        detailTextView.frame = NSRect(x: 0, y: 0, width: fieldWidth, height: 220)
        detailTextView.isRichText = false
        detailTextView.isEditable = true
        detailTextView.isSelectable = true
        detailTextView.font = NSFont.systemFont(ofSize: 13)
        detailTextView.textContainerInset = NSSize(width: 6, height: 6)
        detailTextView.textContainer?.widthTracksTextView = true
        detailTextView.isVerticallyResizable = true
        detailTextView.isHorizontallyResizable = false
        detailTextView.autoresizingMask = [.width]
        detailScroll.documentView = detailTextView
        content.addSubview(detailScroll)

        errorLabel.font = NSFont.systemFont(ofSize: 12)
        errorLabel.textColor = .systemRed
        errorLabel.frame = NSRect(x: fieldX, y: 36, width: fieldWidth, height: 18)
        content.addSubview(errorLabel)

        let cancelButton = NSButton(title: "Cancel", target: self, action: #selector(cancelClicked))
        cancelButton.bezelStyle = .rounded
        cancelButton.keyEquivalent = "\u{1b}"
        cancelButton.frame = NSRect(x: 560 - 20 - 190, y: 12, width: 90, height: 28)
        content.addSubview(cancelButton)

        let saveButton = NSButton(title: "Save", target: self, action: #selector(saveClicked))
        saveButton.bezelStyle = .rounded
        saveButton.keyEquivalent = "\r"
        saveButton.frame = NSRect(x: 560 - 20 - 90, y: 12, width: 90, height: 28)
        content.addSubview(saveButton)
    }

    private func populate(with bug: Bug) {
        titleField.stringValue = bug.title
        if editingBug == nil {
            if let idx = Self.presetTitles.firstIndex(of: bug.title) {
                titleMenu.selectItem(at: idx + 1) // offset past "Custom title…"
            } else {
                titleMenu.selectItem(at: 0)
            }
        }
        severityPopup.selectItem(withTitle: bug.severity)
        exploitabilityPopup.selectItem(withTitle: bug.exploitability)
        packageField.stringValue = bug.packageName
        versionField.stringValue = bug.version
        statusPopup.selectItem(withTitle: bug.status)
        detailTextView.string = bug.detail
    }

    @objc private func titleMenuItemSelected(_ sender: NSPopUpButton) {
        guard sender.indexOfSelectedItem > 0 else { return } // "Custom title…"
        guard let title = sender.titleOfSelectedItem, !title.isEmpty else { return }
        titleField.stringValue = title
        // Replace the description with the chosen preset's description so switching
        // between titles always reflects the newly selected vulnerability.
        if let description = Self.presetDescriptions[title] {
            detailTextView.string = description
        }
        window?.makeFirstResponder(titleField)
        titleField.currentEditor()?.selectedRange = NSRange(location: 0, length: (title as NSString).length)
    }

    @objc private func saveClicked() {
        let title = titleField.stringValue.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !title.isEmpty else {
            errorLabel.stringValue = "A title is required."
            NSSound.beep()
            return
        }
        let bug = Bug(
            id: editingBug?.id ?? UUID().uuidString,
            title: title,
            severity: severityPopup.titleOfSelectedItem ?? "medium",
            exploitability: exploitabilityPopup.titleOfSelectedItem ?? "medium",
            detail: detailTextView.string,
            packageName: packageField.stringValue.trimmingCharacters(in: .whitespacesAndNewlines),
            version: versionField.stringValue.trimmingCharacters(in: .whitespacesAndNewlines),
            status: statusPopup.titleOfSelectedItem ?? "Open",
            createdAt: editingBug?.createdAt ?? Date(),
            filePath: editingBug?.filePath,
            line: editingBug?.line
        )
        if editingBug != nil {
            BugStore.shared.update(bug)
        } else {
            BugStore.shared.add(bug)
        }
        onSaved?(bug)
        dismissSelf()
    }

    @objc private func cancelClicked() {
        dismissSelf()
    }

    private func dismissSelf() {
        if let parent = window?.sheetParent {
            parent.endSheet(window!)
        } else {
            window?.close()
        }
    }
}

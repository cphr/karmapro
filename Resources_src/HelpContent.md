# Karma Pro — User Guide & Help

![Karma Pro Splash](HelpSplash.jpg)

Welcome to **Karma Pro**, an advanced static analysis, machine-learning vulnerability classification, and security auditing application. Karma Pro provides deep architectural inspection, multi-language support, interactive flowcharts, and security tracking.

## 1. Getting Started & Project Navigation
- **Opening Files & Workspaces**: Use **File > Open...** (or press `Cmd+O`) or simply drag and drop any source file or project directory onto the Karma Pro window to load it into the sidebar file tree.
- **Language Filtering**: Karma Pro supports 13 primary languages: **C, C++, Java, C#, Go, Kotlin, Ruby, Python, PHP, Cocoa (Objective-C), Rust, Solidity, and Swift**, plus an **All Languages** option. Use the language dropdown in the toolbar to isolate files by language.
- **File Search**: Use the built-in file search window (**Edit > Find in Files...**) to quickly query filenames and navigate across large codebases.

## 2. Source Viewer, Syntax Highlighting & Code Navigation
- **Syntax Highlighting**: Custom tokenisers and highlighters provide distinct color schemes for keywords, strings, comments, and identifiers across all supported languages.
- **Clickable Functions**: Function names defined in source files are automatically underlined and linked. Clicking a function name jumps directly to its definition and instantly opens its transitive same-file call graph and dataflow in the bottom pane.
- **Right-Click (Context) Menu**: Right-click anywhere in the source viewer to open the context menu. The available actions adapt to what is under the cursor:
  - **Enable / Disable Magnifying Glass Lens** — turns on a magnifier that follows the mouse over the source and magnifies the code around the pointer, so you can read and inspect a code snippet at high zoom without changing the editor's font size. Choose the item again to switch the lens off.
  - **Show Flow Diagram for <function>**: shown when you right-click a function/method name. Opens that function's interactive **control-flow flowchart** (cyclomatic complexity, `if`/`else` branches, loops) in its own window.
  - **Follow the variable '<name>'**: shown when you right-click an identifier. Opens the **variable-flow diagram**: the enclosing function is drawn as a flowchart with every statement that uses the variable **highlighted**. When the variable is passed as an argument to a function defined elsewhere in the project, a **callee box** is added showing only the lines where the mapped parameter is used, and this expands recursively across files. Blue **“call”** arrows leave the call statement and purple **“return”** arrows rejoin the caller at the statement after the call. Click any statement or source line in the diagram to jump straight to it.
  - **Backtrace Analyser…**: opens the **Backtrace Analyser**. Paste a crash/stack trace (from the debugger, a log, or a file such as `stacktrace.txt`) and click **Analyse**; Karma Pro parses the frames and renders a clickable left-to-right **call-stack diagram**. Frames are resolved relative to the currently open project — click a frame to open its source line. Frames that cannot be resolved are shown in red (the trace must originate from the open project).
  - **(AI) How to fix it**: sends the line under the cursor, together with the surrounding project context, to the **AI Assistant** and asks for guidance on fixing the issue on that line (for example, how to remediate a vulnerability flagged by the scanner). Requires the AI Assistant to be connected to OpenRouter with an API key (see section 7).

## 3. Diagrams: Control Flow & Data Flow
- **Control Flow Diagrams**: Visualizes cyclomatic complexity, conditional branches (`if`/`else`), and loops (`while`/`for`) as an interactive flowchart (`FlowChartView`).
- **Dataflow Analysis**: Traces variable assignments, function parameter taint propagation, and inter-procedural call graphs within the same file to reveal how untrusted input reaches critical sinks.

## 4. Security Scanning & Vulnerability Analysis
- **Multi-Language Security Scanner**: Karma Pro parses source code using robust tokenizers, AST parsers, and inter-procedural data-flow analysis, performing precise taint tracking rather than simple regex matching.
- **Supported Languages**: The security analyser covers 13 primary programming languages with deep AST integration: **C, C++, Objective-C (Cocoa), Java, C#, Go, Kotlin, Ruby, Python, PHP, Rust, Solidity, and Swift**.
- **Cross-File Taint Analysis & Project Index**: Karma Pro builds a project-wide  dependency index  across all source files. When taint flows originate from a source function defined in a *different file* than the finding's sink, the vulnerability scanner marks it as **Cross-file** (`Yes` / orange indicator), allowing multi-file modular projects, imports, and requires to be analysed holistically.
- **Vulnerability Categories**: Detects common exploitation vectors including Buffer Overflow, Format String vulnerabilities, Command Injection, SQL Injection, Path Traversal, Server-Side Request Forgery (SSRF), Insecure Deserialization, Weak Cryptography / Randomness, Hardcoded Secrets, Log Injection, XSS (HTML Injection), Race Conditions / TOCTOU, and (for Solidity) Reentrancy, tx.origin Authorization, Predictable Randomness, Unchecked External Call Return, Delegatecall to Untrusted Address, Selfdestruct to Arbitrary Address, pragma-hygiene issues etc.
- **Mobile Security Checks**: Dedicated Android (Java) and iOS/Cocoa (Objective-C) rule sets cover platform-specific risk: WebView hardening (JavaScript bridges, file/universal access, arbitrary-loads ATS bypasses), trust-manager / hostname-verifier bypasses, raw SQL, clipboard and pasteboard leakage, UserDefaults and Keychain accessibility misconfiguration, deprecated UIWebView, JavaScript injection, notification/keyed-archiver misuse, deep-link / open-URL exposure, file-protection level, location tracking, SMS/mail composition, and privacy-sensitive contact access etc.
- **Severity & Exploitability**: Findings are graded by severity (`Critical`, `High`, `Medium`, `Low`), exploitability scores, reachability (whether reachable from entry points), and precise source-to-sink taint paths.
- **Engine Distinction**: Distinguishes findings detected structurally over the parsed Abstract Syntax Tree (**AST**) from heuristic pattern matches (**Heuristic**).

## 5. Bayesian Classifier, ML Trainer & Model Import/Export
- **Bayesian Vulnerability Classifier**: A probabilistic machine-learning classifier that analyses token frequencies and log-odds to evaluate code snippets for vulnerability likelihood.
- **How the ML classifier works**: Karma Pro's ML classification follows the *[Karma* method](https://cipher.org.uk/2026/02/08/Karma-Automated-source-code-defect-identification-method/) an automated, source-code defect identification technique, a **Bayes classifier** is trained on empirical data so it can point to "interesting pieces" of code in any language. The training data comes from **software patches** (.patch/.diff files): in a patch, lines marked `-` are the removed (defective) lines and lines marked `+` are the added (correcting) lines. The classifier's training phase builds a model of prior probabilities, e.g. how often a given token/keyword appears in defective lines versus safe ones.
- **At scan time**, each line of code is reduced to its tokens (special characters and formatting removed), and the classifier estimates the probability the line is a defect versus not a defect using those per-token frequencies. A line is classified as a likely defect when its posterior probability of being a bug exceeds its probability of being safe. Karma Pro renders this as a **confidence score** and a per-file **heatmap**, so you get visual assistance pointing to areas of interest.
- **ML Training Window**: An interactive training suite where you can feed positive (vulnerable) and negative (safe) training samples. The classifier updates its probability models in real time.
- **Model Persistence (Import & Export)**:
  - **Export Model**: Save your trained Bayesian classifier weights and token distributions to a local Karma Pro file to share across teams or back up.
  - **Import Model**: Load previously exported Bayesian model JSON files into Karma Pro to instantly apply pretrained classification logic.
- **ML Scan**: Run probabilistic scans across project files to discover hidden risks alongside confirmed findings. The ML pass is *complementary* to the ruleset/AST scanner: it surfaces probabilistic candidate defects (and can catch language-agnostic "interesting" numbers, variables and functions) that hard-coded rules may miss, while the deterministic scanner provides confirmed, taint-verified findings.

## 6. Security Bugs Tracker Window
The Security Bugs Tracker window provides a centralised, interactive management console for reviewing, filtering, triaging, and inspecting all discovered security vulnerabilities across your scanned project:
- **Comprehensive Finding Grid**: Displays every detected vulnerability grouped or listed with its exact file path, line number, function name, severity badge (`Critical`, `High`, `Medium`, `Low`), and detection engine source.
- **Interactive Filtering & Sorting**: Quickly filter findings by severity level, category (e.g. SQL Injection, Buffer Overflow, Command Injection), or reachability status. Click column headers to sort by file location or risk level.

## 7. AI Assistant 
The **AI** toolbar button (right of the Bugs button) opens the AI Assistant window, which connects Karma Pro to [OpenRouter](https://openrouter.ai) so you can query large language models about the currently open project:
- **Connect**: Paste your OpenRouter API key (from `openrouter.ai/keys`) into the key field and click **Connect**. The key is saved on your machine and remembered across launches.
- **Model Selection**: Pick any model from the dropdown (Claude, GPT-4o, Gemini, Llama, DeepSeek, Mistral, …). The list is fetched live from OpenRouter when a key is set; the **Refresh** button re-fetches it. Your chosen model is remembered and can be changed at any time.
- **Project Context**: Every prompt is automatically anchored to the project currently open in Karma Pro, its path is included in the system message sent with each request. The AI window cannot be opened until a project folder is selected.
- **Prompt Templates Dropdown**: Ships with built-in templates. Selecting an entry pastes its text into the prompt editor at the cursor position.
- **Managing Templates**: Use **Add…** to create a new template (a title for the dropdown plus prompt text), **Edit…** to modify the selected template (built-in ones included), and **Remove** to delete it. All template changes are stored per-user and survive relaunches.
- **Import / Export Prompts**: **Export…** saves every stored prompt template (built-in and custom) to a file you can back up or share. **Import…** adds prompts from such a file entries that are already stored.

## 8. Private Research Wiki
The **Wiki** toolbar button (next to Notes) opens a private research wiki shared across all projects. Write pages in a rich-text editor with a white background, hyperlink selected words instantly with the **Link…** button (or type `[[Page Name]]`), and click any link to open the page, creating it if it doesn't exist yet. Pages can be listed, searched, renamed and deleted, auto-save whenever their window closes, and the whole wiki can be backed up to a `.karmawiki` archive — optionally encrypted with a password and imported back later.


Karma Pro should work from macOS 12.0 (Monterey) and newer versions.

**Brought to you by cipher.org.uk**

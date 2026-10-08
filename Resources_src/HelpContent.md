# Karma Pro — User Guide & Help

![Karma Pro Splash](HelpSplash.jpg)

Welcome to **Karma Pro**, an advanced static analysis, machine-learning vulnerability classification, and security auditing application. Karma Pro provides deep architectural inspection, multi-language support, interactive flowcharts, and security tracking.
## 1. Getting Started & Project Navigation
- **Opening Files & Workspaces**: Use **File > Open...** project directory onto the Karma Pro window to load it into the sidebar file tree.
- **Language Filtering**: Karma Pro supports 14 primary languages: **C, C++, Java, C#, Go, Kotlin, Ruby, Python, PHP, Cocoa (Objective-C), Rust, Solidity, Javascript and Swift**, plus an **All Languages** option. Use the language dropdown in the toolbar to isolate files by language.
- **File Search**: Use the built-in file search window (**Edit > Find in Files...**) to quickly query filenames and navigate across large codebases.
## 2. Source Viewer, Syntax Highlighting & Code Navigation
- **Syntax Highlighting**: Custom tokenisers and highlighters provide distinct color schemes for keywords, strings, comments, and identifiers across all supported languages.
- **Clickable Functions**: Function names defined in source files are automatically underlined and linked. Clicking a function name jumps directly to its definition and instantly opens its transitive same-file call graph and dataflow in the bottom pane.
- **Right-Click (Context) Menu**: Right-click anywhere in the source viewer to open the context menu. The available actions adapt to what is under the cursor:
  - **Focus on <function>**: Shown when you right-click a function/method name, highlights the current function and it displays callers and callees overlayed on the source viewer so it is easier to navigate through the source code between functions/methods.
  - **Show Flow Diagram for <function>**: shown when you right-click a function/method name. Opens that function's interactive **control-flow flowchart** (cyclomatic complexity, `if`/`else` branches, loops) in its own window.
  - **Follow the variable '<name>'**: shown when you right-click an identifier. Opens the **variable-flow diagram**: the enclosing function is drawn as a flowchart with every statement that uses the variable **highlighted**. When the variable is passed as an argument to a function defined elsewhere in the project, a **callee box** is added showing only the lines where the mapped parameter is used, and this expands recursively across files. Blue **“call”** arrows leave the call statement and purple **“return”** arrows rejoin the caller at the statement after the call. Click any statement or source line in the diagram to jump straight to it.
  - **Backtrace Analyser…**: opens the **Backtrace Analyser**. Paste a crash/stack trace (from the debugger, a log, or a file such as `stacktrace.txt`) and click **Analyse** Karma Pro parses the frames and renders a clickable left-to-right **call-stack diagram**. Frames are resolved relative to the currently open project — click a frame to open its source line. Frames that cannot be resolved are shown in red (the trace must originate from the open project).
  - **(AI) How to fix it**: sends the line under the cursor, together with the surrounding project context, to the **AI Assistant** and asks for guidance on fixing the issue on that line (for example, how to remediate a vulnerability flagged by the scanner). Requires the AI Assistant to be connected to OpenRouter with an API key, or Ollama (see section 7).
  - **Simulate <function> in the Debugger** experimental: shown when you right-click a function/method name. Opens the **Karma Pro Debugger**, a lightweight dynamic simulator that steps through the selected function line by line. Right-click a function and choose this item to begin, the window opens scoped to just that function, with the current line highlighted. Use **Step Over**, **Step Into**, **Step Back** and **Reset** at the top of the window to control execution, or **Play** to run automatically. The debugger follows calls into functions defined elsewhere in the open project, switching the source view  to the callee and returning when the call completes. Parameters shown are editable values you can change before stepping. The simulation is approximate and may not cover every language construct.
## 3. Diagrams: Control Flow & Data Flow
- **Control Flow Diagrams**: Visualizes cyclomatic complexity, conditional branches (`if`/`else`), and loops (`while`/`for`) as an interactive flowchart (`FlowChartView`).
- **Dataflow Analysis**: Traces variable assignments, function parameter taint propagation, and inter-procedural call graphs within the same file to reveal how untrusted input reaches critical sinks.
- **Find external entries**: scans the whole project and lists every place where the application receives input from outside, remote-facing receive APIs such as HTTP request parameters, deep links, push payloads, web/client responses, and blockchain transaction input, plus local sources like environment variables and command-line arguments, files. Results are grouped by category and tagged by locality (Remote, Local). Selecting an entry plots its data-flow diagram: an origin box for the locality, then the entry point and the functions the received value flows through. Rows show project-relative paths and clicking a graph node jumps to the exact source line in the source viewer.
- **Show reachability of 'function'** right-click opens a diagram of the function's or method's position in the currently project. It walks the full caller list, every function that calls it, each of those callers' own callers, and so on, all the way up to the top, where a box shows where that it ends: Remote, Local or if no entry point reaches it at all, an amber topmost box confirming the end of the walk. 
- **Complexity distribution** window you see a scatter plot where every source file's functions are laid out left-to-right in source order (X axis) with their cyclomatic complexity measured on the Y axis. Each function is a colour-coded point labelled with its complexity number. Hover any point to see its file, function name, line and complexity, or click it to jump straight to that function in the source viewer. Note in large projects it can be a bit slow to plot.
## 4. Security Scanning & Vulnerability Analysis
- **Multi-Language Security Scanner**: Karma Pro parses source code using robust tokenizers, AST parsers, and inter-procedural data-flow analysis, performing precise taint tracking rather than simple regex matching.
- **Supported Languages**: The security analyser covers 13 primary programming languages with deep AST integration: **C, C++, Objective-C (Cocoa), Java, C#, Go, Kotlin, Ruby, Python, PHP, Rust, Solidity, and Swift**.
- **Cross-File Taint Analysis & Project Index**: Karma Pro builds a project-wide  dependency index  across all source files. When taint flows originate from a source function defined in a *different file* than the finding's sink, the vulnerability scanner marks it as **Cross-file** (`Yes` / orange indicator), allowing multi-file modular projects, imports, and requires to be analysed holistically.
- **Vulnerability Categories**: Detects common exploitation vectors including Buffer Overflow, Format String vulnerabilities, Command Injection, SQL Injection, Path Traversal, Server-Side Request Forgery (SSRF), Insecure Deserialization, Weak Cryptography / Randomness, Hardcoded Secrets, Log Injection, XSS (HTML Injection), Race Conditions / TOCTOU, and (for Solidity) Reentrancy, tx.origin Authorization, Predictable Randomness, Unchecked External Call Return, Delegatecall to Untrusted Address, Selfdestruct to Arbitrary Address, pragma-hygiene issues etc.
- **Mobile Security Checks**: Dedicated Android (Java) and iOS/Cocoa (Objective-C) rule sets cover platform-specific risk: WebView hardening (JavaScript bridges, file/universal access, arbitrary-loads ATS bypasses), trust-manager / hostname-verifier bypasses, raw SQL, clipboard and pasteboard leakage, UserDefaults and Keychain accessibility misconfiguration, deprecated UIWebView, JavaScript injection, notification/keyed-archiver misuse, deep-link / open-URL exposure, file-protection level, location tracking, SMS/mail composition, and privacy-sensitive contact access etc.
- **Severity & Exploitability**: Findings are graded by severity (`Critical`, `High`, `Medium`, `Low`), exploitability scores, reachability (whether reachable from entry points), and precise source-to-sink taint paths.
- **Engine Distinction**: Distinguishes findings detected structurally over the parsed Abstract Syntax Tree (**AST**) from heuristic pattern matches (**Heuristic**). Note: if you also chose AI scan to be performed, you will also see AI results.
## 5. Bayesian Classifier, ML Trainer & Model Import/Export
- **Bayesian Vulnerability Classifier**: A probabilistic machine-learning classifier that analyses token frequencies and log-odds to evaluate code snippets for vulnerability likelihood.
- **How the ML classifier works**: Karma Pro's ML classification follows the *[Karma* method](https://cipher.org.uk/2026/02/08/Karma-Automated-source-code-defect-identification-method/) an automated, source-code defect identification technique, a **Bayes classifier** is trained on empirical data so it can point to "interesting pieces" of code in any language. The training data comes from **software patches** (.patch/.diff files): in a patch, lines marked `-` are the removed (defective) lines and lines marked `+` are the added (correcting) lines. The classifier's training phase builds a model of prior probabilities, e.g. how often a given token/keyword appears in defective lines versus safe ones.
- **At scan time**, each line of code is reduced to its tokens (special characters and formatting removed), and the classifier estimates the probability the line is a defect versus not a defect using those per-token frequencies. A line is classified as a likely defect when its posterior probability of being a bug exceeds its probability of being safe. Karma Pro renders this as a **confidence score** and a per-file **heatmap**, so you get visual assistance pointing to areas of interest.
- **ML Training Window**: An interactive training suite where you can feed positive (vulnerable) and negative (safe) training samples. The classifier updates its probability models in real time.
- **Model Persistence (Import & Export)**:
  - **Export Model**: Save your trained Bayesian classifier weights and token distributions to a local Karma Pro file to share across teams or back up.
  - **Import Model**: Load previously exported Bayesian model JSON files into Karma Pro to instantly apply pretrained classification logic.
- **ML Scan**: Run probabilistic scans across project files to discover hidden risks alongside confirmed findings. The ML pass is *complementary* to the ruleset/AST scanner: it surfaces probabilistic candidate defects (and can catch language-agnostic "interesting" numbers, variables and functions) that hard-coded rules may miss, while the deterministic scanner provides confirmed, taint-verified findings.
## 6. Security Bugs Tracker Tool
The **Security bugs tracker** is a built-in vulnerability tracking tool that helps you organise and work through discovered vulnerabilities.
- **Create & manage reports**: Add, view, edit, and delete bug reports with a title, severity, exploitability, status, description, package name, and version.
- **Use preset templates**: common vulnerability titles (SQLi, XSS, RCE, crypto, memory, mobile, cloud, business logic etc) with ready-made descriptions or write your own.
- **Search**: Filter bugs by title, description, severity, status, package, or ID.
- **Triage**: Color-coded severity and exploitability in the list and details, statuses track.
- **Backup & import**: Export all reports to a .karmapro JSON backup (optionally password-protected) and import them back.
Reports persist locally (survive app restarts) and live in the Karma Pro application support directory.
## 7. AI Assistant 
The **AI** toolbar button (right of the Bugs button) opens the AI Assistant window, which connects Karma Pro to [Ollama](https://ollama.com/) or to [OpenRouter](https://openrouter.ai) so you can query large language models about the currently open project:
- **Connect**: Paste your OpenRouter API key (from `openrouter.ai/keys`) into the key field and click **Connect**. The key is saved on your machine and remembered across launches.
- **Model Selection**: Pick any model from the dropdown (Claude, GPT-4o, Gemini, Llama, DeepSeek, Mistral, …). The list is fetched live from OpenRouter when a key is set the **Refresh** button re-fetches it. Your chosen model is remembered and can be changed at any time.
- **Project Context**: Every prompt is automatically anchored to the project currently open in Karma Pro, its path is included in the system message sent with each request. The AI window cannot be opened until a project folder is selected.
- **Prompt Templates Dropdown**: Ships with built-in templates. Selecting an entry pastes its text into the prompt editor at the cursor position.
- **Managing Templates**: Use **Add…** to create a new template (a title for the dropdown plus prompt text), **Edit…** to modify the selected template (built-in ones included), and **Remove** to delete it. All template changes are stored per-user and survive relaunches.
- **Import / Export Prompts**: **Export…** saves every stored prompt template (built-in and custom) to a file you can back up or share. **Import…** adds prompts from such a file entries that are already stored.
## 8. Private Research Wiki
The **Wiki** toolbar button (next to Notes) opens a private research wiki shared across all projects. Write pages in a rich-text editor with a white background, hyperlink selected words instantly with the **Link…** button (or type `[[Page Name]]`), and click any link to open the page, creating it if it doesn't exist yet. Pages can be listed, searched, renamed and deleted, auto-save whenever their window closes, and the whole wiki can be backed up to a `.karmawiki` archive, optionally encrypted with a password and imported back later.
## 9. Pull Request Monitoring & Review Scanning
The **Karma Pro** menu bar icon can watch repositories on **GitHub**, **GitLab**, **Bitbucket** and **Gitea/Forgejo**, tell you when a pull request opens or changes, and check that pull request and scan it. Monitoring is off by default.
**Adding a public repository**
Public repositories don't need an account, token or login.
- Open the **Karma Pro** menu bar icon and choose **Manage Repositories…**
- Paste the repository URL into the **Repository** field. 
- Leave **Local clone** empty to use a temporary workspace, or point it at an existing local clone.
- Choose a **Scan depth** (see below).
- Optionally list **base branches** to watch, comma-separated, e.g. `main, release`. Empty means every branch.
- Click **Test Connection** to confirm the repository is reachable, then **Add Repository**.
- Choose **Enable Monitoring…** from the menu bar icon.
The repository appears in the list. Untick **Watching** to pause notifications without deleting it.
**Adding a private repository**
Private repositories need a **read-only token**. Karma Pro never approves, comments on or posts to a pull request, so read-only scope is enough. Tokens are stored in your macOS Keychain.
**Accounts setup:**
- Choose the **Provider**.
- Set the **Host**, prefilled for you. Change it only for a self-hosted instance e.g. gitlab.example.com, or the host of an internal Gitea install. For Gitea/Forgejo this is the field that matters, since there is no single public host.
- Enter any **Username**. This is only a label to help you tell accounts apart.
- Paste the **Token** and click **Save Token**.
**Then add the repository** as above, but tick **Private repository**. The status line names the account that will be used, e.g. *uses account "test" on github.com*.
**Several accounts on one provider:** save more than one account per provider and choose per repository which one watches it, so two private repositories belonging to different accounts are monitored independently. The **Account** dropdown appears under the URL as soon as a private repository has more than one saved account that can reach it, listing only accounts whose provider *and* host match the URL, shown as test (github.com). The **Account** column in the repository list shows which account each private repository polls with.
**What monitoring does**
Karma Pro polls each watched repository every **15 minutes** and compares the result against the previous poll.
- A pull request is announced when it **opens**, and again when it **changes** — including a **force-push**, recognised by head commit rather than by title, so a rewritten pull request is not silently missed.
- At most **5** pull requests are announced per poll, the rest are carried to the next.
- A pull request you **Ignore** is not announced again until it is force-pushed to new commits.
- **Alert style** is **Off**, **Notification**, or **Notification + Sound**.
- With **Off**, polling stops and the menu bar icon fades, so you can see that nothing is being watched.
**Notification actions.** **Review** checks the pull request out and scans it, it is the *only* action, so dismissing a notification or letting it time out never starts a review. **Not Now** dismisses it and leaves it reviewable later. **Ignore** stops alerting until the pull request is force-pushed. 
**Reviewing a pull request**
Choosing **Review**, from a notification, or from the banner on a repository you are watching, prepares a workspace and scans it if you choose to do so.
- **Scan**: base and head are both scanned and the findings compared, so the report shows what this pull request **introduced** rather than what the project already contained. Findings that shift line number because of edits elsewhere in the diff are matched to their original instead of reported as new.
- **Diff**: changed files open side by side, base against head, with findings shown against them.
- **Report**: **Report** produces a saveable Markdown document with the pull request's author, branches, head commit, link, files changed and last updated time, plus the findings the scan introduced/
**Scan depth** is chosen per repository when you add it:
- **Changed files only** Only the files this pull request adds or modifies, fastest and smallest. Large repositories or a first look. Cross-file analysis cannot follow taint into files it never fetched, so some findings are missing.
- **Full project** The whole project at the head commit, slower and larger. When the change touches shared code and you need cross-file taint analysis and reachability to work normally.
**Closing a review**: **Close Review** ends the session, clears the file tree and every pane, and removes the on-disk checkouts. Checkouts and findings are cached between reviews for speed; **Manage Repositories** shows the cache size and has **Clear Cache**, which is refused while a review is open, when you are not reviewing however you clear the local cache.
## 10. Scan Project's Packages
The **Packages > Scan project's packages** menu checks the project's own dependencies for known vulnerabilities. A project folder must be open, otherwise the scan does not start.
- **Auto-detection**: manifests and lockfiles are found automatically npm/yarn/pnpm, PyPI, Cargo, Go, RubyGems, Composer, Maven/Gradle, NuGet and Swift Package Manager. Unsupported projects are reported as such.
- **Scan**: click **Scan** to query every resolved package version against **api.osv.dev**. Results are listed by severity with the package, file and line.
- **Results**: click a row to open the packages file at the line, **Ignore issue** hides a finding and **Export Scan** saves the shown findings as a SARIF report.
- **(AI) Is it vulnerable?**: right-click a finding to send the question to the AI Assistant, using whichever model is currently selected.
Karma Pro should work from macOS 12.0 (Monterey) and newer versions.
**ReviewCode.org** is Karma Pro's dedicated website
**Brought to you by cipher.org.uk**
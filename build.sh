#!/bin/bash
# Builds the Karma Pro macOS app bundle from source.
set -e
cd "$(dirname "$0")"

APP="Karma Pro.app"
BIN="$APP/Contents/MacOS/Karma Pro"

SOURCES=(
  Sources/main.swift
  Sources/AppDelegate.swift
  Sources/main/MainWindowController.swift
  Sources/main/FileTreeViewController.swift
  Sources/main/SourceViewer.swift
  Sources/utils/TypeResolver.swift
  Sources/languages/JSFunctionParser.swift
  Sources/languages/JSParser.swift
  Sources/languages/JSExprParser.swift
  Sources/languages/JSPlatform.swift
  Sources/languages/JSAnalyzer.swift
  Sources/detectors/JSSecurityDetector.swift
  Sources/languages/SwiftParser.swift
  Sources/languages/SwiftExprParser.swift
  Sources/languages/SwiftPlatform.swift
  Sources/languages/SwiftAnalyzer.swift
  Sources/detectors/SwiftSecurityDetector.swift
  Sources/utils/SyntaxHighlighter.swift
  Sources/main/FileTree.swift
  Sources/languages/Language.swift
  Sources/graphs/CallGraph.swift
  Sources/languages/CCFunctionParser.swift
  Sources/languages/CAstNode.swift
  Sources/languages/CAstToken.swift
  Sources/languages/CTokenizer.swift
  Sources/languages/CParser.swift
  Sources/languages/CSymbolTable.swift
  Sources/languages/CAnalyzer.swift
  Sources/languages/JavaPlatform.swift
  Sources/languages/JParser.swift
  Sources/languages/JSymbolTable.swift
  Sources/languages/JAnalyzer.swift
  Sources/languages/CSharpPlatform.swift
  Sources/languages/CSharpParser.swift
  Sources/languages/CSharpAnalyzer.swift
  Sources/languages/SolidityAnalyzer.swift
  Sources/languages/SolidityParser.swift
  Sources/languages/SolidityPlatform.swift
  Sources/languages/ScriptPlatform.swift
  Sources/languages/ScriptMethodParser.swift
  Sources/languages/ScriptAnalyzer.swift
  Sources/detectors/AstSecurityDetector.swift
  Sources/detectors/SoliditySecurityDetector.swift
  Sources/detectors/PHPSecurityDetector.swift
  Sources/detectors/JavaSecurityDetector.swift
  Sources/detectors/CSharpSecurityDetector.swift
  Sources/detectors/GoSecurityDetector.swift
  Sources/detectors/KotlinSecurityDetector.swift
  Sources/detectors/PythonSecurityDetector.swift
  Sources/detectors/RubySecurityDetector.swift
  Sources/detectors/RustSecurityDetector.swift
  Sources/detectors/CFamilySecurityDetector.swift
  Sources/detectors/KernelAstDetector.swift
  Sources/detectors/CFamilyWalkDetector.swift
  Sources/graphs/GraphLayout.swift
  Sources/graphs/DataFlowDiagramView.swift
  Sources/graphs/DataFlowWindowController.swift
  Sources/graphs/VariableFlowTracer.swift
  Sources/graphs/VariableFlowDiagramView.swift
  Sources/graphs/VariableFlowWindowController.swift
  Sources/graphs/EntryPointsWindowController.swift
  Sources/graphs/ProjectCallGraph.swift
  Sources/graphs/ReachabilityWindowController.swift
  Sources/tools/EntryPointCatalog.swift
  Sources/tools/EntryPointCollector.swift
  Sources/tools/SimDebugEngine.swift
  Sources/tools/SimDebugWindowController.swift
  Sources/graphs/BacktraceParser.swift
  Sources/graphs/BacktraceDiagramView.swift
  Sources/graphs/BacktraceAnalyserWindowController.swift
  Sources/graphs/ClassUsageWindowController.swift
  Sources/graphs/ControlFlowParser.swift
  Sources/indexes/DefinitionIndex.swift
  Sources/indexes/DefinitionWindowController.swift
  Sources/graphs/DiagramSupport.swift
  Sources/main/EscClosableWindow.swift
  Sources/languages/ObjCMethodParser.swift
  Sources/languages/ObjCAnalyzer.swift
  Sources/indexes/ProjectIndex.swift
  Sources/main/SourceTree.swift
  Sources/indexes/IndexBuildWindowController.swift
  Sources/graphs/FlowChartView.swift
  Sources/graphs/FlowPanelViewController.swift
  Sources/utils/FileSearchWindowController.swift
  Sources/utils/CodeMagnifyingGlassView.swift
  Sources/main/HelpWindowController.swift
  Sources/utils/LicensingWindowController.swift
  Sources/main/SplashWindowController.swift
  Sources/tools/NoteStore.swift
  Sources/tools/BugStore.swift
  Sources/AI/PromptStore.swift
  Sources/AI/OpenRouterClient.swift
  Sources/AI/AIToolRunner.swift
  Sources/AI/AIWindowController.swift
  Sources/tools/NotePopoverController.swift
  Sources/languages/ObjCAst.swift
  Sources/languages/ObjCParser.swift
  Sources/detectors/ObjCSecurityDetector.swift
  Sources/detectors/VulnerabilityScanner.swift
  Sources/main/ScanWindowController.swift
  Sources/tools/NotesWindowController.swift
  Sources/tools/BugListWindowController.swift
  Sources/tools/BugEditorWindowController.swift
  Sources/tools/BackupCrypto.swift
  Sources/tools/WikiStore.swift
  Sources/tools/WikiEditorWindowController.swift
  Sources/tools/WikiWindowController.swift
  Sources/bayes/BayesianClassifier.swift
  Sources/bayes/BayesianModelStore.swift
  Sources/bayes/MLTrainingWindowController.swift
  Sources/bayes/MLScanWindowController.swift
  Sources/bayes/MLScanResultStore.swift
  Sources/bayes/HeatmapWindowController.swift
  Sources/utils/HighlightedLinesViewController.swift
)

mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"

# Minimum macOS the built app will run on. Keep it as low as the code allows so
# the app works on older macOS (the default target is the *current* OS, which
# would otherwise prevent the app from launching on anything older).
MIN_MACOS="12.0"

echo "Compiling Karma Pro…"
swiftc -O -target "x86_64-apple-macos${MIN_MACOS}" -swift-version 5 -o "$BIN" "${SOURCES[@]}"

echo "Copying Info.plist and icon…"
# Always copy the Info.plist and icon from the source resources dir into the bundle,
# so a clean rebuild always produces a complete bundle.
cp Resources_src/Info.plist "$APP/Contents/Info.plist"
printf 'APPL????' > "$APP/Contents/PkgInfo"
if [ -f Resources_src/AppIcon.icns ]; then
  cp Resources_src/AppIcon.icns "$APP/Contents/Resources/AppIcon.icns"
fi
if [ -f Resources_src/SplashImage.jpg ]; then
  cp Resources_src/SplashImage.jpg "$APP/Contents/Resources/SplashImage.jpg"
fi
if [ -f Resources_src/HelpSplash.jpg ]; then
  cp Resources_src/HelpSplash.jpg "$APP/Contents/Resources/HelpSplash.jpg"
fi
if [ -f Resources_src/HelpContent.md ]; then
  cp Resources_src/HelpContent.md "$APP/Contents/Resources/HelpContent.md"
fi
if [ -f Resources_src/AIPrompts.json ]; then
  cp Resources_src/AIPrompts.json "$APP/Contents/Resources/AIPrompts.json"
fi
if [ -d Resources_src/Models ]; then
  # Remove the previous copy first: plain `cp -R src existing-dir` would nest
  # the models as Models/Models and duplicate them on every rebuild.
  rm -rf "$APP/Contents/Resources/Models"
  cp -R Resources_src/Models "$APP/Contents/Resources/Models"
fi

codesign --force --deep --sign - "$APP" 2>/dev/null || true

echo "Built $APP"

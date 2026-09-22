// by cipher.org.uk
import Foundation

// MARK: - Emulated value model

enum SimValueKind: Equatable {
    case int, double, bool, string, buffer, array, object, nullable
}

struct SimDebugValue: Equatable {
    var kind: SimValueKind
    var intValue: Int?
    var doubleValue: Double?
    var boolValue: Bool?
    var stringValue: String?
    var capacity: Int?
    var elementKind: SimValueKind?
    var display: String

    static func int(_ v: Int) -> SimDebugValue {
        SimDebugValue(kind: .int, intValue: v, doubleValue: nil, boolValue: nil,
                      stringValue: nil, capacity: nil, elementKind: nil, display: "\(v)")
    }
    static func double(_ v: Double) -> SimDebugValue {
        SimDebugValue(kind: .double, intValue: nil, doubleValue: v, boolValue: nil,
                      stringValue: nil, capacity: nil, elementKind: nil,
                      display: String(format: "%g", v))
    }
    static func bool(_ b: Bool) -> SimDebugValue {
        SimDebugValue(kind: .bool, intValue: nil, doubleValue: nil, boolValue: b,
                      stringValue: nil, capacity: nil, elementKind: nil, display: b ? "true" : "false")
    }
    static func string(_ s: String) -> SimDebugValue {
        SimDebugValue(kind: .string, intValue: nil, doubleValue: nil, boolValue: nil,
                      stringValue: s, capacity: nil, elementKind: nil, display: "\"\(s)\"")
    }
    static func buffer(_ s: String, capacity: Int) -> SimDebugValue {
        SimDebugValue(kind: .buffer, intValue: nil, doubleValue: nil, boolValue: nil,
                      stringValue: s, capacity: capacity, elementKind: nil,
                      display: "[\(capacity)] \"\(s)\"")
    }
    static func array(_ items: [String]) -> SimDebugValue {
        SimDebugValue(kind: .array, intValue: items.count, doubleValue: nil, boolValue: nil,
                      stringValue: items.joined(separator: ","), capacity: items.count,
                      elementKind: .string,
                      display: "[" + items.joined(separator: ", ") + "]")
    }
    static func object(_ label: String) -> SimDebugValue {
        SimDebugValue(kind: .object, intValue: nil, doubleValue: nil, boolValue: nil,
                      stringValue: nil, capacity: nil, elementKind: nil, display: "«\(label)»")
    }
    static func nullable() -> SimDebugValue {
        SimDebugValue(kind: .nullable, intValue: nil, doubleValue: nil, boolValue: nil,
                      stringValue: nil, capacity: nil, elementKind: nil, display: "nil")
    }

    var truthy: Bool {
        switch kind {
        case .int: return intValue != 0
        case .double: return (doubleValue ?? 0) != 0
        case .bool: return boolValue ?? false
        case .string: return !(stringValue ?? "").isEmpty
        case .buffer, .array: return (capacity ?? 0) > 0
        case .nullable: return false
        case .object: return true
        }
    }

    func asInt() -> Int? {
        switch kind {
        case .int: return intValue
        case .double: return doubleValue.map { Int($0.rounded()) }
        case .bool: return boolValue.map { $0 ? 1 : 0 }
        case .string: return stringValue.flatMap { Int($0) }
        case .buffer, .array: return capacity
        default: return nil
        }
    }

    func asDouble() -> Double? {
        switch kind {
        case .int: return intValue.map { Double($0) }
        case .double: return doubleValue
        case .bool: return boolValue.map { $0 ? 1 : 0 }
        case .string: return stringValue.flatMap { Double($0) }
        default: return nil
        }
    }

    func asString() -> String? {
        switch kind {
        case .string, .buffer: return stringValue
        case .int: return intValue.map { "\($0)" }
        case .double: return doubleValue.map { String(format: "%g", $0) }
        case .bool: return boolValue.map { $0 ? "true" : "false" }
        case .array: return stringValue
        default: return nil
        }
    }
}

// MARK: - User-editable parameter seed

struct SimParameterSeed {
    let name: String
    let typeHint: String
    var value: SimDebugValue
    var isBuffer: Bool
    var capacity: Int

    var summary: String { "\(name): \(value.display)" }
}

extension SimParameterSeed: Equatable {}

// MARK: - Data types handed to the UI

struct SimVariableRow: Equatable {
    let name: String
    var value: SimDebugValue
    let isParameter: Bool
    var changed: Bool
}

struct SimCallFrameView: Equatable {
    let functionName: String
    let fileURL: URL
    let fileName: String
    let line: Int
    let variables: [SimVariableRow]
    let isDone: Bool
    let isActive: Bool
}

struct SimDebugStep {
    let index: Int
    let functionName: String
    let fileURL: URL
    let fileName: String
    let line: Int
    let statementText: String
    let effects: [String]
    let frames: [SimCallFrameView]
    let activeFrameIndex: Int
    let warning: String?
    var restore: [SimFrameVM]
}

enum SimStepMode {
    case over, into
}

// MARK: - Prepared function

struct SimFrameVM: Equatable {
    let function: SimFunction
    var pc: Int
    var locals: [String: SimDebugValue]
    var localOrder: [String]
    var blockStack: [SimBlock]
    var loopIterations: [Int: Int]
    var pendingReturn: SimDebugValue?
    var isDone: Bool
}

enum SimInstrKind: Equatable {
    case code, open, close
    case controlIf, controlElse, controlWhile, controlFor, controlDo, controlSwitch, caseLabel
    case controlTry, controlCatch, controlFinally, controlWith
}

struct SimInstruction: Equatable {
    let kind: SimInstrKind
    let text: String
    let line: Int
}

enum SimBlockKind: Equatable {
    case plain, cond, whileBody, forBody, doBody, switchBody, tryBody
}

struct SimBlock: Equatable {
    let kind: SimBlockKind
    let openIdx: Int
    let conditionIndex: Int
    let taken: Bool
}

struct SimFunction: Equatable {
    let name: String
    let fileURL: URL
    let ext: String
    let signatureText: String
    let instructions: [SimInstruction]
    let params: [SimParameterSeed]
}

struct SimCall {
    let name: String
    let receiver: String?
    let arguments: [String]
    let lhs: String?
    let isCall: Bool
}

// MARK: - Seed values

private struct SimSeeding {
    static func stringForName(_ name: String) -> String {
        let n = name.lowercased()
        if n.contains("name") { return "Alice" }
        if n.contains("user") || n.contains("login") || n.contains("email") { return "alice" }
        if n.contains("msg") || n.contains("message") || n.contains("text") { return "hello world" }
        if n.contains("word") || n.contains("pass") { return "secret" }
        if n.contains("tag") { return "tag1" }
        if n.contains("path") { return "/tmp/file" }
        if n.contains("id") { return "50" }
        return "hello"
    }

    static func intForName(_ name: String) -> Int {
        let n = name.lowercased()
        if n.contains("count") || n.contains("total") || n.contains("max") || n.contains("len") || n.contains("size") { return 100 }
        if n.contains("times") { return 2 }
        if n.contains("flag") || n.contains("mode") || n.contains("op") { return 1 }
        return 50
    }

    static func seedValue(forTypeText typeText: String, name: String) -> SimDebugValue {
        let s = typeText.lowercased()
        if s.hasPrefix("@") { return .object(String(typeText.dropFirst())) }
        if s.contains("float") || s.contains("double") || s.contains("cgfloat") || s.contains("real") {
            return .double(3.5)
        }
        if s.contains("bool") || s.contains("boolean") {
            return .bool(true)
        }
        if s.contains("char") {
            if s.contains("*") || s.contains("[") {
                return .buffer("", capacity: capacityFrom(typeText) ?? 64)
            }
            return .int(120)
        }
        let capacityHint = capacityFrom(typeText)
        if capacityHint != nil {
            return .buffer("", capacity: capacityHint!)
        }
        if s.contains("string") || s.contains("nsstring") || s.contains("text") || s.contains("buffer")
            || s.contains("bytes") || s.contains("data") {
            return .string(stringForName(name))
        }
        if s.contains("int") || s.contains("long") || s.contains("short") || s.contains("size_t")
            || s.contains("ssize_t") || s.contains("number") || s.contains("byte") || s.contains("uint")
            || s.contains("i32") || s.contains("i64") || s.contains("u32") || s.contains("u64")
            || s.contains("u8") || s.contains("i8") {
            return .int(intForName(name))
        }
        if s.contains("array") || s.contains("list") || s.contains("vector") || s.contains("set")
            || s.contains("map") || s.contains("dict") || s.contains("slice") || s.contains("array") {
            return .array([])
        }
        if s.contains("*") {
            return .buffer("", capacity: 128)
        }
        let bareName = s.trimmingCharacters(in: .whitespaces)
        let isBareIdentifier = bareName == name && !s.contains(" ")
        if isBareIdentifier || bareName.count <= 1 {
            let n = name.lowercased()
            let numeric = ["count", "total", "max", "len", "size", "num", "n", "times", "index", "idx",
                           "i", "j", "k", "x", "y", "z", "v", "w", "a", "b", "c", "d", "step", "offset",
                           "width", "height", "delta", "limit", "min", "length"]
            if numeric.contains(n) || (n.count == 1) {
                return .int(intForName(name))
            }
            return .string(stringForName(name))
        }
        return .object(bareName)
    }

    private static func capacityFrom(_ typeText: String) -> Int? {
        if let open = typeText.firstIndex(of: "["), let close = typeText.firstIndex(of: "]") {
            let inside = String(typeText[typeText.index(after: open)..<close]).trimmingCharacters(in: .whitespaces)
            if let n = Int(inside) { return n }
        }
        return nil
    }
}

// MARK: - Engine

final class SimDebugEngine {

    let sourceIndex: ProjectSourceIndex?
    private var definitionIndex: DefinitionIndex?

    private(set) var functionName: String = ""
    private(set) var entryFileURL: URL
    private let entryExt: String

    private var function: SimFunction?
    private var frames: [SimFrameVM] = []
    private(set) var steps: [SimDebugStep] = []
    private var bindings: [(callerIndex: Int, lhs: String?, callLine: Int, calleeName: String)] = []
    private var doneAll = false
    private var lastPoppedReturn: SimDebugValue?
    private var totalExecuted = 0

    private let maxTotalSteps = 2000
    private let maxLoopIterations = 40
    private let maxCallDepth = 8
    private var callDepth = 0
    private let maxSilentSteps = 400

    private let declarationPrefixes = [
        "int ", "char ", "long ", "short ", "float ", "double ", "bool ", "boolean ",
        "var ", "let ", "const ", "unsigned ", "signed ", "size_t ", "ssize_t ",
        "uint", "int8", "int16", "int32", "int64", "void ", "auto ",
        "std::string", "string ", "String ", "NS", "List ", "Dictionary ", "Array ",
        "vector", "array", "dict", "map", "slice", "byte", "bytes ", "Data ", "data "
    ]

    private let builtinNames: Set<String> = [
        "len", "strlen", "count", "size", "malloc", "calloc", "realloc", "new", "Array",
        "make", "range", "str", "String", "string", "description", "tostring", "toString",
        "strconv", "Itoa", "int", "Int", "parseInt", "atoi", "float", "Double", "double",
        "abs", "min", "max"
    ]

    var parameters: [SimParameterSeed] = []
    var isReady: Bool { function != nil }
    var hasRunCompleted: Bool { doneAll }

    /// The 1-based line range covering the simulated function's own statements
    /// (min…max instruction line). Used by the debugger window to scope the
    /// highlighted region to just the function instead of the whole file.
    var functionBodyLineRange: ClosedRange<Int>? {
        guard let function = function else { return nil }
        let lines = function.instructions.map { $0.line }
        guard let lo = lines.min(), let hi = lines.max() else { return nil }
        return lo...hi
    }

    init(sourceIndex: ProjectSourceIndex?, fileURL: URL, functionName: String) {
        self.sourceIndex = sourceIndex
        self.entryFileURL = fileURL.standardizedFileURL
        self.entryExt = fileURL.pathExtension.lowercased()
        self.functionName = functionName
        loadEntry()
    }

    private var sourceText: String = ""

    private func loadEntry() {
        sourceText = resolveSource(for: entryFileURL) ?? ""
        if let sourceIndex = sourceIndex, sourceIndex.entries.count > 0 {
            definitionIndex = DefinitionIndex.build(sourceIndex: sourceIndex)
        } else {
            definitionIndex = nil
        }
        let defs = diagramDefinitions(source: sourceText, ext: entryExt)
        guard let def = defs.first(where: { $0.name == functionName }) ?? defs.first else {
            function = nil
            parameters = []
            return
        }
        guard let fn = SimFunctionBuilder.make(def: def, source: sourceText, ext: entryExt, fileURL: entryFileURL) else {
            function = nil
            parameters = []
            return
        }
        function = fn
        parameters = fn.params
    }

    private func resolveSource(for url: URL) -> String? {
        if let sourceIndex = sourceIndex, let entry = sourceIndex.entries[url.standardizedFileURL] {
            return entry.source
        }
        return try? String(contentsOf: url, encoding: .utf8)
    }

    func initialStep() -> SimDebugStep? {
        guard let function = function else { return nil }
        frames = [freshFrame(function: function)]
        doneAll = false
        totalExecuted = 0
        steps = []
        bindings = []
        callDepth = 0
        lastPoppedReturn = nil
        let first = function.instructions.first
        return makeStep(activeIdx: 0, line: first?.line ?? 1,
                        text: first?.text ?? "— ready —",
                        effects: ["auto-assigned inputs; press Step to begin"],
                        warning: nil)
    }

    func stepForward(mode: SimStepMode) -> SimDebugStep? {
        guard !doneAll else { return nil }
        for _ in 0..<maxTotalSteps {
            switch executeNext(emit: true, mode: mode) {
            case .emitted(let step):
                totalExecuted += 1
                steps.append(step)
                return step
            case .jumped:
                continue
            case .blocked:
                return nil
            case .finished:
                doneAll = true
                return nil
            }
        }
        doneAll = true
        return nil
    }

    func stepBack() -> SimDebugStep? {
        guard let last = steps.popLast() else { return nil }
        frames = last.restore
        if let b = bindings.last, b.callerIndex >= frames.count {
            bindings.removeLast()
        } else if frames.isEmpty {
            return nil
        }
        return steps.last ?? initialStep()
    }

    func reset(withSeeds seeds: [SimParameterSeed]) {
        guard let current = function else { return }
        let rebuilt = SimFunction(name: current.name, fileURL: current.fileURL, ext: current.ext,
                                  signatureText: current.signatureText,
                                  instructions: current.instructions, params: seeds)
        function = rebuilt
        parameters = seeds
        _ = initialStep()
    }

    // MARK: - Engine internals

    private func freshFrame(function: SimFunction) -> SimFrameVM {
        var locals: [String: SimDebugValue] = [:]
        var order: [String] = []
        for p in function.params {
            locals[p.name] = p.value
            order.append(p.name)
        }
        return SimFrameVM(function: function, pc: 0, locals: locals, localOrder: order,
                          blockStack: [], loopIterations: [:], pendingReturn: nil, isDone: false)
    }

    private enum Exec {
        case emitted(SimDebugStep)
        case jumped
        case blocked
        case finished
    }

    private func executeNext(emit: Bool, mode: SimStepMode) -> Exec {
        guard !frames.isEmpty else { return .finished }
        let activeIdx = frames.count - 1
        var frame = frames[activeIdx]

        if frame.isDone || frame.pc >= frame.function.instructions.count {
            return popFrameAndBind(activeIdx: activeIdx)
        }

        let instr = frame.function.instructions[frame.pc]

        switch instr.kind {
        case .code:
            return executeCode(instr, frameIndex: activeIdx, emit: emit, mode: mode)
        case .open:
            frame.blockStack.append(SimBlock(kind: .plain, openIdx: frame.pc, conditionIndex: -1, taken: false))
            frame.pc += 1
            frames[activeIdx] = frame
            return .jumped
        case .close:
            return handleClose(instr, frameIndex: activeIdx, emit: emit)
        case .controlIf:
            return executeIf(instr, frameIndex: activeIdx, emit: emit, mode: mode)
        case .controlElse:
            return executeElse(instr, frameIndex: activeIdx, emit: emit, mode: mode)
        case .controlWhile:
            return executeWhile(instr, frameIndex: activeIdx, emit: emit, mode: mode)
        case .controlFor:
            return executeFor(instr, frameIndex: activeIdx, emit: emit, mode: mode)
        case .controlDo:
            frame.blockStack.append(SimBlock(kind: .doBody, openIdx: frame.pc, conditionIndex: -1, taken: false))
            frame.pc += 1
            frames[activeIdx] = frame
            return .jumped
        case .controlSwitch:
            frame.blockStack.append(SimBlock(kind: .switchBody, openIdx: frame.pc, conditionIndex: frame.pc, taken: false))
            frame.pc += 1
            frames[activeIdx] = frame
            if emit {
                let step = makeStep(activeIdx: activeIdx, instr: instr, effects: ["switch on \(argumentText(of: instr.text))"], warning: nil, mode: mode)
                return .emitted(step)
            }
            return .jumped
        case .caseLabel:
            return executeCaseLabel(instr, frameIndex: activeIdx, emit: emit)
        case .controlTry, .controlCatch, .controlFinally:
            frame.blockStack.append(SimBlock(kind: .tryBody, openIdx: frame.pc, conditionIndex: -1, taken: false))
            frame.pc += 1
            frames[activeIdx] = frame
            return .jumped
        case .controlWith:
            frame.blockStack.append(SimBlock(kind: .cond, openIdx: frame.pc, conditionIndex: -1, taken: false))
            frame.pc += 1
            frames[activeIdx] = frame
            return .jumped
        }
    }

    private func makeStep(activeIdx: Int, instr: SimInstruction, effects: [String], warning: String?, mode: SimStepMode) -> SimDebugStep {
        makeStep(activeIdx: activeIdx, line: instr.line, text: instr.text, effects: effects, warning: warning)
    }

    private func makeStep(activeIdx: Int, line: Int, text: String, effects: [String], warning: String?) -> SimDebugStep {
        let active = frames[activeIdx]
        let views = frames.enumerated().map { idx, f -> SimCallFrameView in
            var rows = f.localOrder.map { name in
                SimVariableRow(name: name, value: f.locals[name] ?? .nullable(),
                               isParameter: f.function.params.contains { $0.name == name },
                               changed: false)
            }
            if let rv = f.pendingReturn {
                rows.append(SimVariableRow(name: "(return)", value: rv, isParameter: false, changed: true))
            }
            return SimCallFrameView(functionName: f.function.name,
                                    fileURL: f.function.fileURL,
                                    fileName: f.function.fileURL.lastPathComponent,
                                    line: f.pc < f.function.instructions.count ? f.function.instructions[f.pc].line : line,
                                    variables: rows,
                                    isDone: f.isDone,
                                    isActive: idx == activeIdx)
        }
        return SimDebugStep(
            index: steps.count + 1,
            functionName: active.function.name,
            fileURL: active.function.fileURL,
            fileName: active.function.fileURL.lastPathComponent,
            line: line,
            statementText: text,
            effects: effects,
            frames: views,
            activeFrameIndex: activeIdx,
            warning: warning,
            restore: frames)
    }

    private func popFrameAndBind(activeIdx: Int) -> Exec {
        guard let popped = frames.popLast() else { return .finished }
        let returnValue = popped.pendingReturn
        if frames.isEmpty { return .finished }
        lastPoppedReturn = returnValue
        if let bind = bindings.popLast() {
            callDepth = max(0, callDepth - 1)
            var caller = frames[bind.callerIndex]
            if let lhs = bind.lhs, !lhs.isEmpty, lhs != "return" {
                if !caller.localOrder.contains(lhs) { caller.localOrder.append(lhs) }
                caller.locals[lhs] = returnValue ?? .nullable()
                frames[bind.callerIndex] = caller
            }
            let rvText = returnValue?.display ?? "nil"
            let step = makeStep(activeIdx: bind.callerIndex, line: bind.callLine,
                                text: "", effects: ["[return from \(bind.calleeName)] \(bind.lhs ?? "→") \(rvText)"],
                                warning: nil)
            return .emitted(step)
        }
        return .jumped
    }

    // MARK: - Control flow

    private func argumentText(of text: String) -> String {
        var s = text.trimmingCharacters(in: .whitespaces)
        if s.hasSuffix(";") { s = String(s.dropLast()).trimmingCharacters(in: .whitespaces) }
        if s.hasSuffix("{") { s = String(s.dropLast()).trimmingCharacters(in: .whitespaces) }
        guard let open = s.firstIndex(of: "(") else { return "" }
        let after = s[s.index(after: open)...]
        var depth = 1
        for (i, c) in after.enumerated() {
            if c == "(" { depth += 1 }
            else if c == ")" {
                depth -= 1
                if depth == 0 {
                    return String(after[..<after.index(after.startIndex, offsetBy: i)]).trimmingCharacters(in: .whitespaces)
                }
            }
        }
        return ""
    }

    private func firstIndex(of bracelessText: String, in text: String) -> String.Index? {
        text.range(of: bracelessText)?.lowerBound
    }

    private func instructionEndsWithBrace(_ text: String) -> Bool {
        let t = text.trimmingCharacters(in: .whitespaces)
        return t.hasSuffix("{")
    }

    private func matchingCloseIndex(from openIdx: Int, in instrs: [SimInstruction]) -> Int? {
        var depth = 0
        var i = openIdx
        while i < instrs.count {
            let k = instrs[i].kind
            if k == .open || k == .controlIf || k == .controlWhile || k == .controlFor
                || k == .controlDo || k == .controlSwitch || k == .controlTry || k == .controlWith
                || (k == .code && instructionEndsWithBrace(instrs[i].text) && !isBareControlKeyword(instrs[i])) {
                depth += 1
            } else if k == .close {
                depth -= 1
                if depth == 0 { return i }
            }
            i += 1
        }
        return nil
    }

    private func isBareControlKeyword(_ instr: SimInstruction) -> Bool {
        let t = instr.text.trimmingCharacters(in: .whitespaces).lowercased()
        return t == "if" || t == "else" || t == "do" || t == "try" || t == "finally" || t == "with" || t == "switch"
    }

    private func advancePastElseChain(closeIdx: Int, instrs: [SimInstruction]) -> Int {
        var i = closeIdx + 1
        while i < instrs.count {
            if instrs[i].kind == .controlElse {
                if instructionEndsWithBrace(instrs[i].text) {
                    if let close = matchingCloseIndex(from: i, in: instrs) {
                        i = close + 1
                        continue
                    }
                }
                i += 1
                continue
            }
            break
        }
        return i
    }

    private func evalBool(_ expr: String, frameIndex: Int) -> Bool {
        eval(expr, frameIndex: frameIndex)?.truthy ?? false
    }

    private func executeIf(_ instr: SimInstruction, frameIndex: Int, emit: Bool, mode: SimStepMode) -> Exec {
        var f = frames[frameIndex]
        let cond = argumentText(of: instr.text)
        let taken = evalBool(cond, frameIndex: frameIndex)
        f.pc += 1
        if instructionEndsWithBrace(instr.text) {
            if taken {
                f.blockStack.append(SimBlock(kind: .cond, openIdx: frameIndex, conditionIndex: frameIndex, taken: true))
                frames[frameIndex] = f
                if emit {
                    let step = makeStep(activeIdx: frameIndex, instr: instr, effects: ["if (\(cond)) → true"], warning: nil, mode: mode)
                    return .emitted(step)
                }
                return .jumped
            }
            frames[frameIndex] = f
            if let closeIdx = matchingCloseIndex(from: instrIndex(instr, in: f), in: f.function.instructions) {
                f.pc = closeIdx + 1
                frames[frameIndex] = f
            }
            if isElseNext(index: instrIndex(instr, in: frames[frameIndex]), instrs: frames[frameIndex].function.instructions) {
                return .jumped
            }
            if emit {
                let step = makeStep(activeIdx: frameIndex, instr: instr, effects: ["if (\(cond)) → false (body skipped)"], warning: nil, mode: mode)
                return .emitted(step)
            }
            return .jumped
        }
        if !taken {
            f.pc += 1
            frames[frameIndex] = f
            if emit {
                let step = makeStep(activeIdx: frameIndex, instr: instr, effects: ["if (\(cond)) → false (statement skipped)"], warning: nil, mode: mode)
                return .emitted(step)
            }
            return .jumped
        }
        frames[frameIndex] = f
        if emit {
            let step = makeStep(activeIdx: frameIndex, instr: instr, effects: ["if (\(cond)) → true"], warning: nil, mode: mode)
            return .emitted(step)
        }
        return .jumped
    }

    private func isElseNext(index: Int, instrs: [SimInstruction]) -> Bool {
        let i = index
        while i < instrs.count, instrs[i].kind == .code {
            if instrs[i].kind == .controlElse { return true }
            break
        }
        while i < instrs.count {
            if instrs[i].kind == .controlElse { return true }
            break
        }
        return false
    }

    private func instrIndex(_ instr: SimInstruction, in f: SimFrameVM) -> Int {
        _ = instr
        return max(0, f.pc - 1)
    }

    private func executeElse(_ instr: SimInstruction, frameIndex: Int, emit: Bool, mode: SimStepMode) -> Exec {
        var f = frames[frameIndex]
        let low = instr.text.lowercased()
        let hasCondition = low.contains("if") && instr.text.contains("(")
        var cond = ""
        if hasCondition {
            cond = argumentText(of: String(instr.text.dropFirst(4))).isEmpty
                ? argumentText(of: instr.text) : argumentText(of: String(instr.text.dropFirst(4)))
            cond = argumentText(of: instr.text)
        }
        let taken = hasCondition ? evalBool(cond, frameIndex: frameIndex) : true
        f.pc += 1
        if instructionEndsWithBrace(instr.text) {
            if taken {
                f.blockStack.append(SimBlock(kind: .cond, openIdx: frameIndex, conditionIndex: frameIndex, taken: true))
                frames[frameIndex] = f
                if emit {
                    let step = makeStep(activeIdx: frameIndex, instr: instr, effects: [hasCondition ? "else if (\(cond)) → true" : "else → true"], warning: nil, mode: mode)
                    return .emitted(step)
                }
                return .jumped
            }
            frames[frameIndex] = f
            if let closeIdx = matchingCloseIndex(from: instrIndex(instr, in: f), in: f.function.instructions) {
                f.pc = closeIdx + 1
                frames[frameIndex] = f
            }
            return .jumped
        }
        frames[frameIndex] = f
        if emit {
            let step = makeStep(activeIdx: frameIndex, instr: instr, effects: [hasCondition ? "else if (\(cond)) → \(taken ? "true" : "false")" : "else → true"], warning: nil, mode: mode)
            return .emitted(step)
        }
        return .jumped
    }

    private func executeWhile(_ instr: SimInstruction, frameIndex: Int, emit: Bool, mode: SimStepMode) -> Exec {
        var f = frames[frameIndex]
        let cond = argumentText(of: instr.text)
        let iterations = f.loopIterations[instr.line] ?? 0
        let taken = iterations < maxLoopIterations && evalBool(cond, frameIndex: frameIndex)
        f.loopIterations[instr.line] = iterations + 1
        f.pc += 1
        if taken {
            f.blockStack.append(SimBlock(kind: .whileBody, openIdx: instrIndex(instr, in: f), conditionIndex: instrIndex(instr, in: f), taken: true))
            frames[frameIndex] = f
            if emit {
                let step = makeStep(activeIdx: frameIndex, instr: instr, effects: ["while (\(cond)) → true (iteration \(iterations + 1))"], warning: nil, mode: mode)
                return .emitted(step)
            }
            return .jumped
        }
        if let closeIdx = matchingCloseIndex(from: instrIndex(instr, in: f), in: f.function.instructions) {
            f.pc = closeIdx + 1
        }
        frames[frameIndex] = f
        if emit {
            let step = makeStep(activeIdx: frameIndex, instr: instr, effects: ["while (\(cond)) → false (body skipped)"], warning: iterations >= maxLoopIterations ? "loop iteration bound reached" : nil, mode: mode)
            return .emitted(step)
        }
        return .jumped
    }

    private func executeFor(_ instr: SimInstruction, frameIndex: Int, emit: Bool, mode: SimStepMode) -> Exec {
        var f = frames[frameIndex]
        let iterations = f.loopIterations[instr.line] ?? 0
        if iterations == 0 {
            if let initText = forInitText(instr.text) {
                applyAssignment(initText, frameIndex: frameIndex)
            }
            f = frames[frameIndex]
        }
        let condOK: Bool
        if let rangeMatch = iterableRange(of: instr.text) {
            let (loopVar, n) = rangeMatch
            let i = frames[frameIndex].locals[loopVar]?.asInt() ?? 0
            condOK = i < n
        } else {
            condOK = forCondText(instr.text).map { evalBool($0, frameIndex: frameIndex) } ?? true
        }
        f = frames[frameIndex]
        let currentIter = f.loopIterations[instr.line] ?? 0
        f.loopIterations[instr.line] = currentIter + 1
        if condOK {
            f.pc += 1
            f.blockStack.append(SimBlock(kind: .forBody, openIdx: instrIndex(instr, in: f), conditionIndex: instrIndex(instr, in: f), taken: true))
            frames[frameIndex] = f
            if emit {
                let step = makeStep(activeIdx: frameIndex, instr: instr, effects: ["for step \(currentIter + 1)"], warning: currentIter >= maxLoopIterations ? "loop iteration bound reached" : nil, mode: mode)
                return .emitted(step)
            }
            return .jumped
        }
        if let closeIdx = matchingCloseIndex(from: instrIndex(instr, in: f), in: f.function.instructions) {
            f.pc = closeIdx + 1
        }
        frames[frameIndex] = f
        if emit {
            let step = makeStep(activeIdx: frameIndex, instr: instr, effects: ["for loop finished"], warning: currentIter >= maxLoopIterations ? "loop iteration bound reached" : nil, mode: mode)
            return .emitted(step)
        }
        return .jumped
    }

    private func forInitText(_ text: String) -> String? {
        let inner = loopInner(text)
        let parts = inner.split(separator: ";").map { String($0).trimmingCharacters(in: .whitespaces) }
        return parts.count >= 1 && inner.contains(";") ? parts[0] : nil
    }

    private func forCondText(_ text: String) -> String? {
        let inner = loopInner(text)
        guard inner.contains(";") else { return nil }
        let parts = inner.split(separator: ";").map { String($0).trimmingCharacters(in: .whitespaces) }
        guard parts.count >= 2 else { return nil }
        return parts[1]
    }

    private func forIncrementText(_ text: String) -> String? {
        let inner = loopInner(text)
        guard inner.contains(";") else { return nil }
        let parts = inner.split(separator: ";").map { String($0).trimmingCharacters(in: .whitespaces) }
        guard parts.count >= 3 else { return nil }
        return parts[2]
    }

    private func loopInner(_ text: String) -> String {
        var s = text.trimmingCharacters(in: .whitespaces)
        if let kw = tryPeekKeyword(s) { s = String(s.dropFirst(kw.count)).trimmingCharacters(in: .whitespaces) }
        if s.hasPrefix("(") { s = String(s.dropFirst()).trimmingCharacters(in: .whitespaces) }
        if s.hasSuffix("{") { s = String(s.dropLast()).trimmingCharacters(in: .whitespaces) }
        if s.hasSuffix(")") { s = String(s.dropLast()).trimmingCharacters(in: .whitespaces) }
        return s
    }

    private func tryPeekKeyword(_ s: String) -> String? {
        for kw in ["while", "for"] where s.hasPrefix(kw) { return kw }
        return nil
    }

    private func iterableRange(of text: String) -> (String, Int)? {
        let lower = text.lowercased()
        guard let r = lower.range(of: " in ") else { return nil }
        let loopVar = String(text[..<r.lowerBound]).trimmingCharacters(in: .whitespaces)
        if loopVar.contains(" ") { return nil }
        var iterable = String(text[r.upperBound...]).trimmingCharacters(in: .whitespaces)
        if iterable.hasSuffix(")") || iterable.hasSuffix("{") { iterable = String(iterable.dropLast()).trimmingCharacters(in: .whitespaces) }
        let v = eval(iterable, frameIndex: frames.count - 1)
        let n: Int
        if let iv = v?.asInt() {
            n = iv
        } else if let cap = v?.capacity {
            n = cap
        } else {
            n = 3
        }
        return (loopVar, n)
    }

    private func executeCaseLabel(_ instr: SimInstruction, frameIndex: Int, emit: Bool) -> Exec {
        var f = frames[frameIndex]
        let label = caseValue(instr.text)
        var matched = false
        if let switchBlock = f.blockStack.last(where: { $0.kind == .switchBody }) {
            let switchInstr = f.function.instructions[switchBlock.conditionIndex]
            let subject = eval(argumentText(of: switchInstr.text), frameIndex: frameIndex)
            if label == "default" {
                matched = true
            } else {
                matched = eval(label, frameIndex: frameIndex)?.display == subject?.display
            }
        } else {
            matched = true
        }
        f.pc += 1
        frames[frameIndex] = f
        if emit {
            let step = makeStep(activeIdx: frameIndex, instr: instr, effects: ["case \(label) \(matched ? "→ matched" : "→ skipped")"], warning: nil, mode: .over)
            return .emitted(step)
        }
        return .jumped
    }

    private func caseValue(_ text: String) -> String {
        var s = text.trimmingCharacters(in: .whitespaces)
        if s.hasPrefix("case ") { s = String(s.dropFirst(5)) }
        if s.hasSuffix(":") { s = String(s.dropLast()) }
        return s.trimmingCharacters(in: .whitespaces)
    }

    private func handleClose(_ instr: SimInstruction, frameIndex: Int, emit: Bool) -> Exec {
        var f = frames[frameIndex]
        let closeIdx = f.pc
        guard let block = f.blockStack.popLast() else {
            f.pc += 1
            frames[frameIndex] = f
            return .jumped
        }
        f.pc = closeIdx + 1
        switch block.kind {
        case .whileBody:
            let condText = f.function.instructions[block.conditionIndex].text
            let cond = argumentText(of: condText)
            let iter = f.loopIterations[f.function.instructions[block.conditionIndex].line] ?? 0
            if iter < maxLoopIterations && evalBool(cond, frameIndex: frameIndex) {
                f.pc = block.conditionIndex
                frames[frameIndex] = f
                return .jumped
            }
            frames[frameIndex] = f
            if emit {
                let step = makeStep(activeIdx: frameIndex, instr: instr, effects: ["while (\(cond)) → false (loop done)"], warning: iter >= maxLoopIterations ? "iteration bound" : nil, mode: .over)
                return .emitted(step)
            }
            return .jumped
        case .forBody:
            if let incText = forIncrementText(f.function.instructions[block.openIdx].text) {
                if let inc = incrementStatement(incText) {
                    mutate(inc.name, to: .int((lookupLocal(inc.name, frameIndex: frameIndex)?.asInt() ?? 0) + inc.delta), frameIndex: frameIndex)
                } else {
                    applyAssignment(incText, frameIndex: frameIndex)
                }
            }
            let ok: Bool
            if let rangeMatch = iterableRange(of: f.function.instructions[block.openIdx].text) {
                let (loopVar, n) = rangeMatch
                ok = frames[frameIndex].locals[loopVar]?.asInt() ?? 0 < n
            } else {
                ok = forCondText(f.function.instructions[block.openIdx].text).map { evalBool($0, frameIndex: frameIndex) } ?? false
            }
            if ok {
                f = frames[frameIndex]
                f.pc = block.openIdx
                frames[frameIndex] = f
                return .jumped
            }
            frames[frameIndex] = f
            return .jumped
        case .doBody:
            let afterIdx = f.pc
            let instrs = f.function.instructions
            if afterIdx < instrs.count, instrs[afterIdx].kind == .code {
                let nxt = instrs[afterIdx].text.trimmingCharacters(in: .whitespaces)
                if nxt.hasPrefix("while") || nxt.hasPrefix("until") {
                    let cond = argumentText(of: nxt)
                    let condTrue = evalBool(cond, frameIndex: frameIndex)
                    let again = nxt.hasPrefix("until") ? !condTrue : condTrue
                    if again {
                        f.pc = block.openIdx + 1
                        f.blockStack.append(SimBlock(kind: .doBody, openIdx: block.openIdx, conditionIndex: -1, taken: false))
                        frames[frameIndex] = f
                        return .jumped
                    }
                    f.pc = afterIdx + 1
                    frames[frameIndex] = f
                    return .jumped
                }
            }
            frames[frameIndex] = f
            return .jumped
        case .cond:
            if block.taken {
                let instrs = f.function.instructions
                let after = advancePastElseChain(closeIdx: closeIdx, instrs: instrs)
                if after != closeIdx + 1 {
                    f.pc = after
                    frames[frameIndex] = f
                    return .jumped
                }
            }
            frames[frameIndex] = f
            return .jumped
        case .switchBody, .tryBody, .plain:
            frames[frameIndex] = f
            return .jumped
        }
    }
}

// MARK: - Code statements

extension SimDebugEngine {

    private func executeCode(_ instr: SimInstruction, frameIndex: Int, emit: Bool, mode: SimStepMode) -> Exec {
        let text = instr.text.trimmingCharacters(in: .whitespaces)

        if text == "break;" {
            if let blockIdx = frames[frameIndex].blockStack.lastIndex(where: { $0.kind == .whileBody || $0.kind == .forBody || $0.kind == .doBody || $0.kind == .switchBody }) {
                let block = frames[frameIndex].blockStack[blockIdx]
                frames[frameIndex].blockStack.removeLast(frames[frameIndex].blockStack.count - blockIdx)
                if let close = matchingCloseIndex(from: block.openIdx, in: frames[frameIndex].function.instructions) {
                    frames[frameIndex].pc = close + 1
                } else {
                    frames[frameIndex].pc += 1
                }
            } else {
                frames[frameIndex].pc += 1
            }
            return emit ? dedupStep(instr, frameIndex: frameIndex, effects: ["break"], emit: true) : .jumped
        }
        if text == "continue;" {
            if let block = frames[frameIndex].blockStack.last, block.kind == .whileBody || block.kind == .forBody {
                frames[frameIndex].pc = block.openIdx
                return .jumped
            }
            frames[frameIndex].pc += 1
            return .jumped
        }

        if text == "return;" || text == "return" || text.hasPrefix("return ") || (text.hasPrefix("return") && !text.hasPrefix("returning")) {
            return executeReturn(text, instr: instr, frameIndex: frameIndex, emit: emit, mode: mode)
        }

        let call = parseCall(in: text)
        if call.isCall {
            let effects = applyCall(text: text, call: call, frameIndex: frameIndex, mode: mode)
            frames[frameIndex].pc += 1
            if emit {
                let step = makeStep(activeIdx: frameIndex, instr: instr, effects: effects, warning: nil, mode: mode)
                return .emitted(step)
            }
            return .jumped
        }

        if let inc = incrementStatement(text) {
            let before = frames[frameIndex].locals[inc.name]?.display ?? "∅"
            mutate(inc.name, to: .int((frames[frameIndex].locals[inc.name]?.asInt() ?? 0) + inc.delta), frameIndex: frameIndex)
            let after = frames[frameIndex].locals[inc.name]?.display ?? "∅"
            frames[frameIndex].pc += 1
            if emit {
                let step = makeStep(activeIdx: frameIndex, instr: instr, effects: ["\(inc.name): \(before) → \(after)"], warning: nil, mode: mode)
                return .emitted(step)
            }
            return .jumped
        }

        if let compound = compoundAssignment(text) {
            let before = frames[frameIndex].locals[compound.name]?.display ?? "∅"
            applyCompound(compound, frameIndex: frameIndex)
            let after = frames[frameIndex].locals[compound.name]?.display ?? "∅"
            frames[frameIndex].pc += 1
            if emit {
                let step = makeStep(activeIdx: frameIndex, instr: instr, effects: ["\(compound.name): \(before) → \(after)"], warning: nil, mode: mode)
                return .emitted(step)
            }
            return .jumped
        }

        if isDeclaration(text) {
            return applyDeclaration(text, instr: instr, frameIndex: frameIndex, emit: emit, mode: mode)
        }

        if let eq = plainAssignment(text, frameIndex: frameIndex) {
            let effect: String
            if eq.name.contains("[") {
                let base = normalizeVarName(eq.name.split(separator: "[").first.map(String.init) ?? "")
                let before = lookupLocal(base, frameIndex: frameIndex)?.display ?? "∅"
                applyAssignment(eq.text, frameIndex: frameIndex)
                let rhsText = topLevelAssignment(eq.text)?.1.trimmingCharacters(in: .whitespaces) ?? ""
                let val = eval(rhsText, frameIndex: frameIndex)?.display ?? "?"
                effect = "\(base): \(before) → (element \(val))"
            } else {
                let before = frames[frameIndex].locals[eq.name]?.display ?? "∅"
                applyAssignment(eq.text, frameIndex: frameIndex)
                let after = frames[frameIndex].locals[eq.name]?.display ?? "∅"
                effect = "\(eq.name): \(before) → \(after)"
            }
            frames[frameIndex].pc += 1
            if emit {
                let step = makeStep(activeIdx: frameIndex, instr: instr, effects: [effect], warning: nil, mode: mode)
                return .emitted(step)
            }
            return .jumped
        }

        frames[frameIndex].pc += 1
        if emit {
            let step = makeStep(activeIdx: frameIndex, instr: instr, effects: [], warning: nil, mode: mode)
            return .emitted(step)
        }
        return .jumped
    }

    private func dedupStep(_ instr: SimInstruction, frameIndex: Int, effects: [String], emit: Bool) -> Exec {
        if emit {
            let step = makeStep(activeIdx: frameIndex, instr: instr, effects: effects, warning: nil, mode: .over)
            return .emitted(step)
        }
        return .jumped
    }

    private func executeReturn(_ text: String, instr: SimInstruction, frameIndex: Int, emit: Bool, mode: SimStepMode) -> Exec {
        var f = frames[frameIndex]
        var expr = text.hasPrefix("return") ? String(text.dropFirst(6)).trimmingCharacters(in: .whitespaces) : ""
        if expr.hasSuffix(";") { expr = String(expr.dropLast()).trimmingCharacters(in: .whitespaces) }
        var rv: SimDebugValue? = nil
        if !expr.isEmpty {
            let call = parseCall(in: expr)
            if call.isCall, definitionIndex?.lookUp(name: call.name, preferredFileURL: f.function.fileURL) != nil {
                let argValues = call.arguments.map { eval($0, frameIndex: frameIndex) }
                if let loc = definitionIndex?.lookUp(name: call.name, preferredFileURL: f.function.fileURL),
                   let result = runSilentProjectCall(location: loc, argValues: argValues, call: call) {
                    rv = result
                }
            }
            if rv == nil { rv = eval(expr, frameIndex: frameIndex) }
        }
        f.pendingReturn = rv
        f.isDone = true
        f.pc += 1
        frames[frameIndex] = f
        let effects = rv.map { ["[return] \($0.display)"] } ?? ["[return] (void)"]
        if emit {
            let step = makeStep(activeIdx: frameIndex, instr: instr, effects: effects, warning: nil, mode: mode)
            return .emitted(step)
        }
        return .jumped
    }

    private func mutate(_ name: String, to value: SimDebugValue, frameIndex: Int) {
        var f = frames[frameIndex]
        let key = resolveLocalKey(name, frameIndex: frameIndex) ?? name
        if !f.localOrder.contains(key) { f.localOrder.append(key) }
        f.locals[key] = value
        frames[frameIndex] = f
    }

    private struct CompoundAssign {
        let name: String
        let op: String
        let rhs: String
    }

    private func compoundAssignment(_ text: String) -> CompoundAssign? {
        var s = text.trimmingCharacters(in: .whitespaces)
        if s.hasSuffix(";") { s = String(s.dropLast()).trimmingCharacters(in: .whitespaces) }
        let ops = ["+=", "-=", "*=", "/=", "%=", "&=", "|=", "^=", "<<=", ">>="]
        for op in ops where s.contains(op) {
            let parts = s.components(separatedBy: op)
            guard parts.count >= 2 else { continue }
            let lhs = parts[0].trimmingCharacters(in: .whitespaces)
            let rhs = parts.dropFirst().joined(separator: op).trimmingCharacters(in: .whitespaces)
            if isIdentifier(lhs) {
                return CompoundAssign(name: lhs, op: op, rhs: rhs)
            }
        }
        if s.contains(".append(") || s.contains(".push(") {
            let op = s.contains(".append(") ? ".append(" : ".push("
            let parts = s.components(separatedBy: op)
            if parts.count >= 2 {
                let lhs = parts[0].trimmingCharacters(in: .whitespaces)
                var rhs = parts.dropFirst().joined(separator: op).trimmingCharacters(in: .whitespaces)
                if rhs.hasSuffix(")") { rhs = String(rhs.dropLast()).trimmingCharacters(in: .whitespaces) }
                if isIdentifier(lhs) {
                    return CompoundAssign(name: lhs, op: op, rhs: rhs)
                }
            }
        }
        return nil
    }

    private func applyCompound(_ c: CompoundAssign, frameIndex: Int) {
        var f = frames[frameIndex]
        guard let base = f.locals[c.name] else { return }
        if c.op == ".append(" || c.op == ".push(" {
            let appended = eval(c.rhs, frameIndex: frameIndex)?.asString() ?? c.rhs
            var newV = base
            let combined = (base.stringValue ?? "") + appended
            newV.stringValue = combined
            if newV.kind == .buffer {
                newV.display = "[\(newV.capacity ?? 0)] \"\(combined)\""
            } else {
                newV.display = "\"\(combined)\""
            }
            f.locals[c.name] = newV
            frames[frameIndex] = f
            return
        }
        let rhs = eval(c.rhs, frameIndex: frameIndex)
        if c.op == "+=", base.kind == .string || base.kind == .buffer, let rv = rhs?.asString() {
            var newV = base
            let combined = (base.stringValue ?? "") + rv
            newV.stringValue = combined
            if newV.kind == .buffer {
                newV.display = "[\(newV.capacity ?? 0)] \"\(combined)\""
            } else {
                newV.display = "\"\(combined)\""
            }
            f.locals[c.name] = newV
            frames[frameIndex] = f
            return
        }
        guard let rhsV = rhs else { return }
        let a = base.asDouble()
        let b = rhsV.asDouble()
        guard let av = a, let bv = b else { return }
        let isInt = base.kind == .int && rhsV.kind == .int
        var result: Double = av
        switch c.op {
        case "+=": result = av + bv
        case "-=": result = av - bv
        case "*=": result = av * bv
        case "/=": result = bv != 0 ? av / bv : av
        case "%=": result = isInt ? Double((base.asInt() ?? 0) % (rhsV.asInt() ?? 1)) : av
        case "&=": result = Double((base.asInt() ?? 0) & (rhsV.asInt() ?? 0))
        case "|=": result = Double((base.asInt() ?? 0) | (rhsV.asInt() ?? 0))
        case "^=": result = Double((base.asInt() ?? 0) ^ (rhsV.asInt() ?? 0))
        case "<<=": result = Double((base.asInt() ?? 0) << (rhsV.asInt() ?? 0))
        case ">>=": result = Double((base.asInt() ?? 0) >> (rhsV.asInt() ?? 0))
        default: break
        }
        let newV: SimDebugValue = isInt ? .int(Int(result)) : .double(result)
        f.locals[c.name] = newV
        frames[frameIndex] = f
    }

    private struct PlainAssign {
        let name: String
        let text: String
    }

    private func plainAssignment(_ text: String, frameIndex: Int) -> PlainAssign? {
        guard let eq = topLevelAssignment(text) else { return nil }
        let lhs = eq.0.trimmingCharacters(in: .whitespaces)
        guard !lhs.isEmpty, !isDeclaration(lhs) else { return nil }
        let elementWrite = lhs.contains("[") && lhs.hasSuffix("]")
        if elementWrite {
            if lookupLocal(lhs.split(separator: "[").map(String.init).first ?? "", frameIndex: frameIndex) != nil {
                return PlainAssign(name: lhs, text: text)
            }
            return nil
        }
        guard isIdentifier(lhs) else { return nil }
        return PlainAssign(name: lhs, text: text)
    }

    private func topLevelAssignment(_ s: String) -> (String, String)? {
        let trimmed = s.trimmingCharacters(in: .whitespaces)
        guard let eq = trimmed.firstIndex(of: "=") else { return nil }
        let lhs = String(trimmed[..<eq])
        if lhs.contains("==") || lhs.contains(">=") || lhs.contains("<=") || lhs.contains("!=") || lhs.contains("=>") {
            var depth = 0
            var isComparison = false
            var i = trimmed.startIndex
            while i < eq {
                let c = trimmed[i]
                if c == "(" { depth += 1 }
                else if c == ")" { depth -= 1 }
                if depth == 0, c == "=" { isComparison = true }
                if depth == 0, c == ">" || c == "<" || c == "!" { isComparison = true }
                i = trimmed.index(after: i)
            }
            if isComparison && depth == 0 {
                if lhs.range(of: ">=") != nil || lhs.range(of: "<=") != nil || lhs.range(of: "!=") != nil {
                    return nil
                }
                if lhs.range(of: "==") != nil {
                    if let lastEq = lhs.range(of: "=", options: [.backwards]) {
                        let ident = String(lhs[..<lastEq.lowerBound]).trimmingCharacters(in: .whitespaces)
                        if isIdentifierIdent(ident) || ident.contains("[") {
                            return (ident, String(trimmed[lastEq.upperBound...]))
                        }
                    }
                    return nil
                }
            }
            if depth == 0, lhs.range(of: "=>") != nil {
                return nil
            }
        }
        var depth = 0
        var pi = trimmed.startIndex
        var assignIndex: String.Index?
        while pi < eq {
            let c = trimmed[pi]
            if c == "(" { depth += 1 }
            else if c == ")" { depth -= 1 }
            if depth == 0 { assignIndex = pi }
            pi = trimmed.index(after: pi)
        }
        guard let ai = assignIndex, ai < eq else { return nil }
        return (String(trimmed[..<eq]), String(trimmed[trimmed.index(after: eq)...]))
    }

    private func normalizeVarName(_ s: String) -> String {
        var t = s.trimmingCharacters(in: .whitespaces)
        while t.hasPrefix("*") || t.hasPrefix("&") { t = String(t.dropFirst()) }
        return t.trimmingCharacters(in: .whitespaces)
    }

    private func resolveLocalKey(_ name: String, frameIndex: Int) -> String? {
        let base = normalizeVarName(name)
        if frames[frameIndex].locals[base] != nil { return base }
        if frames[frameIndex].locals["*" + base] != nil { return "*" + base }
        if frames[frameIndex].locals["&" + base] != nil { return "&" + base }
        return nil
    }

    private func lookupLocal(_ name: String, frameIndex: Int) -> SimDebugValue? {
        guard let key = resolveLocalKey(name, frameIndex: frameIndex) else { return nil }
        return frames[frameIndex].locals[key]
    }

    private func isIdentifierIdent(_ s: String) -> Bool {
        let t = s.trimmingCharacters(in: .whitespaces)
        guard let first = t.first else { return false }
        if !(first.isLetter || first == "_") { return false }
        for c in t where !(c.isLetter || c.isNumber || c == "_") { return false }
        return true
    }

    private func applyAssignment(_ text: String, frameIndex: Int) {
        let trimmed = text.trimmingCharacters(in: .whitespaces)
        if trimmed.hasSuffix(";") {
            applyAssignment(String(trimmed.dropLast()), frameIndex: frameIndex)
            return
        }
        let rhsExpr: String
        let lhs: String
        if trimmed.contains("+=") || trimmed.contains("-=") || trimmed.contains("*=") || trimmed.contains("/=") {
            for op in ["+=", "-=", "*=", "/="] {
                if trimmed.contains(op) {
                    let parts = trimmed.components(separatedBy: op)
                    lhs = parts[0].trimmingCharacters(in: .whitespaces)
                    rhsExpr = parts.dropFirst().joined(separator: op).trimmingCharacters(in: .whitespaces)
                    if let compound = compoundAssignment(trimmed + ";") {
                        applyCompound(compound, frameIndex: frameIndex)
                    }
                    return
                }
            }
            return
        }
        guard let eq = topLevelAssignment(trimmed) else { return }
        lhs = eq.0.trimmingCharacters(in: .whitespaces)
        rhsExpr = eq.1.trimmingCharacters(in: .whitespaces)

        if lhs.contains("[") && lhs.hasSuffix("]") {
            let name = String(lhs.prefix(while: { $0 != "[" })).trimmingCharacters(in: .whitespaces)
            var f = frames[frameIndex]
            guard var tv = lookupLocal(name, frameIndex: frameIndex) else { return }
            let realKey = resolveLocalKey(name, frameIndex: frameIndex) ?? name
            let idxText = String(lhs.drop(while: { $0 != "[" }).dropFirst().dropLast()).trimmingCharacters(in: .whitespaces)
            let rhsV = eval(rhsExpr, frameIndex: frameIndex)
            if rhsV == nil || rhsV?.kind == .nullable { return }
            let char: String
            if let c = rhsV?.asString()?.first { char = String(c) }
            else if let i = rhsV?.asInt(), (0...127).contains(i), let u = UnicodeScalar(i), u != "?" { char = String(u) }
            else if let b = rhsV?.boolValue { char = b ? "1" : "0" }
            else { char = rhsV!.display }
            var s = tv.stringValue ?? ""
            if let i = (idxText.isEmpty ? nil : eval(idxText, frameIndex: frameIndex)?.asInt()), i >= 0, i < s.count {
                let start = s.index(s.startIndex, offsetBy: i)
                s.replaceSubrange(start...start, with: char)
            } else {
                s = s + char
            }
            tv.stringValue = s
            if tv.kind == .buffer {
                tv.display = "[\(tv.capacity ?? 0)] \"\(s)\""
            } else {
                tv.display = "\"\(s)\""
            }
            f.locals[realKey] = tv
            frames[frameIndex] = f
            return
        }

        guard isIdentifier(lhs) else { return }
        let value = evaluateExpressionIncludingCalls(rhsExpr, frameIndex: frameIndex) ?? .nullable()
        mutate(lhs, to: value, frameIndex: frameIndex)
    }

    private func evaluateExpressionIncludingCalls(_ rhs: String, frameIndex: Int) -> SimDebugValue? {
        if let v = eval(rhs, frameIndex: frameIndex) { return v }
        _ = frameIndex
        return nil
    }

    // MARK: - Declaration

    private func isDeclaration(_ text: String) -> Bool {
        var s = text.trimmingCharacters(in: .whitespaces)
        if s.hasSuffix(";") { s = String(s.dropLast()).trimmingCharacters(in: .whitespaces) }
        let lower = s.lowercased()
        return declarationPrefixes.contains { lower.hasPrefix($0) }
    }

    private func applyDeclaration(_ text: String, instr: SimInstruction, frameIndex: Int, emit: Bool, mode: SimStepMode) -> Exec {
        var f = frames[frameIndex]
        var s = text.trimmingCharacters(in: .whitespaces)
        if s.hasSuffix(";") { s = String(s.dropLast()).trimmingCharacters(in: .whitespaces) }

        let rhs: String?
        var decl = s
        if let eq = topLevelAssignment(s) {
            rhs = eq.1.trimmingCharacters(in: .whitespaces)
            decl = eq.0.trimmingCharacters(in: .whitespaces)
        } else {
            rhs = nil
        }

        let name = extractDeclName(decl)
        guard !name.isEmpty else {
            f.pc += 1
            frames[frameIndex] = f
            if emit {
                let step = makeStep(activeIdx: frameIndex, instr: instr, effects: ["(unparsed declaration)"], warning: nil, mode: .over)
                return .emitted(step)
            }
            return .jumped
        }

        var effects: [String] = []
        var value: SimDebugValue?
        let isBufferDecl = decl.contains("*") || decl.contains("[")

        if let r = rhs {
            if isBufferDecl {
                value = evaluateBufferRHS(r)
            } else {
                let call = parseCall(in: r)
                if call.isCall {
                    let resolvable = call.receiver != nil
                        || (definitionIndex?.lookUp(name: call.name, preferredFileURL: f.function.fileURL) != nil)
                        || builtinNames.contains(call.name) || builtinNames.contains(call.name.lowercased())
                    if resolvable {
                        mutate(name, to: .nullable(), frameIndex: frameIndex)
                        let withLhs = SimCall(name: call.name, receiver: call.receiver,
                                              arguments: call.arguments, lhs: name, isCall: true)
                        let callEffects = applyCall(text: r, call: withLhs, frameIndex: frameIndex, mode: mode)
                        f = frames[frameIndex]
                        f.pc += 1
                        frames[frameIndex] = f
                        if emit {
                            let step = makeStep(activeIdx: frameIndex, instr: instr, effects: callEffects, warning: nil, mode: .over)
                            return .emitted(step)
                        }
                        return .jumped
                    }
                }
                value = eval(r, frameIndex: frameIndex)
            }
            if value == nil {
                if r == "\"\"" { value = .string("") }
                else { value = .string(r) }
            }
        } else {
            if isBufferDecl {
                value = .buffer("", capacity: arrayCapacity(of: decl))
            } else {
                value = SimSeeding.seedValue(forTypeText: decl, name: name)
            }
        }

        if let v = value {
            mutate(name, to: v, frameIndex: frameIndex)
            effects = ["\(name) = \(v.display)"]
        }
        f = frames[frameIndex]
        f.pc += 1
        frames[frameIndex] = f
        if emit {
            let step = makeStep(activeIdx: frameIndex, instr: instr, effects: effects, warning: nil, mode: .over)
            return .emitted(step)
        }
        return .jumped
    }

    private func evaluateBufferRHS(_ rhs: String) -> SimDebugValue? {
        let call = parseCall(in: rhs)
        if call.isCall {
            switch call.name {
            case "malloc", "calloc", "realloc", "new", "Array", "make", "valloc":
                if let sizeText = call.arguments.first {
                    if let n = parseCount(sizeText) {
                        return .buffer("", capacity: n)
                    }
                }
                return .buffer("", capacity: 128)
            default:
                break
            }
        }
        return nil
    }

    private func parseCount(_ text: String) -> Int? {
        let t = text.trimmingCharacters(in: .whitespaces)
        if let n = Int(t) { return n }
        if let v = eval(t, frameIndex: frames.count - 1)?.asInt(), frames.count > 0 { return v }
        return nil
    }

    private func extractDeclName(_ decl: String) -> String {
        let tokens = CTokenizer(source: decl).tokenize()
        let typeWords: Set<String> = ["int", "char", "long", "short", "float", "double", "void",
                                      "bool", "boolean", "size_t", "ssize_t", "unsigned", "signed",
                                      "const", "static", "auto", "var", "let", "struct", "class",
                                      "string", "boolean", "byte", "uint", "int8", "int16", "int32",
                                      "int64", "uint8", "uint16", "uint32", "uint64", "NSInteger",
                                      "NSUInteger", "CGFloat", "number", "any", "Array", "List",
                                      "Vector", "Dictionary", "Map", "Set", "slice", "buffer", "data",
                                      "Data", "String"]
        var candidate: String?
        var sawType = false
        var i = 0
        while i < tokens.count {
            let t = tokens[i]
            if t.kind == .keyword {
                if t.text == "return" || t.text == "if" || t.text == "for" || t.text == "while" { return "" }
                candidate = nil
                sawType = true
                i += 1
                continue
            }
            if t.kind == .identifier {
                if typeWords.contains(t.text) || t.text.hasPrefix("std::") {
                    candidate = nil
                    sawType = true
                    i += 1
                    continue
                }
                let isCapsType = t.text.first?.isUppercase == true
                if isCapsType && sawType {
                    candidate = nil
                    sawType = true
                    i += 1
                    continue
                }
                if isCapsType && candidate == nil && i > 0 {
                }
                if sawType == false && candidate == nil && t.text != "let" && t.text != "var" {
                    sawType = true
                }
                candidate = t.text
                i += 1
                continue
            }
            if t.kind == .operator || t.kind == .punct {
                if t.text == "*" || t.text == "&" || t.text == "::" || t.text == "[" || t.text == "]" {
                    i += 1
                    continue
                }
                if t.text == "(" || t.text == ")" || t.text == "=" || t.text == "," {
                    break
                }
                if t.text == "." {
                    if let nxt = tokens[safe: i + 1], nxt.kind == .identifier {
                        i += 1
                        continue
                    }
                }
                i += 1
                continue
            }
            i += 1
        }
        return candidate ?? ""
    }

    private func arrayCapacity(of decl: String) -> Int {
        if let open = decl.firstIndex(of: "["), let close = decl.firstIndex(of: "]") {
            let inside = String(decl[decl.index(after: open)..<close]).trimmingCharacters(in: .whitespaces)
            if let n = Int(inside) { return n }
        }
        return 64
    }

    // MARK: - Increment

    private struct IncStatement {
        let name: String
        let delta: Int
    }

    private func incrementStatement(_ text: String) -> IncStatement? {
        var s = text.trimmingCharacters(in: .whitespaces)
        if s.hasSuffix(";") { s = String(s.dropLast()).trimmingCharacters(in: .whitespaces) }
        if s.hasSuffix("++") || s.hasSuffix("--") {
            let delta = s.hasSuffix("++") ? 1 : -1
            let name = String(s.dropLast(2)).trimmingCharacters(in: .whitespaces)
            if isIdentifier(name) { return IncStatement(name: name, delta: delta) }
        }
        if s.hasPrefix("++") || s.hasPrefix("--") {
            let delta = s.hasPrefix("++") ? 1 : -1
            let name = String(s.dropFirst(2)).trimmingCharacters(in: .whitespaces)
            if isIdentifier(name) { return IncStatement(name: name, delta: delta) }
        }
        return nil
    }

    private func isIdentifier(_ s: String) -> Bool {
        guard let first = s.first else { return false }
        if !(first.isLetter || first == "_") { return false }
        for c in s where !(c.isLetter || c.isNumber || c == "_") { return false }
        return true
    }

    // MARK: - Calls

    private func parseCall(in text: String) -> SimCall {
        var s = text.trimmingCharacters(in: .whitespaces)
        var lhs: String?
        if let eq = topLevelAssignment(s) {
            let left = eq.0.trimmingCharacters(in: .whitespaces)
            if isIdentifierIdent(left) || left.contains("[") {
                lhs = left
                s = eq.1.trimmingCharacters(in: .whitespaces)
            }
        }
        var s2 = s
        if s2.hasSuffix(";") { s2 = String(s2.dropLast()).trimmingCharacters(in: .whitespaces) }
        if s2.hasPrefix("return ") {
            s2 = String(s2.dropFirst(7)).trimmingCharacters(in: .whitespaces)
            if lhs == nil { lhs = "return" }
        }
        guard let open = firstTopLevelParen(in: s2) else {
            return SimCall(name: "", receiver: nil, arguments: [], lhs: lhs, isCall: false)
        }
        let head = String(s2[..<open]).trimmingCharacters(in: .whitespaces)
        let headParts = head.split(separator: ".").map(String.init)
        let possibleName = headParts.last ?? ""
        guard isIdentifier(possibleName), !isControlKeyword(possibleName) else {
            return SimCall(name: "", receiver: nil, arguments: [], lhs: lhs, isCall: false)
        }
        let receiver: String?
        if headParts.count >= 2 {
            receiver = headParts[headParts.count - 2]
        } else {
            receiver = nil
        }
        let args = callArguments(in: s2, open: open)
        return SimCall(name: possibleName, receiver: receiver, arguments: args, lhs: lhs, isCall: true)
    }

    private func isControlKeyword(_ name: String) -> Bool {
        ["if", "else", "while", "for", "switch", "case", "do", "try", "catch", "with", "match", "return", "new"].contains(name)
    }

    private func firstTopLevelParen(in s: String) -> String.Index? {
        var depth = 0
        var inString = false
        var quote: Character = " "
        let chars = Array(s)
        for i in 0..<chars.count {
            let c = chars[i]
            if inString {
                if c == "\\" { continue }
                if c == quote { inString = false }
                continue
            }
            if c == "\"" || c == "'" {
                inString = true
                quote = c
                continue
            }
            if c == "(" {
                if depth == 0 {
                    return s.index(s.startIndex, offsetBy: i)
                }
                depth += 1
            } else if c == ")" {
                if depth == 0 {
                    return s.index(s.startIndex, offsetBy: i)
                }
                depth -= 1
            }
        }
        return nil
    }

    private func callArguments(in s: String, open: String.Index) -> [String] {
        let after = s[s.index(after: open)...]
        let chars = Array(after)
        var depth = 0
        for i in 0..<chars.count {
            if chars[i] == "(" { depth += 1 }
            else if chars[i] == ")" {
                if depth == 0 {
                    let inner = String(after[..<after.index(after.startIndex, offsetBy: i)])
                    return splitTopLevel(inner)
                }
                depth -= 1
            }
        }
        return []
    }

    private func splitTopLevel(_ s: String) -> [String] {
        var out: [String] = []
        var current = ""
        var depth = 0
        var inString = false
        var quote: Character = " "
        for c in s {
            if inString {
                current.append(c)
                if c == "\\" { continue }
                if c == quote { inString = false }
                continue
            }
            if c == "\"" || c == "'" || c == "`" {
                inString = true
                quote = c
                current.append(c)
                continue
            }
            if c == "(" || c == "[" || c == "{" {
                depth += 1
                current.append(c)
                continue
            }
            if c == ")" || c == "]" || c == "}" {
                if depth > 0 { depth -= 1 }
                current.append(c)
                continue
            }
            if c == "," && depth == 0 {
                let t = current.trimmingCharacters(in: .whitespaces)
                if !t.isEmpty { out.append(t) }
                current = ""
                continue
            }
            current.append(c)
        }
        let t = current.trimmingCharacters(in: .whitespaces)
        if !t.isEmpty { out.append(t) }
        return out
    }

    private func applyCall(text: String, call: SimCall, frameIndex: Int, mode: SimStepMode) -> [String] {
        let f = frames[frameIndex]
        let lhs = call.lhs

        if let receiver = call.receiver, isIdentifier(receiver) {
            if f.locals[receiver] != nil {
                if let effects = applyReceiverMutation(receiver, mutator: call.name, args: call.arguments, frameIndex: frameIndex) {
                    return effects
                }
            }
            let unknownEffects = ["≈ \(receiver).\(call.name)(\(call.arguments.joined(separator: ", "))) — not emulated"]
            return bindCallResult(call, fallback: nil, unknownEffects: unknownEffects, frameIndex: frameIndex)
        }

        if let builtin = evaluateBuiltinCall(call, frameIndex: frameIndex) {
            if let rv = builtin {
                return bindCallResult(call, fallback: rv, unknownEffects: [], frameIndex: frameIndex)
            }
            if doesNotReturn(call.name) {
                return ["\(call.name)(\(call.arguments.joined(separator: ", ")))"]
            }
            return bindCallResult(call, fallback: .nullable(), unknownEffects: [], frameIndex: frameIndex)
        }

        if let definitionIndex = definitionIndex,
           let loc = definitionIndex.lookUp(name: call.name, preferredFileURL: f.function.fileURL) {
            let argValues = call.arguments.map { eval($0, frameIndex: frameIndex) }
            if mode == .into, callDepth < maxCallDepth {
                if pushCallee(location: loc, argValues: argValues, call: call, callerIndex: frameIndex) {
                    callDepth += 1
                    bindings.append((callerIndex: frameIndex, lhs: lhs, callLine: f.function.instructions.count > 0 && frames[frameIndex].pc < frames[frameIndex].function.instructions.count ? frames[frameIndex].function.instructions[frames[frameIndex].pc].line : 1, calleeName: call.name))
                    return ["[enter] \(call.name)(\(call.arguments.joined(separator: ", ")))"]
                }
                return ["≈ call \(call.name) — could not resolve definition"]
            }
            if let rv = runSilentProjectCall(location: loc, argValues: argValues, call: call) {
                return bindCallResult(call, fallback: rv, unknownEffects: [], frameIndex: frameIndex)
            }
            return bindCallResult(call, fallback: nil, unknownEffects: ["≈ call \(call.name) — returned nothing"], frameIndex: frameIndex)
        }

        let approximated = ["≈ call \(call.name)(\(call.arguments.joined(separator: ", "))) — not emulated"]
        return bindCallResult(call, fallback: nil, unknownEffects: approximated, frameIndex: frameIndex)
    }

    private func bindCallResult(_ call: SimCall, fallback: SimDebugValue?, unknownEffects: [String], frameIndex: Int) -> [String] {
        guard let lhs = call.lhs else { return unknownEffects }
        if lhs == "return" {
            return unknownEffects
        }
        let finalValue: SimDebugValue
        if let fallback = fallback {
            finalValue = fallback
        } else {
            let firstArg = call.arguments.first.flatMap { eval($0, frameIndex: frameIndex) }
            finalValue = firstArg ?? .nullable()
        }
        if fallsThroughToFallback(unknownEffects) && unknownEffects.isEmpty == false && fallback == nil {
        }
        mutate(lhs, to: finalValue, frameIndex: frameIndex)
        if unknownEffects.isEmpty {
            return ["\(lhs) = \(finalValue.display)"]
        }
        return unknownEffects + ["\(lhs) = \(finalValue.display)"]
    }

    private func fallsThroughToFallback(_ e: [String]) -> Bool { e.isEmpty }

    private func doesNotReturn(_ name: String) -> Bool {
        ["print", "printf", "println", "log", "console.log", "puts", "exit", "raise", "throw"].contains { name.lowercased().contains($0) }
    }

    private func applyReceiverMutation(_ receiver: String, mutator: String, args: [String], frameIndex: Int) -> [String]? {
        var f = frames[frameIndex]
        guard var v = f.locals[receiver] else { return nil }
        let before = v.display
        let name = mutator.lowercased()
        var s = v.stringValue ?? ""
        switch name {
        case "append", "push", "add", "offer", "enqueue", "write", "writebytes", "insert", "concat":
            let chunk = args.first.map { eval($0, frameIndex: frameIndex)?.asString() ?? $0 } ?? ""
            s = s + chunk
        case "clear", "reset", "empty":
            s = ""
        case "reserve", "resize", "extend":
            if let cap = args.first.flatMap({ eval($0, frameIndex: frameIndex)?.asInt() }) {
                v.capacity = max(v.capacity ?? 0, cap)
            }
            return ["\(receiver): \(before) → \(v.display)"]
        case "reverse":
            s = String(s.reversed())
        case "upper", "uppercase", "uppercased":
            s = s.uppercased()
        case "lower", "lowercase", "lowercased":
            s = s.lowercased()
        case "trim", "trimmed":
            s = s.trimmingCharacters(in: .whitespaces)
        default:
            return nil
        }
        if v.kind == .buffer {
            v.stringValue = s
            v.display = "[\(v.capacity ?? 0)] \"\(s)\""
        } else {
            v.stringValue = s
            v.display = "\"\(s)\""
        }
        f.locals[receiver] = v
        frames[frameIndex] = f
        return ["\(receiver): \(before) → \(v.display)"]
    }

    private func pushCallee(location: DefinitionLocation, argValues: [SimDebugValue?], call: SimCall, callerIndex: Int) -> Bool {
        guard let source = resolveSource(for: location.fileURL) else { return false }
        let ext = location.fileURL.pathExtension.lowercased()
        let defs = diagramDefinitions(source: source, ext: ext)
        guard let def = defs.first(where: { $0.name == call.name }),
              let fn = SimFunctionBuilder.make(def: def, source: source, ext: ext, fileURL: location.fileURL) else { return false }
        var frame = freshFrame(function: fn)
        var argCursor = 0
        for i in 0..<fn.params.count {
            let param = fn.params[i]
            let isReceiver = param.name == "self" || param.name == "cls" || param.name == "this"
            if isReceiver {
                continue
            }
            if argCursor < argValues.count, let v = argValues[argCursor] {
                frame.locals[param.name] = v
            }
            argCursor += 1
        }
        frames.append(frame)
        return true
    }

    private func runSilentProjectCall(location: DefinitionLocation, argValues: [SimDebugValue?], call: SimCall) -> SimDebugValue? {
        guard let source = resolveSource(for: location.fileURL) else { return nil }
        let ext = location.fileURL.pathExtension.lowercased()
        let defs = diagramDefinitions(source: source, ext: ext)
        guard let def = defs.first(where: { $0.name == call.name }) else { return nil }
        let fn = SimFunctionBuilder.make(def: def, source: source, ext: ext, fileURL: location.fileURL)
        guard let function = fn else { return nil }
        let depthBefore = frames.count
        var frame = freshFrame(function: function)
        var argCursor = 0
        for i in 0..<function.params.count {
            let param = function.params[i]
            if param.name == "self" || param.name == "cls" || param.name == "this" { continue }
            if argCursor < argValues.count, let v = argValues[argCursor] {
                frame.locals[param.name] = v
            }
            argCursor += 1
        }
        frames.append(frame)
        var guardSteps = 0
        while frames.count > depthBefore, guardSteps < maxSilentSteps {
            let exec = executeNext(emit: false, mode: .over)
            switch exec {
            case .finished:
                break
            default:
                guardSteps += 1
            }
        }
        var rv: SimDebugValue?
        if frames.count == depthBefore {
            rv = lastPoppedReturn
        }
        while frames.count > depthBefore {
            frames.removeLast()
        }
        return rv
    }

    // MARK: - Builtins

    private func evaluateBuiltinCall(_ call: SimCall, frameIndex: Int) -> SimDebugValue?? {
        let args = call.arguments.map { eval($0, frameIndex: frameIndex) }
        let name = call.name.lowercased()
        guard builtinNames.contains(call.name) || builtinNames.contains(name) else { return nil }
        let v = args.first ?? nil
        switch name {
        case "len", "strlen", "count", "size":
            if let v = v {
                if v.kind == .string || v.kind == .buffer { return .int(v.stringValue?.count ?? v.capacity ?? 0) }
                if let iv = v.asInt() { return .int(iv) }
                if let cap = v.capacity { return .int(cap) }
            }
            return .int(0)
        case "malloc", "calloc", "realloc", "new", "Array", "make":
            let size = v?.asInt() ?? 128
            return .buffer("", capacity: size)
        case "range":
            let n = v?.asInt() ?? 0
            let items = (0..<max(0, n)).map { "\($0)" }
            return .array(items)
        case "str", "string", "description", "tostring", "strconv", "itoa":
            return .string(v?.asString() ?? v?.display ?? "nil")
        case "int", "parseint", "atoi":
            return .int(v?.asInt() ?? 0)
        case "float", "double":
            return .double(v?.asDouble() ?? 0)
        case "abs":
            if let iv = v?.asInt() { return .int(abs(iv)) }
            if let d = v?.asDouble() { return .double(abs(d)) }
            return .int(0)
        case "min":
            let a = call.arguments.count > 0 ? eval(call.arguments[0], frameIndex: frameIndex) : nil
            let b = call.arguments.count > 1 ? eval(call.arguments[1], frameIndex: frameIndex) : nil
            if let av = a?.asInt(), let bv = b?.asInt() { return .int(min(av, bv)) }
            if let av = a?.asDouble(), let bv = b?.asDouble() { return .double(min(av, bv)) }
            return .int(0)
        case "max":
            let a = call.arguments.count > 0 ? eval(call.arguments[0], frameIndex: frameIndex) : nil
            let b = call.arguments.count > 1 ? eval(call.arguments[1], frameIndex: frameIndex) : nil
            if let av = a?.asInt(), let bv = b?.asInt() { return .int(max(av, bv)) }
            if let av = a?.asDouble(), let bv = b?.asDouble() { return .double(max(av, bv)) }
            return .int(0)
        default:
            return nil
        }
    }

    private func evaluateBuiltinText(_ text: String, frameIndex: Int) -> SimDebugValue? {
        let call = parseCall(in: text)
        if call.isCall {
            if let r = evaluateBuiltinCall(call, frameIndex: frameIndex) {
                if let rv = r { return rv }
                return .nullable()
            }
        }
        return nil
    }
}

// MARK: - Expression evaluator

extension SimDebugEngine {

    private func eval(_ text: String, frameIndex: Int) -> SimDebugValue? {
        var s = text.trimmingCharacters(in: .whitespaces)
        if s.hasSuffix(";") { s = String(s.dropLast()).trimmingCharacters(in: .whitespaces) }
        if s.isEmpty { return nil }
        // strip balanced outer parens
        while let first = s.first, first == "(", let lastC = s.last, lastC == ")" {
            if let inner = balancedInner(s) {
                s = inner
                continue
            }
            break
        }
        let tokens = CTokenizer(source: s).tokenize()

        if let (v, _) = parseExpression(tokens, from: 0, frameIndex: frameIndex) {
            return v
        }
        return nil
    }

    private func balancedInner(_ s: String) -> String? {
        var depth = 0
        let chars = Array(s)
        for i in 0..<chars.count {
            if chars[i] == "(" { depth += 1 }
            else if chars[i] == ")" {
                depth -= 1
                if depth == 0 {
                    if i == chars.count - 1 {
                        return String(s[s.index(after: s.startIndex)..<s.index(before: s.endIndex)])
                    }
                    return nil
                }
            }
        }
        return nil
    }

    private enum TokIndex {
        static func tokenText(_ t: CAstToken) -> String { t.text }
    }

    private func parseExpression(_ tokens: [CAstToken], from start: Int, frameIndex: Int) -> (SimDebugValue, Int)? {
        guard start < tokens.count else { return nil }
        if tokens[start].text == "true" { return (.bool(true), start + 1) }
        if tokens[start].text == "false" { return (.bool(false), start + 1) }
        if tokens[start].text == "nil" || tokens[start].text == "null" || tokens[start].text == "None" || tokens[start].text == "NULL" {
            return (.nullable(), start + 1)
        }
        return parseUnary(tokens, from: start, frameIndex: frameIndex)
    }

    private func parseUnary(_ tokens: [CAstToken], from start: Int, frameIndex: Int) -> (SimDebugValue, Int)? {
        if start < tokens.count, tokens[start].text == "-" {
            if let (v, next) = parseUnary(tokens, from: start + 1, frameIndex: frameIndex) {
                if let iv = v.asInt() { return (.int(-iv), next) }
                if let d = v.asDouble() { return (.double(-d), next) }
                return (v, next)
            }
        }
        if start < tokens.count, tokens[start].text == "!" {
            if let (v, next) = parseUnary(tokens, from: start + 1, frameIndex: frameIndex) {
                return (.bool(!v.truthy), next)
            }
        }
        if start < tokens.count, tokens[start].text == "~" {
            if let (v, next) = parseUnary(tokens, from: start + 1, frameIndex: frameIndex) {
                return (.int(~(v.asInt() ?? 0)), next)
            }
        }
        return parseLogical(tokens, from: start, frameIndex: frameIndex)
    }

    private func parseTerm(_ tokens: [CAstToken], from start: Int, frameIndex: Int) -> (SimDebugValue, Int)? {
        guard let pair = parseFactor(tokens, from: start, frameIndex: frameIndex) else { return nil }
        var lhs = pair.0
        let next = pair.1
        var i = next
        while i < tokens.count {
            let op = tokens[i].text
            if op == "*" || op == "/" || op == "%" {
                guard let (rhs, j) = parseFactor(tokens, from: i + 1, frameIndex: frameIndex) else { break }
                lhs = combine(op: op, lhs: lhs, rhs: rhs)
                i = j
                continue
            }
            break
        }
        return (lhs, i)
    }

    private func parseSum(_ tokens: [CAstToken], from start: Int, frameIndex: Int) -> (SimDebugValue, Int)? {
        guard let pair = parseTerm(tokens, from: start, frameIndex: frameIndex) else { return nil }
        var lhs = pair.0
        let next = pair.1
        var i = next
        while i < tokens.count {
            let op = tokens[i].text
            if op == "+" || op == "-" {
                guard let (rhs, j) = parseTerm(tokens, from: i + 1, frameIndex: frameIndex) else { break }
                lhs = combine(op: op, lhs: lhs, rhs: rhs)
                i = j
                continue
            }
            break
        }
        return (lhs, i)
    }

    private func parseComparison(_ tokens: [CAstToken], from start: Int, frameIndex: Int) -> (SimDebugValue, Int)? {
        guard let pair = parseSum(tokens, from: start, frameIndex: frameIndex) else { return nil }
        var lhs = pair.0
        let next = pair.1
        var i = next
        while i < tokens.count {
            let op = tokens[i].text
            if op == "==" || op == "!=" || op == "<" || op == ">" || op == "<=" || op == ">=" {
                guard let (rhs, j) = parseSum(tokens, from: i + 1, frameIndex: frameIndex) else { break }
                lhs = combine(op: op, lhs: lhs, rhs: rhs)
                i = j
                continue
            }
            break
        }
        return (lhs, i)
    }

    private func parseLogical(_ tokens: [CAstToken], from start: Int, frameIndex: Int) -> (SimDebugValue, Int)? {
        guard let pair = parseComparison(tokens, from: start, frameIndex: frameIndex) else { return nil }
        var lhs = pair.0
        let next = pair.1
        var i = next
        while i < tokens.count {
            let op = tokens[i].text
            if op == "&&" || op == "||" {
                guard let (rhs, j) = parseComparison(tokens, from: i + 1, frameIndex: frameIndex) else { break }
                let left = lhs.truthy
                let right = rhs.truthy
                lhs = .bool(op == "&&" ? (left && right) : (left || right))
                i = j
                continue
            }
            break
        }
        return (lhs, i)
    }

    private func parseFactor(_ tokens: [CAstToken], from start: Int, frameIndex: Int) -> (SimDebugValue, Int)? {
        guard start < tokens.count else { return nil }
        let t = tokens[start]

        if t.kind == .number {
            let t1 = t.text.replacingOccurrences(of: "_", with: "")
            if let iv = parseNumber(t1) { return (iv, start + 1) }
        }
        if t.kind == .string {
            let raw = unwrapStringLiteral(t.text)
            return (.string(raw), start + 1)
        }
        if t.kind == .character {
            return (.string(unwrapStringLiteral(t.text)), start + 1)
        }
        if t.text == "true" { return (.bool(true), start + 1) }
        if t.text == "false" { return (.bool(false), start + 1) }
        if t.text == "nil" || t.text == "null" || t.text == "None" || t.text == "NULL" || t.text == "nullptr" {
            return (.nullable(), start + 1)
        }
        if t.kind == .identifier {
            if t.text == "self" || t.text == "this" || t.text == "super" {
                return (.object(t.text), start + 1)
            }
            if start + 1 < tokens.count, tokens[start + 1].text == "(" {
                return parseCallExpression(tokens, name: t.text, start: start, frameIndex: frameIndex)
            }
            if start + 1 < tokens.count, tokens[start + 1].text == "[" {
                let subscriptIdx = start + 1
                if let (idxV, after) = parseExpression(tokens, from: subscriptIdx + 1, frameIndex: frameIndex),
                   after < tokens.count && tokens[after].text == "]" {
                    guard let base = lookupLocal(t.text, frameIndex: frameIndex) else { return (nil ?? .nullable(), after + 1) }
                    let i = idxV.asInt() ?? 0
                    let elem: SimDebugValue
                    if let str = base.stringValue, (base.kind == .string || base.kind == .buffer) {
                        if i >= 0 && i < str.count {
                            let ch = String(str[str.index(str.startIndex, offsetBy: i)])
                            elem = .string(ch)
                        } else {
                            elem = .nullable()
                        }
                    } else if let items = base.stringValue, base.kind == .array {
                        let parts = items.split(separator: ",").map(String.init)
                        if i >= 0 && i < parts.count { elem = .int(Int(parts[i]) ?? -1) }
                        else { elem = .nullable() }
                    } else {
                        elem = .object("\(t.text)[\(i)]")
                    }
                    return (elem, after + 1)
                }
                return nil
            }
            if start + 1 < tokens.count, tokens[start + 1].text == "." {
                let member = tokens[start + 2]
                var next = start + 3
                var value = lookupLocal(t.text, frameIndex: frameIndex) ?? SimDebugValue.object(t.text)
                if member.kind == .identifier {
                    let m = member.text.lowercased()
                    if ["count", "length", "size", "len", "count"].contains(m) {
                        if value.kind == .string || value.kind == .buffer {
                            value = .int(value.stringValue?.count ?? value.capacity ?? 0)
                        } else if let cap = value.capacity {
                            value = .int(cap)
                        } else {
                            value = .int(0)
                        }
                    } else if m == "empty" || m == "isempty" || m == "isempty" {
                        value = .bool((value.stringValue ?? "").isEmpty)
                    }
                }
                while next < tokens.count, tokens[next].text == "." {
                    next += 1
                }
                return (value, next)
            }
            if let localV = lookupLocal(t.text, frameIndex: frameIndex) {
                return (localV, start + 1)
            }
            return nil
        }
        if t.text == "(" {
            if let (v, next) = parseExpression(tokens, from: start + 1, frameIndex: frameIndex),
               next < tokens.count, tokens[next].text == ")" {
                return (v, next + 1)
            }
        }
        return nil
    }

    private func parseCallExpression(_ tokens: [CAstToken], name: String, start: Int, frameIndex: Int) -> (SimDebugValue, Int)? {
        guard start + 1 < tokens.count, tokens[start + 1].text == "(" else { return nil }
        var i = start + 2
        var argTokens: [[CAstToken]] = []
        var current: [CAstToken] = []
        var depth = 1
        while i < tokens.count {
            let t = tokens[i]
            if t.text == "(" { depth += 1; current.append(t) }
            else if t.text == ")" {
                depth -= 1
                if depth == 0 {
                    if !current.isEmpty { argTokens.append(current) }
                    break
                }
                current.append(t)
            } else if t.text == "," && depth == 1 {
                if !current.isEmpty { argTokens.append(current) }
                current = []
            } else {
                current.append(t)
            }
            i += 1
        }
        if i >= tokens.count { return nil }
        let next = i + 1
        let argTexts = argTokens.map { tokensText($0) }
        let call = SimCall(name: name, receiver: nil, arguments: argTexts, lhs: nil, isCall: true)
        if let builtin = evaluateBuiltinCall(call, frameIndex: frameIndex) {
            if let rv = builtin { return (rv, next) }
            return (.nullable(), next)
        }
        if name.lowercased() == "sizeof" {
            return (.int(8), next)
        }
        let argValues = call.arguments.map { eval($0, frameIndex: frameIndex) }
        if let definitionIndex = definitionIndex,
           let loc = definitionIndex.lookUp(name: name, preferredFileURL: frames[frameIndex].function.fileURL),
           let rv = runSilentProjectCall(location: loc, argValues: argValues, call: call) {
            return (rv, next)
        }
        return (.object("call \(name)"), next)
    }

    private func tokensText(_ tokens: [CAstToken]) -> String {
        tokens.map { $0.text }.joined(separator: " ")
    }

    private func parseNumber(_ t: String) -> SimDebugValue? {
        var s = t
        if s.hasPrefix("0x") || s.hasPrefix("0X") {
            let hex = String(s.dropFirst(2))
            if let v = Int(hex, radix: 16) { return .int(v) }
        }
        if s.hasPrefix("0b") || s.hasPrefix("0B") {
            let bin = String(s.dropFirst(2))
            if let v = Int(bin, radix: 2) { return .int(v) }
        }
        if s.hasSuffix("L") || s.hasSuffix("l") { s = String(s.dropLast()) }
        if s.hasSuffix("U") || s.hasSuffix("u") { s = String(s.dropLast()) }
        if s.hasSuffix("f") || s.hasSuffix("F") { s = String(s.dropLast()) }
        if s.contains(".") || s.lowercased().contains("e") {
            if let d = Double(s) { return .double(d) }
        }
        if let iv = Int(s) { return .int(iv) }
        if let dv = Double(s) { return .double(dv) }
        return nil
    }

    private func unwrapStringLiteral(_ raw: String) -> String {
        let t = raw.trimmingCharacters(in: .whitespaces)
        if t.hasPrefix("\"") && t.hasSuffix("\"") && t.count >= 2 {
            return String(t.dropFirst().dropLast())
        }
        if t.hasPrefix("'") && t.hasSuffix("'") && t.count >= 2 {
            return String(t.dropFirst().dropLast())
        }
        if t.hasPrefix("\"\"\"") && t.hasSuffix("\"\"\"") { return String(t.dropFirst(3).dropLast(3)) }
        return t
    }

    private func combine(op: String, lhs: SimDebugValue, rhs: SimDebugValue) -> SimDebugValue {
        let isStringOp = op == "+" && (lhs.kind == .string || rhs.kind == .string || lhs.kind == .buffer || rhs.kind == .buffer)
        if isStringOp {
            let combined = (lhs.asString() ?? "") + (rhs.asString() ?? "")
            if lhs.kind == .buffer || rhs.kind == .buffer {
                let cap = lhs.capacity ?? rhs.capacity ?? 0
                return .buffer(combined, capacity: cap)
            }
            return .string(combined)
        }
        if op == "&&" || op == "||" {
            let l = lhs.truthy
            let r = rhs.truthy
            return .bool(op == "&&" ? (l && r) : (l || r))
        }
        if op == "==" || op == "!=" {
            let eqValue: Bool
            if let a = lhs.asInt(), let b = rhs.asInt() { eqValue = a == b }
            else if lhs.kind == .string && rhs.kind == .string { eqValue = lhs.stringValue == rhs.stringValue }
            else { eqValue = lhs.display == rhs.display }
            return .bool(op == "==" ? eqValue : !eqValue)
        }
        if op == "<" || op == ">" || op == "<=" || op == ">=" {
            let cmp: Int
            if let a = lhs.asInt(), let b = rhs.asInt() { cmp = a < b ? -1 : (a > b ? 1 : 0) }
            else if let a = lhs.asDouble(), let b = rhs.asDouble() { cmp = a < b ? -1 : (a > b ? 1 : 0) }
            else if let a = lhs.asString(), let b = rhs.asString() { cmp = a < b ? -1 : (a > b ? 1 : 0) }
            else { cmp = 0 }
            switch op {
            case "<": return .bool(cmp < 0)
            case ">": return .bool(cmp > 0)
            case "<=": return .bool(cmp <= 0)
            default: return .bool(cmp >= 0)
            }
        }
        if op == "&" || op == "|" || op == "^" || op == "<<" || op == ">>" {
            let a = lhs.asInt() ?? 0
            let b = rhs.asInt() ?? 0
            switch op {
            case "&": return .int(a & b)
            case "|": return .int(a | b)
            case "^": return .int(a ^ b)
            case "<<":
                if b >= 0, b < 63 { return .int(a << b) }
                return .int(0)
            default:
                if b >= 0, b < 63 { return .int(a >> b) }
                return .int(0)
            }
        }
        let bothInt = lhs.kind == .int && rhs.kind == .int
        if let a = lhs.asDouble(), let b = rhs.asDouble() {
            var result: Double = 0
            switch op {
            case "+": result = a + b
            case "-": result = a - b
            case "*": result = a * b
            case "/": result = b != 0 ? a / b : 0
            case "%":
                if bothInt {
                    let ai = lhs.asInt() ?? 0
                    let bi = rhs.asInt() ?? 0
                    result = bi != 0 ? Double(ai % bi) : 0
                } else {
                    result = b != 0 ? a.truncatingRemainder(dividingBy: b) : 0
                }
            default: break
            }
            if bothInt, let i = intSafely(result) { return .int(i) }
            return .double(result)
        }
        return .object("?\(op)?")
    }

    private func intSafely(_ d: Double) -> Int? {
        guard d.isFinite, d.rounded() == d else { return nil }
        if d >= Double(Int.max) || d <= Double(Int.min) { return nil }
        return Int(d)
    }
}

// MARK: - Function building

private struct SimFunctionBuilder {

    static func make(def: CCFunctionParser.FunctionDef, source: String, ext: String, fileURL: URL) -> SimFunction? {
        let ns = source as NSString
        guard def.bodyRange.location != NSNotFound, def.bodyRange.length > 0,
              def.bodyRange.location + def.bodyRange.length <= ns.length else { return nil }
        let signatureText = def.signatureRange.location != NSNotFound
            ? ns.substring(with: def.signatureRange) : def.name

        let lang = DiagramLanguage.from(ext: ext) ?? .c
        let bodyText = ns.substring(with: def.bodyRange)

        let bodyOffset: Int
        if lang.usesIndentation {
            guard let braced = diagramBodyToBraced(bodyText, language: lang) else { return nil }
            let instrs = splitStatements(braced.text, lineMap: braced.lineMap, bodyOffset: lineOffsetOf(def.bodyRange.location, in: ns))
            let trimmed = dropSignature(instrs, name: def.name)
            let params = rowParams(signature: signatureText, lang: lang)
            guard !trimmed.isEmpty else {
                return SimFunction(name: def.name, fileURL: fileURL, ext: ext,
                                   signatureText: signatureText, instructions: trimmed, params: params)
            }
            return SimFunction(name: def.name, fileURL: fileURL, ext: ext,
                               signatureText: signatureText, instructions: trimmed, params: params)
        }
        bodyOffset = lineOffsetOf(def.bodyRange.location, in: ns)
        let instrs = splitStatements(bodyText, lineMap: nil, bodyOffset: bodyOffset)
        let trimmed = dropSignature(instrs, name: def.name)
        let params = rowParams(signature: signatureText, lang: lang)
        return SimFunction(name: def.name, fileURL: fileURL, ext: ext,
                           signatureText: signatureText, instructions: trimmed, params: params)
    }

    private static func lineOffsetOf(_ location: Int, in ns: NSString) -> Int {
        var count = 0
        if location > 0 {
            let prefix = ns.substring(with: NSRange(location: 0, length: min(location, ns.length)))
            count = prefix.reduce(into: 0) { acc, c in if c == "\n" { acc += 1 } }
        }
        return count
    }

    private static func rowParams(signature: String, lang: DiagramLanguage) -> [SimParameterSeed] {
        let groups = paramGroups(signature)
        return groups.compactMap { group in
            let extracted = extractParamName(group, lang: lang)
            guard let name = extracted.name, !name.isEmpty else { return nil }
            let value = SimSeeding.seedValue(forTypeText: group, name: name)
            let isBuffer = value.kind == .buffer
            return SimParameterSeed(name: name, typeHint: group,
                                    value: value, isBuffer: isBuffer,
                                    capacity: value.capacity ?? 0)
        }
    }

    private static func paramGroups(_ signature: String) -> [String] {
        guard let open = signature.firstIndex(of: "(") else { return [] }
        let after = signature[signature.index(after: open)...]
        var depth = 1
        for (i, c) in after.enumerated() {
            if c == "(" { depth += 1 }
            else if c == ")" {
                depth -= 1
                if depth == 0 {
                    let inner = String(after[..<after.index(after.startIndex, offsetBy: i)])
                    return splitTopLevel(inner)
                }
            }
        }
        return []
    }

    private static func splitTopLevel(_ s: String) -> [String] {
        var out: [String] = []
        var current = ""
        var depth = 0
        var inString = false
        var quote: Character = " "
        for c in s {
            if inString {
                current.append(c)
                if c == "\\" { continue }
                if c == quote { inString = false }
                continue
            }
            if c == "\"" || c == "'" || c == "`" {
                inString = true
                quote = c
                current.append(c)
                continue
            }
            if c == "(" || c == "[" || c == "<" || c == "{" {
                depth += 1
                current.append(c)
                continue
            }
            if c == ")" || c == "]" || c == ">" || c == "}" {
                if depth > 0 { depth -= 1 }
                current.append(c)
                continue
            }
            if c == "," && depth == 0 {
                let t = current.trimmingCharacters(in: .whitespaces)
                if !t.isEmpty { out.append(t) }
                current = ""
                continue
            }
            current.append(c)
        }
        let t = current.trimmingCharacters(in: .whitespaces)
        if !t.isEmpty { out.append(t) }
        return out
    }

    private static func extractParamName(_ group: String, lang: DiagramLanguage) -> (name: String?, capacity: Int) {
        var tokens: [String] = []
        var current = ""
        for c in group {
            if c == " " || c == "\t" {
                if !current.isEmpty { tokens.append(current); current = "" }
            } else if c == "=" {
                if !current.isEmpty { tokens.append(current); current = "" }
                tokens.append("=")
            } else if c == "," || c == "(" || c == ")" || c == "{" || c == "}" {
                if !current.isEmpty { tokens.append(current); current = "" }
                tokens.append(String(c))
            } else {
                current.append(c)
            }
        }
        if !current.isEmpty { tokens.append(current) }
        tokens = tokens.filter { !["(", ")", "{", "}"].contains($0) }

        var name: String?
        switch lang {
        case .go:
            name = tokens.first
        case .php:
            if let idx = tokens.firstIndex(of: "$"), idx + 1 < tokens.count {
                name = tokens[idx + 1]
            } else if let last = tokens.last {
                name = last
            }
        case .python, .ruby:
            if let ci = tokens.firstIndex(of: "=") {
                name = tokens[max(0, ci - 1)]
            } else {
                name = tokens.last
            }
        case .kotlin, .rust, .swift:
            if let ci = tokens.firstIndex(of: ":"), ci > 0 {
                name = tokens[ci - 1]
            } else {
                name = tokens.last
            }
        default:
            if let ei = tokens.firstIndex(of: "="), ei > 0 {
                name = tokens[ei - 1]
            } else {
                var filtered = tokens.filter { !isTokenTypeWord($0, lang: lang) }
                if filtered.isEmpty { filtered = tokens }
                name = filtered.last
            }
        }
        if let existing = name, existing == "int" || existing == "void" || existing == "char" || existing == "String" || existing == "string" {
            name = nil
        }
        let capacity = capacityFrom(group)
        if capacity != nil, name == nil {
            name = tokens.last
        }
        return (name, capacity ?? 0)
    }

    private static func capacityFrom(_ typeText: String) -> Int? {
        if let open = typeText.firstIndex(of: "["), let close = typeText.firstIndex(of: "]") {
            let inside = String(typeText[typeText.index(after: open)..<close]).trimmingCharacters(in: .whitespaces)
            if !inside.isEmpty, let n = Int(inside) { return n }
            return 64
        }
        return nil
    }

    private static func isTokenTypeWord(_ w: String, lang: DiagramLanguage) -> Bool {
        let typeWords = ["int", "char", "long", "short", "float", "double", "void", "bool",
                         "boolean", "size_t", "ssize_t", "unsigned", "signed", "const", "static",
                         "string", "String", "byte", "uint8_t", "uint16_t", "uint32_t", "uint64_t",
                         "int8_t", "int16_t", "int32_t", "int64_t", "NSInteger", "NSUInteger",
                         "CGFloat", "BOOL", "id", "NSObject", "std", "vector", "array", "list", "map"]
        if lang == .rust {
            return ["usize", "u8", "u16", "u32", "u64", "i8", "i16", "i32", "i64", "f32", "f64", "i32", "str", "String", "bool"].contains(w) || typeWords.contains(w)
        }
        if w.hasSuffix("]") || w.hasSuffix(")") { return false }
        if w.first?.isUppercase == true && !typeWords.contains(w.lowercased()) { return true }
        if w == "*" { return true }
        return typeWords.contains(w.lowercased())
    }

    private static func dropSignature(_ instrs: [SimInstruction], name: String) -> [SimInstruction] {
        guard !instrs.isEmpty else { return instrs }
        let first = instrs[0]
        var start = 0
        if first.kind == .open || (first.kind == .code && first.text.trimmingCharacters(in: .whitespaces).hasSuffix("{")) {
            start = 1
        } else if first.kind == .code && dropIfSignature(first.text, name: name) {
            if instrs.count >= 2 && instrs[1].kind == .open {
                start = 2
            } else {
                start = 1
            }
        }
        return Array(instrs.dropFirst(start))
    }

    private static func dropIfSignature(_ text: String, name: String) -> Bool {
        let t = text.trimmingCharacters(in: .whitespaces)
        if t.contains("=") || t.contains(";") { return false }
        if t.contains(name) { return true }
        let hasParens = t.contains("(") && t.contains(")")
        if hasParens && !t.contains("{") { return true }
        return false
    }

    private static func splitStatements(_ text: String, lineMap: [Int]?, bodyOffset: Int) -> [SimInstruction] {
        var instrs: [SimInstruction] = []
        let chars = Array(text)
        var current = ""
        var stmtStartOutLine = 1
        var outLine = 1
        var depth = 0
        var pDepth = 0
        var inString = false
        var quote: Character = " "
        var blockComment = false
        var i = 0
        let n = chars.count

        func flushCode() {
            let stmt = current.trimmingCharacters(in: .whitespaces)
            if !stmt.isEmpty {
                let fileLine = fileLineValue(outLine: stmtStartOutLine, lineMap: lineMap, bodyOffset: bodyOffset)
                let kind = classify(stmt)
                instrs.append(SimInstruction(kind: kind, text: stmt, line: fileLine))
            }
            current = ""
        }

        func isControlBodyStart(_ stmt: String) -> Bool {
            switch classify(stmt) {
            case .controlIf, .controlElse, .controlWhile, .controlFor, .controlDo,
                 .controlSwitch, .controlTry, .controlCatch, .controlFinally, .controlWith:
                return true
            default:
                return false
            }
        }

        while i < n {
            let c = chars[i]
            let nextChar: Character? = i + 1 < n ? chars[i + 1] : nil
            if inString {
                current.append(c)
                if c == "\\" {
                    if let nc = nextChar { current.append(nc); i += 1 }
                } else if c == quote {
                    inString = false
                }
                i += 1
                continue
            }
            if blockComment {
                if c == "*" , let nc = nextChar, nc == "/" {
                    blockComment = false
                    i += 2
                    continue
                }
                if c == "\n" { outLine += 1 }
                i += 1
                continue
            }
            if c == "@" {
                current.append(c)
                i += 1
                continue
            }
            if (c == "/" && nextChar == "*") {
                blockComment = true
                i += 2
                continue
            }
            if (c == "/" && nextChar == "/") {
                while i < n, chars[i] != "\n" { i += 1 }
                continue
            }
            if c == "#" || c == "'" {
                if c == "'" && nextChar != " " && nextChar != ")" && nextChar != "(" && (nextChar == nil || false) && false {
                }
                if c == "#" {
                    while i < n, chars[i] != "\n" { i += 1 }
                    continue
                }
            }
            if c == "\"" || c == "'" || c == "`" {
                inString = true
                quote = c
                current.append(c)
                i += 1
                continue
            }
            if c == "\n" {
                outLine += 1
                i += 1
                continue
            }
            if c == "(" {
                pDepth += 1
                current.append(c)
                i += 1
                continue
            }
            if c == ")" {
                pDepth = max(0, pDepth - 1)
                current.append(c)
                i += 1
                continue
            }
            if c == "{" {
                let pending = current.trimmingCharacters(in: .whitespaces)
                if !pending.isEmpty, pDepth == 0, isControlBodyStart(pending) {
                    let stmt = pending + " {"
                    let fileLine = fileLineValue(outLine: stmtStartOutLine, lineMap: lineMap, bodyOffset: bodyOffset)
                    instrs.append(SimInstruction(kind: classify(pending), text: stmt, line: fileLine))
                    current = ""
                } else {
                    flushCode()
                    let fileLine = fileLineValue(outLine: outLine, lineMap: lineMap, bodyOffset: bodyOffset)
                    instrs.append(SimInstruction(kind: .open, text: "{", line: fileLine))
                }
                depth = max(0, depth + 1)
                stmtStartOutLine = outLine
                i += 1
                continue
            }
            if c == "}" {
                flushCode()
                depth = max(0, depth - 1)
                let fileLine = fileLineValue(outLine: outLine, lineMap: lineMap, bodyOffset: bodyOffset)
                instrs.append(SimInstruction(kind: .close, text: "}", line: fileLine))
                stmtStartOutLine = outLine
                i += 1
                continue
            }
            if c == ";" && pDepth == 0 {
                current.append(c)
                flushCode()
                stmtStartOutLine = outLine
                i += 1
                continue
            }
            if c == ":" && depth == 0 && pDepth == 0 {
                if current.trimmingCharacters(in: .whitespaces).hasPrefix("case")
                    || current.trimmingCharacters(in: .whitespaces) == "default" {
                    current.append(c)
                    flushCode()
                    stmtStartOutLine = outLine
                    i += 1
                    continue
                }
            }
            current.append(c)
            i += 1
        }
        flushCode()
        return instrs
    }

    private static func fileLineValue(outLine: Int, lineMap: [Int]?, bodyOffset: Int) -> Int {
        if let lineMap = lineMap {
            if outLine >= 1, outLine <= lineMap.count {
                return lineMap[outLine - 1] + bodyOffset
            }
            return bodyOffset + outLine
        }
        return bodyOffset + outLine
    }

    private static func classify(_ stmt: String) -> SimInstrKind {
        let t = stmt.trimmingCharacters(in: .whitespaces)
        let lower = t.lowercased()
        if lower.hasPrefix("case ") || lower == "default" || lower == "default:" {
            return .caseLabel
        }
        if lower.hasPrefix("if ") || lower.hasPrefix("if(") {
            return .controlIf
        }
        if lower.hasPrefix("else") {
            return .controlElse
        }
        if lower.hasPrefix("while ") || lower.hasPrefix("while(") {
            return .controlWhile
        }
        if lower.hasPrefix("for ") || lower.hasPrefix("for(") {
            return .controlFor
        }
        if lower == "do" || lower.hasPrefix("do ") || lower.hasPrefix("do(") {
            return .controlDo
        }
        if lower.hasPrefix("switch ") || lower.hasPrefix("switch(") || lower.hasPrefix("match ") || lower.hasPrefix("match(") {
            return .controlSwitch
        }
        if lower == "try" || lower.hasPrefix("try ") {
            return .controlTry
        }
        if lower.hasPrefix("catch") || lower.hasPrefix("except") {
            return .controlCatch
        }
        if lower == "finally" || lower.hasPrefix("finally ") {
            return .controlFinally
        }
        if lower.hasPrefix("with ") {
            return .controlWith
        }
        let trimmed = t
        if trimmed == "{" || trimmed == "{;" {
            return .open
        }
        if trimmed == "}" {
            return .close
        }
        return .code
    }
}

extension Array {
    subscript(safe index: Int) -> Element? {
        get { indices.contains(index) ? self[index] : nil }
    }
}
// by cipher.org.uk
import Foundation

// MARK: - ObjC native AST
//
// A dedicated Objective-C AST so Cocoa analysis no longer depends on the
// C-AST frontend. The parser (ObjCParser) consumes the shared CTokenizer
// stream and models ObjC's own shapes: class/method declarations, selector
// parts, message expressions, property dot access, and the boxed literals.
// C-style calls remain first-class because ObjC code mixes both freely.

/// One parameter of an ObjC method: the selector label (`forKey:`), the
/// local name, and the declared type.
public struct ObjCParam {
    public let label: String?     // selector part label including ':' (nil for the first part's name-only form)
    public let name: String
    public let type: String
    public let nameOffset: Int

    public init(label: String?, name: String, type: String, nameOffset: Int) {
        self.label = label
        self.name = name
        self.type = type
        self.nameOffset = nameOffset
    }
}

/// A located method (`-`/`+` in an @implementation) or a top-level C
/// function found in the same file. Both share one shape so the detector
/// walks them uniformly.
public struct ObjCMethodDef {
    public let container: String        // @implementation/@interface class name; "" for C functions
    public let isClassMethod: Bool      // `+` methods
    public let isCFunction: Bool        // top-level C function
    public let selector: String         // "storeToken:", "setUpWebViews", "main"
    public let returnType: String
    public let params: [ObjCParam]
    public let nameOffset: Int          // offset of the first selector part / function name
    public let bodyOpenOffset: Int      // offset of '{'
    public let bodyEndOffset: Int       // offset of the closing '}' (inclusive)

    public var bodyRange: NSRange {
        NSRange(location: bodyOpenOffset,
                length: max(0, bodyEndOffset - bodyOpenOffset + 1))
    }
}

/// ObjC expression tree. `offset` is the UTF-16 offset of the expression's
/// first token so findings can be mapped to lines.
public indirect enum ObjCExpr {
    case identifier(String, offset: Int)
    case string(String, offset: Int)                                  // @"..." / "..."
    case number(String, offset: Int)
    case member(base: ObjCExpr, name: String, offset: Int)            // a.b / a->b
    /// Message expression. Parts carry the selector piece (with trailing ':'
    /// when an argument follows) and its argument (nil for a no-arg part).
    case message(receiver: ObjCExpr?, parts: [(selector: String, arg: ObjCExpr?)], offset: Int)
    case call(name: String, args: [ObjCExpr], offset: Int)            // C-style call: foo(a, b)
    case arrayLiteral([ObjCExpr], offset: Int)                        // @[ a, b ]
    case dictLiteral([(key: ObjCExpr, value: ObjCExpr)], offset: Int) // @{ k : v }
    case ternary(cond: ObjCExpr, then: ObjCExpr, else: ObjCExpr, offset: Int)
    case unary(op: String, operand: ObjCExpr, offset: Int)
    case binary(op: String, lhs: ObjCExpr, rhs: ObjCExpr, offset: Int)
    case index(base: ObjCExpr, index: ObjCExpr, offset: Int)          // buf[i] (postfix form)
    case paren(ObjCExpr, offset: Int)
    /// Parse failure / unsupported construct; carries the offset so the walk
    /// can still place any conservative finding.
    case unknown(Int)

    var offset: Int {
        switch self {
        case .identifier(_, let o), .string(_, let o), .number(_, let o),
             .call(_, _, let o), .arrayLiteral(_, let o), .dictLiteral(_, let o),
             .ternary(_, _, _, let o), .unary(_, _, let o), .binary(_, _, _, let o),
             .index(_, _, let o), .paren(_, let o), .unknown(let o):
            return o
        case .member(_, _, let o):
            return o
        case .message(_, _, let o):
            return o
        }
    }

    /// The trailing identifier text of the expression, when any: the selector
    /// tail of a message, the member name, or the identifier itself. Used for
    /// local-variable type inference and sink naming.
    var trailingName: String? {
        switch self {
        case .identifier(let n, _): return n
        case .member(_, let n, _): return n
        case .message(_, let parts, _) where !parts.isEmpty: return parts.last?.selector
        case .call(let n, _, _): return n
        default: return nil
        }
    }
}

/// A parsed statement. Declarations and assignments are modeled explicitly
/// because taint propagation and bounds analysis key off them.
public struct ObjCStmt {
    public enum Kind {
        case declaration(type: String, name: String, isPointer: Bool, arraySize: Int?, initExpr: ObjCExpr?)
        case assignment(target: ObjCExpr, value: ObjCExpr)
        case expression(ObjCExpr)
        case returnStmt(ObjCExpr?)
        /// if/while/for/switch bodies are flattened into the enclosing list,
        /// but the condition expression is preserved for guard analysis.
        case condition(ObjCExpr)
    }
    public let kind: Kind
    public let offset: Int

    public init(kind: Kind, offset: Int) {
        self.kind = kind
        self.offset = offset
    }
}

/// A fully parsed method body: the statements (control-flow flattened) plus
/// the def they belong to.
public struct ObjCFunctionBody {
    public let def: ObjCMethodDef
    public let statements: [ObjCStmt]
}

// MARK: - ObjC type-name helpers

public enum ObjCType {
    /// True for types whose values hold user/external data flows worth
    /// treating as taint sources when produced from reading APIs.
    public static func isKnownSourceFactory(_ selector: String) -> Bool {
        switch selector {
        case "stringWithContentsOfURL:", "stringWithContentsOfFile:",
             "dataWithContentsOfURL:", "dataWithContentsOfFile:",
             "contentsOfURL:", "URLWithString:":
            return true
        default:
            return false
        }
    }
}

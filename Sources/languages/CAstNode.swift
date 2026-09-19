// by cipher.org.uk
import Foundation

/// AST node types for the C/C++ frontend.
/// Every node carries a source range (offset-based) so findings can be
/// attributed to the exact line, fixing the current scanner's line-attribution
/// defects.
public indirect enum CExpr {
    case integerLiteral(String, Int)                 // value, offset
    case floatLiteral(String, Int)
    case stringLiteral(String, Int)
    case charLiteral(String, Int)
    case identifier(String, Int)
    case booleanLiteral(Bool, Int)

    case unary(op: String, operand: CExpr, Int)
    case binary(op: String, lhs: CExpr, rhs: CExpr, Int)
    case ternary(cond: CExpr, thenExpr: CExpr, elseExpr: CExpr, Int)
    case assign(op: String, lhs: CExpr, rhs: CExpr, Int)
    case call(callee: CExpr, args: [CExpr], Int)
    case member(base: CExpr, member: String, isPtr: Bool, Int)
    case index(base: CExpr, index: CExpr, Int)
    case cast(expr: CExpr, Int)
    case sizeOf(expr: CExpr?, typeName: String?, Int)
    case paren(expr: CExpr, Int)
    case comma(lhs: CExpr, rhs: CExpr, Int)
    case arrayInit(elements: [CExpr], Int)
    case newExpr(typeName: String, args: [CExpr], Int)
    case lambda(Int)

    var offset: Int {
        switch self {
        case .integerLiteral(_, let o), .floatLiteral(_, let o), .stringLiteral(_, let o),
             .charLiteral(_, let o), .identifier(_, let o), .booleanLiteral(_, let o),
             .unary(_, _, let o), .binary(_, _, _, let o), .ternary(_, _, _, let o),
             .assign(_, _, _, let o), .call(_, _, let o), .member(_, _, _, let o),
             .index(_, _, let o), .cast(_, let o), .sizeOf(_, _, let o), .paren(_, let o),
             .comma(_, _, let o), .arrayInit(_, let o), .newExpr(_, _, let o),
             .lambda(let o):
            return o
        }
    }
}

public indirect enum CStmt {
    case expr(CExpr)
    case declaration(CDecl)
    case ifStmt(cond: CExpr, thenBranch: CStmt, elseBranch: CStmt?, Int)
    case whileStmt(cond: CExpr, body: CStmt, Int)
    case doWhileStmt(body: CStmt, cond: CExpr, Int)
    case forStmt(init: CStmt?, cond: CExpr?, increment: CExpr?, body: CStmt, Int)
    case returnStmt(CExpr?, Int)
    case breakStmt(Int)
    case continueStmt(Int)
    case block([CStmt])
    case switchStmt(expr: CExpr, cases: [CSwitchCase], Int)
    case gotoStmt(String, Int)
    case labeledStmt(label: String, stmt: CStmt, Int)
    case empty

    var offset: Int {
        switch self {
        case .expr(let e): return e.offset
        case .declaration(let d): return d.offset
        case .ifStmt(_, _, _, let o), .whileStmt(_, _, let o), .doWhileStmt(_, _, let o),
             .forStmt(_, _, _, _, let o), .returnStmt(_, let o), .breakStmt(let o),
             .continueStmt(let o), .switchStmt(_, _, let o), .gotoStmt(_, let o),
             .labeledStmt(_, _, let o):
            return o
        case .block(let s): return s.first?.offset ?? 0
        case .empty: return 0
        }
    }
}

public struct CSwitchCase {
    public let values: [CExpr]      // case values; empty for default
    public let isDefault: Bool
    public let body: [CStmt]
}

public struct CDecl {
    public enum Kind {
        case variable(typeName: String?, name: String, initExpr: CExpr?)
        case functionParam
        case typedef(String)
        case structDef
        case using
        case namespace
        case other
    }
    public let kind: Kind
    public let offset: Int
}

public struct CFunctionDef {
    public let name: String
    public let returnType: String?
    public let params: [CAParam]
    public let body: CStmt          // block
    public let startOffset: Int      // line/accolade start (signature)
    public let bodyOffset: Int       // opening '{' of body
    public let endOffset: Int        // closing '}' of body
    public let isDefinition: Bool
    public let isMethod: Bool        // class/struct member function
    public let qualifiers: Set<String> // static, virtual, etc.
}

public struct CAParam {
    public let type: String?
    public let name: String?
    public let offset: Int
}

public struct CStructDef {
    public let name: String
    public let offset: Int
}

public struct CTranslationUnit {
    public let functions: [CFunctionDef]
    public let structs: [CStructDef]
    public let typedefs: [String]
    public let globalVariables: [String]
    public let namespaces: [String]
}

// by cipher.org.uk
import Foundation

/// Builds a `CFunctionSummary`/flow-fact view of a Java method by reusing the C
/// semantic layer over the shared `CStmt`/`CExpr` representation. This lets the
/// Java frontend reuse `CSymbolTable`'s symbol scoping and taint-relevant flow
/// facts (calls, assignments, returns) without a second, divergent Java model.
public struct JSymbolTable {

    public init() {}

    /// Analyzes a Java method body (already parsed into a `CStmt` block) into a
    /// C-style summary.
    public func analyze(_ method: JMethodDef, block: CStmt) -> CFunctionSummary {
        let fn = CFunctionDef(name: method.name,
                              returnType: nil,
                              params: method.params,
                              body: block,
                              startOffset: method.startOffset,
                              bodyOffset: method.bodyOffset,
                              endOffset: method.bodyRange.location + method.bodyRange.length,
                              isDefinition: true,
                              isMethod: true,
                              qualifiers: method.qualifiers)
        return CSymbolTable().analyze(fn)
    }
}

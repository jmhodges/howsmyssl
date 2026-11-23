/**
 * @name Expression has no effect, but for godebug's Value in the crypto/tls fork
 * @description An expression that has no effect and is used in a void context is most
 *              likely redundant and may indicate a bug. This is go/useless-expression,
 *              less the calls to Value on the godebug stand-in of our fork of
 *              crypto/tls.
 * @kind problem
 * @problem.severity warning
 * @id howsmyssl/go/useless-expression-but-godebug-value
 * @tags quality
 *       reliability
 *       correctness
 *       external/cwe/cwe-480
 *       external/cwe/cwe-561
 * @precision very-high
 */

// This replaces the stock go/useless-expression query, which codeql-config.yml
// turns off. It is the same query except that it doesn't report calls to
// (*Setting).Value of the internal/godebug package in our fork of Go's
// crypto/tls (tls1274/internal/godebug as of this writing). Everything else in
// the fork is still checked.
//
// The fork is a mechanical port of upstream and we keep its lines as close to
// upstream's as we can so the next port is easy to diff. Upstream has lines
// like
//
//     tlssha1.Value() // ensure godebug is initialized
//
// which call into the standard library's internal/godebug. The fork's
// stand-in for that package returns "" from Value, so there the call does
// nothing. The stock query flags each of those, and the fix it wants,
// deleting the line, is exactly the diff from upstream we don't want. (The
// stock query already lets calls to functions with an empty body through,
// which is why the stand-in's IncNonDefault isn't flagged. Value's body is
// one return statement.)
//
// The stand-in's package is matched by the shape of its import path, a
// directory named tls and then the digits of the Go version, then
// internal/godebug, and not by its current name, so that the next port (a
// tls1280/, say) doesn't bring the alerts back.
import go

/**
 * Holds if `e` appears in a syntactic context where its value is discarded.
 */
predicate inVoidContext(Expr e) {
  e = any(ExprStmt es).getExpr()
  or
  exists(LogicalBinaryExpr logical | e = logical.getRightOperand() and inVoidContext(logical))
}

/**
 * Holds if `ce` is a call to a stub function with an empty body.
 */
predicate callToStubFunction(CallExpr ce) { ce.getTarget().getBody().getNumStmt() = 0 }

/**
 * Holds if `ce` is a call to the Value method of Setting in the godebug
 * stand-in of our crypto/tls fork, like
 * github.com/jmhodges/howsmyssl/tls1274/internal/godebug.
 */
predicate callToTLSForkGodebugValue(CallExpr ce) {
  exists(Method m, string pkg |
    m = ce.getTarget() and
    m.hasQualifiedName(pkg, "Setting", "Value") and
    pkg.regexpMatch("(.*/)?tls[0-9]+/internal/godebug")
  )
}

from Expr e
where
  not e.mayHaveOwnSideEffects() and
  inVoidContext(e) and
  // don't flag calls to functions with an empty body
  not callToStubFunction(e) and
  not callToTLSForkGodebugValue(e)
select e, "This expression has no effect."

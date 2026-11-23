/**
 * @name Expression has no effect, outside the crypto/tls fork
 * @description An expression that has no effect and is used in a void context is most
 *              likely redundant and may indicate a bug. This is go/useless-expression,
 *              less the files of our fork of crypto/tls.
 * @kind problem
 * @problem.severity warning
 * @id howsmyssl/go/useless-expression-outside-tls-fork
 * @tags quality
 *       reliability
 *       correctness
 *       external/cwe/cwe-480
 *       external/cwe/cwe-561
 * @precision very-high
 */

// This replaces the stock go/useless-expression query, which codeql-config.yml
// turns off. It is the same query except that it doesn't report anything in
// our fork of Go's crypto/tls (tls1274/ as of this writing).
//
// The fork is a mechanical port of upstream and we keep its lines as close to
// upstream's as we can so the next port is easy to diff. Some of those lines
// do nothing in the fork. For instance, upstream's
//
//     tlssha1.Value() // ensure godebug is initialized
//
// calls into internal/godebug, and the fork's stand-in for that package
// returns "" from Value. The stock query flags each of those, and the fix it
// wants, deleting the line, is exactly the diff from upstream we don't want.
//
// The fork's directory is matched by its shape, tls and then the digits of
// the Go version, and not by its current name, so that the next port (a
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
 * Holds if `f` is a file of our fork of crypto/tls, like tls1274/conn.go or
 * tls1274/internal/godebug/godebug.go.
 */
predicate inTLSFork(File f) { f.getRelativePath().regexpMatch("tls[0-9]+/.*") }

from Expr e
where
  not e.mayHaveOwnSideEffects() and
  inVoidContext(e) and
  // don't flag calls to functions with an empty body
  not callToStubFunction(e) and
  not inTLSFork(e.getFile())
select e, "This expression has no effect."

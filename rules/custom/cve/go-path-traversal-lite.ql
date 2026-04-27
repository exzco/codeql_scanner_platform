/**
 * @name Potential path traversal via dynamic file path
 * @description Detects file open/read/write operations using non-literal file paths.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 8.2
 * @precision medium
 * @id custom/go/path-traversal-lite
 * @tags security
 *       external/cwe/cwe-022
 */

import go

predicate isFileSink(Function fn) {
  fn.hasQualifiedName("os", "Open") or
  fn.hasQualifiedName("os", "OpenFile") or
  fn.hasQualifiedName("io/ioutil", "ReadFile") or
  fn.hasQualifiedName("os", "ReadFile") or
  fn.hasQualifiedName("os", "WriteFile")
}

from CallExpr call, Function fn, Expr pathArg
where
  fn = call.getTarget() and
  isFileSink(fn) and
  pathArg = call.getArgument(0) and
  not pathArg instanceof StringLit
select pathArg, "Non-literal file path reaches file system API; validate path to prevent traversal."

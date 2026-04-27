/**
 * @name Potential command injection via child_process.exec
 * @description Detects child_process.exec calls with non-literal command values.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 9.0
 * @precision medium
 * @id custom/javascript/child-process-exec-lite
 * @tags security
 *       external/cwe/cwe-078
 */

import javascript

from CallExpression call, Expr arg, PropertyAccess callee
where
  callee = call.getCallee() and
  callee.getPropertyName() = "exec" and
  arg = call.getArgument(0) and
  not arg instanceof Literal
select arg, "Dynamic command passed to exec may introduce command injection risk."

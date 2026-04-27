/**
 * @name Potential command injection via dynamic command
 * @description Detects os/exec command invocation where command program argument is non-literal.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 9.1
 * @precision medium
 * @id custom/go/command-injection-lite
 * @tags security
 *       external/cwe/cwe-078
 */

import go

from CallExpr call, Function fn, Expr cmdArg
where
  fn = call.getTarget() and
  fn.hasQualifiedName("os/exec", "Command") and
  cmdArg = call.getArgument(0) and
  not cmdArg instanceof StringLit
select cmdArg, "Dynamic command execution may allow command injection if user input reaches this value."

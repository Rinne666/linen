/**
 * @name input() flows into sqlite3 SQL text
 * @description Finds input() values that reach the SQL text argument of execute().
 * @kind path-problem
 * @problem.severity warning
 * @precision high
 * @id local/python/sqlite-input-to-execute
 * @tags security
 *       external/cwe/cwe-089
 */

import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking

module InputToSqlConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    exists(DataFlow::CallCfgNode call |
      source = call and
      call.getNode().(CallNode).getFunction().(NameNode).getId() = "input"
    )
  }

  predicate isSink(DataFlow::Node sink) {
    exists(DataFlow::MethodCallNode call |
      call.getMethodName() = "execute" and
      sink = call.getArg(0)
    )
  }
}

module InputToSqlFlow = TaintTracking::Global<InputToSqlConfig>;

import InputToSqlFlow::PathGraph

from InputToSqlFlow::PathNode source, InputToSqlFlow::PathNode sink
where InputToSqlFlow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "Input from $@ reaches SQL text here.", source.getNode(), "input()"

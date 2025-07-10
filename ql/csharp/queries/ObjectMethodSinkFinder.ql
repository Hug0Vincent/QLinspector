/**
 * @id synacktiv/csharp/objectmethodsinkfinder
 * @description find new sources for gadget chain based on overridable methods of the Object Type.
 * @name objectmethodsinkfinder
 * @kind path-problem
 * @problem.severity warning
 * @tags security
 */

import csharp
import semmle.code.csharp.dataflow.TaintTracking
private import semmle.code.csharp.security.dataflow.flowsinks.FlowSinks
import GadgetFinder::PathGraph
import libs.Sources as Sources
import libs.GadgetTaintHelpers

/**
 * A data flow sink for gadget.
 */
abstract class Sink extends ApiSinkExprNode { }

private module GadgetFinderConfig implements DataFlow::ConfigSig {
  
  predicate isSource(DataFlow::Node source) {
    source instanceof Sources::Source
  }

  predicate isSink(DataFlow::Node sink) {
    sink instanceof ObjectMethodSink
  }

  predicate isAdditionalFlowStep(DataFlow::Node node1, DataFlow::Node node2) {
    any(GadgetAdditionalTaintStep s).step(node1, node2)
  }

  /**
   * We stop return statement if the caller is the source
   * 
   * Thanks @aschackmull
   * cf: https://github.com/github/codeql/discussions/16973#discussioncomment-10050420
   */
  DataFlow::FlowFeature getAFeature() { 
    result instanceof DataFlow::FeatureHasSourceCallContext
  }
}

class ObjectMethodSink extends Sink {
    ObjectMethodSink(){
        exists(OverridableCallable baseMethod, SerializableType t, MethodCall mc |
            baseMethod.getDeclaringType() instanceof ObjectType and
            baseMethod.hasName(["GetHashCode", "ToString", "Equals", "GetType"]) and
            baseMethod.getInherited(t).getACall() = mc and
            mc.getRawArgument(0) = this.asExpr() and
            isGenericType(mc.getRawArgument(0).getType())
        )
    }
}

module GadgetFinder = TaintTracking::Global<GadgetFinderConfig>;

from GadgetFinder::PathNode source, GadgetFinder::PathNode sink
where GadgetFinder::flowPath(source, sink)
select sink.getNode(), source, sink, "Gadget from $@", source.getNode(), getSourceLocationInfo(source.getNode())
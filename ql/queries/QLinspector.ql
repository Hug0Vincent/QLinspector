/**
 * @id synacktiv/java/qlinspector
 * @description find regular Java gadget chains
 * @name Java deserialization gadget finder
 * @kind path-problem
 * @problem.severity warning
 * @tags security
 */

import java
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.dataflow.FlowSources
import semmle.code.java.dataflow.ExternalFlow
import GadgetFinder::PathGraph
import libs.Source
import libs.DangerousMethods
import libs.GadgetTaintHelpers

private module GadgetFinderConfig implements DataFlow::ConfigSig {
  
  /**
   * We taint the object that is being deserialized and all it's fields.
   * 
   * In fact the tricks here is that the instance parameter (this) is implicitly
   * passed between method calls. 
   * 
   * Thanks @atorralba
   * cf: https://github.com/github/codeql/discussions/16474
   * 
   * We also taint all the objects that are passed as parameters of the source.
   *  readObject(ObjectInputStream taint){...}
   */
  predicate isSource(DataFlow::Node source) {
    source.(DataFlow::InstanceParameterNode).getCallable() instanceof GadgetSource or
    source.asParameter().getCallable() instanceof GadgetSource
  }

  /**
   * A sink is a call to a DangerousMethod where the node is either a parameter
   * to the call or the qualifier like this:
   * 
   *  sink.dangerousMethod()
   *  obj.dangerousMethod(sink)
   * 
   */
  predicate isSink(DataFlow::Node sink) {
    exists(Call c |
      c.getCallee() instanceof DangerousMethod and
      (
        sink.asExpr() = c.getAnArgument() or
        sink.asExpr() = c.getQualifier()
      )
    )
  }

  /**
   * Add custom AdditionalFlowStep.
   */
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

  /**
   * The GadgetSanitizer is here to quickly add barrier steps.
   */
  predicate isBarrier(DataFlow::Node node) {
    node instanceof GadgetSanitizer
  }
}

/**
 * placeholder for adding sanitizing steps
*/
class GadgetSanitizer extends DataFlow::Node {
  GadgetSanitizer() {
    this.getEnclosingCallable().hasName("")
  }
}

/**
 * CodeQL trick to taint all field of a Serilizable object if the object is tainted
 */
private class FieldInheritTaint extends DataFlow::FieldContent, TaintInheritingContent {
  FieldInheritTaint() { this.getField().getDeclaringType().getASupertype*() instanceof TypeSerializable }
}

module GadgetFinder = TaintTracking::Global<GadgetFinderConfig>;

from GadgetFinder::PathNode source, GadgetFinder::PathNode sink
where GadgetFinder::flowPath(source, sink)
select sink.getNode(), source, sink, "Gadget from $@", source.getNode(), getSourceLocationInfo(source.getNode())
/**
 * @id synacktiv/csharp/qlinspector
 * @description find regular C# gadget chains
 * @name C# deserialization gadget finder
 * @kind path-problem
 * @problem.severity warning
 * @tags security
 */

import csharp
import semmle.code.csharp.dataflow.TaintTracking
import GadgetFinder::PathGraph
import libs.Sources as Sources
import libs.DangerousMethods as DangerousMethods
import libs.GadgetTaintHelpers

private module GadgetFinderConfig implements DataFlow::ConfigSig {
  
  predicate isSource(DataFlow::Node source) {
    source instanceof Sources::Source
  }

  /**
   * A sink is a call to a DangerousMethod.
   * 
   *  obj.dangerousMethod(sink)
   * 
   */
  predicate isSink(DataFlow::Node sink) {
    sink instanceof DangerousMethods::Sink
    //sink instanceof DangerousMethods::ExternalDangerousSink
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
 * A sanitizer for a gadget.
 */
abstract class GadgetSanitizer extends DataFlow::Node { }

/**
 * placeholder for adding sanitizing steps
*/
class GenericGadgetSanitizer extends GadgetSanitizer {
  GenericGadgetSanitizer() {
    none()
  }
}

int pathLengthBetweenNodes(GadgetFinder::PathNode src, GadgetFinder::PathNode dst) {
  (result = 0 and src = dst)
  or
  exists(GadgetFinder::PathNode intermediate |
      intermediate.getASuccessor() = dst and
      result <= 10 and
      result = pathLengthBetweenNodes(src, intermediate) + 1
    )
}

//class ControlGadgetSanitizer extends GadgetSanitizer {
//  ControlGadgetSanitizer() {
//    exists(AssignableMemberAccess acc, AssignableMember m |
//      acc.getTarget() = m and
//      m.getType().hasFullyQualifiedName("System.Windows.Forms", "Control") and
//      this.asExpr() = acc
//    )
//  }
//}

module GadgetFinder = TaintTracking::Global<GadgetFinderConfig>;

from GadgetFinder::PathNode source, GadgetFinder::PathNode sink
where GadgetFinder::flowPath(source, sink)
select sink.getNode(), source, sink, "Gadget from $@", source.getNode(), getSourceLocationInfo(source.getNode())
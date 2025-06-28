import csharp
import GadgetTaintHelpers
import RequestForgery as RequestForgery 
private import semmle.code.csharp.security.dataflow.flowsinks.FlowSinks
import semmle.code.csharp.security.dataflow.UnsafeDeserializationQuery as UnsafeDeserialization
import semmle.code.csharp.security.dataflow.CodeInjectionQuery as CodeInjection 
import semmle.code.csharp.security.dataflow.CommandInjectionQuery as CommandInjection
import semmle.code.csharp.security.dataflow.TaintedPathQuery as TaintedPath
import semmle.code.csharp.security.dataflow.XMLEntityInjectionQuery as XmlEntityInjection
import semmle.code.csharp.security.dataflow.ResourceInjectionQuery as ResourceInjection

/**
 * A data flow sink for gadget.
 */
abstract class Sink extends ApiSinkExprNode { }



/**
 * A sink for delegate calls to find more `TypeConfuseDelegate` like gadgets.
 */
class DangerousDelegateSink extends Sink {

  DangerousDelegateSink() {
    exists(DelegateCall dc |
      dc.getNumberOfRuntimeArguments() > 0 and

      // Every parameter must be string or generic
      not exists(Type t |
        t = dc.getARuntimeArgument().getType() and
        not isStringOrGeneric(t)
      ) and

      // Sink expression is an argument passed to the delegate call
      this.getExpr() = dc.getARuntimeArgument()
    )
  }
}


private class ClaimsSink extends Sink {
  ClaimsSink() {
    exists(Constructor c |
      c.getDeclaringType().hasFullyQualifiedName("System.Security.Claims", ["ClaimsIdentity", "ClaimsPrincipal"]) and
      c.hasName(["ClaimsIdentity", "ClaimsPrincipal"]) and
      c.getParameter(0).getType().hasName("SerializationInfo")
    |
      c.getACall().getArgument(0) = this.asExpr()
    )
  }
}


class ExternalDangerousSink extends Sink {
  ExternalDangerousSink(){
    this instanceof UnsafeDeserialization::Sink
    or this instanceof CodeInjection::Sink
    or this instanceof CommandInjection::Sink
    or this instanceof TaintedPath::Sink
    or this instanceof XmlEntityInjection::Sink
    or this instanceof ResourceInjection::Sink
    or this instanceof RequestForgery::Sink
  }
}
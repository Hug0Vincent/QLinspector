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

/**
 * Sink to detect variant of the `ClaimsIdentity` and `ClaimsPrincipal` gadgets.
 */
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

/**
 * Sink for reflection. It includes property call / method call
 */
private class ReflectionSink extends Sink {
  ReflectionSink() {
    exists(Call c |
      (
        (
          // System.Type.GetProperty(string)
          c.getTarget().getDeclaringType().hasFullyQualifiedName("System", "Type") and
          c.getTarget().hasName("GetProperty")
        ) or (
          // System.Type.GetMethod(string)
          c.getTarget().getDeclaringType().hasFullyQualifiedName("System", "Type") and
          c.getTarget().hasName("GetMethod")
        ) or (
          // System.Reflection.PropertyInfo.GetValue(object)
          c.getTarget().getDeclaringType().hasFullyQualifiedName("System.Reflection", "PropertyInfo") and
          c.getTarget().hasName("GetValue")
        ) or (
          // System.ComponentModel.PropertyDescriptorCollection.Find(string, bool)
          c.getTarget().getDeclaringType().hasFullyQualifiedName("System.ComponentModel", "PropertyDescriptorCollection") and
          c.getTarget().hasName("Find")
        ) or (
          // System.ComponentModel.PropertyDescriptor.GetValue(object)
          c.getTarget().getDeclaringType().hasFullyQualifiedName("System.ComponentModel", "PropertyDescriptor") and
          c.getTarget().hasName("GetValue")
        ) or (
          // System.Reflection.MethodInfo.Invoke(object, object[])
          c.getTarget().getDeclaringType().hasFullyQualifiedName("System.Reflection", "MethodInfo") and
          c.getTarget().hasName("Invoke")
        )
      ) 
      and
      c.getArgument(0) = this.asExpr()
    )
  }
}

/**
 * Sinks stolen from other built-in queries.
 */
class ExternalDangerousSink extends Sink {
  ExternalDangerousSink(){
    this instanceof UnsafeDeserialization::Sink
    or this instanceof CodeInjection::Sink
    or this instanceof CommandInjection::Sink
    //or this instanceof TaintedPath::Sink
    or this instanceof XmlEntityInjection::Sink
    or this instanceof ResourceInjection::Sink
    or this instanceof RequestForgery::Sink
  }
}
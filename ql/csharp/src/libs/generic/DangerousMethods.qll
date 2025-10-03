import csharp
import libs.generic.GadgetTaintHelpers
import libs.generic.sinks.RequestForgery as RequestForgery
private import semmle.code.csharp.security.dataflow.flowsinks.FlowSinks
private import semmle.code.csharp.dataflow.internal.ExternalFlow
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

private class ExternalGadgetSink extends Sink {
  ExternalGadgetSink() { sinkNode(this, "gadget-sink") }
}

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
 * Sink for reflection. It includes property call / method call
 * 
 * We can't add it with a model see: https://github.com/github/codeql/discussions/19911#discussioncomment-14349249
 */
private class ReflectionSink extends Sink {
  ReflectionSink() {
    exists(Call c |
      (
        (
          c.getArgument(0) = this.asExpr() and 
          (
            (
              // System.Type.Get*(string)
              c.getTarget().getDeclaringType().hasFullyQualifiedName("System", "Type") and
              c.getTarget().hasName(["GetProperty", "GetMethod", "GetMember"])
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
              c.getTarget().getDeclaringType().hasFullyQualifiedName("System.Reflection", "MethodBase") and
              c.getTarget().hasName("Invoke")
            )
          )
        ) or
        (
          // System.Type.InvokeMember(...)
          c.getTarget().getDeclaringType().hasFullyQualifiedName("System", "Type") and
          c.getTarget().hasName("InvokeMember") and
          c.getArgumentForName(["name", "target", "args"]) = this.asExpr()
        )
      )
    )
  }
}

class DLLImport extends Method {
  DLLImport(){
    this.getAnAttribute().getType().hasName("DllImportAttribute")
  }

  string getLib(){
    exists(Attribute attr |
      this.getAnAttribute() = attr and
      attr.getConstructorArgument(0).(StringLiteral).getValue().toLowerCase() = result
    )
  }
}

class LinuxLoadLibDLLImportSink extends Sink {
  LinuxLoadLibDLLImportSink(){
    exists(MethodCall c, DLLImport m |
      c.getTarget() = m and 

      m.getLib() = "libdl.so" and
      m.getName() = "dlopen" and

      c.getArgument(0) = this.asExpr()
    )
  }
}

class MacLoadLibDLLImportSink extends Sink {
  MacLoadLibDLLImportSink(){
    exists(MethodCall c, DLLImport m |
      c.getTarget() = m and 

      m.getLib() = "libSystem.dylib" and
      m.getName() = "dlopen" and

      c.getArgument(0) = this.asExpr()
    )
  }
}

class WinLoadLibDLLImportSink extends Sink {
  WinLoadLibDLLImportSink(){
    exists(MethodCall c, DLLImport m |
      c.getTarget() = m and 

      m.getLib() = "kernel32.dll" and
      m.getName() = "LoadLibrary" and

      c.getArgument(0) = this.asExpr()
    )
  }
}

/**
 * Sink for dangerous file operations.
 * 
 * There is a lot of room for improvement.
 */
private class DangerousFileOperationSink extends Sink {
  DangerousFileOperationSink() {
    exists(MethodCall c, Method m |
      c.getARuntimeTarget() = m and

      // Select interesting classes
      getASuperType*(m.getDeclaringType()).hasFullyQualifiedName("System.IO", 
        ["FileStream", "Stream", "File", "Directory", "BinaryWriter", "MemoryStream", "StreamWriter", "StringWriter", "TextWriter"]
      ) and

      // filter methods
      m.getName().matches(["%Write%", "%Create%", "%Append%", "%Delete%", "%Open%", "%Replace%", "%Move%", "%Copy%", "Exists"]) and

      // filter arguments
      this.getExpr() = c.getArgumentForName(["path", "buffer", "value", "content", "contents"])
    ) or
    exists( Constructor m |
      getASuperType*(m.getDeclaringType()).hasFullyQualifiedName("System.IO", "FileStream") and
      this.getExpr() = m.getACall().getArgumentForName("path")
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
    // replaced by DangerousFileOperationSink
    //or this instanceof TaintedPath::Sink
    or this instanceof XmlEntityInjection::Sink
    or this instanceof ResourceInjection::Sink
    or this instanceof RequestForgery::Sink
  }
}
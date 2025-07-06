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
              c.getTarget().getDeclaringType().hasFullyQualifiedName("System.Reflection", "MethodInfo") and
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

/**
 * Sink for asembly loading operations.
 */
private class AssemblySink extends Sink {
  AssemblySink() {
    exists(MethodCall c |
      c.getTarget().getDeclaringType().hasFullyQualifiedName("System.Reflection", "Assembly") and
      (
        (
          // Assembly.LoadFrom(string)
          c.getTarget().hasName(["LoadFrom", "LoadFile"]) and
          c.getArgument(0) = this.asExpr()
        ) or 
        (
           // Assembly.Load(Byte[] ...)
          c.getTarget().hasName("Load") and
          c.getTarget().getParameter(0).getType().hasFullyQualifiedName("System", "Byte[]") and
          c.getArgument(0) = this.asExpr()
        )
      )
    )
  }
}

/**
  * A property assignment for ApplicationBase in a AppDomainSetup object.
  * 
  * Based on the Xunit1Executor gadget from @chudyPB
  */
private class AppDomainSetupSink extends Sink {
  AppDomainSetupSink() {
    exists(Property p |
      p.hasName("ApplicationBase") and
      p.getDeclaringType().hasFullyQualifiedName("System", "AppDomainSetup")
    |
      p.getAnAssignedValue() = this.asExpr()
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
 * Sink for Activator, not sure.
 */
private class ActivatorSink extends Sink {
  ActivatorSink() {
    exists(MethodCall c |
      c.getTarget().getDeclaringType().hasFullyQualifiedName("System", "Activator") and
      (
        (
           // Activator.CreateInstance (...)
          c.getTarget().hasName("CreateInstance") and
          c.getArgument(0) = this.asExpr()
        )
      )
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
      c.getTarget() = m and

      // Select interesting classes
      m.getDeclaringType*().hasFullyQualifiedName("System.IO", 
        ["FileStream", "Stream", "File", "Directory", "BinaryWriter", "MemoryStream", "StreamWriter", "StringWriter", "TextWriter"]
      ) and

      // filter methods
      m.getName().matches(["%Write%", "%Create%", "%Append%", "%Delete%", "%Open%", "%Replace%", "%Move%", "%Copy%"]) and

      // filter arguments
      this.getExpr() = c.getArgumentForName(["path", "buffer", "value", "content", "contents"])
    ) or
    exists( Constructor m |
      m.getDeclaringType*().hasFullyQualifiedName("System.IO", "FileStream") and
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
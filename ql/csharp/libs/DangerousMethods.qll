import csharp
import GadgetTaintHelpers
import RequestForgery as RequestForgery 
import SystemManagement
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

/**
  * AppDomain.SetData(sink, sink)
  */
private class AppDomainSink extends Sink {
  AppDomainSink() {
    exists(MethodCall c, Method m |
      c.getTarget() = m and
      m.getDeclaringType().hasFullyQualifiedName("System", "AppDomain") and
      m.hasName("SetData") and
      this.getExpr() = c.getAnArgument()
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
 * Sink for dangerous classes in System.Management like this:
 */
private class DangerousManagementSink extends Sink {
  DangerousManagementSink(){
    this.asExpr() = any(ManagementSink m).getASink()
  }
}

private class PSAutomationSink extends Sink {
  PSAutomationSink(){
    exists(Callable m, Call c |
      c.getTarget() = m and
      m.getDeclaringType().hasFullyQualifiedName("System.Management.Automation", "Powershell") and

      m.hasName(["AddCommand", "Create", "AddScript"]) and
      this.getExpr() = c.getArgument(0)  
    )
    or
    exists(Property p |
      p.hasName("Commands") and
      p.getDeclaringType().hasFullyQualifiedName("System.Management.Automation", "Powershell") and
      p.getAnAssignedValue() = this.asExpr()
    )
  }
}

/**
 * Stolen from the Veeam blacklist.
 * Probably found by CODE WHITE GmbH.
 * 
 * It triggers NTLM auth.
 */
private class ActivationContextSink extends Sink {
  ActivationContextSink(){
    exists(Callable m, Call c |
      c.getTarget() = m and
      m.getDeclaringType().hasFullyQualifiedName("System", "ActivationContext") and

      this.getExpr() = c.getArgumentForName("manifestPaths")
    )
  }
}

/**
 * URLDNS like gadgets
 * 
 * Internally calls System.IO.LongPathHelper.TryExpandShortFileName
 */
private class ShortNameSink extends Sink {
  ShortNameSink(){
    exists(Method m, MethodCall c |
      c.getTarget() = m and
      m.getDeclaringType().hasFullyQualifiedName("System.IO", "Path") and
      m.hasName("GetFullPath") and
      m.isStatic() and

      // Path.GetFullPath(string path)
      this.getExpr() = c.getArgument(0)
    )
  }
}

/**
 * DataSet/DataTable
 */
private class DataSink extends Sink {
  DataSink(){
    exists(Method m, MethodCall c |
      c.getTarget() = m and
      getASuperType*(m.getDeclaringType()).hasFullyQualifiedName("System.Data", ["DataSet", "DataTable"]) and
      m.getName().matches("ReadXml%") and

      this.getExpr() = c.getArgument(0)
    )
  }
}

private class DirectoryEntrySink extends Sink {
  DirectoryEntrySink(){
    exists(Constructor m, Call c |
      c.getTarget() = m and
      m.getDeclaringType().hasFullyQualifiedName("System.DirectoryServices", "DirectoryEntry") and

      this.getExpr() = c.getArgumentForName("path")
    )
  }
}

/**
 * XmlDocument
 * No XXE by default but idk it might give some new vectors.
 */
private class XmlDocumentSink extends Sink {
  XmlDocumentSink(){
    exists(Method m, MethodCall c |
      c.getTarget() = m and
      getASuperType*(m.getDeclaringType()).hasFullyQualifiedName("System.Xml", "XmlDocument") and
      m.getName().matches("Load%") and

      this.getExpr() = c.getArgument(0)
    )
  }
}

/**
 * WorkflowMarkupSerializer / WorkflowMarkupSerializationHelpers
 * 
 * XOML deserialization
 */
private class WorkflowMarkupSerializerSink extends Sink {
  WorkflowMarkupSerializerSink(){
    exists(Method m, MethodCall c |
      c.getTarget() = m and
      getASuperType*(m.getDeclaringType()).hasFullyQualifiedName("System.Workflow.ComponentModel.Serialization", ["WorkflowMarkupSerializer", "WorkflowMarkupSerializationHelpers"]) and
      m.hasName(["Deserialize", "LoadXomlDocument"]) and

      this.getExpr() = c.getArgumentForName(["reader", "textReader"])
    )
  }
}

/**
 * WorkflowTheme
 * 
 * Call WorkflowMarkupSerializer.Deserialize
 */
private class WorkflowThemeSink extends Sink {
  WorkflowThemeSink(){
    exists(Method m, MethodCall c |
      c.getTarget() = m and
      getASuperType*(m.getDeclaringType()).hasFullyQualifiedName("System.Workflow.ComponentModel.Design", "WorkflowTheme") and
      m.hasName("Load") and

      this.getExpr() = c.getArgumentForName("themeFilePath")
    )
  }
}

/**
 * WorkflowDesignerLoader
 */
private class WorkflowDesignerLoaderSink extends Sink {
  WorkflowDesignerLoaderSink(){
    exists(Method m, MethodCall c |
      c.getTarget() = m and
      getASuperType*(m.getDeclaringType()).hasFullyQualifiedName("System.Workflow.ComponentModel.Design", "WorkflowDesignerLoader") and
      m.hasName("GetFileReader") and

      this.getExpr() = c.getArgumentForName("filePath")
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
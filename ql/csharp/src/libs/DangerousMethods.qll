import csharp
import GadgetTaintHelpers
import RequestForgery as RequestForgery 
import SystemManagement
import ComponentModel
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
  * AppDomain
  */
private class AppDomainSink extends Sink {
  AppDomainSink() {
    exists(MethodCall c, Method m |
      c.getTarget() = m and
      m.getDeclaringType().hasFullyQualifiedName("System", "AppDomain") and
      m.hasName(["SetData", "Deserialize"]) and

      this.getExpr() = c.getArgumentForName(["name", "data", "blob"])
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

/**
 * we can pass many path types in the constructor that might result in 
 * implicit authentication if entries are fetched.
 */
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
 * SessionSecurityTokenHandler
 */
private class SessionSecurityTokenHandlerSink extends Sink {
  SessionSecurityTokenHandlerSink(){
    exists(Method m, MethodCall c |
      c.getTarget() = m and
      getASuperType*(m.getDeclaringType()).hasFullyQualifiedName("System.IdentityModel.Tokens", "SessionSecurityTokenHandler") and
      m.hasName("ReadToken") and

      this.getExpr() = c.getArgument(0)
    )
  }
}

/**
 * WorkflowDesigner
 */
private class WorkflowDesignerSink extends Sink {
  WorkflowDesignerSink(){
    exists(Method m, MethodCall c |
      c.getTarget() = m and
      getASuperType*(m.getDeclaringType()).hasFullyQualifiedName("System.Activities.Presentation", "WorkflowDesigner") and
      m.hasName("set_PropertyInspectorFontAndColorData") and

      this.getExpr() = c.getArgument(0)
    )
  }
}

private class XamlImageInfoSink extends Sink {
  XamlImageInfoSink(){
    exists(Constructor m, Call c |
      c.getTarget() = m and
      m.getDeclaringType().hasFullyQualifiedName("System.Activities.Presentation.Internal", "ManifestImages+XamlImageInfo") and

      this.getExpr() = c.getArgumentForName("stream")
    )
  }
}

/**
 * Adding sinks from this paper
 * https://soroush.me/downloadable/use_of_deserialisation_in_dotnet_framework_methods_and_classes.pdf
 * 
 * While CodeQL should be able to find them if the DLL is analyzed, it can be useful for future research.
 */

private class ResourceReaderSink extends Sink {
  ResourceReaderSink(){
    exists(Constructor m, Call c |
      c.getTarget() = m and
      m.getDeclaringType().hasFullyQualifiedName("System.Resources", "ResourceReader") and

      this.getExpr() = c.getArgument(0)
    )
  }
}

private class ResourceManagerSink extends Sink {
  ResourceManagerSink(){
    exists(Method m, MethodCall c |
      c.getTarget() = m and
      m.getDeclaringType().hasFullyQualifiedName("System.Resources", "ResourceManager") and
      m.hasName(["GetObject"]) and

      this.getExpr() = c.getArgument(0)
    )
  }
}

private class SettingsPropertyValueSink extends Sink {
  SettingsPropertyValueSink(){
    exists(Constructor m, Call c |
      c.getTarget() = m and
      m.getDeclaringType().hasFullyQualifiedName("System.Configuration", "SettingsPropertyValue") and

      this.getExpr() = c.getArgument(0)
    )
  }
}

private class TypedDataSetGeneratorSink extends Sink {
  TypedDataSetGeneratorSink(){
    exists(Method m, MethodCall c |
      c.getTarget() = m and
      getASuperType*(m.getDeclaringType()).hasFullyQualifiedName("System.Data.Design", "TypedDataSetGenerator") and
      m.hasName(["Generate", "GetProviderName"]) and

      this.getExpr() = c.getArgumentForName(["inputFileContent"])
    )
  }
}

private class MethodSignatureGeneratorSink extends Sink {
  MethodSignatureGeneratorSink(){
    exists(Method m, MethodCall c |
      c.getTarget() = m and
      getASuperType*(m.getDeclaringType()).hasFullyQualifiedName("System.Data.Design", "MethodSignatureGenerator") and
      m.hasName("SetMethodSourceContent") and

      this.getExpr() = c.getArgumentForName("methodSourceContent")
    )
  }
}

private class TypedDataSetSchemaImporterExtensionSink extends Sink {
  TypedDataSetSchemaImporterExtensionSink(){
    exists(Method m, MethodCall c |
      c.getTarget() = m and
      getASuperType*(m.getDeclaringType()).hasFullyQualifiedName("System.Data.Design", "TypedDataSetSchemaImporterExtension") and
      m.hasName("ImportSchemaType") and

      this.getExpr() = c.getArgumentForName("schemas")
    )
  }
}

private class DbConvertSink extends Sink {
  DbConvertSink(){
    exists(Method m, MethodCall c |
      c.getTarget() = m and
      getASuperType*(m.getDeclaringType()).hasFullyQualifiedName("System.Data.Linq", "DBConvert") and
      m.hasName("ChangeType") and

      this.getExpr() = c.getArgumentForName("value")
    )
  }
}

private class ApplicationTrustSink extends Sink {
  ApplicationTrustSink(){
    exists(Method m, MethodCall c |
      c.getTarget() = m and
      getASuperType*(m.getDeclaringType()).hasFullyQualifiedName("System.Security.Policy", "ApplicationTrust") and
      m.hasName("ObjectFromXml") and

      this.getExpr() = c.getArgumentForName("elObject")
    )
  }
}

private class OutputCacheSink extends Sink {
  OutputCacheSink(){
    exists(Method m, MethodCall c |
      c.getTarget() = m and
      getASuperType*(m.getDeclaringType()).hasFullyQualifiedName("System.Web.Caching", "OutputCache") and
      m.hasName("Deserialize") and

      this.getExpr() = c.getArgumentForName("stream")
    )
  }
}

private class AltSerializationSink extends Sink {
  AltSerializationSink(){
    exists(Method m, MethodCall c |
      c.getTarget() = m and
      m.getDeclaringType().hasFullyQualifiedName("System.Web.Util", "AltSerialization") and
      m.hasName("ReadValueFromStream") and

      this.getExpr() = c.getArgumentForName("reader")
    )
  }
}

/**
 * SessionStateItemCollection sink is in DeserializeItem, but the stream is set in Deserialize.
 * 
 * need to check this one.
 */
private class AltSerialization2Sink extends Sink {
  AltSerialization2Sink(){
    exists(Method m, MethodCall c |
      c.getTarget() = m and
      m.getDeclaringType().hasFullyQualifiedName(["System.Web", "System.Web.SessionState"], ["HttpStaticObjectsCollection", "SessionStateItemCollection"]) and
      m.hasName("Deserialize") and

      this.getExpr() = c.getArgumentForName("reader")
    )
  }
}

private class DataObjectSink extends Sink {
  DataObjectSink(){
    exists(Method m, MethodCall c |
      c.getTarget() = m and
      m.getDeclaringType().hasFullyQualifiedName(["System.Windows.Forms", "System.Windows"], "DataObject") and
      m.hasName(["ReadObjectFromHandleDeserializer", "ReadObjectFromHandle", "SetData"]) and

      this.getExpr() = c.getArgumentForName(["stream", "handle", "data"])
    )
  }
}

private class SecurityExceptionSink extends Sink {
  SecurityExceptionSink(){
    exists(Method m, MethodCall c |
      c.getTarget() = m and
      m.getDeclaringType().hasFullyQualifiedName("System.Security", "SecurityException") and
      m.hasName("ByteArrayToObject") and

      this.getExpr() = c.getArgumentForName("array")
    )
  }
}

private class RolePrincipalSink extends Sink {
  RolePrincipalSink(){
    exists(Callable m, Call c |
      c.getTarget() = m and
      getASuperType*(m.getDeclaringType()).hasFullyQualifiedName("System.Web.Security", "RolePrincipal") and
      m.hasName(["InitFromEncryptedTicket", "RolePrincipal"]) and

      this.getExpr() = c.getArgumentForName("encryptedTicket")
    )
  }
}

private class IsolatedStorageSink extends Sink {
  IsolatedStorageSink(){
    exists(Method m, MethodCall c |
      c.getTarget() = m and
      getASuperType*(m.getDeclaringType()).hasFullyQualifiedName("System.IO.IsolatedStorage", "IsolatedStorage") and
      m.hasName("InitStore") and
      m.getRawParameter(3).getDeclaringType().hasName("Stream") and

      this.getExpr() = c.getArgumentForName(["domain","app", "assem"])
    )
  }
}

private class MsmqDecodeHelperSink extends Sink {
  MsmqDecodeHelperSink(){
    exists(Method m, MethodCall c |
      c.getTarget() = m and
      getASuperType*(m.getDeclaringType()).hasFullyQualifiedName("System.ServiceModel.Channels", "MsmqDecodeHelper") and
      m.hasName("DeserializeForIntegration") and

      this.getExpr() = c.getArgumentForName("bodyStream")
    )
  }
}

private class TransactionsSink extends Sink {
  TransactionsSink(){
    exists(Method m, MethodCall c |
      c.getTarget() = m and
      getASuperType*(m.getDeclaringType()).hasFullyQualifiedName(["System.Transactions.Oletx", "System.Transactions"], ["OletxResourceManager", "TransactionManager"]) and
      m.hasName("Reenlist") and

      this.getExpr() = c.getArgumentForName(["prepareInfo", "recoveryInformation"])
    )
  }
}

// SqlTrackingWorkflowInstance skipped, it require SQL injection.

private class ApplicationProxyInternalSink extends Sink {
  ApplicationProxyInternalSink(){
    exists(Method m, MethodCall c |
      c.getTarget() = m and
      getASuperType*(m.getDeclaringType()).hasFullyQualifiedName("MS.Internal.AppModel", "ApplicationProxyInternal") and
      m.hasName("DeserializeJournaledObject") and

      this.getExpr() = c.getArgumentForName("inputStream")
    )
  }
}

private class DataStreamsSink extends Sink {
  DataStreamsSink(){
    exists(Method m, MethodCall c |
      c.getTarget() = m and
      getASuperType*(m.getDeclaringType()).hasFullyQualifiedName("MS.Internal.AppModel", "DataStreams") and
      m.hasName("LoadSubStreams") and

      this.getExpr() = c.getArgumentForName("subStreams")
    )
  }
}

private class ControlSink extends Sink {
  ControlSink(){
    exists(Method m, MethodCall c |
      c.getTarget() = m and
      getASuperType*(m.getDeclaringType()).hasFullyQualifiedName("System.Windows.Forms", "Control") and
      m.hasName(["Load", "Read"]) and

      this.getExpr() = c.getArgumentForName(["pPropBag", "istream", "stream"])
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
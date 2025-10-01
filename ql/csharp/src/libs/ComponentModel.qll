import csharp
import DangerousMethods

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
 * Activity
 * 
 * based on: https://github.com/seresharp/NetPositive/blob/ec6db41da25c0cba96d2a8a7cd9308b0118f06d7/NetPositive/Definitions/Methods/IndirectDeserialization.json#L5
 */
private class ActivitySink extends Sink {
  ActivitySink(){
    exists(Method m, MethodCall c |
      c.getTarget() = m and
      getASuperType*(m.getDeclaringType()).hasFullyQualifiedName("System.Workflow.ComponentModel", "Activity") and
      m.hasName("Load") and

      this.getExpr() = c.getArgument(0)
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
      m.hasName(["GetFileReader", "LoadDesignerLayout"]) and

      this.getExpr() = c.getArgumentForName(["filePath", "layoutReader"])
    )
  }
}

/**
 * XomlComponentSerializationService
 */
private class XomlComponentSerializationServiceSink extends Sink {
  XomlComponentSerializationServiceSink(){
    exists(Method m, MethodCall c |
      c.getTarget() = m and
      getASuperType*(m.getDeclaringType()).hasFullyQualifiedName("System.Workflow.ComponentModel.Design", "XomlComponentSerializationService") and
      m.hasName(["LoadStore", "Deserialize", "DeserializeTo"]) and

      this.getExpr() = c.getArgumentForName(["stream", "store"])
    )
  }
}

/**
 * CompositeActivityDesigner
 */
private class CompositeActivityDesignerSink extends Sink {
  CompositeActivityDesignerSink(){
    exists(Method m, MethodCall c |
      c.getTarget() = m and
      getASuperType*(m.getDeclaringType()).hasFullyQualifiedName("System.Workflow.ComponentModel.Design", "CompositeActivityDesigner") and
      m.hasName("DeserializeActivitiesFromDataObject") and

      this.getExpr() = c.getArgumentForName("dataObj")
    )
  }
}
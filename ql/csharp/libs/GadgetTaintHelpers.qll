import csharp
import semmle.code.csharp.dataflow.TaintTracking
import semmle.code.csharp.dataflow.DataFlow
import semmle.code.csharp.serialization.Serialization
import codeql.util.Unit
import Source

class GadgetAdditionalTaintStep extends Unit {
    /**
     * Holds if the step from `node1` to `node2` should be considered a taint
     * step for the `GadgetFinderConfig` configuration.
     */
    abstract predicate step(DataFlow::Node node1, DataFlow::Node node2);
}

/**
 * We want to propagate output of SerializationInfo:
 * 
 *  Data = info.GetString("Data");
 */
class SerializationInfoGetTaintStep extends GadgetAdditionalTaintStep {
  override predicate step(DataFlow::Node fromNode, DataFlow::Node toNode) {
    exists(MethodCall mc, Method m |
      mc.getTarget() = m and
      m.getName().matches("Get%") and
      m.getDeclaringType().hasFullyQualifiedName("System.Runtime.Serialization", "SerializationInfo") and

      // Taint flows from the qualifier (info) to the call result
      fromNode.asExpr() = mc.getQualifier() and
      toNode.asExpr() = mc
    )
  }
}


/**
 * Not perfect but it works. `TaintInheritingContentis` not available in csharp
 * We taint each `AssignableMemberAccess` (Field /Member) if it's accessed from
 * a GadgetSource Callable.
 * 
 * This is useful for deserilization callbacks.
 */
class GadgetSourceAssignableMemberAccess extends AssignableMemberAccess {
    GadgetSourceAssignableMemberAccess(){
        exists(Callable c, AssignableMember f | 
            this.getEnclosingCallable() = c and
            reachableFromOnDeserialized(c) and
            this = f.getAnAccess() and
            f instanceof SerializedMember
        )
    }
}

/**
 * Hold if there is a path between a `GadgetSource` method 
 * and `dst`.
 */
predicate reachableFromOnDeserialized(Callable dst) {
  exists(Callable src |
    src instanceof GadgetSource and 
    src.calls*(dst)
  )
}

/**
   * A field/property that can be serialized, either explicitly
   * or as a member of a serialized type.
   */
  private class SerializedMember extends AssignableMember {
    SerializedMember() {

      // This field is a member of an explicitly serialized type
      this.getDeclaringType() instanceof SerializableType and
      not this.(Attributable).getAnAttribute().getType() instanceof NotSerializedAttributeClass
    }
  }

/*
private class JsonSerializedMemberAttributeClass extends Class {
    JsonSerializedMemberAttributeClass(){
        this.hasName([
                "JsonPropertyAttribute", "JsonDictionaryAttribute", "JsonRequiredAttribute",
                "JsonArrayAttribute", "JsonConverterAttribute", "JsonExtensionDataAttribute",
                "SerializableAttribute", // System.SerializableAttribute
                "DataMemberAttribute" // System.DataMemberAttribute
              ])
    }
}
*/

/** Any attribute class that marks a member to not be serialized. */
class NotSerializedAttributeClass extends Class {
    NotSerializedAttributeClass() {
      this.hasName(["JsonIgnoreAttribute", "NonSerializedAttribute"])
    }
  }

Callable getSourceCallable(DataFlow::Node n){
    result = n.asParameter().getCallable() or
    exists(Call call |
      call.getAnArgument() = n.asExpr() |
      result = call.getTarget()
    )
}
  
/**
 * Just display location of a Node as a string with line an column info:
 *  readObject (Myclass:10:43)
 */
string getSourceLocationInfo(DataFlow::Node n){
    result = getSourceCallable(n) + " (" + n.getEnclosingCallable().getDeclaringType().toString() + ":" + n.getLocation().getStartLine() + ":" + n.getLocation().getStartColumn() + ")"
}
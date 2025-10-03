import csharp
import semmle.code.csharp.dataflow.TaintTracking
import semmle.code.csharp.dataflow.DataFlow
import semmle.code.csharp.serialization.Serialization
private import semmle.code.csharp.dataflow.internal.DataFlowPrivate as DataFlowPrivate
import codeql.util.Unit

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
 * Propagates taint from a tainted element to a serializable field or property access:
 * 
 *    object res = fromNode.ToNode
 * 
 * Since `SerializationInfo` is also controlled we add an exception for the 
 * `System.Runtime.Serialization` namespace to catch this:
 * 
 *    SerializationInfo info
 *    SerializationInfoEnumerator enumerator = info.GetEnumerator();
 *    (byte[])enumerator.Value;
 * 
 * Poor attempt to mimic `TaintInheritingContents`.
 */
class SerializableAssignableTaintStep extends GadgetAdditionalTaintStep {

  override predicate step(DataFlow::Node fromNode, DataFlow::Node toNode) {
    exists(AssignableMemberAccess acc, AssignableMember m |
      acc.getTarget() = m and

      (
        m instanceof SerializableMember or
        acc.getQualifier().getType().hasFullyQualifiedName("System.Runtime.Serialization", _)
      ) and

      // Taint flows from the qualifier to the member access
      fromNode.asExpr() = acc.getQualifier() and
      toNode.asExpr() = acc
    )
  }
}

/**
   * A field/property that can be serialized.
   */
  abstract class SerializableMember extends AssignableMember {}

  class DefaultSerializableMember extends SerializableMember {
    DefaultSerializableMember() {
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
abstract class NotSerializedAttributeClass extends Class { }

/** Any attribute class that marks a member to be serialized. */
class SerializedAttributeClass extends Class {
    SerializedAttributeClass() {
      this.hasName(["SerializableAttribute"])
    }
  }

/**
 * Predicate to check wether a type is a string or a generic type.
 */
predicate isStringOrGeneric(Type t) {
  t instanceof StringType or
  t instanceof TypeParameter or
  t instanceof ObjectType
}

predicate isGenericType(Type t) {
  t instanceof TypeParameter or
  t instanceof ObjectType
}

ValueOrRefType getASuperType(ValueOrRefType t) { t.getABaseType() = result }

/**
 * Try to get a callable from a node.
 * 
 * If you add a new source type you might 
 * need to add logic here to see it in the result.
 * The last condition is however quite permissive.
 */
Callable getSourceCallable(DataFlow::Node n){
    result = n.asParameter().getCallable() or
    exists(Call call |
      call.getAnArgument() = n.asExpr() |
      result = call.getTarget()
    ) or
    result = n.(DataFlowPrivate::InstanceParameterNode).getCallable(_) or
    result = n.asExpr().getEnclosingCallable()
}
  
/**
 * Just display location of a Node as a string with line an column info:
 *  readObject (Myclass:10:43)
 */
string getSourceLocationInfo(DataFlow::Node n){
    result = getSourceCallable(n) + " (" + n.getEnclosingCallable().getDeclaringType().toString() + ":" + n.getLocation().getStartLine() + ":" + n.getLocation().getStartColumn() + ")"
}
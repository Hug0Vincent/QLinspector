import java
import semmle.code.java.dataflow.TaintTracking


class GadgetAdditionalTaintStep extends Unit {
    /**
     * Holds if the step from `node1` to `node2` should be considered a taint
     * step for the `GadgetFinderConfig` configuration.
     */
    abstract predicate step(DataFlow::Node node1, DataFlow::Node node2);
}
  
/**
 * We want to propagate output of getters:
 * 
 *  Obj sink = taintedSource.getField();
 * 
 * In this example we add a taint on the sink object.
 */
class GetterTaintStep extends GadgetAdditionalTaintStep {
    override predicate step(DataFlow::Node fromNode, DataFlow::Node toNode) {
        exists(MethodCall ma, Method m | 
        
        ma.getMethod() = m and
        m.getName().matches("get%") and
        m.getNumberOfParameters() = 0 and
        
        fromNode.asExpr() = ma.getQualifier() and
        toNode.asExpr() = ma
        
        )
    }
}
  
/**
 * We want to propagate output of setters:
 * 
 *  Obj sink = new CustomObject();
 *  sink.setField(taintedSource);
 * 
 * In this example we add a taint on the sink object.
 */
class SetterTaintStep extends GadgetAdditionalTaintStep {
    override predicate step(DataFlow::Node fromNode, DataFlow::Node toNode) {
        exists(MethodCall ma, Method m | 
        
        ma.getMethod() = m and
        m.getName().matches("set%") and
        m.getNumberOfParameters() = 1 and
        
        fromNode.asExpr() = ma.getArgument(0) and
        toNode.asExpr() = ma.getQualifier()
        
        )
    }
}
  
/**
 * We want to taint constructed object where the constructor takes our sourceNode
 * as parameter:
 * 
 *  CustomObject toNode = new CustomObject(arg1, fromNode, arg3);
 */
class ConstructorTaintStep extends GadgetAdditionalTaintStep {
    override predicate step(DataFlow::Node fromNode, DataFlow::Node toNode) {
        exists(ConstructorCall ma | 
        
        fromNode.asExpr() = ma.getAnArgument() and
        toNode.asExpr() = ma
        
        )
    }
}
  
  
/**
 * We want to add additional taint step when the ObjectInputStream is accessed
 * Like this:
 * 
 *  private void readObject(ObjectInputStream fromNode) {
 *      ObjectInputStream.GetField gf = fromNode.readFields();
 *      Object toNode = gf.get("val", null);
 *      ...
 *      dangerousMethod(toNode)
 */
class ObjectInputStreamTaintStep extends GadgetAdditionalTaintStep {
    override predicate step(DataFlow::Node fromNode, DataFlow::Node toNode) {
      exists(MethodCall mc, Method m | 
        (
          (
            mc.getMethod() = m and
            m.getName().matches("read%") and
            m.getDeclaringType().hasQualifiedName("java.io", "ObjectInputStream")
          ) 
          or
          (
            mc.getMethod() = m and
            m.hasName("get") and
            m.getDeclaringType().getASupertype*().hasQualifiedName("java.io", "ObjectInputStream$GetField")
          )
        )
        
        and
        
        fromNode.asExpr() = mc.getQualifier() and
        toNode.asExpr() = mc
        
      )
    }
}

Callable getSourceCallable(DataFlow::Node n){
    result = n.asParameter().getCallable() or 
    result = n.(DataFlow::InstanceParameterNode).getCallable()
}
  
/**
 * Just display location of a Node as a string with line an column info:
 *  readObject (Myclass:10:43)
 */
string getSourceLocationInfo(DataFlow::Node n){
    result = getSourceCallable(n) + " (" + n.getEnclosingCallable().getDeclaringType().toString() + ":" + n.getLocation().getStartLine() + ":" + n.getLocation().getStartColumn() + ")"
}
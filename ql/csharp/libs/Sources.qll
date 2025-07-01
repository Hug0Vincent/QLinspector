import csharp
import semmle.code.csharp.serialization.Serialization
import NewtonsoftJson
private import semmle.code.csharp.dataflow.internal.DataFlowPrivate as DataFlowPrivate

/**
 * A data flow source for a gadget.
 */
abstract class Source extends DataFlow::Node { }

class ParameterSource extends Source {
    ParameterSource(){
        this.asParameter().getCallable() instanceof GadgetSource or
        this.(DataFlowPrivate::InstanceParameterNode).getCallable(_) instanceof GadgetSource
    }  
}

/*
class TmpMemberAccess extends Source {
    TmpMemberAccess(){
        this.asExpr() instanceof GadgetSourceAssignableMemberAccess
    }  
}
*/

/**
 * In his research: https://github.com/thezdi/presentations/blob/main/2023_Hexacon/whitepaper-net-deser.pdf
 * @chudyPB has identified several deserialization gadgets that can be activated by an arbitrary getter call like:
 *  - SecurityException
 *  - SettingsPropertyValue
 */
class GetterSource extends Source {
    GetterSource(){
        this.(DataFlowPrivate::InstanceParameterNode).getCallable(_) instanceof Getter
    }
}

class GadgetSource extends Callable {
    GadgetSource(){
        this = any(SerializableType s).getAnAutomaticCallback()
    }
}
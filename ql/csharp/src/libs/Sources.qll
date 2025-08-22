import csharp
import semmle.code.csharp.serialization.Serialization
import NewtonsoftJson
private import semmle.code.csharp.dataflow.internal.DataFlowPrivate as DataFlowPrivate
import semmle.code.csharp.dispatch.OverridableCallable

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
/*
class GetterSource extends Source {
    GetterSource(){
        this.(DataFlowPrivate::InstanceParameterNode).getCallable(_) instanceof Getter
    }
}
*/

class ObjectMethodSource extends Source {
    ObjectMethodSource(){
        exists(OverridableCallable baseMethod, SerializableType t |
            baseMethod.getDeclaringType() instanceof ObjectType and
            baseMethod.hasName(["ToString", "GetHashCode", "Equals"]) and
            this.(DataFlowPrivate::InstanceParameterNode).getCallable(_) = baseMethod.getInherited(t)
        )
    }
}

class TypeConverterSource extends Source {
    TypeConverterSource(){
        exists(OverridableCallable baseMethod, SerializableType t |
            baseMethod.getDeclaringType().hasFullyQualifiedName("System.ComponentModel", "TypeConverter") and
            baseMethod.hasName("ConvertFrom") and
            this.asParameter() = baseMethod.getInherited(t).getParameter(2)
        )
    }
}

class GadgetSource extends Callable {
    GadgetSource(){
        this = any(SerializableType s).getAnAutomaticCallback()
    }
}
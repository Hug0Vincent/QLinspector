import csharp
import semmle.code.csharp.serialization.Serialization
import NewtonsoftJson

class GadgetSource extends Callable {
    GadgetSource(){
        this = any(SerializableType s).getAnAutomaticCallback()
    }
}
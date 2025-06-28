import csharp
import semmle.code.csharp.serialization.Serialization
import NewtonsoftJson

/**
 * A data flow source for a gadget.
 */
abstract class Source extends DataFlow::Node { }

class GadgetSource extends Callable {
    GadgetSource(){
        this = any(SerializableType s).getAnAutomaticCallback()
    }
}
import csharp
import GadgetTaintHelpers

/** Abstract base for any WMI-related callable sink. */
abstract class ManagementSink extends Callable {
  /** Returns an expression that is a sink (i.e., a dangerous argument to this callable). */
  abstract Expr getASink();
}

class ManagementObjectSink extends ManagementSink {
    ManagementObjectSink(){
        getASuperType*(this.getDeclaringType()).hasFullyQualifiedName("System.Management", "ManagementObject") and
        (   
            this instanceof Constructor or
            this.hasName("InvokeMethod")
        ) 
    }

    override Expr getASink(){
        result = this.getACall().getArgumentForName(["methodName", "args", "path", "options"])
    }
}

class ManagementObjectSearcherSink extends ManagementSink {
    ManagementObjectSearcherSink(){
        this.getDeclaringType().hasFullyQualifiedName("System.Management", "ManagementObjectSearcher") and
        this instanceof Constructor
    }

    override Expr getASink(){
        result = this.getACall().getArgumentForName("query")
    }
}

class ObjectQuerySink extends ManagementSink {
    ObjectQuerySink(){
        getASuperType*(this.getDeclaringType()).hasFullyQualifiedName("System.Management", "ObjectQuery") and
        (   
            this instanceof Constructor or
            this.hasName("ParseQuery")
        ) 
    }

    override Expr getASink(){
        result = this.getACall().getArgumentForName("query")
    }
}

class ManagementScopeSink extends ManagementSink {
    ManagementScopeSink(){
        this.getDeclaringType().hasFullyQualifiedName("System.Management", "ManagementScope") and
        this instanceof Constructor
    }

    override Expr getASink(){
        result = this.getACall().getArgumentForName("path")
    }
}
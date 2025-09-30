/**
 * @id synacktiv/csharp/sink-to-model
 * @description Transform a sink to a model
 * @name sink-to-model
 * @kind table
 */

import csharp
import libs.DangerousMethods as DangerousMethods
private import semmle.code.csharp.security.dataflow.flowsinks.FlowSinks

class GadgetSink extends Callable {

    Parameter p;

    GadgetSink(){
        (
            this.getDeclaringType().hasFullyQualifiedName("", "") and
            this.hasName("") and
            p = this.getAParameter() and 
            p.hasName("")
        )or
        (
           this.getDeclaringType().hasFullyQualifiedName("", "") and
            this.hasName("") and
            p = this.getParameter(0)
        )
    }

    int getParamPosition(){
        p = this.getParameter(result)
    }

    string getSignature(){
        result = "(" + this.parameterTypesToString() + ")"
    }

    string generateModel(){
        result = "- [\"" +
        this.getDeclaringType().getNamespace() + 
        "\", \"" +
        this.getDeclaringType() +
        "\", True, \"" +
        this.getName() +
        "\", \"" +
        this.getSignature() +
        "\", \"\", " +
        "\"Argument[" + getParamPosition() + "]\", \"gadget-sink\", \"manual\"]"
    }

    private string parameterTypeToString(int i) {
        exists(Parameter param | 
            param = this.getParameter(i) and
            result = param.getType().getFullyQualifiedName()
        )
    }

    language[monotonicAggregates]
    override string parameterTypesToString() {
        result =
        concat(int i | exists(this.getParameter(i)) | this.parameterTypeToString(i), "," order by i)
    }

}

from GadgetSink s
select s.generateModel()
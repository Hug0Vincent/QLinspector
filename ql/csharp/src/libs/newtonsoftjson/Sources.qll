import csharp
import libs.newtonsoftjson.NewtonsoftJson
import libs.generic.Sources
import semmle.code.csharp.dispatch.OverridableCallable

class NewtonsoftJsonGadgetSource extends GadgetSource {
  NewtonsoftJsonGadgetSource() {
    this = any(JsonSerializableType j).getAnAutomaticCallback()
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
import csharp
import semmle.code.csharp.serialization.Serialization
import libs.GadgetTaintHelpers

/**
 * A constructor marked with the [JsonConstructor] attribute.
 */
class JsonConstructor extends Constructor {
  JsonConstructor() {
    this.(Attributable).getAnAttribute().getType().hasName("JsonConstructorAttribute")
  }
}

/**
 * A type serializable by Newtonsoft.Json, considering typical Json.NET serialization
 * conventions: public parameterless constructor, [JsonConstructor], or single public constructor.
 */
class JsonSerializableType extends SerializableType {

    JsonSerializableType() { this.getAnAttribute().getType().hasName("SerializableAttribute") }
  

  /**
   * Json.NET deserialization callbacks, like methods marked with [OnDeserializing]/[OnDeserialized] or constructors.
   */
  override Callable getADeserializationCallback() {
    exists(Callable c | 
      c instanceof JsonSerilizationCallBack and 
      this.hasCallable(c) and
      c = result
    )
  }

  /**
   * Json.NET serialized members: properties or fields with common JSON attributes.
   */
  override Field getASerializedField() {
    result.getDeclaringType() = this and
    (
      // Has relevant Json.NET attributes (JsonProperty, JsonRequired, JsonIgnore, etc.)
      exists(Attribute attr | 
        attr = result.getAnAttribute() and
        attr.getType().hasName([
                "JsonPropertyAttribute", "JsonDictionaryAttribute", "JsonRequiredAttribute",
                "JsonArrayAttribute", "JsonConverterAttribute", "JsonExtensionDataAttribute",
                "SerializableAttribute", // System.SerializableAttribute
                "DataMemberAttribute" // System.DataMemberAttribute
              ])
      )
      or
      // Public properties or fields without [JsonIgnore]
      (
        result.isPublic()
      )
      and not result.getAnAttribute().getType() instanceof NotSerializedAttributeClass
    )
  }
}

abstract class JsonSerilizationCallBack extends Callable {}

class JsonConstructorSerilizationCallBack extends JsonSerilizationCallBack {
    JsonConstructorSerilizationCallBack(){
      this instanceof JsonConstructor
      or
      // Public parameterless constructor
      (
        this.(Constructor).getNumberOfParameters() = 0 and 
        this.(Constructor).isPublic()
      )
      or
      // Single public constructor with parameters
      (
        count(Constructor c |c = this.getDeclaringType().getAConstructor()) = 1 and
        this.(Constructor).isPublic()
      )
    }
}

class JsonDecoratorSerilizationCallBack extends JsonSerilizationCallBack, Method {
    JsonDecoratorSerilizationCallBack(){
        this.(Attributable).getAnAttribute().getType().hasName("OnDeserializedAttribute") or
        this.(Attributable).getAnAttribute().getType().hasName("OnDeserializingAttribute")
    }
}

class JsonSettersSerilizationCallBack extends JsonSerilizationCallBack, Setter {
    JsonSettersSerilizationCallBack(){
        exists(Property p |
          p.getDeclaringType() = this.getDeclaringType() and
          p.getSetter() = this and
          this.isPublic()
      )
    }
}

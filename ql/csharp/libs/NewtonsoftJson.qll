import csharp
import semmle.code.csharp.serialization.Serialization
import libs.GadgetTaintHelpers

/**
 * A type serializable by Newtonsoft.Json, considering typical Json.NET serialization
 * conventions: public parameterless constructor, [JsonConstructor], or single public constructor.
 */
class JsonSerializableType extends SerializableType {

    // Every type is serializable
    JsonSerializableType() { this.getAConstructor()  instanceof JsonConstructorSerilizationCallBack}
    //JsonSerializableType() { none()}

  /**
   * Json.NET deserialization callbacks, like methods marked with [OnDeserializing]/[OnDeserialized] or constructors.
   */
  override Callable getADeserializationCallback() {
    result instanceof JsonSerilizationCallBack and 
    result.getDeclaringType() = this
  }

  /**
   * Not working, the `SerializableType` type force the return value to be a `Field` 
   * but we can have `Property`.
   * 
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

/**
 * A constructor marked with the [JsonConstructor] attribute.
 */
class JsonConstructor extends Constructor {
  JsonConstructor() {
    this.(Attributable).getAnAttribute().getType().hasName("JsonConstructorAttribute")
  }
}

/**
 * A method that can be called during Json.net deserialization.
 */
abstract class JsonSerilizationCallBack extends Callable {}

class JsonConstructorSerilizationCallBack extends JsonSerilizationCallBack, Constructor {
    JsonConstructorSerilizationCallBack(){
      this instanceof JsonConstructor
      or
      // Public parameterless constructor
      (
        this.getNumberOfParameters() = 0 and 
        this.isPublic()
      )
      or
      // Single public constructor with parameters
      (
        count(Constructor c |c = this.getDeclaringType().getAConstructor()) = 1 and
        this.isPublic()
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
          (
            this.isPublic() or
            p.getAnAttribute().getType().hasName("JsonPropertyAttribute")
          ) 

          // JSON.net don't call static setters
          and not this.isStatic()
      )
    }
}

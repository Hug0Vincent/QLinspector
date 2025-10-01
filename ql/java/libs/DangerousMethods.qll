import java

/**
 * RefType
 */

class JakartaType extends RefType {
  JakartaType() { getPackage().hasName(["javax.el", "jakarta.el"]) }
}

class ELProcessor extends JakartaType {
  ELProcessor() { hasName("ELProcessor") }
}

class NioFiles extends RefType {
  NioFiles() { hasQualifiedName("java.nio.file", "Files")}
}

class ExpressionFactory extends JakartaType {
  ExpressionFactory() { hasName("ExpressionFactory") }
}

class ValueExpression extends JakartaType {
  ValueExpression() { hasName("ValueExpression") }
}

class MethodExpression extends JakartaType {
  MethodExpression() { hasName("MethodExpression") }
}

class LambdaExpression extends JakartaType {
  LambdaExpression() { hasName("LambdaExpression") }
}

class ClassLoaderType extends RefType {
  ClassLoaderType(){ hasQualifiedName("java.lang", "ClassLoader")}
}

class URLClassLoader extends RefType {
  URLClassLoader(){ hasQualifiedName("java.net", "URLClassLoader")}
}

class NamingContext extends RefType {
  NamingContext(){hasQualifiedName("javax.naming", "Context")}
}

class LdapContext extends RefType {
  LdapContext(){hasQualifiedName("com.sun.jndi.ldap", "LdapCtx")}
}

class BeanFactory extends RefType {
  BeanFactory(){ hasQualifiedName("org.springframework.beans.factory", "BeanFactory")}
}

class SpringframeworkExpression extends RefType {
  SpringframeworkExpression() { this.hasQualifiedName("org.springframework.expression", "Expression") }
}

class H2JdbcConnectionType extends RefType {
  H2JdbcConnectionType() { this.hasQualifiedName("org.h2.jdbc", "JdbcConnection") }
}

class OGNLTypes extends RefType {
  OGNLTypes(){
    hasQualifiedName("ognl", "Ognl") or
    hasQualifiedName("ognl", "Node") or 
    hasQualifiedName("ognl.enhance", "ExpressionAccessor") or 
    hasQualifiedName("org.apache.commons.ognl", "Ognl") or
    hasQualifiedName("org.apache.commons.ognl", "Node") or
    hasQualifiedName("org.apache.commons.ognl.enhance", "ExpressionAccessor") or
    hasQualifiedName("com.opensymphony.xwork2.ognl", "OgnlUtil") or 
    hasQualifiedName("com.opensymphony.xwork2.ognl", "OgnlValueStack")
  }
}

class DataSourceType extends RefType {
  DataSourceType(){hasQualifiedName("javax.sql", "DataSource")}
}

class DriverManagerType extends RefType {
  DriverManagerType(){hasQualifiedName("javax.sql", "DriverManager")}
}

class JexlRefType extends RefType {
  JexlRefType() {
    this.getPackage().hasName(["org.apache.commons.jexl2", "org.apache.commons.jexl3"])
  }
}

class JexlBuilder extends JexlRefType {
  JexlBuilder() { this.hasName("JexlBuilder") }
}

class JexlEngine extends JexlRefType {
  JexlEngine() { this.hasName("JexlEngine") }
}

class JxltEngine extends JexlRefType {
  JxltEngine() { this.hasName("JxltEngine") }
}

class UnifiedJexl extends JexlRefType {
  UnifiedJexl() { this.hasName("UnifiedJEXL") }
}

class StringSubstitutorType extends RefType {
  StringSubstitutorType() { this.hasQualifiedName("org.apache.commons.text", "StringSubstitutor") }
}

class ScriptEngineType extends RefType {
  ScriptEngineType() { this.hasQualifiedName("javax.script", "ScriptEngine") }
}

class CompiledScriptType extends RefType {
  CompiledScriptType() { this.hasQualifiedName("javax.script", "CompiledScript") }
}

class InvocableType extends RefType {
  InvocableType() { this.hasQualifiedName("javax.script", "Invocable") }
}

class FreemarkerTemplateType extends RefType {
  FreemarkerTemplateType() { this.hasQualifiedName("freemarker.template", "Template") }
}

/**
 * Methods or constructors
 */

class ExpressionEvaluationMethods extends Method {
    ExpressionEvaluationMethods(){
        this instanceof ValueExpressionMethods or
        this instanceof ExpressionFactoryMethods or
        this instanceof MethodExpressionMethods or
        this instanceof LambdaExpressionMethods or
        this instanceof ELProcessorMethods or
        this instanceof SpringframeworkExpressionMethods or
        this instanceof JexlMethods
    }
}

class ValueExpressionMethods extends Method {
  ValueExpressionMethods(){
    this.getDeclaringType().getASupertype*() instanceof ValueExpression and
    hasName(["getValue", "setValue"])
  }
}

class ExpressionFactoryMethods extends Method {
  ExpressionFactoryMethods(){
    this.getDeclaringType().getASupertype*() instanceof ValueExpression and
    hasName(["createValueExpression", "createMethodExpression"])
  }
}

class MethodExpressionMethods extends Method {
  MethodExpressionMethods(){
    this.getDeclaringType().getASupertype*() instanceof MethodExpression and
    hasName("invoke")
  }
}

class LambdaExpressionMethods extends Method {
  LambdaExpressionMethods(){
    this.getDeclaringType().getASupertype*() instanceof LambdaExpression and
    hasName("invoke")
  }
}

class ELProcessorMethods extends Method {
  ELProcessorMethods(){
    this.getDeclaringType().getASupertype*() instanceof ELProcessor and
    hasName(["eval", "getValue", "setValue", "setVariable"])
  }
}

class SpringframeworkExpressionMethods extends Method {
  SpringframeworkExpressionMethods(){
    this.getDeclaringType().getASupertype*() instanceof SpringframeworkExpression and
    hasName(["getValue", "getValueTypeDescriptor", "getValueType", "setValue"])
  }
}

class ReflectionInvocationMethods extends Method {
    ReflectionInvocationMethods(){
        hasQualifiedName("java.lang.reflect", "Method", "invoke")
    }
}

class RuntimeExec extends Method {
  RuntimeExec(){
    hasQualifiedName("java.lang", "Runtime", "exec")
  }
}

class URL extends Method {
  URL(){
    (this.getDeclaringType().getASupertype*().hasQualifiedName("java.net", "URL") and this.hasName("openStream")) or 
    (this.getDeclaringType().getASupertype*().hasQualifiedName("java.net", "URLConnection") and this.hasName("connect"))
  }
}

class ProcessBuilder extends Constructor {
  ProcessBuilder(){
    hasQualifiedName("java.lang", "ProcessBuilder", "ProcessBuilder")
  }
}

class Files extends Method {
  Files(){
    getDeclaringType().getASupertype*() instanceof NioFiles and (
      hasName([
              "readAllBytes", "readAllLines", "readString", "lines", "newBufferedReader",
              "newBufferedWriter", "newInputStream", "newOutputStream", "newByteChannel"
            ])
    )

  }
}

class FileInputStream extends Constructor {
  FileInputStream(){
    this.getDeclaringType().getASupertype*().hasQualifiedName("java.io", "FileInputStream") and this.hasName("FileInputStream")
  }
}

class FileOutputStream extends Callable {
  FileOutputStream(){
    (this instanceof Constructor and this.hasQualifiedName("java.io", "FileOutputStream", "FileOutputStream")) or 
    this.getDeclaringType().getASupertype*().hasQualifiedName("java.io", "FileOutputStream") and this.hasName("write")
  }
}

class FilesMethods extends Callable {
  FilesMethods(){
    this instanceof Files or
    this instanceof FileInputStream or 
    this instanceof FileOutputStream
  }
}

class System extends Method {
  System(){
    hasQualifiedName("java.lang", "System", "setProperty") or
    hasQualifiedName("java.lang", "System", "setProperties")
  }
}

class ScriptEngineMethods extends Method {
  ScriptEngineMethods(){
    ( this.getDeclaringType().getASupertype*() instanceof ScriptEngineType and this.hasName("eval") ) or
    ( this.getDeclaringType().getASupertype*() instanceof InvocableType and this.hasName(["invokeMethod", "invokeFunction"]) ) or 
    
    // https://securitylab.github.com/advisories/GHSL-2023-229_GHSL-2023-230_kafka-ui/
    ( this.getDeclaringType().getASupertype*() instanceof CompiledScriptType and this.hasName("eval") )
  }
}

/**
 * Want to search for BCEL class loader but it's removed in recent java versions
 * https://www.leavesongs.com/penetration/where-is-bcel-classloader.html
 */
class ClassLoaderMethods extends Callable {
  ClassLoaderMethods(){
    this.getDeclaringType().getASupertype*() instanceof ClassLoaderType and (
      this instanceof Constructor or
      hasName("defineClass")
      // false positive
      //hasName("loadClass")
    )
    
  }
}

// remote class loading with these methods can be interesting
class URLClassLoaderMethods extends Callable {
  URLClassLoaderMethods(){
    this.getDeclaringType().getASupertype*() instanceof URLClassLoader and (
        this instanceof Constructor or
        hasName("newInstance") or 
        hasName("getMBeansFromURL") or 
        hasName("readExternal") or
        hasName("addURL")
      )
  }
}

class ClassLoader extends Callable {
  ClassLoader(){
    this instanceof ClassLoaderMethods or
    this instanceof URLClassLoaderMethods
  }
}

 class NamingContextLookup extends Callable {
  NamingContextLookup(){
    this.getDeclaringType().getASupertype*() instanceof NamingContext and (
      hasName("lookup")
    )
  }
}

// https://github.com/voidfyoo/rwctf-2021-old-system/tree/main/writeup
class LdapContextLookup extends Callable {
  LdapContextLookup(){
    this.getDeclaringType().getASupertype*() instanceof LdapContext and (
      hasName("c_lookup")
    )
  }
}

class ContextLookup extends Callable {
  ContextLookup(){
    this instanceof NamingContextLookup or
    this instanceof LdapContextLookup
  }
}

// fixed DefaultListableBeanFactory is not serializable a reference of the BeanFactory 
// is returned which is not known by the server 
class SpringBeansMethods extends Callable {
  SpringBeansMethods(){
    this.getDeclaringType().getASupertype*() instanceof BeanFactory and (
      ( this.hasName("getBean") and this.getNumberOfParameters() = 1)
    )
  }
}

class OGNLEvaluationMethods extends Callable {
  OGNLEvaluationMethods(){
    this.getDeclaringType().getASupertype*() instanceof OGNLTypes and
    this.hasName(["getValue", "findValue","setValue","callMethod","get","set"])
  }
}

class DataSourceMethods extends Callable {
  DataSourceMethods(){
    this.getDeclaringType().getASupertype*() instanceof DataSourceType and hasName("getConnection")
  }
}

class DriverManagerMethods extends Callable {
  DriverManagerMethods(){
    this.getDeclaringType() instanceof DriverManagerType and hasName("getConnection")
  }
}

// not sure about this one
class C3P0ComboPoolDataSourceMethods extends Callable {
  C3P0ComboPoolDataSourceMethods(){
    this.getDeclaringType().getASupertype*().hasQualifiedName("com.mchange.v2.c3p0", "AbstractComboPooledDataSource") and this.hasName("setJdbcUrl")
  }
}

class JavaClassMethods extends Callable {
  JavaClassMethods(){
    hasQualifiedName("java.lang", "Class", "newInstance")
  }
}

class H2Methods extends Callable {
  H2Methods(){
    (this instanceof Constructor and this.getDeclaringType().getASupertype*() instanceof H2JdbcConnectionType)
  }
}

class XMLDecoderMethods extends Callable {
  XMLDecoderMethods(){
    this.getDeclaringType().getASupertype*().hasQualifiedName("java.beans", "XMLDecoder") and this.hasName("readObject")
  }
}

class SnakeYAMLMethods extends Callable {
  SnakeYAMLMethods(){
    this.getDeclaringType().getASupertype*().hasQualifiedName("org.yaml.snakeyaml", "Yaml") and this.hasName(["load", "loadAll"])
  }
}

class KyroMethods extends Callable {
  KyroMethods(){
    this.getDeclaringType().getASupertype*().hasQualifiedName("com.esotericsoftware.kryo", "Kryo") and this.hasName("readObject")
  }
}

/**
 * https://semgrep.dev/docs/cheat-sheets/java-xxe
 */
class XXEMethods extends Callable {
  XXEMethods(){
    (this.getDeclaringType().getASupertype*().hasQualifiedName("javax.xml.parser", "DocumentBuilder") and this.hasName("parse") )or
    (this.getDeclaringType().getASupertype*().hasQualifiedName("org.jdom2.input", "SAXBuilder") and this.hasName("build") )or
    (this.getDeclaringType().getASupertype*().hasQualifiedName("javax.xml.parsers", "SAXParser") and this.hasName("parse") )or
    (this.getDeclaringType().getASupertype*().hasQualifiedName("org.dom4j.io", "SAXReader") and this.hasName("read") )or
    (this.getDeclaringType().getASupertype*().hasQualifiedName("javax.xml.transform", "Transformer") and this.hasName("transform") )or
    (this.getDeclaringType().getASupertype*().hasQualifiedName("javax.xml.validation", "SchemaFactory") and this.hasName("newSchema") )or
    (this.getDeclaringType().getASupertype*().hasQualifiedName("javax.xml.validation", "Validator") and this.hasName("validate") )or
    (this.getDeclaringType().getASupertype*().hasQualifiedName("org.xml.sax", "XMLReader") and this.hasName("parse"))

  }
}

/**
 * A method that creates a JEXL script.
 */
class CreateJexlScriptMethod extends Method {
  CreateJexlScriptMethod() {
    this.getDeclaringType().getASupertype*() instanceof JexlEngine and this.hasName("createScript")
  }
}

/**
 * A method that creates a JEXL template.
 */
class CreateJexlTemplateMethod extends Method {
  CreateJexlTemplateMethod() {
    (
      this.getDeclaringType().getASupertype*() instanceof JxltEngine or
      this.getDeclaringType().getASupertype*() instanceof UnifiedJexl
    ) and
    this.hasName("createTemplate")
  }
}

/**
 * A method that creates a JEXL expression.
 */
class CreateJexlExpressionMethod extends Method {
  CreateJexlExpressionMethod() {
    (
      (this.getDeclaringType().getASupertype*() instanceof JexlEngine or this.getDeclaringType().getASupertype*() instanceof JxltEngine) and this.hasName("createExpression")
    ) or
    ( this.getDeclaringType().getASupertype*() instanceof UnifiedJexl and this.hasName("parse") )
  }
}

/**
 * Jexl idea stolen here: 
 * https://github.com/github/codeql/blob/main/java/ql/lib/semmle/code/java/security/JexlInjectionQuery.qll
 * https://x.com/pwntester/status/1582321752566161409
 */
class JexlMethods extends Method {
  JexlMethods(){
    this instanceof CreateJexlScriptMethod or
    this instanceof CreateJexlTemplateMethod or
    this instanceof CreateJexlExpressionMethod
  }
}

/**
 * Text4Shell
 * https://securitylab.github.com/advisories/GHSL-2022-018_Apache_Commons_Text/
 */
class StringSubstitutorMethods extends Method {
  StringSubstitutorMethods(){
    this.getDeclaringType().getASupertype*() instanceof StringSubstitutorType and
    this.hasName(["replace", "replaceIn"])
  }
}

class FreemarkerMethods extends Method {
  FreemarkerMethods(){
    this.getDeclaringType().getASupertype*() instanceof FreemarkerTemplateType and
    this.hasName("process")
  }
}

class QuickTestMethods extends Callable {
  QuickTestMethods(){
    this.getDeclaringType().getASupertype*() instanceof TypeSerializable and (
      hasName("writeObject")
  )
  }
}

class DangerousMethod extends Callable {
  DangerousMethod(){
    this instanceof ExpressionEvaluationMethods or
    this instanceof ReflectionInvocationMethods or
    this instanceof RuntimeExec or
    this instanceof URL or
    this instanceof ProcessBuilder or 
    this instanceof FilesMethods or
    this instanceof ScriptEngineMethods or
    this instanceof ClassLoader or
    this instanceof ContextLookup or
    this instanceof OGNLEvaluationMethods or
    this instanceof DataSourceMethods or
    this instanceof JavaClassMethods or
    this instanceof H2Methods or 
    this instanceof DriverManagerMethods or
    this instanceof System or
    this instanceof XXEMethods or
    this instanceof C3P0ComboPoolDataSourceMethods or
    this instanceof StringSubstitutorMethods or
    //this instanceof SpringBeansMethods

    /*
     * We might be able to find bridge gadgets like in
     * ysoserial.net
     */
    this instanceof XMLDecoderMethods or
    this instanceof SnakeYAMLMethods or
    this instanceof KyroMethods

    //this instanceof QuickTestMethods

  }
}
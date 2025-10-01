/**
 * Provides a taint-tracking configuration for reasoning about user input that is used to construct web queries.
 */

import csharp
private import semmle.code.csharp.security.dataflow.flowsinks.FlowSinks
private import semmle.code.csharp.frameworks.system.Net

/**
 * A data flow sink for server side request forgery vulnerabilities.
 */
abstract class Sink extends ApiSinkExprNode { }

/** The `System.Net.WebClient` class. */
class SystemNetHttpWebClientClass extends SystemNetClass {
  SystemNetHttpWebClientClass() { this.hasName("WebClient") }
}

/** The `System.Net.WebRequest` class. */
class SystemNetHttpWebRequestClass extends SystemNetClass {
  SystemNetHttpWebRequestClass() { this.hasName("WebRequest") }
}

/** The `System.Net.Http` namespace. */
class SystemNetHttpNamespace extends Namespace {
  SystemNetHttpNamespace() {
    this.getParentNamespace() instanceof SystemNetNamespace and
    this.hasName("Http")
  }
}

/** A class in the `System.Net.Http` namespace. */
class SystemNetHttpClass extends Class {
  SystemNetHttpClass() { this.getNamespace() instanceof SystemNetHttpNamespace }
}

/** The `System.Net.Http.HttpClient` class. */
class SystemNetHttpHttpClientClass extends SystemNetHttpClass {
  SystemNetHttpHttpClientClass() { this.hasName("HttpClient") }
}

/**
  * An argument to a `WebRequest.Create` call taken as a
  * sink for Server Side Request Forgery(SSRF) Vulnerabilities. *
  */
private class SystemNetWebRequestCreateSink extends Sink {
  SystemNetWebRequestCreateSink() {
    exists(Method m |
      m.getDeclaringType() instanceof SystemNetHttpWebRequestClass and
      m.hasName("Create")
    |
      m.getACall().getArgument(0) = this.asExpr()
    )
  }
}

/**
  * An argument to a new HTTP Request call of a `System.Net.Http.HttpClient` object
  * taken as a sink for Server Side Request Forgery(SSRF) Vulnerabilities.
  */
private class SystemNetHttpClientSink extends Sink {
  SystemNetHttpClientSink() {
    exists(Method m |
      m.getDeclaringType() instanceof SystemNetHttpHttpClientClass and
      m.hasName([
          "DeleteAsync", "GetAsync", "GetByteArrayAsync", "GetStreamAsync", "GetStringAsync",
          "PatchAsync", "PostAsync", "PutAsync"
        ])
    |
      m.getACall().getArgument(0) = this.asExpr()
    )
  }
}

/**
  * An property assignment for BaseAddress.
  */
private class SystemNetClientBaseAddressSink extends Sink {
  SystemNetClientBaseAddressSink() {
    exists(Property p, Type t |
      p.hasName("BaseAddress") and
      t = p.getDeclaringType() and
      (
        t instanceof SystemNetHttpWebClientClass or
        t instanceof SystemNetHttpHttpClientClass
      )
    |
      p.getAnAssignedValue() = this.asExpr()
    )
  }
}

/**
  * An argument to a new HTTP Request call of a `System.Net.WebClient` object
  * taken as a sink for Server Side Request Forgery(SSRF) Vulnerabilities.
  */
private class SystemNetWebClientSink extends Sink {
  SystemNetWebClientSink() {
    exists(Method m |
      m.getDeclaringType() instanceof SystemNetHttpWebClientClass and
      m.hasName([
          "OpenRead", "OpenReadAsync", "DownloadData", "DownloadDataAsync", "DownloadFile",
          "DownloadFileAsync", "DownloadString", "DownloadStringAsync", "OpenWrite", 
          "OpenWriteAsync", "UploadData", "UploadDataAsync", "UploadFile", "UploadFileAsync",
          "UploadValues", "UploadValuesAsync", "UploadString", "UploadStringAsync"
        ])
    |
      m.getACall().getArgument(0) = this.asExpr()
    )
  }
}
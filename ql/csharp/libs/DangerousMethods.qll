import csharp

class ProcessStartMethod extends Callable {
  ProcessStartMethod(){
    this.getDeclaringType().hasFullyQualifiedName("System.Diagnostics", "Process") and
    this.hasName("Start")
  }
}

class DangerousMethod extends Callable {
  DangerousMethod(){
    this instanceof ProcessStartMethod
  }
}
/**
 * @id synacktiv/java/commonbeanutilsgadgetfinder
 * @description find sinks for CommonBeanutils gadget chain
 * @name CommonsBeanutilsGadgetFinder
 * @kind path-problem
 * @problem.severity error
 * @tags security
 */

 import java
 import libs.DangerousMethods
 import libs.Source
 import libs.GadgetHelpers

/*
    https://www.praetorian.com/blog/relution-remote-code-execution-java-deserialization-vulnerability/
*/
from Callable c0,  Callable c1, DangerousExpression de
where c0 instanceof CommonsBeanutilsSource and
findGadgetChain(c0, c1, de)
select c0, c0, c1, "recursive call to dangerous expression $@", de, de.toString()
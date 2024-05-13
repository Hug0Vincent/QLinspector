/**
 * @id synacktiv/java/beanfactorygadgetfinder
 * @description find sinks for BeanFactory gadget chain
 * @name BeanFactoryGadgetFinder
 * @kind path-problem
 * @problem.severity error
 * @tags security
 */

 import java
 import libs.DangerousMethods
 import libs.Source
 import libs.Gadget

/*
    https://www.veracode.com/blog/research/exploiting-jndi-injections-java
*/
from Callable c0,  Callable c1, DangerousExpression de
where c0 instanceof BeanFactorySource and
findGadgetChain(c0, c1, de)
select c0, c0, c1, "recursive call to dangerous expression $@", de, de.toString()
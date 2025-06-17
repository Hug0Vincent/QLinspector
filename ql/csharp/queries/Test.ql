/**
 * @id synacktiv/csharp/test
 * @description test
 * @name test
 * @kind table
 * @tags audit
 */

import csharp
import libs.Source
import libs.DangerousMethods
import libs.GadgetTaintHelpers

from  Constructor g
where g.hasName("FullyInstrumentedType") and 
count(Constructor c |c = g.getDeclaringType().getAConstructor()) = 2
select g
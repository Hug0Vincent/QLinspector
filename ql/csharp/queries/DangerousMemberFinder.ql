/**
 * @id synacktiv/csharp/dangerousmemberfinder
 * @description find types that have a dangerous member like WindowsPrincipal.
 * @name dangerousmemberfinder
 * @kind problem
 * @problem.severity warning
 * @tags security
 */

import csharp
import libs.KnownGadgets
import libs.GadgetTaintHelpers

from Field f, Type memberType, Type declaringType
where 
  f.getType() instanceof KnownDangerousType and
  not f.getAnAttribute().getType() instanceof NotSerializedAttributeClass and
  f.getDeclaringType().getAnAttribute().getType() instanceof SerializedAttributeClass and
  memberType = f.getType() and
  declaringType = f.getDeclaringType()
select f, "Dangerous member $@ of type $@", f, f.getName(), memberType, memberType.getName()
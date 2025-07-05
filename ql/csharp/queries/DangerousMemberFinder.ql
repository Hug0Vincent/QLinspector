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

from AssignableMember member, Type memberType, Type declaringType
where 
  member.getType() instanceof KnownDangerousType and
  not member.getAnAttribute().getType() instanceof NotSerializedAttributeClass and
  member.getDeclaringType().getAnAttribute().getType() instanceof SerializedAttributeClass and
  memberType = member.getType() and
  declaringType = member.getDeclaringType()
select member, "Dangerous member $@ of type $@", member, member.getName(), memberType, memberType.getName()
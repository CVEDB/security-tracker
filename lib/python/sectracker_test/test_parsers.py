# Test for sectracker.parsers
# Copyright (C) 2010 Florian Weimer <fw@deneb.enyo.de>
# 
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
# 
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA

from sectracker.parsers import *
import sectracker.parsers as p
from sectracker.xpickle import safeunlink, EXTENSION

o = sourcepackages("../../data/packages/sid__main_Sources")
assert isinstance(o, dict)
assert "bash" in o
assert o["bash"].name == "bash"
assert "bash" in o["bash"].binary

p._debug_enabled = True

safeunlink("../../data/DSA/list" + EXTENSION)
dsalist("../../data/DSA/list")

safeunlink("../../data/DTSA/list" + EXTENSION)
dtsalist("../../data/DTSA/list")

safeunlink("../../data/DLA/list" + EXTENSION)
dlalist("../../data/DLA/list")

Message = sectracker.diagnostics.Message
for (line, res, xmsgs) in [
        (' - foo <unfixed>',
         PackageAnnotation(17, "package", None, "foo", "unfixed", None,
                           None, []), ()),
        (' - foo',
         PackageAnnotation(17, "package", None, "foo", "unfixed", None,
                           None, []), ()),
        (' [lenny] - foo <unfixed>',
         PackageAnnotation(17, "package", "lenny", "foo", "unfixed", None,
                           None, []), ()),
        (' [lenny] - foo <undetermined> (bug #1234)',
         PackageAnnotation(17, "package", "lenny", "foo", "undetermined",
                           None, None, [PackageBugAnnotation(1234)]), ()),
        (' [lenny] - foo <itp> (bug #1234)',
         PackageAnnotation(17, "package", "lenny", "foo", "itp", None,
                           None, [PackageBugAnnotation(1234)]), ()),
        (' [lenny] - foo <itp>',
         PackageAnnotation(17, "package", "lenny", "foo", "itp", None,
                           None, []),
         (Message("CVE", 17, "error",
                  "<itp> needs Debian bug reference"),)),
        (' [lenny] - foo 1.0',
         PackageAnnotation(17, "package", "lenny", "foo", "fixed", "1.0" ,
                           None, []), ()),
        (' [lenny] - foo <unfixed> (bug filed)',
         PackageAnnotation(17, "package", "lenny", "foo", "unfixed", None,
                           None, []),
         (Message("CVE", 17, "error",
                  "invalid inner annotation: 'bug filed'"),)),
        (' [lenny] - foo <unfixed> (bug filed; bug #1234)',
         PackageAnnotation(17, "package", "lenny", "foo", "unfixed", None,
                           None, [PackageBugAnnotation(1234)]),
         (Message("CVE", 17, "error",
                  "invalid inner annotation: 'bug filed'"),)),
        (' [lenny] - foo <unfixed> (low)',
         PackageAnnotation(17, "package", "lenny", "foo", "unfixed", None,
                           None, [PackageUrgencyAnnotation("low")]), ()),
        (' [lenny] - foo <unfixed> (low; low)',
         PackageAnnotation(17, "package", "lenny", "foo", "unfixed", None,
                           None, [PackageUrgencyAnnotation("low")]),
         (Message("CVE", 17, "error", "duplicate urgency: 'low'"),)),
        (' [lenny] - foo <unfixed> (bug #1234; garbled)',
         PackageAnnotation(17, "package", "lenny", "foo", "unfixed", None,
                           None, [PackageBugAnnotation(1234)]),
         (Message("CVE", 17, "error",
                        "invalid inner annotation: 'garbled'"),)),
        (' [lenny] - foo <no-dsa> (explanation goes here)',
         PackageAnnotation(17, "package", "lenny", "foo", "no-dsa", None,
                           "explanation goes here", []), ()),
        (' [lenny] - foo <end-of-life> (explanation goes here)',
         PackageAnnotation(17, "package", "lenny", "foo", "end-of-life",
                           None, "explanation goes here", []),
         ()),
        (' [lenny] - foo <not-affected> (explanation goes here)',
         PackageAnnotation(17, "package", "lenny", "foo", "not-affected",
                           None,
                           "explanation goes here", []), ()),
        ('\t{CVE-2009-1234 CVE-2009-1235}',
         XrefAnnotation(17, "xref",
                        ["CVE-2009-1234", "CVE-2009-1235"]),
         ()),
        ('\t{}', None,
         (Message("CVE", 17, "error", "empty cross-reference"),)),
        (' NOT-FOR-US: Plan 9',
         StringAnnotation(17, "NOT-FOR-US", "Plan 9"), ()),
        (' TODO: to-do', StringAnnotation(17, "TODO", "to-do"), ()),
        (' NOTE: note', StringAnnotation(17, "NOTE", "note"), ()),
        (' RESERVED', FlagAnnotation(17, 'RESERVED'), ()),
        (' REJECTED', FlagAnnotation(17, 'REJECTED'), ()),
        (' garbled', None,
         (Message("CVE", 17, "error", "invalid annotation"),)),
        (' [lenny] - foo <garbled> (bug #1234)', None,
         (Message("CVE", 17, "error",
                  "invalid pseudo-version: 'garbled'"),)),
        ]:
    diag = sectracker.diagnostics.Diagnostics()
    diag.setlocation("CVE", 17)
    r = p._annotationdispatcher(line, diag)
    msgs = diag.messages()
    assert tuple(msgs) == xmsgs, repr(msgs)
    assert r == res, repr(r)

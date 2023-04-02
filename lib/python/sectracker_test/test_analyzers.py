# tests for sectracker.analyzers
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

import os

from sectracker.analyzers import *
from sectracker.diagnostics import Diagnostics
import sectracker.parsers as p
from sectracker.repo import Config

# mergelists
diag = Diagnostics()
bugdb = mergelists((p.cvelist("../../data/CVE/list"),
                    p.dsalist("../../data/DSA/list"),
                    p.dlalist("../../data/DLA/list"),
                    p.dtsalist("../../data/DTSA/list")), diag)
assert "CVE-1999-0001" in bugdb
assert "DSA-135" in bugdb
assert "CVE-2006-0225" in bugdb
assert bugdb["CVE-2006-0225"].annotations[0].package == "openssh"

# extractversions
if not os.path.exists("sectracker_test/tmp"):
    os.makedirs("sectracker_test/tmp")
c = Config("../../data/config.json", "sectracker_test/tmp/repo")
c.update()
rpv = extractversions(c, bugdb, diag)
if False:
    for r, pv in rpv.items():
        for p, v in pv.items():
            if len(v) > 1:
                print(r, p, v)

# copysources
copysrc = copysources(bugdb, diag)
assert "CVE-2008-0225" in copysrc
assert "DSA-1472-1" in copysrc["CVE-2008-0225"]

# fixedversions
vdb = fixedversions(bugdb, copysrc, rpv, diag)
if False:
    for v in vdb:
        print(v)

assert bestversion(c, "sid", "bash").name == "bash"
assert bestversion(c, "sid", "bash", ("unsupported", "supported")).name \
    == "bash"

for err in diag.messages():
    print("%s:%d: %s: %s" % (err.file, err.line, err.level, err.message))
assert not diag.messages()

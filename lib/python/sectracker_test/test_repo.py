# Test cases for sectracker.repo
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

import os.path
import shutil
import tempfile

from sectracker.repo import *
import sectracker.analyzers as a
from sectracker.diagnostics import Diagnostics
import sectracker.parsers as p

tmp = tempfile.mkdtemp()
try:
    r = RepoCollection(tmp)
    r.verbose = True
    mirror = "http://localhost:9999/"
    r.add("lenny", mirror + "debian/dists/lenny")
    r.add("lenny-security", mirror + "debian-security/dists/lenny/updates")
    r.add("lenny-proposed-updates", mirror + "debian/dists/lenny-proposed-updates")
    r.add("squeeze", mirror + "debian/dists/squeeze")
    r.add("sid", mirror + "debian/dists/sid")
    r.update()
    fm = r.filemap()
    assert "sid" in fm
    assert "main" in fm["sid"]
    o = p.sourcepackages(fm["sid"]["main"])
    assert "bash" in o
    assert o["bash"].name == "bash"
    assert "bash" in o["bash"].binary
finally:
    shutil.rmtree(tmp)

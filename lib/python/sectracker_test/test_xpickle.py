# Tests for sectracker.xpickle
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

import tempfile
import sectracker.xpickle as x

with tempfile.NamedTemporaryFile() as t:
    try:
        data = "foo bar baz\n"
        t.write(data.encode())
        t.flush()

        l = x._wraploader("foo", lambda p, f: f.read())
        assert l(t.name) == data
        assert l(t.name) == data
        t.write(data.encode())
        t.flush()
        assert l(t.name) == (data + data)
    finally:
        x.safeunlink(t.name + x.EXTENSION)

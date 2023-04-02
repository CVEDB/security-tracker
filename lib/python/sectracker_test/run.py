# sectracker_tests/run.py -- run Python tests with the correct search path
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

if __name__ != "__main__":
    raise Exception("run must be executed directly")

import os.path
import subprocess
import sys

def pathsetup():
    prefix = sys.path[0]
    trailer = "/sectracker_test"
    if not os.path.exists(prefix + "/run.py") \
            or prefix[-len(trailer):] != trailer:
        raise Exception("cannot find path to ourselves")
    path = sys.path[:]
    path[0] = prefix[:-len(trailer)]
    return (prefix, path)
(ourpath, pythonpath) = pathsetup()
os.chdir(ourpath + "/..")

env = {}
env.update(os.environ)
env["PYTHONPATH"] = ":".join(pythonpath)

files = os.listdir(ourpath)
files.sort()
errors = False
for name in files:
    if name[-3:] != ".py" or name == "run.py":
        continue
    fullpath = "%s/%s" % (ourpath, name)
    print("* Running", name)
    p = subprocess.Popen(("python3", "--", fullpath), env=env)
    ret = p.wait()
    if ret != 0:
        print("Test exited with status", ret)
        print()
    errors = errors or ret != 0
if errors:
    print("ERROR: some tests aborted with errors")
    sys.exit(1)

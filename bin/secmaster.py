#!/usr/bin/python2
# secmaster -- access to data on security-master.debian.org
# Copyright (C) 2011 Florian Weimer <fw@deneb.enyo.de>
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
from __future__ import print_function

# Name of the security-master host
HOST = "seger.debian.org"

import json
import subprocess

import setup_paths
import debian_support

def listqueue():
    """Returns a list of pairs (PACKAGE, SET-OF-DISTRIBUTIONS).
    
    PACKAGE is a debian_support.BinaryPackage object.
    SET-OF-DISTRIBUTIONS contains normalized distribution names,
    using the code names (sid etc.).
    """
    ssh = subprocess.Popen(
        ("ssh", HOST, "secure-testing/bin/list-queue"),
        stdin=open("/dev/null"),
        stdout=subprocess.PIPE)
    data = ssh.stdout.read()
    ssh.wait()
    if ssh.returncode != 0:
        raise IOError("unexpected ssh return code: " + repr(ssh.returncode))
    data = json.loads(data)
    if data["version"] != 1:
        raise IOError("unexpected version number: " + repr(data["version"]))

    distdict = {}
    def normdist(dist):
        if dist.endswith("-security"):
            dist = dist[:-9]
        return debian_support.releasecodename(dist)
        
    return [(debian_support.BinaryPackage(row[0:5]),
             set(normdist(dist) for dist in row[5]))
            for row in data["binary"]]

if __name__ == "__main__":
    for pkg, archs in listqueue():
        print(" ".join(pkg.astuple()), "=>", ", ".join(archs))

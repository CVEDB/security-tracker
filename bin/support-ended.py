#!/usr/bin/python3
#
# Copyright 2016 Guido Günther <agx@sigxcpu.org>
#
# This file is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 2 of the License, or
# (at your option) any later version.
#
# This file is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this file.  If not, see <https://www.gnu.org/licenses/>.

"""Check if and when support ended for a given package"""

import argparse
import datetime
import glob
import os
import re
import sys


release_mapping = {
    'deb6': ('squeeze', '2016-02-29'),
    'deb7': ('wheezy',  '2018-05-31'),
    'deb8': ('jessie',  '2020-06-30'),
    'deb9': ('stretch', '2022-06-30'),
    # End date not yet fixed
    'deb10': ('buster', None),
    'deb11': ('bullseye', None),
}


SUPPORT_ENDED = 0  # security support ended in at least one suite
SUPPORT_FULL  = 2  # fully supported in all known suites


def relnum_to_relname(relnum):
    return release_mapping[relnum][0]


def release_eol(relnum):
    eolstr = release_mapping[relnum][1]
    return iso8601date_to_datetime(eolstr) if eolstr else None


def iso8601date_to_datetime(datestr):
    return datetime.datetime.strptime(datestr, "%Y-%m-%d")


def find_releases(pkg, dir, days):
    rels = []
    pkg_re = re.compile(r"(?P<PKG>%s)\s+[^\s]+\s+(?P<EOL>[0-9]{4}-[0-9]{2}-[0-9]{2})" % pkg)
    pattern = "security-support-ended.deb*"
    lists = glob.glob(os.path.join(dir, pattern))
    if not lists:
        raise Exception("No lists matching %s found in %s" % (pattern, dir))

    end = datetime.datetime.today() + datetime.timedelta(days=days) if days else None

    for fn in lists:
        _, ext = os.path.splitext(fn)
        rel = ext[1:]
        sup_needed_til = end or release_eol(rel)
        with open(fn) as f:
            for line in f:
                m = pkg_re.match(line)
                if m:
                    pkgeol = iso8601date_to_datetime(m.group("EOL"))
                    if not sup_needed_til or pkgeol < sup_needed_til:
                        rels.append(relnum_to_relname(rel))
                    break
    return rels


def main():
    parser = argparse.ArgumentParser(
        description='Check if and when security support ended for a given package')
    parser.add_argument('--lists',  help='Directory that contains the lists of unsupported packages ',
                        default='/usr/share/debian-security-support/')
    parser.add_argument('--days',  help='days of security support left, 0 == LTS Release end', type=int, default=0)
    parser.add_argument('package', nargs=1, help='package to check')

    args = parser.parse_args()

    pkg = args.package[0]
    rels = find_releases(pkg, args.lists, args.days)
    if rels:
        for rel in rels:
            print("%s unsupported in %s" % (pkg, rel))
    else:
        return SUPPORT_FULL
    return SUPPORT_ENDED

if __name__ == '__main__':
    sys.exit(main())

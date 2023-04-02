# Copyright 2016 Chris Lamb <lamby@debian.org>
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

import setup_paths  # noqa # pylint: disable=unused-import

import config
import os
import re
import requests

re_line = re.compile(r'(?!#)(?P<pkg>[^\s]+)')


class DebSecSupport(set):
    def __init__(self, update_cache):
        if update_cache:
            self.update_cache()

        self.load()

    def update_cache(self):
        print("Updating {} from {} ...".format(self.cache, self.url))

        response = requests.get(self.url, allow_redirects=True)
        response.raise_for_status()

        with open(self.cache, 'w') as f:
            f.write(response.text)

    def load(self):
        with open(self.cache, 'r') as f:
            for x in f.readlines():
                m = re_line.match(x)

                if m is not None:
                    self.add(m.group('pkg'))


class UnsupportedPackages(DebSecSupport):
    URL = "https://salsa.debian.org/debian/debian-security-support/raw/master/security-support-ended.deb{}"
    CACHED_DATA_PATH = "~/.cache/security-support-ended.deb{}"

    def __init__(self, codename, update_cache=True):
        # codename to version number
        dists = list(config.get_config().keys())
        self.debian_version = dists.index(codename) + 1

        self.url = self.URL.format(self.debian_version)

        self.cache = os.path.expanduser(self.CACHED_DATA_PATH).format(
            self.debian_version,
        )

        super(UnsupportedPackages, self).__init__(update_cache)


class LimitedSupportPackages(DebSecSupport):
    URL = "https://salsa.debian.org/debian/debian-security-support/raw/master/security-support-limited"
    CACHED_DATA_PATH = "~/.cache/security-support-limited"

    def __init__(self, update_cache=True):
        self.url = self.URL
        self.cache = os.path.expanduser(self.CACHED_DATA_PATH)
        super(LimitedSupportPackages, self).__init__(update_cache)

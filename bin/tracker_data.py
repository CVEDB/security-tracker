# Copyright 2015 Raphael Hertzog <hertzog@debian.org>
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

import json
import os.path
import re
import subprocess

import requests
import six

import setup_paths # noqa
from debian_support import PointUpdateParser


class TrackerData(object):
    DATA_URL = "https://security-tracker.debian.org/tracker/data/json"
    GIT_URL = "https://salsa.debian.org/security-tracker-team/security-tracker.git"
    CACHED_DATA_DIR = "~/.cache"
    CACHED_DATA_PATH = "~/.cache/debian_security_tracker.json"
    CACHED_REVISION_PATH = "~/.cache/debian_security_tracker.rev"
    GET_REVISION_COMMAND = \
        "LC_ALL=C git ls-remote %s | awk '/HEAD$/ { print $1 }'" % GIT_URL
    DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'data')

    def __init__(self, update_cache=True):
        self._latest_revision = None
        self.cached_data_dir = os.path.expanduser(self.CACHED_DATA_DIR)
        self.cached_data_path = os.path.expanduser(self.CACHED_DATA_PATH)
        self.cached_revision_path = os.path.expanduser(
            self.CACHED_REVISION_PATH)
        if update_cache:
            self.update_cache()
        self.load()

    @property
    def latest_revision(self):
        """Return the current revision of the Git repository"""
        # Return cached value if available
        if self._latest_revision is not None:
            return self._latest_revision
        # Otherwise call out to git to get the latest revision
        output = subprocess.check_output(self.GET_REVISION_COMMAND,
                                         shell=True)
        self._latest_revision = output.strip()
        return self._latest_revision

    def _cache_must_be_updated(self):
        """Verify if the cache is out of date"""
        if os.path.exists(self.cached_data_path) and os.path.exists(
                self.cached_revision_path):
            with open(self.cached_revision_path, 'r') as f:
                try:
                    revision = f.read()
                except ValueError:
                    revision = None
            if revision == self.latest_revision:
                return False
        return True

    def update_cache(self):
        """Update the cached data if it's out of date"""
        if not self._cache_must_be_updated():
            return

        print("Updating {} from {} ...".format(self.CACHED_DATA_PATH,
                                               self.DATA_URL))
        response = requests.get(self.DATA_URL, allow_redirects=True)
        response.raise_for_status()
        # if ~/.cache does not exist, then open() will fail
        if not os.path.exists(self.cached_data_dir):
            os.mkdir(self.cached_data_dir, mode=0o700)
        with open(self.cached_data_path, 'w') as cache_file:
            cache_file.write(response.text)
        with open(self.cached_revision_path, 'w') as rev_file:
            rev_file.write('{}'.format(self.latest_revision))

    def load(self):
        with open(self.cached_data_path, 'r') as f:
            self.data = json.load(f)
        self.load_dsa_dla_needed()
        self.load_point_updates()

    @classmethod
    def parse_needed_file(self, inputfile):
        PKG_RE = '^(\S+)(?:\s+\((.*)\))?$'
        SEP_RE = '^--$'
        state = 'LOOK_FOR_SEP'
        result = {}
        package = ''
        for line in inputfile:
            # Always strip whitespace from end of line
            line = line.rstrip()
            if state == 'LOOK_FOR_SEP':
                res = re.match(SEP_RE, line)
                if not res:
                    if package:
                        result[package]['more'] += '\n' + line
                    continue
                package = ''
                state = 'LOOK_FOR_PKG'
            elif state == 'LOOK_FOR_PKG':
                res = re.match(PKG_RE, line)
                if res:
                    package = res.group(1)
                    result[package] = {
                        'taken_by': res.group(2),
                        'more': '',
                    }
                state = 'LOOK_FOR_SEP'
        return result

    def load_dsa_dla_needed(self):
        with open(os.path.join(self.DATA_DIR, 'dsa-needed.txt'), 'r') as f:
            self.dsa_needed = self.parse_needed_file(f)
        with open(os.path.join(self.DATA_DIR, 'dla-needed.txt'), 'r') as f:
            self.dla_needed = self.parse_needed_file(f)

    def load_point_updates(self):
        self.oldstable_point_update = PointUpdateParser.parseNextOldstablePointUpdate()
        self.stable_point_update = PointUpdateParser.parseNextPointUpdateStable()

    def iterate_packages(self):
        """Iterate over known packages"""
        for pkg in self.data:
            yield pkg

    def iterate_pkg_issues(self, pkg):
        for id, data in six.iteritems(self.data[pkg]):
            data['package'] = pkg
            yield Issue(id, data)

class IssueStatus(object):

    def __init__(self, status, reason=None):
        self.status = status
        self.reason = reason

    def __str__(self):
        return str((self.status, self.reason))

class Issue(object):
    '''Status of a security issue'''

    def __init__(self, name, data):
        self.name = name
        self.data = data

    def get_status(self, release):
        data = self.data['releases'].get(release)
        if data is None:
            status = 'not-affected'
            # XXX: ask for data to differentiate between "package not in
            # release" and "package not-affected"
            reason = 'unknown'
        elif data['status'] == 'resolved':
            status = 'resolved'
            reason = 'fixed in {}'.format(
                self.data['releases'][release]['fixed_version'])
        elif data.get('nodsa_reason', None) == 'ignored':
            status = 'ignored'
            reason = 'no-dsa'
        elif data['status'] == 'undetermined':
            status = 'ignored'
            reason = 'undetermined'
        elif 'nodsa' in data:
            status = 'ignored'
            reason = 'no-dsa'
        elif data['urgency'] == 'unimportant':
            status = 'ignored'
            reason = 'unimportant'
        elif data['urgency'] == 'end-of-life':
            status = 'ignored'
            reason = 'unsupported'
        else:
            status = 'open'
            reason = 'nobody fixed it yet'
        return IssueStatus(status, reason)

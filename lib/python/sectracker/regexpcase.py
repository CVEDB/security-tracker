# sectracker.regexpcase -- Python module for regexp-based dispatching
# Copyright (C) 2009, 2010 Florian Weimer <fw@deneb.enyo.de>
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

import re

class RegexpCase(object):
    def __init__(self, rules, prefix=None, suffix=None, default=None):
        offset = 0
        probes = []
        maycall = default is None or callable(default)

        # We use a single regular expression and use special probe
        # captures to figure out which one has actually matched.
        # Hopefully, the regular expression engine will make this run
        # fast.
        for (regexp, action) in rules:
            compiled = re.compile(regexp)
            probes.append((offset, offset + 1, offset + compiled.groups + 1,
                           action))
            offset += compiled.groups + 1
            if action is not None:
                maycall = maycall and callable(action)
        self.probes = tuple(probes)
        self.maycall = maycall

        if not self.probes:
            raise ValueError("empty rule list")
        if prefix is None:
            prefix = "^(?:("
        else:
            if re.compile(prefix).groups > 0:
                raise ValueError("prefix must not contain captures")
            prefix = "^(?:" + prefix + ")(?:("

        if suffix is None:
            suffix = "))$"
        else:
            if re.compile(suffix).groups > 0:
                raise ValueError("suffix must not contain captures")
            suffix = "))(?:" + suffix + ")$"

        self.regexp = re.compile(
            prefix + ')|('.join(regexp for (regexp, action) in rules)
            + suffix)

        self.default = default

    def match(self, key):
        match = self.regexp.match(key)
        if match is None:
            return (None, self.default)
        groups = match.groups()
        for (probe, i, j, action) in self.probes:
            if groups[probe] is not None:
                return (groups[i:j], action)
        raise AssertionError("pattern and offset list incongruent")

    def __getitem__(self, key):
        return self.match(key)[1]

    def __call__(self, key, *args):
        if not self.maycall:
            raise TypeError("not all actions are callable")
        (groups, action) = self.match(key)
        if action is None:
            return None
        if groups is None:
            groups = key
        return action(groups, *args)

def rule(regexp):
    """Add a regular expression to the function, for the rule list"""
    return lambda f: (regexp, f)

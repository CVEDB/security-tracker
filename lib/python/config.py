# config.py -- methods to read global configuration from data/config.json
# Copyright (C) 2019 Emilio Pozuelo Monfort <pochu@debian.org>
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

# TODO: the OrderedDict use can be dropped once we use Python 3 (>= 3.7)
from collections import OrderedDict
import json
import os

_config = None

def get_config():
    global _config
    if not _config:
        d = os.path.dirname(os.path.abspath(__file__))

        with open(d + '/../../data/config.json') as f:
            config = json.load(f, object_pairs_hook=OrderedDict)

        _config = config['distributions']

    return _config

def get_supported_releases():
    config = get_config()

    return [d for d in config.keys() if 'release' in config[d]]

def get_all_releases():
    config = get_config()

    return list(config.keys())

def get_release_codename(release, suffix=''):
    config = get_config()

    for r in config.keys():
        if 'release' in config[r] and config[r]['release'] == release:
            return r + suffix

    raise ValueError("invalid release name: " + repr(release))

def get_release_alias(codename):
    config = get_config()

    return config[codename]['release']

# sectracker.repo -- mirror Debian repository metadata
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

import bz2 as _bz2
import hashlib as _hashlib
import gzip as _gzip
import json
import os as _os
import re as _re
import tempfile as _tempfile
import urllib as _urllib

import debian_support as _debian_support
import sectracker.xpickle as _xpickle
import sectracker.parsers as _parsers

MARKER_NAME = "DEBIAN_REPO_MIRROR"

_re_name = _re.compile(r'^[a-z0-9-]+$')
_re_hashentry = _re.compile('^\s*([0-9a-fA-F]{20,})\s+(\d+)\s+(\S+)$')

def _splitfield(data, field):
    tup = tuple(data[field].strip().split())
    if tup == ():
        data[field] = ('',)
    else:
        data[field] = tup

def _splithashes(path, data, field):
    result = {}
    for line in data[field].split('\n'):
        if line == "":
            continue
        match = _re_hashentry.match(line)
        if match is None:
            raise ValueError("invalid line in %r: %r" % (path, line))
        digest, size, name = match.groups()
        result[name] = digest
    data[field] = result

def _parserelease(path, f):
    data = {}
    for p in _debian_support.PackageFile(path, f):
        for k, v in p:
            data[k.lower()] = v
        break # file contains only one record
    _splitfield(data, "components")
    _splitfield(data, "architectures")
    _splithashes(path, data, "md5sum")
    _splithashes(path, data, "sha256")
    return data

def _unbzip2hash(src, dst):
    dec = _bz2.BZ2Decompressor()
    digest = _hashlib.sha256()
    while True:
        data = src.read(8192)
        if data == '':
            break
        data = dec.decompress(data)
        dst.write(data)
        digest.update(data)
    return digest.hexdigest()

def _downloadbz2(url, target, expecteddigest):
    try:
        bz2src = _urllib.request.urlopen(url)
        try:
            dgst = _xpickle.replacefile(
                target, lambda fname, f: _unbzip2hash(bz2src, f))
            if dgst == expecteddigest:
                return True
            return False
        finally:
            bz2src.close()
    except IOError:
        return False

def _downloadgz(url, target, expecteddigest):
    with _tempfile.NamedTemporaryFile() as t:
        try:
            (filename, headers) = _urllib.request.urlretrieve(url, t.name)
        except IOError:
            return False
        gfile = _gzip.GzipFile(t.name)
        try:
            def copy(fname, f):
                digest = _hashlib.sha256()
                while True:
                    data = gfile.read(8192)
                    if data == b'':
                        break
                    f.write(data)
                    digest.update(data)
                if digest.hexdigest() == expecteddigest:
                    return True
                return False
            return _xpickle.replacefile(target, copy)
        finally:
            gfile.close()
    return True

class RepoCollection(object):
    def __init__(self, root):
        """Creates a new repository mirror.
        
        root: path in the local file system"""
        self.root = root
        self.repos = {}
        self.used = ()
        self.releases = None
        self.verbose = False

        if not _os.path.exists(root):
            _os.makedirs(root)
        l = _os.listdir(root)
        if len(l) == 0:
            open(root + "/" + MARKER_NAME, "w").close()
        elif MARKER_NAME not in l:
            raise ValueError("not a Debian repository mirror directory: "
                             + repr(root))

    def add(self, name, url):
        """Adds a repository, given its name and the root URL"""
        if _re_name.match(name) is None:
            raise ValueError("invalid repository name: " + repr(name))
        if name in self.repos:
            raise ValueError("repository already registered: " + repr(name))
        if url[-1:] != '/':
            url += '/'
        self.repos[name] = url

    def update(self):
        self._initused()
        for (name, url) in self.repos.items():
            if not self._updatelrelease(name):
                continue
            if not self.hasrelease(name):
                continue
            rel = self.release(name)
            hashes = rel["sha256"]
            for comp in rel["components"]:
                plainpath = self._sourcepath(comp)
                plainurl = url + plainpath
                if not plainpath in hashes:
                    self.warn("not downloaded because uncompressed version not present in Release file: " + plainurl)
                    continue
                uncompressed_digest = hashes[plainpath]
                listname = self._listname(uncompressed_digest)
                if _os.path.exists(listname):
                    continue
                success = False
                for suffix, method in ((".bz2", _downloadbz2),
                                       (".gz", _downloadgz)):
                    if method(plainurl + suffix, listname,
                              uncompressed_digest):
                        success = True
                        break
                if not success:
                    self.warn("download failed: " + plainurl)

    def _updatelrelease(self, name):
        url = self.repos[name]
        relname = self._relname(name)
        self._markused(relname)
        try:
            def download(fname, f):
                _urllib.request.urlretrieve(url + 'Release', fname)
            _xpickle.replacefile(relname, download)
            return True
        except IOError:
            self.warn("download of Release file failed: " + url)
            return False

    def hasrelease(self, name):
        if name not in self.repos:
            raise ValueError("name not registered: " + repr(name))
        return _os.path.exists(self._relname(name))

    def release(self, name):
        if name not in self.repos:
            raise ValueError("name not registered: " + repr(name))
        with open(self._relname(name)) as f:
            return _parserelease(name, f)

    def filemap(self, load=False):
        """Returns dictionaries mapping repositories to components to files.
        If load is true, the files are loaded using the source packages
        parser."""
        d = {}
        for name in self.repos:
            rel = self.release(name)
            hashes = rel["sha256"]
            comps = {}
            for comp in rel["components"]:
                plainpath = self._sourcepath(comp)
                if not plainpath in hashes:
                    self.warn("failed to find %s/%s" % (name, comp))
                    continue
                digest = hashes[plainpath]
                listname = self._listname(digest)
                if not _os.path.exists(listname):
                    self.warn("file %s for %s/%s not present" %
                              (listname, name, comp))
                    continue
                if load:
                    comps[comp] = _parsers.sourcepackages(listname)
                else:
                    comps[comp] = listname
            d[name] = comps
        return d

    def _relname(self, name):
        return "%s/r_%s" % (self.root, name)

    def _sourcepath(self, comp):
        # Hack to deal with the "updates/" special case.
        comp = comp.split("/")[-1]
        return comp + "/source/Sources"

    def _listname(self, digest):
        return "%s/h_%s" % (self.root, digest)

    def _initused(self):
        self.used = set()
        self.used.add("%s/%s" % (self.root, MARKER_NAME))

    def _markused(self, name):
        self.used.add(name)
        self.used.add(name + _xpickle.EXTENSION)

    def _haslist(self, digest):
        return _os.path.exists(self._listname(digest))

    def warn(self, msg):
        if self.verbose:
            print(msg)

class Config(object):
    def __init__(self, config, root):
        with open(config) as f:
            self.config = json.load(f)
        self.repositories = self.config["repositories"]
        self.distributions = self.config["distributions"]
        self.releases = {}

        self.collection = RepoCollection(root)
        for k,v in self.repositories.items():
            self.collection.add(k, v)

        for d, dobj in self.distributions.items():
            for m, mobj in dobj.get("members", {}).items():
                for mem in mobj:
                    if mem not in self.repositories:
                        raise ValueError(
                            "distributions[%r][%r] (%r) not a valid repository"
                            % (d, m, mem))
            if "release" in dobj:
                rel = dobj["release"]
                if rel in self.releases:
                    raise ValueError(
                        "distributions[%r] is duplicate of %r (previous was %r)"
                        % (d, rel, self.releases[rel]))
                self.releases[rel] = d

        self._filemap_cache = None

    def update(self):
        self.collection.update()
        self._filemap_cache = None
        
    def filemap(self):
        if self._filemap_cache is None:
            self._filemap_cache = self.collection.filemap(load=True)
        return self._filemap_cache

    def releasepackageversions(self):
        """Returns dictionaries mapping release codenames to packages
        to a set of versions."""
        fm = self.filemap()
        r = {}
        for d, dobj in self.distributions.items():
            pkgver = {}
            for mobj in dobj.get("members", {}).values():
                for mem in mobj:
                    for comps in fm[mem].values():
                        for src in comps.values():
                            if src.name in pkgver:
                                pkgver[src.name].add(src.version)
                            else:
                                pkgver[src.name] = set((src.version,))
            r[d] = pkgver
        return r

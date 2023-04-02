# debian_support.py -- Python module for Debian metadata
# Copyright (C) 2005 Florian Weimer <fw@deneb.enyo.de>
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

"""This module implements facilities to deal with Debian-specific metadata."""

import gzip, lzma
import io
import json
import os.path
import re
import sys
import tempfile

try:
    from urllib.request import urlopen
    from urllib.error import URLError
except ImportError:
    from urllib2 import urlopen
    from urllib2.error import URLError

try:
    from cStringIO import StringIO as streamIO
except ImportError:
    from io import BytesIO as streamIO

from helpers import isstring

try:
    from hashlib import sha1
except ImportError:
    import sha
    sha1 = sha.new

import apt_pkg
apt_pkg.init()

import config

# Timeout for downloads.
TIMEOUT = 30

class ParseError(Exception):
    """An exception which is used to signal a parse failure.

    Attributes:

    filename - name of the file
    lineno - line number in the file
    msg - error message

    """
    
    def __init__(self, filename, lineno, msg):
        assert isinstance(lineno, int)
        self.filename = filename
        self.lineno = lineno
        self.msg = msg

    def __str__(self):
        return self.msg

    def __repr__(self):
        return "ParseError(%s, %d, %s)" % (repr(self.filename),
                                           self.lineno,
                                           repr(self.msg))

    def printOut(self, file):
        """Writes a machine-parsable error message to file."""
        file.write("%s:%d: %s\n" % (self.filename, self.lineno, self.msg))
        file.flush()

# This regular expression is used to strip ~bpo1 and ~volatile1 from
# version numbers before they are compared.
_version_normalize_regexp = re.compile(r"~(?:bpo|volatile)[0-9.+]+$")

class Version:
    """Version class which uses the original APT comparison algorithm.

    ~bpo and ~volatile suffixes are ignored."""

    def __init__(self, version):
        """Creates a new Version object."""
        try:
            if isinstance(version, unicode):
                version = version.encode('UTF-8')
        except:
            pass

        assert isstring(version), repr(version)
        assert version != ""
        self.__asString = version
        self.__forCompare = _version_normalize_regexp.sub("", version)

    def __str__(self):
        return self.__asString

    def __repr__(self):
        return 'Version(%r)' % self.__asString

    def __cmp__(self, other):
        return apt_pkg.version_compare(self.__forCompare, other.__forCompare)

    def __lt__(self, other):
        return self.__cmp__(other) <  0

    def __le__(self, other):
        return self.__cmp__(other) <=  0

    def __eq__(self, other):
        return self.__cmp__(other) ==  0

    def __gt__(self, other):
        return self.__cmp__(other) >  0

    def __ge__(self, other):
        return self.__cmp__(other) >=  0

def version_compare(a, b):
    """Compares two versions according to the Debian algorithm.
    
    ~bpo and ~volatile suffixes are ignored."""
    a = _version_normalize_regexp.sub("", a)
    b = _version_normalize_regexp.sub("", b)

    return apt_pkg.version_compare(a, b)

class PackageFile:
    """A Debian package file.

    Objects of this class can be used to read Debian's Source and
    Packages files."""

    re_field = re.compile(r'^([A-Za-z][A-Za-z0-9-]+):(?:\s*(.*?))?\s*$')
    re_continuation = re.compile(r'^\s+(?:\.|(\S.*?)\s*)$')

    def __init__(self, name, fileObj=None):
        """Creates a new package file object.

        name - the name of the file the data comes from
        fileObj - an alternate data source; the default is to open the
                  file with the indicated name.
        """
        if fileObj is None:
            fileObj = open(name)
        self.name = name
        self.file = fileObj
        self.lineno = 0

    def readline(self):
        line = self.file.readline()

        if line != None and not isstring(line):
            line = line.decode('utf-8')

        return line

    def __iter__(self):
        line = self.readline()
        self.lineno += 1
        pkg = []
        while line:
            if line == '\n':
                if len(pkg) == 0:
                    self.raiseSyntaxError('expected package record')
                yield pkg
                pkg = []
                line = self.readline()
                self.lineno += 1
                continue
            
            match = self.re_field.match(line)
            if not match:
                self.raiseSyntaxError("expected package field")
            (name, contents) = match.groups()
            contents = contents or ''

            while True:
                line = self.readline()
                self.lineno += 1
                match = self.re_continuation.match(line)
                if match:
                    (ncontents,) = match.groups()
                    if ncontents is None:
                        ncontents = ""
                    contents = "%s\n%s" % (contents, ncontents)
                else:
                    break
            pkg.append((name, contents))
        if pkg:
            yield pkg

    def raiseSyntaxError(self, msg, lineno=None):
        if lineno is None:
            lineno = self.lineno
        raise ParseError(self.name, lineno, msg)

class PseudoEnum:
    """A base class for types which resemble enumeration types."""
    def __init__(self, name, order):
        self._name = name
        self._order = order
    def __repr__(self):
        return '%s(%r)'% (self.__class__.__name__, self._name)
    def __str__(self):
        return self._name
    def __hash__(self):
        return hash(self._order)
    def __lt__(self, other):
        return self._order < other._order
    def __le__(self, other):
        return self._order <= other._order
    def __eq__(self, other):
        return self._order == other._order
    def __gt__(self, other):
        return self._order > other._order
    def __ge__(self, other):
        return self._order >= other._order

class Release(PseudoEnum): pass

def listReleases():
    releases = {}
    rels = ["experimental"] + config.get_all_releases()
    for r in range(len(rels)):
        releases[rels[r]] = Release(rels[r], r)
    Release.releases = releases
    return releases
def internRelease(name, releases=listReleases()):
    if name in releases:
        return releases[name]
    else:
        return None
del listReleases

def readLinesSHA1(lines):
    m = sha1()
    for l in lines:
        if sys.version_info.major == 3:
            l = l.encode('utf-8')
        m.update(l)
    return m.hexdigest()

def patchesFromEdScript(source,
                        re_cmd=re.compile(r'^(\d+)(?:,(\d+))?([acd])$')):
    """Converts source to a stream of patches.

    Patches are triples of line indexes:

    - number of the first line to be replaced
    - one plus the number of the last line to be replaced
    - list of line replacements

    This is enough to model arbitrary additions, deletions and
    replacements.
    """

    i = iter(source)
    
    for line in i:
        match = re_cmd.match(line)
        if match is None:
            raise ValueError("invalid patch command: " + repr(line))

        (first, last, cmd) = match.groups()
        first = int(first)
        if last is not None:
            last = int(last)

        if cmd == 'd':
            first = first - 1
            if last is None:
                last = first + 1
            yield (first, last, [])
            continue

        if cmd == 'a':
            if last is not None:
                raise ValueError("invalid patch argument: " + repr(line))
            last = first
        else:                           # cmd == c
            first = first - 1
            if last is None:
                last = first + 1

        lines = []
        for l in i:
            if l == '':
                raise ValueError("end of stream in command: " + repr(line))
            if l == '.\n' or l == '.':
                break
            lines.append(l)
        yield (first, last, lines)

def patchLines(lines, patches):
    """Applies patches to lines.  Updates lines in place."""
    for (first, last, args) in patches:
        lines[first:last] = args

def replaceFile(lines, local):
    local_new = local + '.new'
    new_file = open(local_new, 'w+')

    try:
        for l in lines:
            new_file.write(l)
        new_file.close()
        os.rename(local_new, local)
    finally:
        if os.path.exists(local_new):
            os.unlink(local_new)

def downloadCompressedLines(remote):
    """Downloads a file from a remote location and uncompresses it.

    Returns the lines in the file."""

    if remote.endswith('.gz'):
        cls = gzip
    elif remote.endswith('.xz'):
        cls = lzma
    else:
        raise ValueError('file format not supported: %s' % remote)

    data = urlopen(remote, timeout=TIMEOUT)
    try:
        b = io.BytesIO(cls.decompress(data.read()))
        t = io.TextIOWrapper(b, 'utf-8')
        return t.readlines()
    finally:
        data.close()

def downloadLines(remote):
    try:
        return downloadCompressedLines(remote + '.xz')
    except URLError:
        return downloadCompressedLines(remote + '.gz')

def downloadFile(remote, local):
    """Copies a compressed remote file to the local system.

    remote - URL, without compression suffix
    local - name of the local file
    """

    lines = downloadLines(remote)

    replaceFile(lines, local)
    return lines

def updateFile(remote, local, verbose=None):
    """Updates the local file by downloading a remote patch.

    Returns a list of lines in the local file.
    """

    try:
        local_file = open(local)
    except IOError:
        if verbose:
            print("updateFile: no local copy, downloading full file")
        return downloadFile(remote, local)

    lines = local_file.readlines()
    local_file.close()
    local_hash = readLinesSHA1(lines)
    patches_to_apply = []
    patch_hashes = {}
    
    index_name = remote + '.diff/Index'

    re_whitespace=re.compile('\s+')

    try:
        index_url = urlopen(index_name, timeout=TIMEOUT)
        index_fields = list(PackageFile(index_name, index_url))
    except ParseError:
        if verbose:
            print("updateFile: could not interpret patch index file")
        return downloadFile(remote, local)
    except IOError:
        if verbose:
            print("updateFile: could not download patch index file")
        return downloadFile(remote, local)

    for fields in index_fields:
        for (field, value) in fields:
            if field == 'SHA1-Current':
                (remote_hash, remote_size) = re_whitespace.split(value)
                if local_hash == remote_hash:
                    if verbose:
                        print("updateFile: local file is up-to-date")
                    return lines
                continue

            if field =='SHA1-History':
                for entry in value.splitlines():
                    if entry == '':
                        continue
                    (hist_hash, hist_size, patch_name) \
                                = re_whitespace.split(entry)

                    # After the first patch, we have to apply all
                    # remaining patches.
                    if patches_to_apply or  hist_hash == local_hash:
                        patches_to_apply.append(patch_name)
                        
                continue
            
            if field == 'SHA1-Patches':
                for entry in value.splitlines():
                    if entry == '':
                        continue
                    (patch_hash, patch_size, patch_name) \
                                 = re_whitespace.split(entry)
                    patch_hashes[patch_name] = patch_hash
                continue
            
            if verbose:
                print("updateFile: field %s ignored" % repr(field))
        
    if not patches_to_apply:
        if verbose:
            print("updateFile: could not find historic entry", local_hash)
        return downloadFile(remote, local)

    for patch_name in patches_to_apply:
        if verbose:
            print("updateFile: downloading patch " + repr(patch_name))
        try:
            # We could remove the extension here and call downloadLines
            # when diff files come with another compression
            patch_contents = downloadCompressedLines(remote + '.diff/'
                                                     + patch_name + '.gz')
        except IOError:
            return downloadFile(remote, local)
        if readLinesSHA1(patch_contents ) != patch_hashes[patch_name]:
            if verbose:
                print("updateFile: patch was garbled: " + repr(patch_name))
            return downloadFile(remote, local)
        patchLines(lines, patchesFromEdScript(patch_contents))
        
    new_hash = readLinesSHA1(lines)
    if new_hash != remote_hash:
        if verbose:
            print("updateFile: patch failed, got %s instead of %s"
                % (new_hash, remote_hash))
        return downloadFile(remote, local)

    replaceFile(lines, local)
    return lines

def mergeAsSets(*args):
    """Create an order set (represented as a list) of the objects in
    the sequences passed as arguments."""
    s = {}
    for x in args:
        for y in x:
            s[y] = True
    l = list(s.keys())
    l.sort()
    return l

class BinaryPackage(object):
    __slots__ = ("name", "version", "arch", "source", "source_version")

    def __init__(self, data=None):
        if data is not None:
            self.loadtuple(data)

    def loadentry(self, lines):
        """Loads an entry from the Packages file.

        LINES is a sequence of string pairs (KEY, VALUE).
        """
        pkg_name = None
        pkg_version = None
        pkg_arch = None
        pkg_source = None
        pkg_source_version = None
        for (name, contents) in lines:
            name = name.lower()
            if name == "package":
                pkg_name = contents
            elif name == "version":
                pkg_version = contents
            elif name == "source":
                match = self.re_source.match(contents)
                if match is None:
                    raise SyntaxError(('package %s references '
                                       + 'invalid source package %s') %
                                      (pkg_name, repr(contents)))
                (pkg_source, pkg_source_version) = match.groups()
            elif name == "architecture":
                pkg_arch = contents
        if pkg_name is None:
            raise SyntaxError\
                  ("package record does not contain package name")
        if pkg_version is None:
            raise SyntaxError\
                  ("package record for %s does not contain version"
                   % pkg_name)
        if pkg_arch is None:
            raise SyntaxError\
                  ("package record for %s lacks Architecture: field"
                   % pkg_name)
        if pkg_source is None:
            pkg_source = pkg_name
        if pkg_source_version is None:
            pkg_source_version = pkg_version
        self.loadtuple((pkg_name, pkg_version, pkg_arch,
                        pkg_source, pkg_source_version))

    def loadtuple(self, data):
        if None in data:
            raise ValueError("None not permitted: " + repr(data))
        self.name, self.version, self.arch, self.source, self.source_version =\
            data
    
    def load822(self, data):
        "Loads this object from a Deb822-like object."

        pkg = data["Package"]
        version = data["Version"]
        if "Source" in data:
            source = data.get("Source", None)
            match = self.re_source.match(source)
            if match is None:
                raise ValueError("invalid Source field: " + repr(source))
            src, src_version = match.groups()
            if src_version is None:
                src_version = version
        else:
            src = pkg
            src_version = version
        self.loadtuple((pkg, version, data["Architecture"], src, src_version))

    def astuple(self):
        return (self.name, self.version, self.arch,
                self.source, self.source_version)

    def __repr__(self):
        return "BinaryPackage(" + repr(self.astuple()) + ")"

def findresource(*pathseq):
    """Finds the file refered to PATHSEQ, relative to the installation
    based directory."""
    for path in sys.path:
        path = os.path.realpath(path)
        path = os.path.dirname(path)
        path = os.path.dirname(path)
        path = os.path.join(path, *pathseq)
        if os.path.exists(path):
            return path
    raise IOError("not found: " + repr(os.path.join(*pathseq)))

_config = None
def getconfig():
    """Returns the configuration in data/config.json."""
    global _config
    if _config is not None:
        return _config
    _config = json.load(open(findresource("data", "config.json")))
    return _config

class PointUpdateParser:
    @staticmethod
    def parseNextPointUpdateStable():
        """ Reads data/next-point-update.txt and returns a dictionary such as:

            {'CVE-2014-10402': {'libdbi-perl': '1.642-1+deb10u2'},
             'CVE-2019-10203': {'pdns': '4.1.6-3+deb10u1'}
            }
        """
        return PointUpdateParser._parsePointUpdateFile(
            findresource("data", "next-point-update.txt")
        )

    @staticmethod
    def parseNextOldstablePointUpdate():
        """ Returns a dictionary with the same structure as
            PointUpdateParser.parseNextPointUpdateStable() for the file
            data/next-oldstable-point-update.txt
        """
        return PointUpdateParser._parsePointUpdateFile(
            findresource("data", "next-oldstable-point-update.txt")
        )

    @staticmethod
    def _parsePointUpdateFile(file_path):
        CVE_RE = 'CVE-[0-9]{4}-[0-9X]{4,}'
        result = {}

        with open(file_path) as f:
            for line in f:
                res = re.match(CVE_RE, line)
                if res:
                    cve = res.group(0)
                    result[cve] = {}
                    continue
                elif line.startswith('\t['):
                    dist, _, pkg, ver = line.split()
                    result[cve][pkg] = ver
        return result

_releasecodename = None
def releasecodename(dist):
    """Converts a release name to the code name.
    For instance, "sid" and "unstable" are turned into "sid"."""
    global _releasecodename
    if _releasecodename is None:
        result = {}
        for (codename, obj) in getconfig()["distributions"].items():
            result[codename] = codename
            if "release" in obj:
                result[obj["release"]] = codename
        _releasecodename = result
    try:
        return _releasecodename[dist]
    except:
        raise ValueError("invalid release name: " + repr(dist))

def test():
    # Version
    assert Version('0') < Version('a')
    assert Version('1.0') < Version('1.1')
    assert Version('1.2') < Version('1.11')
    assert Version('1.0-0.1') < Version('1.1')
    assert Version('1.0-0.1') < Version('1.0-1')
    assert Version('1.0-0.1') == Version('1.0-0.1')
    assert Version('1.0-0.1') < Version('1.0-1')
    assert Version('1.0final-5sarge1') > Version('1.0final-5') \
           > Version('1.0a7-2')
    assert Version('0.9.2-5') < Version('0.9.2+cvs.1.0.dev.2004.07.28-1.5')
    assert Version('1:500') < Version('1:5000')
    assert Version('100:500') > Version('11:5000')
    assert Version('1.0.4-2') > Version('1.0pre7-2')

    # Release
    assert internRelease('sarge') < internRelease('etch')

    # PackageFile
    # for p in PackageFile('../../data/packages/sarge/Sources'):
    #     assert p[0][0] == 'Package'
    # for p in PackageFile('../../data/packages/sarge/Packages.i386'):
    #     assert p[0][0] == 'Package'

    # Helper routines
    assert readLinesSHA1([]) == 'da39a3ee5e6b4b0d3255bfef95601890afd80709'
    assert readLinesSHA1(['1\n', '23\n']) \
           == '14293c9bd646a15dc656eaf8fba95124020dfada'

    file_a = list(map(lambda x: "%d\n" % x, range(1, 18)))
    file_b = ['0\n', '1\n', '<2>\n', '<3>\n', '4\n', '5\n', '7\n', '8\n',
              '11\n', '12\n', '<13>\n', '14\n', '15\n', 'A\n', 'B\n', 'C\n',
              '16\n', '17\n',]
    patch = ['15a\n', 'A\n', 'B\n', 'C\n', '.\n', '13c\n', '<13>\n', '.\n',
             '9,10d\n', '6d\n', '2,3c\n', '<2>\n', '<3>\n', '.\n', '0a\n',
             '0\n', '.\n']
    patchLines(file_a, patchesFromEdScript(patch))
    assert ''.join(file_b) == ''.join(file_a)

    assert len(mergeAsSets([])) == 0
    assert ''.join(mergeAsSets("abc", "cb")) == "abc"

    assert repr(internRelease("sid")) == "Release('sid')"

if __name__ == "__main__":
    test()

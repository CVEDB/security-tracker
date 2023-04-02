# sectracker.parsers -- various text file parsers
# Copyright (C) 2010 Florian Weimer <fw@deneb.enyo.de>
# Copyright (C) 2019 Brian May <bam@debian.org>
# Copyright (C) 2020 Emilio Pozuelo Monfort <pochu@debian.org>
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

from dataclasses import dataclass
import typing
import traceback
import re
import sys
from sys import intern

import debian_support
import sectracker.regexpcase as _regexpcase
from collections import namedtuple as _namedtuple
import sectracker.xpickle as _xpickle
import sectracker.diagnostics

FORMAT = "5"

_debug_enabled = False

def _sortedtuple(seq):
    l = list(seq)
    l.sort()
    return tuple(l)

@_xpickle.loader("BINARY" + FORMAT)
def binarypackages(name, f):
    """Returns a sequence of binary package names"""
    obj = set(v for p in debian_support.PackageFile(name, f)
            for k, v in p if k == "Package")
    return _sortedtuple(obj)

SourcePackage = _namedtuple("SourcePackage", "name version binary")

@_xpickle.loader("SOURCE" + FORMAT)
def sourcepackages(name, f):
    """Returns a dictionary of source package objects"""
    data = {}
    for p in debian_support.PackageFile(name, f):
        pkg_name = pkg_version = pkg_binary = None
        for name, contents in p:
            if name == "Package":
                pkg_name = intern(contents)
            elif name == "Version":
                pkg_version = contents
            elif name == "Binary":
                pkg_binary = _sortedtuple(contents.replace(",", " ")
                                          .strip().split())
        if pkg_name is None:
            raise SyntaxError("package record does not contain package name")
        if pkg_version is None:
            raise SyntaxError("package record for %s does not contain version"
                              % pkg_name)
        if pkg_binary is None:
            raise SyntaxError("package record lacks Binary field")

        if pkg_name in data:
            oversion = debian_support.Version(data[pkg_name].version)
            if oversion >= debian_support.Version(pkg_version):
                continue
        data[pkg_name] = SourcePackage(pkg_name, pkg_version, pkg_binary)
    return data

@dataclass
class FlagAnnotation:
    line: int
    type: str

@dataclass
class StringAnnotation:
    line: int
    type: str
    description: str

@dataclass
class XrefAnnotation:
    line: int
    type: str
    bugs: typing.List[str]

@dataclass
class PackageAnnotation:
    line: int
    type: str
    release: str
    package: str
    kind: str
    version: str
    description: str
    flags: list

@dataclass
class PackageBugAnnotation:
    bug: int

@dataclass
class PackageUrgencyAnnotation:
    severity: str

def _annotationdispatcher():
    # Parser for inner annotations, like (bug #1345; low)
    @_regexpcase.rule('(unimportant|low|medium|high)')
    def innerflag(groups, diag, flags):
        f = groups[0]
        if PackageUrgencyAnnotation(f) in flags:
            diag.error("duplicate urgency: " + repr(f))
        else:
            flags.append(PackageUrgencyAnnotation(f))
    @_regexpcase.rule(r'bug #(\d+)')
    def innerbug(groups, diag, flags):
        no = int(groups[0])
        if PackageBugAnnotation(no) in flags:
            diag.error("duplicate bug number: " + groups[0])
        else:
            flags.append(PackageBugAnnotation(no))
    def innerdefault(text, diag, flags):
        diag.error("invalid inner annotation: " + repr(text))
    innerdispatch = _regexpcase.RegexpCase((innerflag, innerbug),
                                           default=innerdefault)

    def parseinner(diag, inner):
        if not inner:
            return []
        flags = []
        for innerann in inner.split(";"):
            innerdispatch(innerann.strip(), diag, flags)

        urgencies = [f for f in flags if isinstance(f, PackageUrgencyAnnotation)]
        if len(urgencies) > 1:
            diag.error("multiple urgencies: " + ", ".join(urgency))

        return flags

    # Parsers for indented annotations (NOT-FOR-US:, " - foo <unfixed>" etc.)

    @_regexpcase.rule(r'(?:\[([a-z]+)\]\s)?-\s([A-Za-z0-9:.+-]+)\s*'
                      + r'(?:\s([A-Za-z0-9:.+~-]+)\s*)?(?:\s\((.*)\))?')
    def package_version(groups, diag):
        release, package, version, inner = groups
        flags = parseinner(diag, inner)
        if version is None:
            kind = "unfixed"
        else:
            kind = "fixed"
        return PackageAnnotation(
            line=diag.line(),
            type="package",
            release=release,
            package=package,
            kind=kind,
            version=version,
            description=None,
            flags=flags,
        )

    pseudo_freetext = "no-dsa not-affected end-of-life ignored postponed".split()
    pseudo_struct = set("unfixed removed itp undetermined".split())
    @_regexpcase.rule(r'(?:\[([a-z]+)\]\s)?-\s([A-Za-z0-9:.+-]+)'
                      + r'\s+<([a-z-]+)>\s*(?:\s\((.*)\))?')
    def package_pseudo(groups, diag):
        release, package, kind, inner = groups
        if kind in pseudo_freetext:
            return PackageAnnotation(
                line=diag.line(),
                type="package",
                release=release,
                package=package,
                kind=kind,
                version=None,
                description=inner,
                flags=[],
            )
        elif kind in pseudo_struct:
            flags = parseinner(diag, inner)
            if kind == "itp" and not [flag for flag in flags if isinstance(flag, PackageBugAnnotation)]:
                diag.error("<itp> needs Debian bug reference")
            return PackageAnnotation(
                line=diag.line(),
                type="package",
                release=release,
                package=package,
                kind=kind,
                version=None,
                description=None,
                flags=flags,
            )
        else:
            diag.error("invalid pseudo-version: " + repr(kind))
            return None

    @_regexpcase.rule(r'\{(.*)\}')
    def xref(groups, diag):
        x = groups[0].strip().split()
        if x:
            return XrefAnnotation(line=diag.line(), type="xref", bugs=list(x))
        else:
            diag.error("empty cross-reference")
            return None
        
    return _regexpcase.RegexpCase(
        ((r'(RESERVED|REJECTED)',
          lambda groups, diag: FlagAnnotation(diag.line(), groups[0])),
         (r'(NOT-FOR-US|NOTE|TODO):\s+(\S.*)',
          lambda groups, diag: StringAnnotation(diag.line(), *groups)),
         package_version, package_pseudo, xref),
        prefix=r"\s+", suffix=r"\s*",
        default=lambda text, diag: diag.error("invalid annotation"))
_annotationdispatcher = _annotationdispatcher()

@dataclass
class Header:
    line: int
    name: str
    description: str

@dataclass
class Bug:
    file: str
    header: Header
    annotations: list # TODO: use a list of annotations

def _parselist(path, f, parseheader, finish):
    lineno = 0
    headerlineno = None
    bugs = []
    diag = sectracker.diagnostics.Diagnostics()
    header = None
    anns = []
    anns_types = set()
    relpkg = set()

    for line in f.readlines():
        lineno += 1
        diag.setlocation(path, lineno)

        if line[:1] in " \t":
            if header is None:
                diag.error("header expected")
                continue
            ann = _annotationdispatcher(line, diag)
            if ann is not None:
                # Per-annotation checks (spanning multiple annotations)
                anns_types.add(ann.type)
                if ann.type == "package":
                    rp = (ann.release, ann.package)
                    if rp in relpkg:
                        diag.error("duplicate package annotation")
                        ann = None
                    else:
                        relpkg.add(rp)
            if ann is not None:
                anns.append(ann)
        else:
            if header is not None:
                # Per-bug global checks
                if "NOT-FOR-US" in anns_types and "package" in anns_types:
                    diag.error("NOT-FOR-US conflicts with package annotations",
                               line=headerlineno)
                if "REJECTED" in anns_types and "package" in anns_types:
                    diag.warning("REJECTED bug has package annotations",
                                 line=headerlineno)
                bugs.append(finish(header, headerlineno, anns, diag))
                del anns[:]
                anns_types = set()
                relpkg = set()
            headerlineno = lineno
        
            header = parseheader(line)
            if header is None:
                diag.error("malformed header")
                continue

    if header is not None:
        bugs.append(finish(header, headerlineno, anns, diag))

    if _debug_enabled:
        for m in diag.messages():
            sys.stderr.write(str(m) + "\n")
            print("%s:%d: %s: %s" % (m.file, m.line, m.level, m.message))

    return bugs

@_xpickle.loader("CVE" + FORMAT)
def cvelist(path, f):
    re_header = re.compile(r'^((?:CVE-\d{4}-(?:\d{4,}|XXXX)|TEMP-\d+-\S+))\s+(.*?)\s*$')
    def parseheader(line):
        match = re_header.match(line)
        if match is None:
            return None
        name, desc = match.groups()
        if desc:
            if desc[0] == '(':
                if desc[-1] != ')':
                    diag.error("error", "missing ')'")
            elif desc[0] == '[':
                if desc[-1] != ']':
                    diag.error("missing ']'")
        return (name, desc)
    def finish(header, headerlineno, anns, diag):
        name, desc = header
        return Bug(path, Header(headerlineno, name, desc), list(anns))
    return _parselist(path, f, parseheader, finish)

def writecvelist(data, f):
    for bug in data:
        if isinstance(bug, Bug):
            f.write(bug.header.name)
            if bug.header.description:
                f.write(" ")
                f.write(bug.header.description)
            f.write("\n")
            for annotation in bug.annotations:
                if isinstance(annotation, FlagAnnotation):
                    f.write("\t")
                    f.write(annotation.type)
                    f.write("\n")
                elif isinstance(annotation, StringAnnotation):
                    f.write("\t")
                    f.write(annotation.type)
                    f.write(": ")
                    f.write(annotation.description)
                    f.write("\n")
                elif isinstance(annotation, PackageAnnotation):
                    f.write("\t")
                    if annotation.release:
                        f.write("[")
                        f.write(str(annotation.release))
                        f.write("] ")
                    f.write("- ")
                    f.write(annotation.package + " ")
                    if annotation.version:
                        f.write(annotation.version)
                    elif annotation.kind:
                        f.write("<")
                        f.write(annotation.kind)
                        f.write(">")
                    items = []
                    for flag in annotation.flags:
                        if isinstance(flag, PackageBugAnnotation):
                            items.append("bug #%s" % flag.bug)
                        elif isinstance(flag, PackageUrgencyAnnotation):
                            items.append(flag.severity)
                        else:
                            raise RuntimeError("Got unexpected package flag type %s" % type(flag))
                    if annotation.description:
                        items.append(str(annotation.description))
                    if items:
                        f.write(" (")
                        f.write("; ".join(items))
                        f.write(")")
                    f.write("\n")
                elif isinstance(annotation, XrefAnnotation):
                    if annotation.bugs:
                        f.write("\t{")
                        f.write(" ".join(annotation.bugs))
                        f.write("}\n")
                else:
                    raise RuntimeError("Got unexpected annotation type %s" % type(annotation))
        else:
            raise RuntimeError("Got unexpected bug type %s" % type(bug))

def _checkrelease(anns, diag, kind):
    for ann in anns:
        if ann.type == "package" and ann.release is None:
            diag.error("release annotation required in %s file" % kind,
                       line=ann.line)

@_xpickle.loader("DSA" + FORMAT)
def dsalist(path, f):
    re_header = re.compile(r'^\[(\d\d) ([A-Z][a-z][a-z]) (\d{4})\] '
                            + r'(DSA-\d+(?:-\d+)?)\s+'
                            + r'(.*?)\s*$')
    def parseheader(line):
        match = re_header.match(line)
        if match is None:
            return None
        return match.groups()
    def finish(header, headerlineno, anns, diag):
        d, m, y, name, desc = header
        _checkrelease(anns, diag, "DSA")
        return Bug(path, Header(headerlineno, name, None), list(anns))
    return _parselist(path, f, parseheader, finish)

@_xpickle.loader("DTSA" + FORMAT)
def dtsalist(path, f):
    re_header = re.compile(
        r'^\[([A-Z][a-z]{2,}) (\d\d?)(?:st|nd|rd|th), (\d{4})\] '
        + r'(DTSA-\d+-\d+)\s+'
        + r'(.*?)\s*$')
    def parseheader(line):
        match = re_header.match(line)
        if match is None:
            return None
        return match.groups()
    def finish(header, headerlineno, anns, diag):
        d, m, y, name, desc = header
        _checkrelease(anns, diag, "DTSA")
        return Bug(path, Header(headerlineno, name, None), list(anns))
    return _parselist(path, f, parseheader, finish)

@_xpickle.loader("DLA" + FORMAT)
def dlalist(path, f):
    re_header = re.compile(r'^\[(\d\d) ([A-Z][a-z][a-z]) (\d{4})\] '
                            + r'(DLA-\d+(?:-\d+)?)\s+'
                            + r'(.*?)\s*$')
    def parseheader(line):
        match = re_header.match(line)
        if match is None:
            return None
        return match.groups()
    def finish(header, headerlineno, anns, diag):
        d, m, y, name, desc = header
        _checkrelease(anns, diag, "DLA")
        return Bug(path, Header(headerlineno, name, None), list(anns))
    return _parselist(path, f, parseheader, finish)

@_xpickle.loader("EXT" + FORMAT)
def extadvlist(path, f):
    re_header = re.compile(r'^\[(\d\d) ([A-Z][a-z][a-z]) (\d{4})\] '
                            + r'([A-Z]+-\d+(?:-\d+)?)\s+'
                            + r'(.*?)\s*$')
    def parseheader(line):
        match = re_header.match(line)
        if match is None:
            return None
        return match.groups()
    def finish(header, headerlineno, anns, diag):
        d, m, y, name, desc = header
        _checkrelease(anns, diag, "EXT")
        return Bug(path, Header(headerlineno, name, None), list(anns))
    return _parselist(path, f, parseheader, finish)

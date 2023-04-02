# sectracker.analyzers -- vulnerability analysis
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

import apt_pkg as _apt_pkg
import re as _re

from collections import namedtuple as _namedtuple

# _apt_pkg.version_compare is the Debian version comparison algorithm
_apt_pkg.init()

def mergelists(listfiles, diag):
    """Merge the (already parsed) list files in listfiles.
    Returns a dictionary mapping bug names to bug tuples.
    If duplicate bug names are encountered, an error is recorded
    in diag."""
    result = {}
    for listfile in listfiles:
        for bug in listfile:
            header = bug.header
            name = header.name
            if name in result:
                diag.error("duplicate bug %r" % name,
                           file=bug.file, line=header.line)
                diag.error("location of previous bug",
                           file=result[name].file, line=result[name].header.line)
                continue
            result[name] = bug
    return result

def extractversions(config, bugdb, diag):
    """Extracts version information from list files.

    Uses the repository configuration config to obtain a nested
    dictionary, mapping release names to packages and sets of
    versions.  Then scans the bug database dictionary for additional
    versions for those releases.  If an unknown release is
    encountered, an error message is added to diag."""

    rpv = config.releasepackageversions()
    for bug in bugdb.values():
        for ann in bug.annotations:
            if ann.type == "package" and ann.version is not None \
                    and ann.release is not None:
                if ann.release not in rpv:
                    diag.error(file=bug.file, line=ann.line,
                               message="unknown release: %r" % ann.release)
                else:
                    pv = rpv[ann.release]
                    if ann.package in pv:
                        pv[ann.package].add(ann.version)
                    else:
                        pv[ann.package] = set((ann.version,))
    return rpv

_re_source = _re.compile("^DT?SA-")

def copysources(bugdb, diag):
    """Returns a dictionary, mapping bug names to their copy sources.
    
    As a side effect, this checks cross-references.  Errors found
    there are recorded in diag."""

    result = {}
    for bug in bugdb.values():
        copy_source = bug.header.name
        if not _re_source.match(copy_source):
            copy_source = None
        for ann in bug.annotations:
            if ann.type != "xref":
                continue
            for target in ann.bugs:
                if target not in bugdb:
                    diag.error("reference to unknown bug %r" % target,
                               file=bug.file, line=ann.line)
                    continue
                if copy_source is not None:
                    if target in result:
                        result[target].add(copy_source)
                    else:
                        result[target] = set((copy_source,))
    return result

Vulnerability = _namedtuple("Vulnerability", "bug package fixed fixed_other")

def fixedversions(bugdb, copysrc, versions, diag):
    """Determine vulnerable versions.

    Returns named tuples with fields "bug", "package", "fixed",
    "fixed_other"."""

    assert "sid" in versions # should come from extractversions()

    def buildpackages1(bug, target=None):
        packages = {}
        xref = () # current {} contents
        for ann in bug.annotations:
            # only copy if target is listed in current {} list
            if ann.type == "package" and (target is None or target in xref):
                if ann.package not in packages:
                    packages[ann.package] = {}
                pkg = packages[ann.package]
                pkg[ann.release] = (bug, ann)
            elif ann.type == "xref":
                xref = ann.bugs
        return packages

    def buildpackages(bug):
        packages = buildpackages1(bug)
        if bug.header.name not in copysrc:
            return packages
        copiers = [buildpackages1(bugdb[b], target=bug.header.name)
                   for b in copysrc[bug.header.name]]
        for c in copiers:
            for pname, creleases in c.items():
                if pname not in packages:
                    packages[pname] = creleases
                    continue
                preleases = packages[pname]
                for rel, cbugann in creleases.items():
                    if rel in preleases:
                        pbug, pann = preleases[rel]
                        cbug, cann = cbugann
                        if pbug is bug:
                            # Never override annotations in the CVE file.
                            continue
                        diag.warning("annotation on %s overridden"
                                     % pbug.header.name,
                                     file=pbug.file, line=pann.line)
                        diag.warning("  by annotation on %s via %s" 
                                     % (cbug.header.name, bug.header.name),
                                     file=cbug.file, line=cann.line)
                    preleases[rel] = cbugann
        return packages

    def latentlyvulnerable(packages):
        for pname, preleases in packages.items():
            if None not in preleases:
                diag.warning("package %s is latently vulnerable in unstable"
                             % pname,
                             file=bug.file, line=bug.header.line)
                for (pbug, pann) in preleases.values():
                    diag.warning("%s vulnerability in %s"
                                 % (pname, pann.release),
                                 file=pbug.file, line=pann.line)

    def convertversion(ann):
        # None: unfixed
        # version-string: fixed in that version
        # True: never vulnerable
        if ann.urgency == "unimportant" or ann.kind == "not-affected":
            return True
        ver = ann.version
        if ver is not None:
            return ver
        return None
        
    def extractunstable(preleases):
        if None not in preleases:
            return None
        return convertversion(preleases[None][1])

    def getversions(pname, version_items=versions.items()):
        # FIXME: extractversions() should return flipped nested
        # dictionary, to make the following easier.
        for rel, pkgs in version_items:
            if rel == "sid":
                continue
            if pname in pkgs:
                for ver in pkgs[pname]:
                    yield rel, ver

    result = []
    for bug in bugdb.values():
        if _re_source.match(bug.header.name):
            # Copy sources are dealt with by copying their
            # annotations.
            continue

        packages = buildpackages(bug)
        latentlyvulnerable(packages)

        for pname, preleases in packages.items():
            unstable_fixed = extractunstable(preleases)
            if unstable_fixed is True:
                # unstable was never vulnerable, which overrides
                # all other annoations
                continue

            other_versions = set()
            for rel, ver in getversions(pname):
                if unstable_fixed is not None \
                        and _apt_pkg.version_compare(ver, unstable_fixed) >= 0:
                    # This version is already covered by the
                    # unstable fix.
                    continue
                if rel in preleases:
                    refver = convertversion(preleases[rel][1])
                    if refver is None:
                        continue
                    if refver is True:
                        # Annotations like <not-affected>.
                        other_versions.add(ver)
                        continue
                    if _apt_pkg.version_compare(ver, refver) >= 0:
                        other_versions.add(ver)
            result.append(Vulnerability(bug.header.name, pname,
                                        unstable_fixed, other_versions))
    return result

def bestversion(config, codename, pkg, requested_members=None):
    """Returns the source package with the highest version among the
    requested sub-repository members."""
    members = config.distributions[codename]["members"]
    fm = config.filemap()
    bestver = None
    bestpkg = None
    for name, mems in members.items():
        if requested_members is None or name in requested_members:
            for mem in mems:
                for comp in fm[mem].values():
                    if pkg in comp:
                        curpkg = comp[pkg]
                        curver = curpkg.version
                        if bestver is None or _apt_pkg.version_compare(curver, bestver) > 0:
                            bestver = curver
                            bestpkg = curpkg
    return bestpkg


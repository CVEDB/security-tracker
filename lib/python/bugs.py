# bugs.py -- read bug lists used by Debian's testing security team
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

import debian_support
import functools
import os
import re
import hashlib

from helpers import isstring

class Urgency(debian_support.PseudoEnum): pass

def listUrgencies():
    urgencies = {}
    urgs = ('high', 'medium', 'low', 'unimportant', 'end-of-life', 'not yet assigned')
    for u in range(len(urgs)):
        urgencies[urgs[u]] = Urgency(urgs[u], -u)
    Urgency.urgencies = urgencies
    return urgencies
def internUrgency(name, urgencies=listUrgencies()):
    if name in urgencies:
        return urgencies[name]
    else:
        return None
del listUrgencies

def to_integer(expr):
    ei = int(expr)
    assert ei == expr, expr
    return ei

class PackageNote:
    """A package note.

    The following member variables are defined:

    release - the release the package note applies to; None means "testing",
              notes for other releases never apply to testing
    """
    
    def __init__(self, package, fixed_version, release, urgency):
        self.id = None
        self.package = package
        if (isstring(fixed_version)):
            self.fixed_version = debian_support.Version(fixed_version)
        else:
            self.fixed_version = fixed_version
        if release == '':
            self.release = None
        else:
            if isstring(release):
                release = debian_support.internRelease(release)
                if release is None:
                    raise ValueError("invalid release")
            self.release = release
        if isstring(urgency):
            urgency = internUrgency(urgency)
        if urgency is None:
            raise ValueError("invalid urgency")
        self.urgency = urgency
        self.bugs = []
        self.package_kind = "unknown"
        self.bug_origin = None

    def writeDB(self, cursor, bug_name, bug_origin=''):
        """Writes the object to an SQLite database."""

        if self.fixed_version:
            v = str(self.fixed_version)
        else:
            v = None
        if self.release:
            r = str(self.release)
        else:
            r = ''
        cursor.execute("""INSERT INTO package_notes
        (bug_name, package, fixed_version, release, urgency, bug_origin,
         package_kind)
        VALUES (?, ?, ?, ?, ?, ?, ?)""",
                       (bug_name, self.package, v, r,
                        str(self.urgency), bug_origin, self.package_kind))
        for (rowid,) in cursor.execute('SELECT last_insert_rowid()'):
            self.id = rowid
            for b in self.bugs:
                cursor.execute("""INSERT INTO debian_bugs (bug, note)
                VALUES (?, ?)""", (b, rowid))
            return
        assert False

    def loadBugs(self, cursor):
        id = to_integer(self.id)
        assert len(self.bugs) == 0
        for (b,) in cursor.execute\
                ("SELECT bug FROM debian_bugs WHERE note = ?", (id,)):
            self.bugs.append(int(b))

    def merge(self, other):
        """Add the contents of another, compatible package note to this one."""
        assert self.release is other.release
        assert self.package == other.package
        self.bugs = debian_support.mergeAsSets(self.bugs, other.bugs)
        self.urgency = max(self.urgency, other.urgency)
        if self.fixed_version is None or other.fixed_version is None:
            self.fixed_version = None
        else:
            self.fixed_version = max(self.fixed_version, other.fixed_version)

class PackageNoteFromDB(PackageNote):
    def __init__(self, cursor, nid):
        for (bug_name, package, fixed_version, release, urgency,
             package_kind, bug_origin) in cursor.execute\
            ("""SELECT bug_name, package, fixed_version, release, urgency,
            package_kind, bug_origin
            FROM package_notes WHERE id = ?""", (nid,)):
            PackageNote.__init__(package, fixed_version, release, urgency)
            self.id = nid
            self.bug_name = bug_name
            self.package_kind = package_kind
            self.loadBugs(cursor)
            return
        raise ValueError("invalid package note ID %d" % id)

class PackageNoteParsed(PackageNote):
    """Subclass with a constructor that parses package notes."""

    re_bug = re.compile(r'^bug #(\d+)$')
    re_notes_split = re.compile(r'\s*;\s+') 

    def __init__(self, package, version, notes, release=None):
        bugs = []
        urgency = 'not yet assigned'
        if notes is not None:
            for n in self.re_notes_split.split(notes):
                u = internUrgency(n)
                if u:
                    urgency = u
                    continue

                if n == 'bug filed':
                    continue

                match = self.re_bug.match(n)
                if match:
                    (bug,) = match.groups()
                    bugs.append(int(bug))
                    continue

                raise SyntaxError('unknown package note %s\n' % repr(n))
        PackageNote.__init__(self, package, version, release, urgency)
        self.bugs = bugs

class PackageNoteNoDSA:
    def __init__(self, package, release, comment, reason=None):
        assert isstring(package) and package != ''
        assert isstring(release) and release != ''
        assert isstring(comment)
        if not reason:
            reason = ''
        else:
            assert isstring(reason)
        self.package = package
        release = debian_support.internRelease(release)
        if release is None:
            raise ValueError("invalid release")
        self.release = release
        self.comment = comment
        self.reason = reason

    def writeDB(self, cursor, bug_name):
        cursor.execute("""INSERT INTO package_notes_nodsa
        (bug_name, package, release, comment, reason)
        VALUES (?, ?, ?, ?, ?)""",
                       (bug_name, self.package, str(self.release),
                        self.comment, self.reason))

class BugBase:
    "Base class for entries in the bug list."""

    re_cve_name = re.compile(r'^CVE-\d{4}-\d{4,}$')

    def __init__(self, fname, lineno, date, name, description, comments):
        assert isstring(fname)
        lineno = to_integer(lineno)
        self.source_file = fname
        self.source_line = lineno
        self.date = date
        self.name = name
        self.description = description
        self.comments = comments
        self.notes = []
        self.xref = []
        self.not_for_us = False
        self.is_extend = False

    def isFromCVE(self):
        """Returns True if the name has been officially assigned.

        Our database is mostly CVE-driven, but sometimes we need names
        which have not been assigned yet.  Therefore, we generate
        identifiers on the fly.
        """
        return self.re_cve_name.match(self.name) is not None

    def cveStatus(self):
        if self.isFromCVE():
            return 'ASSIGNED'
        else:
            return ''

    def writeDB(self, cursor):
        """Writes the record to an SQLite3 database."""

        if self.not_for_us:
            not_for_us = 1
        else:
            not_for_us = 0

        import apsw

        if not self.is_extend:
            try:
                cursor.execute("""INSERT INTO bugs
                (name, cve_status, not_for_us, description, release_date,
                 source_file, source_line)
                VALUES (?, ?, ?, ?, ?, ?, ?)""",
                               (self.name, self.cveStatus(), not_for_us,
                                self.description, self.date or '',
                                self.source_file, self.source_line))
            except apsw.ConstraintError:
                raise ValueError("bug name %s is not unique" % self.name)

        for (typ, c) in self.comments:
            cursor.execute("""INSERT INTO bugs_notes
            (bug_name, typ, comment) VALUES (?, ?, ?)""",
                           (self.name, typ, c))

        for n in self.notes:
            n.writeDB(cursor, self.name)

        for x in self.xref:
            try:
                cursor.execute("""INSERT INTO bugs_xref
                (source, target) VALUES (?, ?)""",
                               (self.name, x))
            except apsw.ConstraintError:
                raise ValueError(
                      "cross reference to %s appears multiple times" % x)

class Bug(BugBase):
    """Class for bugs for which we have some data."""

    def __init__(self, fname, lineno, date, name, description, comments, notes,
                 xref, not_for_us=False, is_extend=False):
        for n in notes:
            assert isinstance(n, PackageNote) \
                   or isinstance(n, PackageNoteNoDSA)
        assert len(xref) == 0 or isstring(xref[0])
        assert isinstance(not_for_us, bool)
        BugBase.__init__(self, fname, lineno, date, name,
                         description, comments)
        self.notes = notes
        self.xref = xref
        self.not_for_us = not_for_us
        self.is_extend = is_extend

    def mergeNotes(self):
        """Merge notes so that there is only one note for each
        (package, release) pair."""
        if len(self.notes) < 2:
            return
        notes = {}
        for n in self.notes:
            key = (n.package, n.release)
            if key in notes:
                notes[key].merge(n)
            else:
                notes[key] = n
        l = list(notes.keys())

        # The release part of a key can be None, so we have to deal
        # with that when sorting.
        l.sort(key=lambda n: (n[0], n[1] or debian_support.internRelease('sid')))

        nts = []
        for key in l:
            nts.append(notes[key])
        self.notes = nts

class BugFromDB(Bug):
    def __init__(self, cursor, name):
        assert isstring(name)

        def lookup(bug):
            for r in cursor.execute('SELECT * FROM bugs WHERE name = ?',
                                    (bug,)):
                return r
            else:
                return None

        def lookup_dsa(bug):
            for r in cursor.execute(
                """SELECT * FROM bugs
                WHERE name = ? OR name LIKE (? || '-%')
                ORDER BY release_date DESC
                LIMIT 1""", (bug, bug,)):
                return r
            else:
                return None

        r = lookup(name)
        if r is None:
            name_components = name.split('-')
            name_source = name_components[0]
            if name_source == 'DSA' and 2 <= len(name_components) <= 3:
                r = lookup_dsa('DSA-' + name_components[1])
            if r is None:
                raise ValueError("unknown bug " + repr(name))

        rdesc = cursor.getdescription()
        data = {}
        for j in range(len(rdesc)):
            data[rdesc[j][0]] = r[j]
        name = data['name']
        Bug.__init__(self, data['source_file'], data['source_line'],
                     data['release_date'], name,
                     data['description'], comments=[],
                     notes=[], xref=[],
                     not_for_us=not not data['not_for_us'])
        for (x,) in cursor.execute\
            ('SELECT target FROM bugs_xref WHERE source = ?', (name,)):
            self.xref.append(x)
        for (t, c) in cursor.execute\
            ("""SELECT typ, comment FROM bugs_notes
            WHERE bug_name = ?
            ORDER BY rowid""",
             (name,)):
            self.comments.append((t, c))

        # temporary list required because loadBugs needs the cursor
        for (nid, package, fixed_version, release, urgency, package_kind,
             bug_origin) in list(cursor.execute
            ("""SELECT id, package, fixed_version, release, urgency,
            package_kind, bug_origin
            FROM package_notes WHERE bug_name = ?""", (name,))):
            n = PackageNote(package, fixed_version, release, urgency)
            n.id = nid
            n.bug_name = name
            n.package_kind = package_kind
            n.bug_origin = bug_origin
            n.loadBugs(cursor)
            self.notes.append(n)

    def getDebianBugs(self, cursor):
        """Returns a list of Debian bugs to which the bug report refers."""
        return [x[0] for x in cursor.execute(
            """SELECT DISTINCT bug FROM package_notes, debian_bugs
            WHERE package_notes.bug_name = ?
            AND debian_bugs.note = package_notes.id
            ORDER BY bug""", (self.name,))]

    def getStatus(self, cursor):
        """Calculate bug status.

        Returns list of tuples (RELEASE, STATUS, REASON)."""
        
        return list(cursor.execute(
            """SELECT release, status, reason
            FROM bug_status WHERE bug_name = ?""",
            (self.name,)))

class BugReservedCVE(BugBase):
    """Class for reserved CVE entries."""
    def __init__(self, fname, lineno, name, comments=None):
        if comments is None:
            comments = []
        BugBase.__init__(self, fname, lineno, None, name, "RESERVED", comments)
        # for-us bugs are upgraded to real Bug objects.
        self.not_for_us = True
    def cveStatus(self):
        return 'RESERVED'

class BugRejectedCVE(Bug):
    """Class for rejected CVE entries."""
    def cveStatus(self):
        return 'REJECTED'

def temp_bug_name(bug_number, description):
    """Build a unique temporary name from the bug number and a
    truncated hash of the description."""
    digest = hashlib.md5()
    digest.update(description.encode('utf-8'))
    hexdigest = digest.hexdigest()[0:6].upper()
    return 'TEMP-%07d-%s' % (bug_number, hexdigest)

class FileBase(debian_support.PackageFile):
    re_non_ascii = re.compile(r'.*([^\n\t -~]).*')
    re_empty = re.compile(r'^(?:\s*$|--)')
    re_indent = re.compile(r'^\s+(.*?)\s*$')
    re_begin_claim = re.compile(r'^begin claimed by (\S+)\s*$')
    re_end_claim = re.compile(r'^end claimed by (\S+)\s*$')
    re_stop = re.compile(r'^STOP:')

    re_xref_required = re.compile(r'^\{')
    re_xref = re.compile(r'^\{\s*([^\}]+?)\s*\}$')
    re_whitespace = re.compile(r'\s+')
    re_xref_entry = re.compile('^(?:CVE-\d{4}-\d{4,}'
                               + r'|VU#\d{6}'
                               + r'|DSA-\d+(?:-\d+)?|DTSA-\d+-\d+|DLA-\d+-\d+)$')
    re_xref_entry_own = re.compile(
        '^(?:CVE-\d{4}-\d{4,}|DSA-\d+(?:-\d+)?|DTSA-\d+-\d+|DLA-\d+-\d+)$')

    re_package_required = re.compile(r'^(?:\[.*\]\s*)?-')
    re_package_version = re.compile(
        r'^(?:\[([a-z]+)\]\s)?-\s([A-Za-z0-9:.+-]+)\s*'
        + r'(?:\s([A-Za-z0-9:.+~-]+)\s*)?(?:\s\((.*)\))?$')
    re_package_no_version = re.compile(
        r'^(?:\[([a-z]+)\]\s)?-\s([A-Za-z0-9:.+-]+)'
        + r'\s+<([a-z-]+)>\s*(?:\s\((.*)\))?$')
    re_not_for_us_required = re.compile(r'^NOT-FOR-US:')
    re_not_for_us = re.compile(r'^NOT-FOR-US:\s+(.*?)\s*$')
    re_reserved = re.compile(r'^(?:NOTE:\s+reserved|RESERVED)\s*$')
    re_rejected = re.compile(r'^(?:NOTE:\s+rejected|REJECTED)\s*$')
    re_note = re.compile(r'^NOTE:\s+(.*)$')
    re_todo = re.compile(r'^TODO:\s+(.*)$')
    is_extend = False

    def __init__(self, name, fileObj=None):
        debian_support.PackageFile.__init__(self, name, fileObj)
        self.removed_packages = {}

    def isUniqueName(self, name):
        """Returns True if the name is a real, unique name."""
        return True

    def matchHeader(self, line):
        """Parses the header of a record.

        Must be overriden by child classes."""
        assert False

    def getLine(self):
        while 1:
            self.line = self.file.readline()
            self.lineno += 1

            if self.line == '' or not self.re_empty.match(self.line):
                break

        match = self.re_non_ascii.match(self.line)
        if match is not None:
            self.raiseSyntaxError('invalid non-printable character %s'
                                  % repr(match.groups()[0]))

    def rawRecords(self):
        """Generator which returns raw records.

        These records are 4-tuples with the following contents:

        - line number of the start of the record
        - release data; can be None
        - something which resembles a CVE name; is not necessarily unique
          if it does not match the CVE syntax
        - part of the CVE description
        - subrecords, a list of pairs line number/string
        """

        self.getLine()
        record = []
        after_stop = False
        while self.line:
            first_line = self.lineno
           
            if self.re_stop.match(self.line):
                after_stop = True
                self.getLine()
                continue
                
            # We ignore claims, but check their syntax nevertheless.
            match = self.re_begin_claim.match(self.line)
            if match:
                self.getLine()
                continue
            match = self.re_end_claim.match(self.line)
            if match:
                self.getLine()
                continue
            
            (date, record_name, description) = self.matchHeader(self.line)

            record = []
            while self.line:
                self.getLine()

                match = self.re_indent.match(self.line)
                if match:
                    (r,) = match.groups()
                    record.append((self.lineno, r))
                else:
                    break
            # line contains the next line at this point.

            if after_stop and len(record) == 0:
                # Patch in not-for-us field, so that bugs after STOP:
                # are ignored.
                record = [(first_line, 'NOT-FOR-US: entry too old')]

            yield (first_line, date, record_name, description, record)

    def __iter__(self):
        """Generator for Bug objects."""
        for (first_lineno, date, record_name, description, record)\
                in self.rawRecords():

            not_for_us = None
            xref = []
            pkg_notes = []
            comments = []
            cve_reserved = False
            cve_rejected = False

            for (lineno, r) in record:
                def handle_xref(re_required, re_real, re_entry, target):
                    if re_required.match(r):
                        match = re_real.match(r)
                        if match:
                            (xref_string,) = match.groups()
                            for x in self.re_whitespace.split(xref_string):
                                if re_entry.match(x):
                                    target.append(x)
                                else:
                                    self.raiseSyntaxError(
                                        "invalid cross reference " + repr(x),
                                         lineno)
                            return True
                        else:
                            self.raiseSyntaxError(
                                "expected cross reference, got: " + repr(r),
                                lineno)
                    else:
                        return False
                                
                if handle_xref(self.re_xref_required, self.re_xref,
                               self.re_xref_entry, xref):
                    continue

                def addPackageNote(note):
                    self.checkPackageNote(pkg_notes, note, lineno)
                    pkg_notes.append(note)

                if self.re_package_required.match(r):
                    match = self.re_package_version.match(r)
                    if match:
                        (release, p, v, d) = match.groups()
                        addPackageNote(PackageNoteParsed(p, v, d, release=release))
                        continue

                    match = self.re_package_no_version.match(r)
                    if match:
                        (release, p, v, d) = match.groups()
                        if v == 'not-affected':
                            addPackageNote(PackageNoteParsed
                                             (p, '0', 'unimportant',
                                              release=release))
                            if d:
                                # Not exactly ideal, but we have to
                                # record the free-form text in some
                                # way.
                                if r[-1] == '\n':
                                    r = r[:-1]
                                comments.append(('NOTE', r))
                        elif v == 'end-of-life':
                            addPackageNote(PackageNoteParsed
                                             (p, None, 'end-of-life',
                                              release=release))
                            if d:
                                # Not exactly ideal, but we have to
                                # record the free-form text in some
                                # way.
                                if r[-1] == '\n':
                                    r = r[:-1]
                                comments.append(('NOTE', r))
                        elif v in ('no-dsa','ignored','postponed'):
                            if not release:
                                self.raiseSyntaxError(
                                    "no-dsa note needs release specification",
                                    lineno)
                            if not d:
                                self.raiseSyntaxError(
                                    "no-dsa note needs comment",
                                    lineno)
                            if v in ('ignored','postponed'):
                                reason = v
                            else:
                                reason = None
                            addPackageNote(PackageNoteNoDSA(
                                release=release,
                                package=p,
                                comment=d,
                                reason=reason))
                            if d:
                                # Not exactly ideal, but we have to
                                # record the free-form text in some
                                # way.
                                if r[-1] == '\n':
                                    r = r[:-1]
                                comments.append(('NOTE', r))
                        elif v == 'itp':
                            x = PackageNoteParsed(p, None, d, release=release)
                            x.package_kind = 'itp'
                            if not x.bugs:
                                self.raiseSyntaxError(
                                    "ITP note needs Debian bug reference",
                                    lineno)
                            addPackageNote(x)
                        elif v == 'unfixed':
                            addPackageNote(PackageNoteParsed
                                             (p, None, d, release=release))
                        elif v == 'removed':
                            addPackageNote(PackageNoteParsed
                                             (p, None, d, release=release))
                            self.removed_packages[p] = True
                        elif v == 'undetermined':
                            addPackageNote(PackageNoteParsed
                                             (p, 'undetermined', d, release=release))
                        else:
                            self.raiseSyntaxError(
                                "invalid special version %s in package entry"
                                % repr(r), lineno)
                        continue
                    
                    self.raiseSyntaxError(
                        "expected package entry, got: " + repr(r), lineno)

                if self.re_not_for_us_required.match(r):
                    match = self.re_not_for_us.match(r)
                    if match:
                        (not_for_us,) = match.groups()
                        if not_for_us is None:
                            not_for_us = ''
                        continue
                    else:
                        self.raiseSyntaxError("expected NOT-FOR-US entry, "
                                              + "got: " + repr(r), lineno)

                match = self.re_reserved.match(r)
                if match:
                    cve_reserved = True
                    continue

                match = self.re_rejected.match(r)
                if match:
                    cve_rejected = True
                    continue

                match = self.re_note.match(r)
                if match:
                    (note,) = match.groups()
                    comments.append(('NOTE', note))
                    continue

                match = self.re_todo.match(r)
                if match:
                    (todo,) = match.groups()
                    comments.append(('TODO', todo))
                    continue

                self.raiseSyntaxError('expected CVE annotation, got: %s'
                                      % repr(r), lineno)
                break

            if cve_reserved:
                if not self.isUniqueName(record_name):
                    self.raiseSyntaxError\
                        ('reserved CVE entries must have CVE names',
                         first_lineno)
                if len(pkg_notes) > 0:
                    # The bug has extra data even though it is marked
                    # reserved by CVE, we have to issue the full
                    # version because the official CVE lags a bit.
                    yield self.finishBug(Bug(self.file.name, first_lineno,
                                             date, record_name, description,
                                             comments,
                                             notes=pkg_notes, xref=xref))
                else:
                    yield BugReservedCVE(self.file.name, first_lineno,
                                         record_name, comments)

            elif cve_rejected:
                if not self.isUniqueName(record_name):
                    self.raiseSyntaxError\
                        ('rejected CVE entries must have CVE names',
                         first_lineno)
                yield self.finishBug(BugRejectedCVE(
                        self.file.name, first_lineno, date,
                        record_name, description,
                        comments, notes=pkg_notes, xref=xref))

            elif not_for_us is not None:
                if not self.isUniqueName(record_name):
                    self.raiseSyntaxError\
                        ('not-for-us bug must have CVE name', first_lineno)
                if len(pkg_notes) > 0:
                    self.raiseSyntaxError\
                        ('package information not allowed in not-for-us bugs',
                         first_lineno)
                if not_for_us:
                    comments[:0] = [('NOTE', 'NOT-FOR-US: ' + not_for_us)]
                yield self.finishBug(Bug(self.file.name, first_lineno, date,
                                         record_name, description, comments,
                                         [], xref=xref,
                                         not_for_us=True))
            else:
                if not self.isUniqueName(record_name):
                    first_bug = 0
                    for n in pkg_notes:
                        for b in getattr(n, 'bugs', []):
                            first_bug = b
                            break
                        if first_bug:
                            break
                    record_name = temp_bug_name(first_bug, description)
                yield self.finishBug(Bug(self.file.name, first_lineno, date,
                                         record_name, description,
                                         comments, notes=pkg_notes, xref=xref,
                                         is_extend=self.is_extend))

    def finishBug(self, bug):
        """Applies a transformation to the bug after it has been
        parsed, or adds some additional checking."""
        return bug

    def checkPackageNote(self, notes, note, lineno):
        if not notes:
            return

        prev_note = notes[-1]
        if prev_note.package != note.package:
            if prev_note.release and prev_note.release == debian_support.internRelease('experimental'):
                #self.raiseSyntaxError("experimental release note must come before the package note")
                pass
            elif note.release and note.release != debian_support.internRelease('experimental'):
                self.raiseSyntaxError("release note must follow its package note", lineno)
        else:
            if prev_note.release and note.release and prev_note.release < note.release:
                self.raiseSyntaxError("release notes not ordered properly", lineno)


class CVEFile(FileBase):
    """A CVE file, as used by the Debian testing security team."""
    
    re_cve = re.compile(r'^(CVE-\d{4}-(?:\d{4,}|XXXX))\s+(.*?)\s*$')

    def __init__(self, name, fileObj=None):
        FileBase.__init__(self, name, fileObj)
        self.no_version_needs_note = True

    def isUniqueName(self, name):
        return BugBase.re_cve_name.match(name) is not None

    def matchHeader(self, line):
        match = self.re_cve.match(line)
        if not match:
            self.raiseSyntaxError("expected CVE record, got: %s" % repr(line))
            (record_name, description) = match.groups()
        (cve, desc) = match.groups()
        if desc:
            if desc[0] == '(':
                if desc[-1] != ')':
                    self.raiseSyntaxError("missing closing parenthesis")
                else:
                    desc = desc[1:-1]
            elif desc[0] == '[':
                if desc[-1] != ']':
                    self.raiseSyntaxError("missing closing bracket")
                else:
                    desc = desc[1:-1]
        return (None, cve, desc)

    def finishBug(self, bug):
        # Merge identical package notes, for historical reasons.
        bug.mergeNotes()
        return bug

    def checkPackageNote(self, notes, note, lineno):
        # dont check old entries for now
        if self.lineno >= 100000:
            return

        super().checkPackageNote(notes, note, lineno)


class CVEExtendFile(CVEFile):
    # This is an extend file. The main CVEFile can have a 'CVE-2018-XXXX' (sic)
    # identifier, which will get converted to TEMP-* automatically. However to
    # refer to that one from here, we need to use the TEMP-* identifier, so we
    # allow those in the regex
    re_cve = re.compile(r'^(CVE-\d{4}-(?:\d{4,}|XXXX)|TEMP-\d+-\S+)\s+(.*?)\s*$')

    is_extend = True

    def isUniqueName(self, name):
        # an extend file can have TEMP-* entries to refer to the temp values
        # for e.g. CVE-2018-XXXX. Consider TEMP-* entries as unique, so they
        # don't get re-hashed and their notes get added to the original entries
        if name.startswith('TEMP-'):
            return True

        return CVEFile.isUniqueName(self, name)

    def checkPackageNote(self, notes, note, lineno):
        pass


class DSAFile(FileBase):
    """A DSA file.

    Similar to a CVE file, only that it contains DSAs as its main
    reference point, and release dates.
    """

    def __init__(self, name, fileObj=None):
        FileBase.__init__(self, name, fileObj)

        self.base = os.path.basename(os.path.dirname(self.name))
        self.re_dsa = re.compile(r'^\[(\d\d) ([A-Z][a-z][a-z]) (\d{4})\] '
                                + r'(' + self.base + '-\d+(?:-\d+)?)\s+'
                                + r'(.*?)\s*$')

    month_names = {'Jan': 1,
                   'Feb': 2,
                   'Mar': 3,
                   'Apr': 4,
                   'May': 5,
                   'Jun': 6,
                   'Jul': 7,
                   'Aug': 8,
                   'Sep': 9,
                   'Oct': 10,
                   'Nov': 11,
                   'Dec': 12}

    def matchHeader(self, line):
        match = self.re_dsa.match(line)
        if not match:
            self.raiseSyntaxError("expected %s record, got: %s" % (self.base, repr(line)))
            (record_name, description) = match.groups()
        (day, month, year, name, desc) = match.groups()
        try:
            month = self.month_names[month]
        except KeyError:
            self.raiseSyntaxError("invalid month name %s" % repr(month))
        return ("%s-%02d-%s" % (year, month, day), name, desc)

    def finishBug(self, bug):
        # Merge identical package notes, for historical reasons.
        bug.mergeNotes()
        return bug

    def checkPackageNote(self, notes, note, lineno):
        pass


class DTSAFile(FileBase):
    """A DTSA file.

    Like a DSA file, but the date format is different.
    """

    re_dsa = re.compile\
             (r'^\[([A-Z][a-z]{2,}) (\d\d?)(?:st|nd|rd|th), (\d{4})\] '
              + r'(DTSA-\d+-\d+)\s+'
              + r'(.*?)\s*$')
    month_names = {'January': 1,
                   'February': 2,
                   'March': 3,
                   'April': 4,
                   'May': 5,
                   'June': 6,
                   'July': 7,
                   'August': 8,
                   'September': 9,
                   'October': 10,
                   'November': 11,
                   'December': 12}

    def matchHeader(self, line):
        match = self.re_dsa.match(line)
        if not match:
            self.raiseSyntaxError("expected DTSA record, got: %s" % repr(line))
            (record_name, description) = match.groups()
        (month, day, year, name, desc) = match.groups()
        try:
            month = self.month_names[month]
        except KeyError:
            self.raiseSyntaxError("invalid month name %s" % repr(month))
        return ("%s-%02d-%02d" % (year, month, int(day)), name, desc)

    def finishBug(self, bug):
        for n in bug.notes:
            if n.release is None:
                self.raiseSyntaxError(
                    "release annotations required in DTSA files",
                    lineno=bug.source_line)
        return bug

    def checkPackageNote(self, notes, note, lineno):
        pass


def test():
    assert internUrgency("high") > internUrgency("medium")

    assert FileBase.re_non_ascii.match('illegal \xf6 character\n')

    note = PackageNoteParsed('chmlib', '0.36-1', 'bug #327431; medium')
    assert note.bugs == [327431]
    assert note.package == 'chmlib'
    assert note.fixed_version == debian_support.Version('0.36-1')
    assert note.urgency == internUrgency('medium')

    for p in CVEFile('../../data/CVE/list'):
        pass

if __name__ == "__main__":
    test()

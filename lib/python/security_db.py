# security_db.py -- simple, CVE-driven Debian security bugs database
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

"""This module implements a small database for tracking security bugs.

Note that the database is always secondary to the text files.  The
database is only an implementation tool, and not used for maintaining
the data.

The data is kept in a SQLite 3 database.

FIXME: Document the database schema once it is finished.
"""

from apt_pkg import version_compare
import apsw
import base64
import bugs
from collections import namedtuple
import pickle
import glob
import itertools
import os
import os.path
import re
import sys
import zlib

import config
import debian_support
from debian_support import PointUpdateParser

from helpers import isstring

class InsertError(Exception):
    """Class for capturing insert errors.

    The 'errors' member collects all error messages.
    """

    def __init__(self, errors):
        assert len(errors) > 0, errors
        assert isinstance(errors, list), errors
        self.errors = errors

    def __str__(self):
        return self.errors[0] + ' [more...]'

def mergeLists(a, b):
    """Merges two lists."""
    if isstring(a):
        if a == "":
            a = []
        else:
            a = a.split(',')
    if isstring(b):
        if b == "":
            b = []
        else:
            b = b.split(',')
    result = {}
    for x in a:
        result[x] = 1
    for x in b:
        result[x] = 1
    result = list(result.keys())
    result.sort()
    return result

class NVDEntry:
    """A class for an entry in the nvd_data table.
    Objects have the same fileds as the table."""
    def __init__(self, row, description):
        for x in range(len(row)):
            setattr(self, description[x][0], row[x])
    def rangeString(self):
        result = []
        if self.range_local:
            result.append("local")
        if self.range_remote:
            result.append("remote")
        if self.range_user_init:
            result.append("user-initiated")
        return ", ".join(result)

class SchemaMismatch(Exception):
    """Raised to indicate a schema mismatch.

    The caller is expected to remove and regenerate the database."""

# Returned by getBugsForSourcePackage().
# all/open/unimportant/resolved are sequences of BugForSourcePackage.
BugsForSourcePackage = namedtuple(
    "BugsForSourcePackage",
    "all_releases all open unimportant resolved")

# Returned by getBugsForSourcePackage().  releases is a sequence of
# BugForSourcePackageRelease.  global_state is the aggregated state
# across all releases (open/resolved/unimportant).
BugForSourcePackage = namedtuple(
    "BugForSourcePackage",
    "bug description global_state releases")

# Returned by getBugsForSourcePackage(). release, subrelease, version
# come from the source_packages table.  vulnerable comes from
# source_package_status.  state is open/no-dsa/resolved/unimportant
# and inferred from vulnerable and package_notes_nodsa.
# The reason field holds no-dsa substates, which can be ignored/postponed
BugForSourcePackageRelease = namedtuple(
    "BugForSourcePackageRelease",
    "release subrelease version vulnerable state comment reason")

# Internally used by getBugsForSourcePackage().
BugsForSourcePackage_internal = namedtuple(
    "BugsForSourcePackage_internal",
    "bug_name description release subrelease version vulnerable urgency")
BugsForSourcePackage_query = \
"""SELECT bugs.name AS bug_name, bugs.description AS description,
    sp.release AS release, sp.subrelease AS subrelease, sp.version AS version,
    st.vulnerable AS vulnerable, st.urgency AS urgency
  FROM bugs
  JOIN source_package_status st ON (bugs.name = st.bug_name)
  JOIN source_packages sp ON (st.package = sp.rowid)
  WHERE sp.name = ?
  AND (bugs.name LIKE 'CVE-%' OR bugs.name LIKE 'TEMP-%')
  ORDER BY bugs.name COLLATE version DESC, sp.release"""
# Sort order is important for the groupby operation below.

def getBugsForSourcePackage(cursor, pkg):
    data = [BugsForSourcePackage_internal(*row) for row in
            cursor.execute(BugsForSourcePackage_query, (pkg,))]
    # Filter out special releases such as backports.
    data = [row for row in data
            if debian_support.internRelease(row.release) is not None]
    # Obtain the set of releases actually in used, by canonical order.
    all_releases = tuple(sorted(set(row.release for row in data),
                                   key = debian_support.internRelease))
    # dict from (bug_name, release) to the no-dsa reason/comment string.
    no_dsas = {}
    for bug_name, release, reason, comment in cursor.execute(
            """SELECT bug_name, release, reason, comment FROM package_notes_nodsa
            WHERE package = ?""", (pkg,)):
        no_dsas[(bug_name, release)] = [reason, comment]

    all_bugs = []
    # Group by bug name.
    for bug_name, data in itertools.groupby(data,
                                            lambda row: row.bug_name):
        data = tuple(data)
        description = data[0].description
        open_seen = False
        unimportant_seen = False
        releases = {}
        # Group by release.
        for release, data1 in itertools.groupby(data, lambda row: row.release):
            data1 = tuple(data1)
            # The best row is the row with the highest version number.
            # If there is a tie, the empty subrelease row wins.
            best_row = data1[0]
            for row in data1[1:]:
                cmpresult = version_compare(row.version, best_row.version)
                if cmpresult > 0 \
                   or (cmpresult == 0 and row.subrelease == ''):
                    best_row = row
            reason = None
            comment = None

            # Compute state.  Update state-seen flags for global state
            # determination.
            if best_row.vulnerable:
                if best_row.urgency == 'unimportant':
                    state = 'unimportant'
                    unimportant_seen = True
                else:
                    open_seen = True
                    reason, comment = no_dsas.get((bug_name, best_row.release), [None, None])
                    if comment is not None:
                        state = 'no-dsa'
                    else:
                        state = 'open'
            else:
                state = 'resolved'

            bug = BugForSourcePackageRelease(
                best_row.release, best_row.subrelease, best_row.version,
                best_row.vulnerable, state, comment, reason)
            releases[best_row.release] = bug

        # Compute global_state.
        if open_seen:
            global_state = 'open'
        elif unimportant_seen:
            global_state = 'unimportant'
        else:
            global_state = 'resolved'

        all_bugs.append(BugForSourcePackage(bug_name, description,
                                            global_state, releases))

    # Split all_bugs into per-state sequences.
    per_state = {'all_releases': all_releases,
                 'all': all_bugs}
    for state in ("open", "unimportant", "resolved"):
        per_state[state] = tuple(bug for bug in all_bugs
                                 if bug.global_state == state)

    return BugsForSourcePackage(**per_state)

# Returned by DB.getDSAsForSourcePackage().
DSAsForSourcePackage = namedtuple(
    "DSAsForSourcePackage",
    "bug description")

class DB:
    """Access to the security database.

    This is a wrapper around an SQLite database object (which is
    accessible as the "db" member.

    Most operations need a special cursor object, which can be created
    with a cursor object.  The name "cursor" is somewhat of a
    misnomer because these objects are quite versatile.
    """

    def __init__(self, name, verbose=False):
        self.name = name
        self.db = apsw.Connection(name)
        self.verbose = verbose
        c = self.cursor()

        # This gives us better performance (it's usually the file
        # system block size).  This must come first to be effective.

        c.execute("PRAGMA page_size = 4096")

        # Enable WAL.  This means that updates will not block readers.
        c.execute("PRAGMA journal_mode = WAL")

        self.schema_version = 23
        self._initFunctions()

        for (v,) in c.execute("PRAGMA user_version"):
            if v == 0:
                self.initSchema()
            elif v == 20:
                self._initSchema20()
            elif v == 21:
                # Remove legacy views.
                for view in ('testing_status', 'stable_status',
                             'oldstable_status'):
                    try:
                        c.execute('DROP VIEW ' + view)
                    except apsw.SQLError:
                        pass
                c.execute("PRAGMA user_version = 22")
            elif v == 22:
                self._initSchema22()
            elif v != self.schema_version:
                if self.verbose:
                    print("DB: schema version mismatch: expected %d, got %d"
                          % (self.schema_version, v))
                raise SchemaMismatch(repr(v))
            self._initViews(c)
            return
        assert False

    def __del__(self):
        self.db.close()

    def cursor(self):
        """Creates a new database cursor.

        Also see the writeTxn method."""
        return self.db.cursor()

    def writeTxn(self):
        """Creates a cursor for an exclusive transaction.

        No other process may modify the database at the same time.
        After finishing the work, you should invoke the commit or
        rollback methods below.
        """
        c = self.cursor()
        c.execute("BEGIN TRANSACTION EXCLUSIVE")
        return c

    def commit(self, cursor):
        """Makes the changes in the transaction permanent."""
        cursor.execute("COMMIT")

    def rollback(self, cursor):
        """Undos the changes in the transaction."""
        cursor.execute("ROLLBACK")

    def initSchema(self):
        """Creates the database schema."""
        cursor = self.cursor()

        # Set the schema version to an invalid value which is
        # different from zero.  We can use this to detect a partially
        # created schema.

        cursor.execute("PRAGMA user_version = 1")

        cursor.execute("""CREATE TABLE inodeprints
        (file TEXT NOT NULL PRIMARY KEY,
         inodeprint TEXT NOT NULL,
         parsed BLOB)""")

        cursor.execute("""CREATE TABLE version_linear_order
        (id INTEGER NOT NULL PRIMARY KEY,
         version TEXT NOT NULL UNIQUE)""")

        cursor.execute(
            """CREATE TABLE source_packages
            (name TEXT NOT NULL,
            release TEXT NOT NULL,
            subrelease TEXT NOT NULL,
            archive TEXT NOT NULL,
            version TEXT NOT NULL,
            version_id INTEGER NOT NULL DEFAULT 0,
            PRIMARY KEY (name, release, subrelease, archive))""")

        cursor.execute(
            """CREATE TABLE binary_packages
            (name TEXT NOT NULL,
            release TEXT NOT NULL,
            subrelease TEXT NOT NULL,
            archive TEXT NOT NULL,
            version TEXT NOT NULL,
            source TEXT NOT NULL,
            source_version TEXT NOT NULL,
            archs TEXT NOT NULL,
            PRIMARY KEY (name, release, subrelease, archive, version, source,
            source_version))""")
        cursor.execute(
            """CREATE INDEX binary_packages_source
            ON binary_packages(source)""")

        cursor.execute("""CREATE TABLE package_notes
        (id INTEGER NOT NULL PRIMARY KEY,
         bug_name TEXT NOT NULL,
         package TEXT NOT NULL,
         fixed_version TEXT
             CHECK (fixed_version IS NULL OR fixed_version <> ''),
         fixed_version_id INTEGER NOT NULL DEFAULT 0,
         release TEXT NOT NULL,
         package_kind TEXT NOT NULL DEFAULT 'unknown',
         urgency TEXT NOT NULL,
         bug_origin TEXT NOT NULL DEFAULT '')""")
        cursor.execute(
            """CREATE UNIQUE INDEX package_notes_bug
            ON package_notes(bug_name, package, release)""")
        cursor.execute(
            """CREATE INDEX package_notes_package
            ON package_notes(package)""")

        cursor.execute("""CREATE TABLE debian_bugs
        (bug INTEGER NOT NULL,
         note INTEGER NOT NULL,
         PRIMARY KEY (bug, note))""")

        cursor.execute("""CREATE TABLE bugs
        (name TEXT NOT NULL PRIMARY KEY,
         cve_status TEXT NOT NULL
             CHECK (cve_status IN
                    ('', 'CANDIDATE', 'ASSIGNED', 'RESERVED', 'REJECTED')),
         not_for_us INTEGER NOT NULL CHECK (not_for_us IN (0, 1)),
         description TEXT NOT NULL,
         release_date TEXT NOT NULL,
         source_file TEXT NOT NULL,
         source_line INTEGER NOT NULL)""")

        cursor.execute("""CREATE TABLE bugs_notes
        (bug_name TEXT NOT NULL CHECK (typ <> ''),
         typ TEXT NOT NULL CHECK (typ IN ('TODO', 'NOTE')),
         release TEXT NOT NULL DEFAULT '',
         comment TEXT NOT NULL CHECK (comment <> ''))""")

        cursor.execute("""CREATE TABLE bugs_xref
        (source TEXT NOT NULL,
         target TEXT NOT NULL,
         PRIMARY KEY (source, target))""")
        cursor.execute("CREATE INDEX bugs_xref_target ON bugs_xref(target)")

        cursor.execute("""CREATE TABLE bug_status
        (bug_name TEXT NOT NULL,
         release TEXT NOT NULL,
         status TEXT NOT NULL
             CHECK (status IN ('vulnerable', 'fixed', 'unknown', 'undetermined',
                               'partially-fixed', 'todo')),
         reason TEXT NOT NULL,
         PRIMARY KEY (bug_name, release))""")

        cursor.execute("""CREATE TABLE source_package_status
        (bug_name TEXT NOT NULL,
         package INTEGER NOT NULL,
         vulnerable INTEGER NOT NULL,
         urgency TEXT NOT NULL,
         PRIMARY KEY (bug_name, package))""")
        cursor.execute(
            """CREATE INDEX source_package_status_package
            ON source_package_status(package)""")

        cursor.execute(
            "CREATE TABLE removed_packages (name TEXT NOT NULL PRIMARY KEY)")

        cursor.execute(
            """CREATE TABLE nvd_data
            (cve_name TEXT NOT NULL PRIMARY KEY,
            cve_desc TEXT NOT NULL,
            discovered TEXT NOT NULL,
            published TEXT NOT NULL,
            severity TEXT NOT NULL,
            range_local INTEGER,
            range_remote INTEGER,
            range_user_init INTEGER,
            loss_avail INTEGER NOT NULL,
            loss_conf INTEGER NOT NULL,
            loss_int INTEGER NOT NULL,
            loss_sec_prot_user INTEGER NOT NULL,
            loss_sec_prot_admin INTEGER NOT NULL,
            loss_sec_prot_other INTEGER NOT NULL)""")

        cursor.execute(
            """CREATE TABLE debsecan_data
            (name TEXT NOT NULL PRIMARY KEY,
            data TEXT NOT NULL)""")

        self._initNoDSA(cursor)

        self._initNextPointRelease(cursor)

        cursor.execute("PRAGMA user_version = %d" % self.schema_version)

    def _initSchema20(self):
        cursor = self.db.cursor()

        cursor.execute("PRAGMA user_version = 1")
        self._initNoDSA(cursor)
        self._initViews(cursor)
        cursor.execute("DELETE FROM inodeprints WHERE file ='data/CVE/list'")
        cursor.execute("PRAGMA user_version = %d" % self.schema_version)

    def _initNoDSA(self, cursor):
        cursor.execute(
            """CREATE TABLE package_notes_nodsa
            (bug_name TEXT NOT NULL,
            package TEXT NOT NULL,
            release TEXT NOT NULL,
            reason TEXT NOT NULL,
            comment TEXT NOT NULL,
            PRIMARY KEY (bug_name, package, release))
            """)

    def _initSchema22(self):
        cursor = self.db.cursor()

        cursor.execute("PRAGMA user_version = 1")
        self._initNextPointRelease(cursor)
        cursor.execute("PRAGMA user_version = %d" % self.schema_version)

    def _initNextPointRelease(self, cursor):
        cursor.execute(
            """CREATE TABLE next_point_update
            (cve_name TEXT NOT NULL,
            release TEXT NOT NULL,
            PRIMARY KEY (cve_name, release))
            """)

    def _initViews(self, cursor):
        testing = config.get_release_codename('testing')
        cursor.execute(
            """CREATE TEMPORARY VIEW testing_status AS
            SELECT DISTINCT sp.name AS package, st.bug_name AS bug,
            sp.archive AS section, st.urgency AS urgency,
            st.vulnerable AS vulnerable,
            (SELECT vulnerable
            FROM source_packages AS sidp, source_package_status AS sidst
            WHERE sidp.name = sp.name
            AND sidp.release = 'sid' AND sidp.subrelease = ''
            AND sidp.archive = sp.archive
            AND sidst.bug_name = st.bug_name
            AND sidst.package = sidp.rowid) AS unstable_vulnerable,
            COALESCE((SELECT NOT vulnerable
            FROM source_packages AS tsecp, source_package_status AS tsecst
            WHERE tsecp.name = sp.name
            AND tsecp.release = '%s' AND tsecp.subrelease = 'security'
            AND tsecp.archive = sp.archive
            AND tsecst.bug_name = st.bug_name
            AND tsecst.package = tsecp.rowid), 0) AS testing_security_fixed,
            (SELECT range_remote FROM nvd_data
             WHERE cve_name = st.bug_name) AS remote,
            (EXISTS (SELECT * FROM package_notes_nodsa AS pnd
            WHERE pnd.bug_name = st.bug_name
            AND pnd.package = sp.name
            AND pnd.release = '%s')) AS no_dsa
            FROM source_package_status AS st, source_packages AS sp
            WHERE st.vulnerable > 0 AND sp.rowid = st.package
            AND sp.release = '%s' AND sp.subrelease = ''
            ORDER BY sp.name, st.urgency, st.bug_name"""
            % (testing, testing, testing))

        releases = config.get_supported_releases()
        releases.remove(config.get_release_codename('testing'))
        releases.remove('sid')

        for release in releases:
            alias = config.get_release_alias(release)
            cursor.execute(
                """CREATE TEMPORARY VIEW %s_status AS
                SELECT DISTINCT sp.name AS package, st.bug_name AS bug,
                sp.archive AS section, st.urgency AS urgency,
                st.vulnerable AS vulnerable,
                (SELECT range_remote FROM nvd_data
                 WHERE cve_name = st.bug_name) AS remote,
                (SELECT comment FROM package_notes_nodsa AS pnd
                 WHERE pnd.bug_name = st.bug_name
                 AND pnd.package = sp.name
                 AND pnd.release = '%s') AS no_dsa,
                (SELECT reason FROM package_notes_nodsa AS pnd
                 WHERE pnd.bug_name = st.bug_name
                 AND pnd.package = sp.name
                 AND pnd.release = '%s') AS no_dsa_reason
                FROM source_package_status AS st, source_packages AS sp
                WHERE st.vulnerable > 0 AND sp.rowid = st.package
                AND sp.release = '%s' AND sp.subrelease = ''
                AND NOT COALESCE((SELECT NOT vulnerable
                FROM source_packages AS secp, source_package_status AS secst
                WHERE secp.name = sp.name
                AND secp.release = '%s' AND ( secp.subrelease = 'security' OR secp.subrelease = 'lts' )
                AND secp.archive = sp.archive
                AND secst.bug_name = st.bug_name
                AND secst.package = secp.rowid), 0)
                ORDER BY sp.name, urgency_to_number(urgency), st.bug_name"""
                % (alias, release, release, release, release))

        cursor.execute(
            """CREATE TEMPORARY VIEW debian_cve AS
            SELECT debian_bugs.bug, st.bug_name
            FROM package_notes, debian_bugs, source_package_status AS st
            WHERE package_notes.bug_name = st.bug_name
            AND debian_bugs.note = package_notes.id""")

    def _initFunctions(self):
        """Registers user-defined SQLite functions."""

        def string_list_add(lst, *args):
            for arg in args:
                lst.append(arg)
        def string_list_to_string(lst):
            return ', '.join(lst)
        def string_list_factory():
            return ([], string_list_add, string_list_to_string)
        self.db.createaggregatefunction("string_list", string_list_factory)

        def string_set_add(lst, *args):
            for arg in args:
                for arch in arg.split(','):
                    lst[arch] = True
        def string_set_to_archs(lst):
            l = list(lst.keys())
            l.sort()
            return ','.join(l)
        def string_set_factory():
            return ({}, string_set_add, string_set_to_archs)
        self.db.createaggregatefunction("string_set", string_set_factory)

        urgencies = ['high', 'medium', 'low', 'unimportant']
        def urgency_to_number(u):
            try:
                return urgencies.index(u)
            except ValueError:
                return 999
        self.db.createscalarfunction("urgency_to_number", urgency_to_number, 1)

        def releasepart_to_number(r):
            # expects a string in the form "codename (security)"
            try:
                # split the (optional) subrelease
                u=r.split()[0]
                # split the (optional) component
                u=u.split('/')[0]
                return release_to_number(u)
            except ValueError:
                return -1
        self.db.createscalarfunction("releasepart_to_number", releasepart_to_number, 1)

        def subreleasepart_to_number(r):
            # expects a string in the form "codename (security)"
            try:
                if not "(" in r:
                    return 0
                u=r.split('(', 1)[1].split(')')[0]
                return subrelease_to_number(u)
            except ValueError:
                return -1
        self.db.createscalarfunction("subreleasepart_to_number", subreleasepart_to_number, 1)

        releases = config.get_all_releases()
        def release_to_number(u):
            try:
                return releases.index(u)
            except ValueError:
                return -1
        self.db.createscalarfunction("release_to_number", release_to_number, 1)

        subreleases = ['', 'security', 'lts']
        def subrelease_to_number(u):
            try:
                return subreleases.index(u)
            except ValueError:
                return -1
        self.db.createscalarfunction("subrelease_to_number", subrelease_to_number, 1)

        archives = ['main', 'contrib', 'non-free']
        def archive_to_number(u):
            try:
                return archives.index(u)
            except ValueError:
                return -1
        self.db.createscalarfunction("archive_to_number", archive_to_number, 1)

        def release_name(release, subrelease, archive):
            if archive != 'main':
                release = release + '/' + archive
            if subrelease:
                return "%s (%s)" % (release, subrelease)
            else:
                return release
        self.db.createscalarfunction("release_name", release_name, 3)

        self.db.createcollation("version", debian_support.version_compare)

        def source_arch():
            return "source"
        self.db.createscalarfunction("source_arch", source_arch, 0)

    def filePrint(self, filename):
        """Returns a fingerprint string for filename."""

        st = os.stat(filename)
        # The "1" is a version number which can be used to trigger a
        # re-read if the code has changed in an incompatible way.
        return repr((st.st_size, st.st_ino, st.st_mtime, 1))

    def _parseFile(self, cursor, filename):
        current_print = self.filePrint(filename)

        def do_parse(packages):
            if self.verbose:
                print("    reading " + repr(filename))

            re_source = re.compile\
                (r'^([a-zA-Z0-9.+-]+)(?:\s+\(([a-zA-Z0-9.+:~-]+)\))?$')

            data = {}
            for pkg in packages:
                pkg_name = None
                pkg_version = None
                pkg_arch = None
                pkg_source = None
                pkg_source_version = None
                pkg_extra_source_only = False
                for (name, contents) in pkg:
                    if name == "Package":
                        pkg_name = contents
                    elif name == "Version":
                        pkg_version = contents
                    elif name == "Source":
                        match = re_source.match(contents)
                        if match is None:
                            raise SyntaxError(('package %s references '
                                               + 'invalid source package %s') %
                                              (pkg_name, repr(contents)))
                        (pkg_source, pkg_source_version) = match.groups()
                    elif name == "Architecture":
                        pkg_arch = contents
                    elif name == "Extra-Source-Only":
                        pkg_extra_source_only = contents.strip() == "yes"
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
                if pkg_extra_source_only:
                    # Skip, sources are included only for GPL
                    # compliance reasons.
                    continue
                if pkg_name in data:
                    oversion = debian_support.Version(data[pkg_name][0])
                    if oversion < debian_support.Version(pkg_version):
                        data[pkg_name] = (pkg_version, pkg_arch,
                                         pkg_source, pkg_source_version)
                else:
                    data[pkg_name] = (pkg_version, pkg_arch,
                                     pkg_source, pkg_source_version)

            return data

        def toString(data):
            return pickle.dumps(data)

        for (old_print, contents) in cursor.execute(
            "SELECT inodeprint, parsed FROM inodeprints WHERE file = ?",
            (filename,)):
            if old_print == current_print:
                return (True, pickle.loads(contents))
            result = do_parse(debian_support.PackageFile(filename))
            cursor.execute("""UPDATE inodeprints SET inodeprint = ?, parsed = ?
            WHERE file = ?""", (current_print, toString(result), filename))
            return (False, result)

        # No inodeprints entry, load file and add one.
        result = do_parse(debian_support.PackageFile(filename))
        cursor.execute("""INSERT INTO inodeprints (file, inodeprint, parsed)
        VALUES (?, ?, ?)""", (filename, current_print, toString(result)))
        return (False, result)

    def readPackages(self, cursor, directory):
        """Reads a directory of package files."""

        if self.verbose:
            print("readPackages:")

        self._readSourcePackages(cursor, directory)
        self._readBinaryPackages(cursor, directory)

        if self.verbose:
            print("  finished")

    def _readSourcePackages(self, cursor, directory):
        """Reads from directory with source package files."""

        re_sources = re.compile(r'.*/([a-z-]+)_([a-z-]*)_([a-z-]+)_Sources$')

        if self.verbose:
            print("  reading source packages")

        for filename in glob.glob(directory + '/*_Sources'):
            match = re_sources.match(filename)
            if match is None:
                raise ValueError("invalid file name: " + repr(filename))

            (release, subrelease, archive) = match.groups()
            (unchanged, parsed) = self._parseFile(cursor, filename)
            if unchanged:
                continue

            cursor.execute(
                """DELETE FROM source_packages
                WHERE release = ? AND subrelease = ? AND archive = ?""",
                (release, subrelease, archive))
            self._clearVersions(cursor)

            def gen():
                for name in parsed.keys():
                    (version, archs, source, source_version) = parsed[name]
                    assert source is None
                    assert source_version is None
                    yield name, release, subrelease, archive, version
            cursor.executemany(
                """INSERT INTO source_packages
               (name, release, subrelease, archive, version)
               VALUES (?, ?, ?, ?, ?)""",
                gen())

    def _readBinaryPackages(self, cursor, directory):
        """Reads from a directory with binary package files."""

        re_packages \
            = re.compile(
            r'.*/([a-z-]+)_([a-z-]*)_([a-z-]+)_([a-z0-9-]+)_Packages$')

        if self.verbose:
            print("  reading binary packages")

        # First check for any changes.

        filenames = glob.glob(directory + '/*_Packages')
        filenames.sort()
        changed = False
        for filename in filenames:
            changed = True
            for (old_print,) in cursor.execute(
                "SELECT inodeprint FROM inodeprints WHERE file = ?",
                (filename,)):
                if self.filePrint(filename) == old_print:
                    changed = False
            if changed:
                break
        if not changed:
            if self.verbose:
                print("    finished (no changes)")
            return

        # Real import.  We have to re-read all Packages files even if
        # only some of them have changed because the database only
        # stores aggregated data, and there is no efficient way to
        # handle updates of the records related to a single file.

        packages = {}
        unchanged = True
        for filename in filenames:
            match = re_packages.match(filename)
            if match is None:
                raise ValueError("invalid file name: " + repr(filename))

            (release, subrelease, archive, architecture) = match.groups()
            (unch, parsed) = self._parseFile(cursor, filename)
            unchanged = unchanged and unch
            for name in parsed.keys():
                (version, arch, source, source_version) = parsed[name]
                if source is None:
                    source = name
                if source_version is None:
                    source_version = version
                if arch != 'all' and arch != architecture:
                    raise ValueError("invalid architecture %s for package %s"
                                       % (arch, name))
                key = (name, release, subrelease, archive, version,
                       source, source_version)
                if key in packages:
                    packages[key][arch] = 1
                else:
                    packages[key] = {arch : 1}

        if unchanged:
            if self.verbose:
                print("    finished (no changes)")
            return

        if self.verbose:
            print("    deleting old data")
        cursor.execute("DELETE FROM binary_packages")
        self._clearVersions(cursor)

        l = list(packages.keys())

        if len(l) == 0:
            raise ValueError("no binary packages found")

        l.sort()
        def gen():
            for key in l:
                archs = list(packages[key].keys())
                archs.sort()
                archs = ','.join(archs)
                yield key + (archs,)

        if self.verbose:
            print("    storing binary package data")

        cursor.executemany(
            """INSERT INTO binary_packages
            (name, release, subrelease, archive, version,
            source, source_version, archs)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            gen())

    def getSources(self):
        config = debian_support.getconfig()
        sources = config["sources"]

        return sources

    def genDBAdvisoryString(self, field, dtsa=False):
        sources = self.getSources()
        advs = []

        for src in sources:
            name = src["name"]
            cls = src["class"]
            if cls == 'DSAFile':
                advs.append(name)

            if cls == 'DTSAFile' and dtsa:
                advs.append(name)

        advs = ["{} LIKE '{}-%'".format(field, adv) for adv in advs]
        return " OR ".join(advs)

    def readBugs(self, cursor, path):
        if self.verbose:
            print("readBugs:")

        def clear_db(cleared=[False]):
            # Avoid clearing the database multiple times.
            if cleared[0]:
                return
            else:
                cleared[0] = True

            cursor.execute("DELETE FROM debian_bugs")
            cursor.execute("DELETE FROM bugs")
            cursor.execute("DELETE FROM package_notes")
            cursor.execute("DELETE FROM bugs_notes")
            cursor.execute("DELETE FROM bugs_xref")
            cursor.execute("DELETE FROM package_notes_nodsa")
            cursor.execute("DELETE FROM removed_packages")
            cursor.execute("DELETE FROM next_point_update")

            # The *_status tables are regenerated anyway, no need to
            # delete them here.

            self._clearVersions(cursor)

        def do_parse(source, cleared=[False]):
            errors = []

            clear_db()

            if self.verbose:
                print("  reading " + repr(source.name))

            for bug in source:
                try:
                    bug.writeDB(cursor)
                except ValueError as e:
                    errors.append("%s: %d: error: %s"
                                  % (bug.source_file, bug.source_line, e))
            if errors:
                raise InsertError(errors)

            cursor.executemany(
                "INSERT OR IGNORE INTO removed_packages (name) VALUES (?)",
                map(lambda x: (x,), source.removed_packages.keys()))

        def has_changed(filename):
            current_print = self.filePrint(filename)
            for (old_print,) in cursor.execute(
                "SELECT inodeprint FROM inodeprints WHERE file = ?",
                (filename,)):
                if old_print == current_print:
                    return False
                else:
                    return True
            return True

        source_removed_packages = '/packages/removed-packages'
        sources = self.getSources()
        source_paths = [src["path"] for src in sources]

        unchanged = True
        for filename in source_paths + [source_removed_packages]:
            if has_changed(path + filename):
                unchanged = False
                break
        if unchanged:
            if self.verbose:
                print("  finished (no changes)")
            return

        clear_db()

        def read_one(source):
            filename = source.name
            current_print = self.filePrint(filename)

            do_parse(source)
            cursor.execute(
                """INSERT OR REPLACE INTO inodeprints (inodeprint, file)
                VALUES (?, ?)""", (current_print, filename))

        for src in sources:
            srcpath = src["path"]
            cls = src["class"]
            cls = getattr(bugs, cls)
            read_one(cls(path + srcpath))

        if self.verbose:
            print("  update removed packages")
        self.readRemovedPackages(cursor, path + source_removed_packages)

        errors = []

        if self.verbose:
            print("  check cross-references")

        for (bug,) in cursor.execute(
            """SELECT DISTINCT target FROM bugs_xref
        EXCEPT SELECT name FROM bugs"""):
            if bug[0:3] == "VU#":
                continue
            errors.append("reference to unknown bug " + bug)

        if self.verbose:
            print("  copy notes")

        # Copy notes from DSA/DTSA/DLA to CVE.

        old_source = ''
        source_like = self.genDBAdvisoryString("source", dtsa=True)
        for source, target in list(cursor.execute(
            """SELECT source, target FROM bugs_xref
            WHERE (""" + source_like +  """)
            AND target LIKE 'CVE-%'""")):
            if source != old_source:
                source_bug = bugs.BugFromDB(cursor, source)
                old_source = source
            for n in source_bug.notes:
                # We do not copy recursively.
                assert not n.bug_origin

                if n.release:
                    rel = str(n.release)
                else:
                    rel = ''
                present = False

                for (version, note_id) in list(cursor.execute(
                    """SELECT fixed_version, id
                    FROM package_notes
                    WHERE bug_name = ? AND package = ? AND release = ?""",
                    (target, n.package, rel))):
                    if version is None:
                        # The target is marked as unfixed.  Our
                        # version cannot win.
                        present = True
                        continue

                    if (n.fixed_version is None
                        or n.fixed_version > debian_support.Version(version)):
                        # If our version is larger, it is the definitive one.
                        # Remove the existing entry in this case.
                        cursor.execute(
                            "DELETE FROM debian_bugs WHERE note = ?",
                            (note_id,))
                        cursor.execute(
                            """DELETE FROM package_notes
                            WHERE bug_name = ? AND package = ?
                            AND release = ?""",
                            (target, n.package, rel))
                    else:
                        present = True
                if not present:
                    n.writeDB(cursor, target, bug_origin=source)

        def insert_next_point_update(cve_names, code_name):
            for cve_name in cve_names:
                cursor.execute(
                    """INSERT OR REPLACE INTO next_point_update (cve_name, release)
                    VALUES (?, ?)""", (cve_name, code_name))

        def read_next_point_update():
            if self.verbose:
                print("    insert next-point-update.txt/next-oldstable-point-update.txt")

            insert_next_point_update(PointUpdateParser.parseNextPointUpdateStable(),
                                     config.get_release_codename('stable'))

            insert_next_point_update(PointUpdateParser.parseNextOldstablePointUpdate(),
                                     config.get_release_codename('oldstable'))

        read_next_point_update()

        if errors:
            raise InsertError(errors)

        if self.verbose:
            print("  finished")

    def availableReleases(self, cursor=None):
        """Returns a list of tuples (RELEASE, ARCHIVE,
        SOURCES-PRESENT, ARCHITECTURE-LIST)."""
        if cursor is None:
            cursor = self.cursor()

        result = []
        result.append(('', '', '', False, []))
        for (rel, subrel, archive, archs) in cursor.execute(
            """SELECT * FROM
            (SELECT DISTINCT release, subrelease, archive, archs
            FROM binary_packages
            UNION SELECT DISTINCT release, subrelease, archive, source_arch() as archs
            FROM source_packages)
            ORDER BY release_to_number(release), subrelease_to_number(subrelease), archive_to_number(archive)"""):
            if "source" in archs:
                sources=True
            else:
                sources=False
            (p_rel, p_subrel, p_archive, p_sources, p_archs) = result.pop()
            if rel == p_rel and subrel == p_subrel and archive == p_archive:
                sources = sources or p_sources
                result.append((rel, subrel, archive, sources, mergeLists(p_archs, archs)))
            else:
                result.append((p_rel, p_subrel, p_archive, p_sources, mergeLists([], p_archs)))
                result.append((rel, subrel, archive, sources, mergeLists([], archs)))
        result.pop(0)

        return result

    def getFunnyPackageVersions(self):
        """Returns a list of (PACKAGE, RELEASE, ARCHIVE, VERSION,
        SOURCE-VERSION) tuples such that PACKAGE is both a source and
        binary package, but the associated version numbers are
        different."""

        return list(self.db.cursor().execute(
            """SELECT DISTINCT name, release, archive, version, source_version
            FROM binary_packages
            WHERE name = source AND version <> source_version
            ORDER BY name, release, archive"""))

    def _clearVersions(self, cursor):
        cursor.execute("DELETE FROM version_linear_order")

    def _updateVersions(self, cursor):
        """Updates the linear version table."""

        if self.verbose:
            print("updateVersions:")

        for x in cursor.execute("SELECT * FROM version_linear_order LIMIT 1"):
            if self.verbose:
                print("  finished (no changes)")
            return

        if self.verbose:
            print("  reading")

        versions = []
        for (v,) in cursor.execute(
            """SELECT DISTINCT *
            FROM (SELECT fixed_version FROM package_notes
                WHERE fixed_version IS NOT NULL
            UNION ALL SELECT version FROM source_packages)"""):
            versions.append(debian_support.Version(v))

        if self.verbose:
            print("  calculating linear order")
        versions.sort()

        if self.verbose:
            print("  storing linear order")
        for v in versions:
            cursor.execute(
                "INSERT INTO version_linear_order (version) VALUES (?)",
                (str(v),))

        if self.verbose:
            print("  updating package notes")
        cursor.execute(
            """UPDATE package_notes
            SET fixed_version_id = (SELECT id FROM version_linear_order
            WHERE version = package_notes.fixed_version)
            WHERE fixed_version IS NOT NULL""")

        if self.verbose:
            print("  updating source packages")
        cursor.execute(
            """UPDATE source_packages
            SET version_id = (SELECT id FROM version_linear_order
            WHERE version = source_packages.version)""")

        if self.verbose:
            print("  finished")

    def calculateVulnerabilities(self, cursor):
        """Calculate vulnerable packages.

        To each package note, a release-specific vulnerability status
        is attached.  Currently, only testing is processed.

        Returns a list strings describing inconsistencies.
        """

        result = []

        self._updateVersions(cursor)

        if self.verbose:
            print("calculateVulnerabilities:")
            print("  checking version consistency in package notes")

        # The following does not work because stable->security ->
        # testing -> unstable propagation is no longer available.
        if False:
            # Ignore testing because stable issues may be
            # fast-tracked into testing, bypassing unstable.
            testing = config.get_release_codename('testing')
            for (bug_name, pkg_name, rel, unstable_ver, rel_ver) \
                    in list(cursor.execute(
            """SELECT a.bug_name, a.package, b.release,
            a.fixed_version, b.fixed_version
            FROM package_notes a, package_notes b
            WHERE a.bug_name = b.bug_name AND a.package = b.package
            AND a.release = '' AND b.release NOT IN ('', '%s')
            AND a.fixed_version IS NOT NULL
            AND a.fixed_version_id < b.fixed_version_id""" % (testing,))):
                b = bugs.BugFromDB(cursor, bug_name)
                result.append("%s:%d: inconsistent versions for package %s"
                              % (b.source_file, b.source_line, pkg_name))
                result.append("%s:%d: unstable: %s"
                              % (b.source_file, b.source_line, unstable_ver))
                result.append("%s:%d: release %s: %s"
                              % (b.source_file, b.source_line, repr(rel), rel_ver))

        if self.verbose:
            print("  checking source packages")
        cursor.execute(
            """UPDATE package_notes SET package_kind = 'unknown'
            WHERE package_kind IN ('source', 'binary')""")
        cursor.execute(
            """UPDATE package_notes SET package_kind = 'source'
            WHERE package_kind = 'unknown'
            AND EXISTS (SELECT * FROM source_packages AS p
                        WHERE p.name = package_notes.package)""")
        cursor.execute(
            """UPDATE package_notes SET package_kind = 'source'
            WHERE package_kind = 'unknown'
            AND EXISTS (SELECT * FROM removed_packages AS p
                        WHERE p.name = package_notes.package)""")

        for (bug_name, package) in list(cursor.execute(
            """SELECT n.bug_name, n.package
            FROM package_notes AS n
            WHERE n.package_kind = 'itp'
            AND ((EXISTS (SELECT * FROM source_packages
                         WHERE name = n.package))
                 OR (EXISTS (SELECT * FROM binary_packages
                             WHERE name = n.package)))""")):
            b = bugs.BugFromDB(cursor, bug_name)
            result.append("%s:%d: ITPed package %s is in the archive"
                          % (b.source_file, b.source_line, package))

        if result:
            return result

        if self.verbose:
            print("  remove old status")
        cursor.execute("DELETE FROM source_package_status")
        cursor.execute("DELETE FROM bug_status")

        if self.verbose:
            print("  calculate package status")
            print("    source packages (unqualified)")

        cursor.execute(
            """INSERT INTO source_package_status
            SELECT n.bug_name, p.rowid,
            CASE WHEN n.fixed_version == 'undetermined' THEN 2
            ELSE CASE WHEN n.fixed_version IS NULL THEN 1
            ELSE CASE WHEN p.version_id < n.fixed_version_id THEN 1
            ELSE 0 END END END,
            n.urgency
            FROM package_notes AS n, source_packages AS p
            WHERE n.release = '' AND p.name = n.package""")

        # Release annotations always override previous results,
        # therefore we use INSERT OR REPLACE.

        if self.verbose:
            print("    source packages (qualified)")
        cursor.execute(
            """INSERT OR REPLACE INTO source_package_status
            SELECT n.bug_name, p.rowid,
            CASE WHEN n.fixed_version == 'undetermined' THEN 2
            ELSE CASE WHEN n.fixed_version IS NULL THEN 1
            ELSE CASE WHEN p.version_id < n.fixed_version_id THEN 1
            ELSE 0 END END END,
            n.urgency
            FROM package_notes AS n, source_packages AS p
            WHERE p.name = n.package
            AND p.release = n.release""")

        # assign nvd urgencies to those that have not yet been assigned
        if self.verbose:
            print("    insert nvd urgencies")
        cursor.execute(
            """REPLACE INTO source_package_status
            SELECT s.bug_name, s.package, s.vulnerable,
            CASE WHEN n.severity == 'Medium' THEN 'medium**'
            ELSE CASE WHEN n.severity == 'High' THEN 'high**'
            ELSE CASE WHEN n.severity == 'Low' THEN 'low**'
            ELSE 'not yet assigned' END END END
            FROM nvd_data AS n, source_package_status AS s
            WHERE s.bug_name == n.cve_name
            AND s.urgency == 'not yet assigned'""")
        cursor.execute(
            """REPLACE INTO package_notes
            SELECT p.id, p.bug_name, p.package, p.fixed_version,
            p.fixed_version_id, p.release, p.package_kind,
            CASE WHEN n.severity == 'Medium' THEN 'medium'
            ELSE CASE WHEN n.severity == 'High' THEN 'high'
            ELSE CASE WHEN n.severity == 'Low' THEN 'low'
            ELSE 'not yet assigned' END END END,
            p.bug_origin
            FROM nvd_data AS n, package_notes AS p
            WHERE p.bug_name == n.cve_name
            AND p.urgency == 'not yet assigned'""")

        # Calculate the release-specific bug status.

        if self.verbose:
            print("  calculate release status")

        c = self.cursor()

        for (bug_name,) in cursor.execute(
            "SELECT name FROM bugs WHERE NOT not_for_us"):

            self._calcUnstable(c, bug_name)

            for release in config.get_supported_releases():
                if release == 'sid':
                    continue

                alias = config.get_release_alias(release)
                self._calcTesting(c, bug_name, alias, release)

        return result

    def _calcUnstable(self, cursor, bug_name):
        """Update bug_status with bug_name for unstable."""

        vulnerable_packages = []
        undetermined_packages = []
        unimportant_packages = []
        have_something = False
        for (package, vulnerable, urgency) in cursor.execute(
            """SELECT DISTINCT sp.name, st.vulnerable, n.urgency
            FROM source_package_status AS st,
            source_packages AS sp, package_notes AS n
            WHERE st.bug_name = ? AND sp.rowid = st.package
            AND sp.release = 'sid'
            AND n.bug_name = st.bug_name AND n.package = sp.name
            ORDER BY sp.name""",
            (bug_name,)):
            have_something = True
            if vulnerable == 1:
                if urgency == 'unimportant':
                    unimportant_packages.append( package )
                else:
                    vulnerable_packages.append(package)
            elif vulnerable == 2:
                undetermined_packages.append(package)

        if vulnerable_packages or undetermined_packages:
            pkgs = ""
            status = 'undetermined'
            if vulnerable_packages:
                status = 'vulnerable'
                if len(vulnerable_packages) == 1:
                    pkgs += "package %s is vulnerable. " % vulnerable_packages[0]
                else:
                    pkgs += ("packages %s are vulnerable. "
                            % ', '.join(vulnerable_packages))
            if undetermined_packages:
                if len(undetermined_packages) == 1:
                    pkgs += "package %s may be vulnerable but needs to be checked." % undetermined_packages[0]
                else:
                    pkgs += ("packages %s may be vulnerable but need to be checked."
                             % ', '.join(undetermined_packages))
            cursor.execute("""INSERT INTO bug_status
                (bug_name, release, status, reason)
                VALUES (?, 'unstable', ?, ?)""", (bug_name, status, pkgs))
        elif unimportant_packages:
            if len(unimportant_packages) == 1:
                pkgs = "package %s is vulnerable; however, the security impact is unimportant." % unimportant_packages[0]
            else:
                pkgs = "packages %s are vulnerable; however, the security impact is unimportant." % (', '.join(unimportant_packages))
            cursor.execute("""INSERT INTO bug_status
                (bug_name, release, status, reason)
                VALUES (?, 'unstable', 'fixed', ?)""", (bug_name, pkgs))
        else:
            if have_something:
                status = "not vulnerable."
            else:
                status = "not known to be vulnerable."
            cursor.execute("""INSERT INTO bug_status
                (bug_name, release, status, reason)
                VALUES (?, 'unstable', 'fixed', ?)""",
                      (bug_name, status))

    def _calcTesting(self, cursor, bug_name, suite, nickname):
        """Update bug_status with bug_name for testing/stable."""

        # Note that there is at most one source package per
        # note/release/subrelease triple, but we should check that
        # here.

        status = {'' : {}, 'security' : {}, 'lts' : {}}
        for (package, note, subrelease, vulnerable, urgency) in cursor.execute(
            """SELECT DISTINCT sp.name, n.id, sp.subrelease,
            st.vulnerable, n.urgency
            FROM source_package_status AS st,
            source_packages AS sp, package_notes AS n
            WHERE st.bug_name = ? AND sp.rowid = st.package
            AND sp.release = ? AND sp.subrelease IN ('', 'security', 'lts')
            AND n.bug_name = st.bug_name AND n.package = sp.name
            ORDER BY sp.name""",
            (bug_name, nickname)):
            status[subrelease][(package, note)] = (vulnerable,urgency)

        # Check if any packages in plain testing are vulnerable, and
        # if all of those have been fixed in the security archive.
        fixed_in_security = True
        unfixed_pkgs = {}
        undet_pkgs = {}
        unimp_pkgs = {}
        for ((package, note), (vulnerable, urgency)) in status[''].items():
            if vulnerable == 1:
                if urgency == 'unimportant':
                    unimp_pkgs[package] = True
                else:
                    unfixed_pkgs[package] = True
                if status['security'].get((package, note), True):
                    fixed_in_security = False
                elif status['lts'].get((package, note), True):
                    fixed_in_security = False
            elif vulnerable == 2:
                undet_pkgs[package] = True

        unfixed_pkgs = list(unfixed_pkgs.keys())
        unfixed_pkgs.sort()
        undet_pkgs = list(undet_pkgs.keys())
        undet_pkgs.sort()
        unimp_pkgs = list(unimp_pkgs.keys())
        unimp_pkgs.sort()

        pkgs = ""
        result = "undetermined"
        if len(unfixed_pkgs) == 0 and len(undet_pkgs) == 0:
            if len(status[''].keys()) == 0:
                pkgs += "not known to be vulnerable."
            else:
                pkgs += "not vulnerable."
            result = "fixed"
        if len(unfixed_pkgs) > 0:
            if len(unfixed_pkgs) == 1:
                pkgs += "package " + unfixed_pkgs[0] + " is "
            else:
                pkgs += "packages " + ", ".join(unfixed_pkgs) + " are "
            if fixed_in_security:
                pkgs = "%sfixed in %s-security. " % (pkgs, suite)
                if suite == "stable":
                    result = "fixed"
                else:
                    result = "partially-fixed"
            else:
                pkgs += "vulnerable. "
                result = "vulnerable"
        if len(undet_pkgs) > 0:
            if len(undet_pkgs) == 1:
                pkgs += "package " + undet_pkgs[0] + " may be vulnerable but needs to be checked."
            else:
                pkgs += "packages " + ", ".join(undet_pkgs) + " may be vulnerable but need to be checked."
        if len(unimp_pkgs) > 0 and len(undet_pkgs) == 0 and len(unfixed_pkgs) == 0:
            result = "fixed"
            if len(unimp_pkgs) == 1:
                pkgs = "package %s is vulnerable; however, the security impact is unimportant." % unimp_pkgs[0]
            else:
                pkgs = "packages %s are vulnerable; however, the security impact is unimportant." % (', '.join(unimp_pkgs))

        cursor.execute("""INSERT INTO bug_status
        (bug_name, release, status, reason)
        VALUES (?, ?, ?, ?)""",
              (bug_name, suite, result, pkgs))

    def calculateDebsecan0(self, release):
        """Create data for the debsecan tool (VERSION 0 format)."""

        c = self.cursor()

        c.execute("""CREATE TEMPORARY TABLE vulnlist (
        name TEXT NOT NULL,
        package TEXT NOT NULL,
        note INTEGER NOT NULL,
        PRIMARY KEY (name, package)
        )""")

        # Populate the table with the unstable vulnerabilities;
        # override them with the release-specific status.

        c.execute("""INSERT INTO vulnlist
        SELECT bug_name, package, id FROM package_notes WHERE release = ''""")

        if release != 'sid':
            c.execute("""INSERT OR REPLACE INTO vulnlist
            SELECT bug_name, package, id FROM package_notes
            WHERE release = ?""", (release,))

        urgency_to_flag = {'low' : 'L', 'medium' : 'M', 'high' : 'H',
                           'not yet assigned' : ' '}

        result = ["VERSION 0\n"]
        for (name, package, fixed_version, kind, urgency, remote, description,
             note_id) in list(c.execute("""SELECT
                vulnlist.name, vulnlist.package,
                COALESCE(n.fixed_version, ''),
                n.package_kind, n.urgency,
                (SELECT range_remote FROM nvd_data
                 WHERE cve_name = vulnlist.name) AS remote,
                bugs.description,
                n.id
                FROM vulnlist, bugs, package_notes AS n
                WHERE bugs.name = vulnlist.name
                AND n.id = vulnlist.note
                ORDER BY vulnlist.package""")):
            if fixed_version == '0' or urgency == 'unimportant' \
                    or urgency == 'end-of-life' \
                    or kind not in ('source', 'binary', 'unknown'):
                continue

            # Normalize FAKE-* names a bit.  The line number (which
            # makes the name unique) is completely useless for the
            # client.

            if name[0:5] == 'TEMP-':
                name = '-'.join(name.split('-')[0:2])

            # Determine if a fix is available for the specific
            # release.

            fix_available = ' '
            if kind == 'source':
                fix_available_sql = """SELECT st.vulnerable
                    FROM source_packages AS p, source_package_status AS st
                    WHERE p.name = ?
                    AND p.release = ?
                    AND p.subrelease IN ('', 'security', 'lts')
                    AND st.bug_name = ?
                    AND st.package = p.rowid
                    ORDER BY p.version COLLATE version DESC"""
            else:
                fix_available_sql = ''

            if fix_available_sql:
                for (v,) in c.execute(fix_available_sql,
                                      (package, release, name)):
                    assert v is not None
                    if not v:
                        fix_available = 'F'
                    break

            if kind == 'source':
                kind = 'S'
            elif kind == 'binary':
                kind = 'B'
            else:
                kind = ' '

            if remote is None:
                remote = '?'
            elif remote:
                remote = 'R'
            else:
                remote = ' '

            result.append("%s,%c%c%c%c,%s,%s,%s\n"
                          % (name,
                             kind, urgency_to_flag[urgency], remote,
                             fix_available,
                             package, fixed_version, description))
        result = base64.encodebytes(zlib.compress(''.join(result).encode('utf-8'), 9))

        c.execute(
            "INSERT OR REPLACE INTO debsecan_data (name, data) VALUES (?, ?)",
            ('release/' + release, result))

        c.execute("DROP TABLE vulnlist")

    def calculateDebsecan1(self):
        """Calculates debsecan data (release-independent, VERSION 1)."""

        c = self.cursor()

        result_start = ['VERSION 1']
        bug_to_index = {}
        bug_to_remote_flag = {}

        def fill_bug_to_index():
            index = 0
            for (bug, desc, remote) in c.execute(
                """SELECT DISTINCT p.bug_name, b.description,
                (SELECT range_remote FROM nvd_data
                 WHERE cve_name = p.bug_name)
                FROM package_notes AS p, bugs AS b
                WHERE (p.bug_name LIKE 'CVE-%' OR p.bug_name LIKE 'TEMP-%')
                AND p.urgency <> 'unimportant'
                AND COALESCE(p.fixed_version, '') <> '0'
                AND p.package_kind IN ('source', 'binary', 'unknown')
                AND b.name = p.bug_name
                ORDER BY p.bug_name"""):
                if remote is None:
                    remote = '?'
                elif remote:
                    remote = 'R'
                else:
                    remote = ' '

                result_start.append("%s,,%s" % (bug, desc))
                bug_to_index[bug] = index
                bug_to_remote_flag[bug] = remote
                index += 1
            result_start.append('')
        fill_bug_to_index()

        urgency_to_flag = {'low' : 'L', 'medium' : 'M', 'high' : 'H',
                           'not yet assigned' : ' '}

        vuln_list = []
        source_packages = {}
        def fill_vuln_list(source_packages=source_packages):
            for (bug, package) in list(c.execute(
                """SELECT DISTINCT bug_name, package
                FROM package_notes
                WHERE (bug_name LIKE 'CVE-%' OR bug_name LIKE 'TEMP-%')
                AND package_kind IN ('source', 'binary', 'unknown')
                GROUP BY package, bug_name
                ORDER BY package, bug_name""")):

                # By default, unstable is unfixed even if there are
                # only release-specific annotations available.  This
                # is slightly at odds with the web front end (see
                # data/latently-vulnerable) which does not normally
                # report unstable versions as vulnerable in this case.
                # However, in our tracking model, the main branch
                # (sid) cannot be non-vulnerable, while the
                # release-specific branches are.
                unstable_fixed = ''

                total_urgency = ''
                other_versions = {}
                is_binary = False
                is_unknown = False
                fixed_releases = {}
                for (release, kind, urgency, version) in list(c.execute(
                    """SELECT release, package_kind, urgency, fixed_version
                    FROM package_notes WHERE bug_name = ? AND package = ?""",
                    (bug, package))):
                    if not total_urgency:
                        total_urgency = urgency
                    elif total_urgency == 'unknown':
                        if urgency != 'unimportant':
                            total_urgency = urgency
                    elif urgency == 'unknown':
                        if total_urgency == 'unimportant':
                            total_urgency = 'unknown'
                    elif bugs.internUrgency(urgency) \
                             > bugs.internUrgency(total_urgency):
                        total_urgency = urgency

                    if kind == 'binary':
                        is_binary = True
                    elif kind == 'source':
                        source_packages[package] = True
                    else:
                        is_unknown = True

                    if release == '':
                        unstable_fixed = version
                        if version:
                            v_ref = debian_support.Version(version)
                            for (v,) in c.execute("""SELECT version
                            FROM source_packages WHERE name = ?
                            AND release = 'sid' AND subrelease = ''""",
                                                  (package,)):
                                if debian_support.Version(v) >= v_ref:
                                    fixed_releases['sid'] = True
                                    break
                    elif version is not None:
                        fixed_releases[release] = True

                        # Collect newer versions in the same release
                        # (which are supposed to fix the same bug).

                        v_ref = debian_support.Version(version)
                        for (v,) in c.execute("""SELECT fixed_version
                        FROM package_notes
                        WHERE package = ? AND release = ?""",
                                              (package, release)):
                            if v is None:
                                continue
                            if debian_support.Version(v) >= v_ref:
                                other_versions[v] = True

                        # The second part of this SELECT statement
                        # covers binary-only NMUs.
                        for (v,) in c.execute("""SELECT version
                        FROM source_packages WHERE name = ?1
                        AND release = ?2 AND subrelease IN ('', 'security', 'lts')
                        UNION ALL SELECT source_version
                        FROM binary_packages WHERE source = ?1
                        AND release = ?2 AND subrelease IN ('', 'security', 'lts')""",
                                              (package, release)):
                            if debian_support.Version(v) >= v_ref:
                                other_versions[v] = True

                if not total_urgency:
                    total_urgency = 'unknown'

                # Check if the issue does not actually mark any
                # packages as vulnerable.  (If unstable_fixed == '0',
                # release-specific annotations cannot create
                # vulnerabilities, either.)
                if total_urgency == 'unimportant' or unstable_fixed == '0' \
                        or total_urgency == 'end-of-life':
                    continue

                if unstable_fixed is None:
                    unstable_fixed = ''
                bs_flag = 'S'
                if is_binary:
                    assert not is_unknown
                    bs_flag = 'B'
                elif is_unknown:
                    bs_flag = ' '

                other_versions = list(other_versions.keys())
                other_versions.sort()
                other_versions = ' '.join(other_versions)

                vuln_list.append(("%s,%d,%c%c%c"
                                  % (package, bug_to_index[bug],
                                     bs_flag, urgency_to_flag[total_urgency],
                                     bug_to_remote_flag[bug]),
                                  fixed_releases.keys(),
                                  ",%s,%s"
                                  % (unstable_fixed, other_versions)))
        fill_vuln_list()
        source_packages = list(source_packages.keys())
        source_packages.sort()

        def store_value(name, value):
            value = base64.encodebytes(zlib.compress(value.encode('utf-8'), 9))
            c.execute("""INSERT OR REPLACE INTO debsecan_data
            VALUES (?, ?)""", (name, value))

        def gen_release(release):
            result = result_start[:]

            for (prefix, releases, suffix) in vuln_list:
                if release in releases:
                    fixed = 'F'
                else:
                    fixed = ' '
                result.append(prefix + fixed + suffix)
            result.append('')

            for sp in source_packages:
                bp_list = []
                for (bp,) in c.execute("""SELECT name FROM binary_packages
                WHERE source = ? AND release = ? AND subrelease = ''
                ORDER BY name""",
                                       (sp, release)):
                    bp_list.append(bp)
                if bp_list != [sp]:
                    # We intentionally store the empty list, it means
                    # that the source package is obsolete as a whole.
                    result.append("%s,%s" % (sp, ' '.join(bp_list)))
            result.append('')

            store_value('release/1/' + release, '\n'.join(result))

        for release in config.get_supported_releases():
            gen_release(release)

        result = result_start
        for (prefix, release, suffix) in vuln_list:
            result.append(prefix + ' ' + suffix)
        result.append('')
        result.append('')
        result.append('')
        store_value ('release/1/GENERIC', '\n'.join(result))

    def calculateDebsecan(self):
        """Calculate all debsecan data."""
        for release in config.get_supported_releases():
            self.calculateDebsecan0(release)
        self.calculateDebsecan1()

    def getDebsecan(self, name):
        """Returns the debsecan data item NAME."""
        for (data,) in self.cursor().execute(
            "SELECT data FROM debsecan_data WHERE name = ?", (name,)):
            return base64.decodebytes(data)
        else:
            return None

    def updateNVD(self, cursor, data, incremental):
        """Adds (and overwrites) NVD data stored in the database.  This
        can be used for incremental updates if incremental is True."""
        if not incremental:
            cursor.execute("DELETE FROM nvd_data");
        cursor.executemany("INSERT OR REPLACE INTO nvd_data VALUES (?"
                           + (", ?" * (len(data[0]) - 1))
                           + ")", data)

    def getNVD(self, cursor, cve_name):
        """Returns a dictionary with NVD data corresponding to the CVE name,
        or None."""
        for row in cursor.execute("SELECT * FROM nvd_data WHERE cve_name = ?",
                                  (cve_name,)):
            return NVDEntry(row, cursor.getdescription())
        return None

    def getSourcePackageVersions(self, cursor, pkg):
        """A generator which returns tuples (RELEASE-LIST, VERSION),
        the available versions of the source package pkg."""

        releases = config.get_supported_releases()
        values = [pkg] + releases

        for (release, version) in cursor.execute(
            """SELECT release_name(release, subrelease, archive)
            AS release, version FROM source_packages
            WHERE name = ?
            AND release IN (""" + ",".join("?" * len(releases)) + """)
            GROUP BY release, version
            ORDER BY release_to_number(release), subrelease_to_number(subrelease), version COLLATE version""", values):
            yield release, version

    def getBinaryPackageVersions(self, cursor, pkg):
        """A generator which returns tuples (RELEASE-LIST,
        SOURCE-PACKAGE, VERSION, ARCH-LIST), the available versions of
        the binary package pkg."""

        for (releases, source, version, archs) in cursor.execute(
            """SELECT string_list(release) AS releases, source, version, archs
            FROM (SELECT release, source, version, string_set(archs) AS archs
            FROM binary_packages
            WHERE name = ?
            GROUP BY release, source, version
            ORDER BY release_to_number(release))
            GROUP BY source, version, archs""", (pkg,)):
            yield releases.split(', '), source, version, archs.split(',')

    def getBinaryPackagesForSource(self, cursor, pkg):
        """A generator which returns tuples (PACKAGES, RELEASE-LIST,
        VERSION), the available binary packages built from the source
        package pkg."""

        for (packages, releases, version, archs) in cursor.execute(
            """SELECT string_list(package) AS packages, releases, version,
            archs
            FROM (SELECT package, string_list(rel) AS releases, version, archs
            FROM (SELECT name AS package,
            release_name(release, subrelease, archive) AS rel,
            version, string_set(archs) AS archs
            FROM binary_packages
            WHERE source = ?
            GROUP BY name, release, subrelease, archive, version
            ORDER BY release_to_number(release), subrelease_to_number(subrelease))
            GROUP BY package, version, archs
            ORDER BY package)
            GROUP BY releases, version, archs
            ORDER BY version COLLATE version""", (pkg,)):
            yield (packages.split(', '), releases.split(', '),
                   archs.split(','), version)

    def getSourcePackages(self, cursor, bug):
        """A generator which returns tuples (SOURCE-PACKAGE,
        RELEASE-LIST, VERSION, VULNERABLE-FLAG) of source packages
        which are related to the given bug."""

        releases = config.get_supported_releases()
        values = [bug] + releases

        for (package, releases, version, vulnerable) in cursor.execute(
            """SELECT package, string_list(release), version, vulnerable
            FROM (SELECT p.name AS package,
            release_name(p.release, p.subrelease, p.archive) AS release,
            p.version AS version, s.vulnerable AS vulnerable
            FROM source_package_status AS s, source_packages AS p
            WHERE s.bug_name = ? AND p.rowid = s.package
            AND release in (""" + ",".join("?" * len(releases)) + """))
            GROUP BY package, version, vulnerable
            ORDER BY package, releasepart_to_number(release), subreleasepart_to_number(release), version COLLATE version""",
            values):
            yield package, releases.split(', '), version, vulnerable

    def getBugsFromDebianBug(self, cursor, number):
        """A generator which returns a list of tuples
        (BUG-NAME, URGENCY, DESCRIPTION)."""

        return cursor.execute(
            """SELECT DISTINCT bugs.name, package_notes.urgency,
            bugs.description
            FROM debian_bugs, package_notes, bugs
            WHERE debian_bugs.bug = ? AND package_notes.id = debian_bugs.note
            AND bugs.name = package_notes.bug_name
            ORDER BY bug_name""", (number,))

    def isSourcePackage(self, cursor, pkg):
        """Returns a true value if pkg is a source package."""
        ((flag,),) = cursor.execute(
            "SELECT EXISTS (SELECT * FROM source_packages WHERE name = ?)",
            (pkg,))
        return flag

    def isBinaryPackage(self, cursor, pkg):
        """Returns a true value if pkg is a binary package."""
        ((flag,),) = cursor.execute(
            "SELECT EXISTS (SELECT * FROM binary_packages WHERE name = ?)",
            (pkg,))
        return flag

    def getDSAsForSourcePackage(self, cursor, package):
        bugs_like = self.genDBAdvisoryString("bugs.name", dtsa=False)
        for row in cursor.execute(
            """SELECT DISTINCT bugs.name, bugs.description
            FROM bugs, package_notes as p
            WHERE p.bug_name = bugs.name
            AND ( """ + bugs_like + """ )
            AND p.package = ?
            ORDER BY bugs.release_date DESC""", (package,)):
            yield DSAsForSourcePackage(*row)


    def getTODOs(self, cursor=None, hide_check=False):
        """Returns a list of pairs (BUG-NAME, DESCRIPTION)."""
        if cursor is None:
            cursor = self.cursor()
        if hide_check:
            return cursor.execute(
                """SELECT DISTINCT bugs.name, bugs.description, bugs_notes.comment
                FROM bugs_notes, bugs
                WHERE bugs_notes.typ = 'TODO'
                AND bugs_notes.comment <> 'check'
                AND bugs.name = bugs_notes.bug_name
                ORDER BY name COLLATE version""")
        else:
            return cursor.execute(
                """SELECT DISTINCT bugs.name, bugs.description, bugs_notes.comment
                FROM bugs_notes, bugs
                WHERE bugs_notes.typ = 'TODO'
                AND bugs.name = bugs_notes.bug_name
                ORDER BY name COLLATE version""")

    def getBugXrefs(self, cursor, bug):
        """Returns a generator for a list of bug names.  The listed
        bugs refer to the given bug, or the bug refers to them."""

        for (bug_name,) in cursor.execute(
            """SELECT DISTINCT bug
            FROM (SELECT target AS bug
            FROM bugs_xref WHERE source = ?
            UNION ALL SELECT source AS bug
            FROM bugs_xref WHERE target = ?
            UNION ALL SELECT bug_origin AS bug FROM package_notes
            WHERE bug_name = ? AND bug_origin <> '')
            WHERE bug <> ?
            ORDER BY bug""", (bug, bug, bug, bug)):
            yield bug_name

    def readRemovedPackages(self, cursor, filename):
        """Reads a file of removed packages and stores it in the database.
        The original contents of the removed_packages table is preserved."""

        f = open(filename)

        re_package = re.compile(r'^\s*([a-z0-9]\S+)\s*$')

        # Not very good error reporting, but changes to that file are
        # rare.

        def gen():
            for line in f:
                if line == '':
                    break
                if line[0] == '#' or line == '\n':
                    continue
                match = re_package.match(line)
                if match:
                    yield match.groups()
                else:
                    raise ValueError("not a package: " + repr(line))

        cursor.executemany(
            "INSERT OR IGNORE INTO removed_packages (name) VALUES (?)", gen())

    def getUnknownPackages(self, cursor):
        """Returns a generator for a list of unknown packages.
        Each entry has the form (PACKAGE, BUG-LIST)."""

        old_package = ''
        bugs = []
        for (package, bug_name) in cursor.execute(
            """SELECT DISTINCT package, bug_name
            FROM package_notes WHERE package_kind = 'unknown'
            AND COALESCE (release, '') <> 'experimental'
            AND NOT EXISTS (SELECT * FROM removed_packages
                            WHERE name = package)
            ORDER BY package, bug_name"""):
            if package != old_package:
                if old_package:
                    yield (old_package, bugs)
                old_package = package
                bugs = []
            bugs.append(bug_name)
        if old_package:
            yield (old_package, bugs)

    def getFakeBugs(self, cursor=None, vulnerability=0):
        """Returns a list of pairs (BUG-NAME, DESCRIPTION)."""

        if cursor is None:
            cursor = self.cursor()

        return list(cursor.execute(
            """ SELECT DISTINCT  b.name, b.description
                FROM bugs AS b,
                source_package_status AS st
                WHERE
                b.name = st.bug_name AND
                st.vulnerable=? AND
                st.bug_name > 'TEMP-' AND st.bug_name LIKE 'TEMP-%'
                ORDER BY st.bug_name""",(vulnerability,)))

    def getUnreportedVulnerabilities(self, cursor=None):
        """Returns a list of pairs (BUG_NAME, DESCRIPTION)
        of vulnerabilities which are unfixed in unstable and lack a filed bug.
        """
        if cursor is None:
            cursor = self.cursor()
        last_bug = None
        result = []
        for bug, pkg in cursor.execute(
"""SELECT DISTINCT source_package_status.bug_name, source_packages.name
  FROM source_packages
  JOIN source_package_status
    ON source_packages.rowid = source_package_status.package
  JOIN package_notes
    ON source_packages.name = package_notes.package
      AND package_notes.bug_name = source_package_status.bug_name
      AND source_packages.release = 'sid'
      AND package_notes.release = ''
  WHERE source_package_status.bug_name LIKE 'CVE-%'
  AND package_notes.urgency <> 'unimportant'
  AND package_notes.rowid NOT IN (SELECT note FROM debian_bugs)
  AND source_package_status.vulnerable
  ORDER BY source_package_status.bug_name, source_packages.name"""):
            if last_bug is None or last_bug != bug:
                last_bug = bug
                result.append((bug, []))
            result[-1][1].append(pkg)
        return result

    def getITPs(self, cursor):
        """Returns a generator for a list of unknown packages.
        Each entry has the form (PACKAGE, BUG-LIST, DEBIAN-BUG-LIST)."""

        # The "|| ''" is required to convert the string_set argument
        # to a string.
        for (package, bugs, debian_bugs) in cursor.execute(
            """SELECT DISTINCT n.package, string_set(n.bug_name),
            string_set(db.bug || '')
            FROM package_notes AS n, debian_bugs AS db
            WHERE package_kind = 'itp'
            AND db.note = n.id
            GROUP BY n.package
            ORDER BY n.package"""):
            yield (package, bugs.split(','), map(int, debian_bugs.split(',')))

    def check(self, cursor=None):
        """Runs a simple consistency check and prints the results."""

        if cursor is None:
            cursor = self.cursor()

        for (package, release, archive, architecture, source) in\
            cursor.execute(
            """SELECT package, release, archive, architecture, source
            FROM binary_packages
            WHERE NOT EXISTS
            (SELECT *
                    FROM source_packages AS sp
                    WHERE sp.package = binary_packages.source
                    AND sp.release = binary_packages.release
                    AND sp.archive = binary_packages.archive)
            """):
            print("error: binary package without source package")
            print("  binary package:", package)
            print("  release:", release)
            if archive:
                print("  archive:", archive)
            print("  architecture:", architecture)
            print("  missing source package:", source)

        for (package, release, archive, architecture, version,
             source, source_version) \
            in cursor.execute("""SELECT binary_packages.package,
            binary_packages.release, binary_packages.archive,
            binary_packages.architecture,binary_packages.version,
            sp.package, sp.version
            FROM binary_packages, source_packages AS sp
            WHERE sp.package = binary_packages.source
            AND sp.release = binary_packages.release
            AND sp.archive = binary_packages.archive
            AND sp.version <> binary_packages.source_version"""):
            assert debian_support.Version(version) != debian_support.Version(source_version)
            if debian_support.Version(version) <= debian_support.Version(source_version):
                print("error: binary package is older than source package")
            else:
                print("warning: binary package is newer than source package")
            print("  binary package: %s (%s)" % (package, version))
            print("  source package: %s (%s)" % (source, source_version))
            print("  release:", release)
            if archive:
                print("  archive:", archive)
            print("  architecture:", architecture)

def test():
    assert mergeLists(u'',u'') == [], mergeLists(u'', u'')
    assert mergeLists(u'', []) == []
    assert mergeLists(u'a', u'a') == [u'a']
    assert mergeLists(u'a', u'b') == [u'a', u'b']
    assert mergeLists(u'a,c', u'b') == [u'a', u'b', 'c']
    assert mergeLists(u'a,c', [u'b', u'de']) == [u'a', u'b', u'c', u'de']

    import os
    db_file = 'test_security.db'
    try:
        db = DB(db_file)
    except SchemaMismatch:
        os.unlink(db_file)
        db = DB(db_file)

    cursor = db.writeTxn()
    db.readBugs(cursor, '../../data')
    db.commit(cursor)

    b = bugs.BugFromDB(cursor, 'CVE-2005-2491')
    assert b.name == 'CVE-2005-2491', b.name
    assert b.description == 'Integer overflow in pcre_compile.c in Perl Compatible Regular ...', b.description
    assert len(b.xref) == 2, b.xref
    assert not b.not_for_us
    assert 'DSA-800-1' in b.xref, b.xref
    assert 'DTSA-10-1' in b.xref, b.xref
    assert 'DLA-23-1' in b.xref, b.xref
    assert tuple(b.comments) == (('NOTE', 'gnumeric/goffice includes one as well; according to upstream not exploitable in gnumeric,'),
                                 ('NOTE', 'new copy will be included any way')),\
                                 b.comments

    assert len(b.notes) == 4, len(b.notes)

    for n in b.notes:
        assert n.release is None
        if n.package == 'pcre3':
            assert n.fixed_version == debian_support.Version('6.3-0.1etch1')
            assert tuple(n.bugs) == (324531,), n.bugs
            assert n.urgency == bugs.internUrgency('medium')
        elif n.package == 'python2.1':
            assert n.fixed_version == debian_support.Version('2.1.3dfsg-3')
            assert len(n.bugs) == 0, n.bugs
            assert n.urgency == bugs.internUrgency('medium')
        elif n.package == 'python2.2':
            assert n.fixed_version == debian_support.Version('2.2.3dfsg-4')
            assert len(n.bugs) == 0, n.bugs
            assert n.urgency == bugs.internUrgency('medium')
        elif n.package == 'python2.3':
            assert n.fixed_version == debian_support.Version('2.3.5-8')
            assert len(n.bugs) == 0, n.bugs
            assert n.urgency == bugs.internUrgency('medium')
        else:
            assert False

    assert bugs.BugFromDB(cursor, 'DSA-311').isKernelOnly()

if __name__ == "__main__":
    test()

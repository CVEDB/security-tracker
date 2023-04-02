#!/usr/bin/python3

import email.utils
import json
import os.path
import re
import sys
import time

import setup_paths  # noqa
import bugs
import config
import debian_support
import security_db
from web_support import *

if __name__ == "__main__":
    if len(sys.argv) not in (3, 5):
        print("usage: python tracker_service.py SOCKET-PATH DATABASE-PATH")
        print("       python tracker_service.py URL HOST PORT DATABASE-PATH")
        sys.exit(1)
    if len(sys.argv) == 3:
        socket_name = sys.argv[1]
        db_name = sys.argv[2]
        webservice_base_class = WebService
    else:
        server_base_url = sys.argv[1]
        server_address = sys.argv[2]
        server_port = int(sys.argv[3])
        socket_name = (server_base_url, server_address, server_port)
        db_name = sys.argv[4]
        webservice_base_class = WebServiceHTTP
else:
    webservice_base_class = WebServiceHTTP

def clean_dict(d):
    """ taken from http://w3facility.org/question/exclude-emptynull-values-from-json-serialization/
    Delete keys with the value ``None`` in a dictionary, recursively.

    This alters the input so you may wish to ``copy`` the dict first.
    """
    # d.iteritems isn't used as you can't del or the iterator breaks.
    for key, value in list(d.items()):
        if value is None:
            del d[key]
        elif isinstance(value, dict):
            clean_dict(value)
    return d  # For convenience

class BugFilter:
    default_action_list = [('high_urgency', 'high', 'urgency'),
                           ('medium_urgency', 'medium', 'urgency'),
                           ('low_urgency', 'low', 'urgency'),
                           ('unimportant_urgency', 'unimportant', 'urgency'),
                           ('unassigned_urgency', 'not yet assigned', 'urgency'),
                           ('endoflife_urgency', 'end-of-life', 'urgency'),

                           ('remote', 'hide remote scope', 'scope'),
                           ('local', 'hide local scope', 'scope'),
                           ('unclear', 'hide unclear scope', 'scope'),

                           ('undetermined_issues', 'include issues to be checked (shown in purple)', 'extra'),]

    def __init__(self, params, nonodsa=False, noignored=False, nopostponed=False):
        self.action_list = self.default_action_list
        if not nonodsa:
            self.action_list = self.action_list +  [('nodsa', 'include issues tagged <no-dsa>', 'nodsa')]
        if not noignored:
            self.action_list = self.action_list +  [('noignored', 'include issues tagged <ignored>', 'nodsa')]
        if not nopostponed:
            self.action_list = self.action_list +  [('nopostponed', 'include issues tagged <postponed>', 'nodsa')]
        self.params = {}
        for (prop, desc, field) in self.action_list:
            self.params[prop] = int(params.get(prop, (0,))[0])
        self.filters=params.get('filter')
        if not self.filters:
            self.filters=['high_urgency', 'medium_urgency', 'low_urgency', 'unassigned_urgency']

    def actions(self, url):
        """Returns a HTML snippet which can be used to change the filter."""

        l = []
        l.append(INPUT(type='hidden', name='filter', value='1'))
        for (prop, desc, field) in self.action_list:
            if prop in self.filters:
                l.append(LABEL(INPUT(desc, type='checkbox', name='filter', value=prop, onChange='this.form.submit()', checked='checked'), rel=field))
                self.params[prop]=1
            else:
                l.append(LABEL(INPUT(desc, type='checkbox', name='filter', value=prop, onChange='this.form.submit()'), rel=field))

        return FORM(tag("SPAN",l, id="filters"),
                    tag("NOSCRIPT", [INPUT(type='submit', value='Apply')]),
                    method='get')

    def urgencyFiltered(self, urg, vuln):
        """Returns True for urgencies that should be filtered."""
        filterlow = not self.params['low_urgency'] and \
                    urg in ('low', 'low**')
        filtermed = not self.params['medium_urgency'] and \
                    urg in ('medium', 'medium**')
        filterhigh = not self.params['high_urgency'] and \
                    urg in ('high', 'high**')
        filterund = not self.params['undetermined_issues'] and vuln == 2
        filteruni = not self.params['unimportant_urgency'] \
                    and urg == 'unimportant'
        filteruna = not self.params['unassigned_urgency'] \
                    and urg ==  'not yet assigned'
        filterend = not self.params['endoflife_urgency'] \
                    and urg == 'end-of-life'
        return filterlow or filtermed or filterhigh or filterund or filteruni or filteruna or filterend

    def remoteFiltered(self, remote):
        filterr = self.params['remote'] and remote and remote is not None
        filterl = self.params['local'] and not remote and remote is not None
        filteru = self.params['unclear'] and remote is None
        return filterr or filterl or filteru

    def nodsaFiltered(self, nodsa):
        """Returns True for no DSA issues if filtered."""
        return nodsa and not self.params['nodsa']
    def ignoredFiltered(self, no_dsa_reason):
        """Returns True for ignored issues if filtered."""
        return no_dsa_reason == 'ignored' and not self.params['noignored']
    def postponedFiltered(self, no_dsa_reason):
        """Returns True for postponedissues if filtered."""
        return no_dsa_reason == 'postponed' and not self.params['nopostponed']

class TrackerService(webservice_base_class):
    nvd_text =  P('''If a "**" is included, the urgency field was automatically
        assigned by the NVD (National Vulnerability Database). Note that this
        rating is automatically derived from a set of known factors about the
        issue (such as access complexity, confidentiality impact, exploitability,
        remediation level, and others). Human intervention is involved in
        determining the values of these factors, but the rating itself comes
        from a fully automated formula.''')

    json_generation_interval = 5 * 60 # in seconds

    def __init__(self, socket_name, db_name):
        webservice_base_class.__init__(self, socket_name)
        self.db = security_db.DB(db_name)
        self.json_data = None # the JSON dump itself
        self.json_timestamp = None # timestamp of JSON generation
        self.json_last_modified = None

        self.stable_releases = config.get_supported_releases()
        self.stable_releases.remove(config.get_release_codename('testing'))
        self.stable_releases.remove('sid')
        self.stable_releases.reverse()

        self.register('', self.page_home)
        self.register('*', self.page_object)
        self.register('redirect/*', self.page_redirect)
        self.register('source-package/*', self.page_source_package)

        for release in self.stable_releases:
            alias = config.get_release_alias(release)
            self.register('status/release/' + alias,
                          self.page_status_release_stable_like)
            self.register('status/release/' + alias + '-backports',
                          self.page_status_release_backports_like)

        self.register('status/release/testing',
                      self.page_status_release_testing)
        self.register('status/release/unstable',
                      self.page_status_release_unstable)
        self.register('status/dtsa-candidates',
                      self.page_status_dtsa_candidates)
        self.register('status/todo', self.page_status_todo)
        self.register('status/undetermined', self.page_status_undetermined)
        self.register('status/unimportant', self.page_status_unimportant)
        self.register('status/itp', self.page_status_itp)
        self.register('status/unreported', self.page_status_unreported)
        self.register('data/unknown-packages', self.page_data_unknown_packages)
        self.register('data/missing-epochs', self.page_data_missing_epochs)
        self.register('data/latently-vulnerable',
                      self.page_data_latently_vulnerable)
        self.register('data/releases', self.page_data_releases)
        self.register('data/funny-versions', self.page_data_funny_versions)
        self.register('data/fake-names', self.page_data_fake_names)
        self.register('data/pts/1', self.page_data_pts)
        self.register('data/json', self.page_json)
        self.register('debsecan/**', self.page_debsecan)
        self.register('data/report', self.page_report)
        self.register('style.css', self.page_style_css)
        self.register('logo.png', self.page_logo_png)
        self.register('distributions.json', self.page_distributions_json)
        self.register('script.js', self.page_script_js)

    def page_style_css(self, path, params, url):
        with open('../static/style.css', 'r') as f:
            content=f.read()
            return BinaryResult(content,'text/css')

    def page_logo_png(self, path, params, url):
        with open('../static/logo.png', 'rb') as f:
            content=f.read()
            return BinaryResult(content,'image/png')

    def page_distributions_json(self, path, params, url):
        with open('../static/distributions.json', 'r') as f:
            content=f.read()
            return BinaryResult(content,'application/json')

    def page_script_js(self, path, params, url):
        with open('../static/script.js', 'r') as f:
            content=f.read()
            return BinaryResult(content,'text/javascript')


    def page_home(self, path, params, url):
        query = params.get('query', ('',))[0]
        if query:
            if '/' in query:
                return self.page_not_found(url, query)
            else:
                return RedirectResult(url.scriptRelativeFull(query))

        def gen_stable_links():
            links = []
            for release in self.stable_releases:
                alias = config.get_release_alias(release)
                links.append(('status/release/' + alias,
                       'Vulnerable packages in the ' + alias + ' suite'))
                links.append(('status/release/' + alias + '-backports',
                       'Vulnerable packages in backports for ' + alias))
            return links

        return self.create_page(
            url, 'Security Bug Tracker',
            [P(
            """The data in this tracker comes solely from the bug database maintained
by Debian's security team located in the security-tracker Git """,
            A("https://salsa.debian.org/security-tracker-team/security-tracker/tree/master/data", "repository"),
            """.  The data represented here is derived from: """,
            A("https://www.debian.org/security/#DSAS", "DSAs"),
            """ issued by the Security Team; issues tracked in the """,
            A("https://cve.mitre.org/cve/", "CVE database"),
            """, issues tracked in the """,
            A("https://nvd.nist.gov/", "National Vulnerability Database"),
            """ (NVD), maintained by NIST; and security issues
discovered in Debian packages as reported in the BTS."""),
             P("""All external data (including Debian bug reports and official Debian
security advisories) must be added to this database before it appears
here. Please help us keep this information up-to-date by """,
               A(url.scriptRelative("data/report"), "reporting"),
               """ any discrepancies or change of status that you are
aware of and/or help us improve the quality of this information by """,
               A(url.scriptRelative("data/report"), "participating"),
               "."),

            NAV(make_menu(
            url.scriptRelative,
            *[('status/release/unstable',
             'Vulnerable packages in the unstable suite'),
            ('status/release/testing',
             'Vulnerable packages in the testing suite')]
            + gen_stable_links() +
            [('status/dtsa-candidates', "Candidates for DTSAs"),
            ('status/todo', 'TODO items'),
            ('status/undetermined', 'Packages that may be vulnerable but need to be checked (undetermined issues)'),
            ('status/unimportant', 'Packages that have open unimportant issues'),
            ('status/itp', 'ITPs with potential security issues'),
            ('status/unreported', 'Open vulnerabilities without filed Debian bugs'),
            ('data/unknown-packages',
             'Packages names not found in the archive'),
            ('data/fake-names', 'Tracked issues without a CVE name'),
            ('data/missing-epochs',
             'Package versions which might lack an epoch'),
            ('data/latently-vulnerable',
             'Packages which are latently vulnerable in unstable'),
            ('data/funny-versions',
             'Packages with strange version numbers'),
            ('data/releases',
             'Covered Debian releases and architectures'),
            ('data/json',
             'All information in JSON format')
            ])),

            self.make_search_button(url),
            P("""(You can enter CVE names, Debian bug numbers and package
names in the search forms.)"""),

             H3("External interfaces"),
             P("""If you want to automatically open a relevant web page for
some object, use the """,
               CODE(str(url.scriptRelative("redirect/")), EM("object")),
               """ URL.  If no information is contained in this database,
the browser is automatically redirected to the corresponding external
data source.""")],
            search_in_page=True)

    def page_object(self, path, params, url):
        obj = path[0]
        return self.page_object_or_redirect(url, obj, False)

    def page_redirect(self, path, params, url):
        if path == ():
            obj = ''
        else:
            obj = path[0]
        return self.page_object_or_redirect(url, obj, True)

    def page_object_or_redirect(self, url, obj, redirect):
        c = self.db.cursor()

        if not obj:
            # Redirect to start page.
            return RedirectResult(url.scriptRelativeFull(""))

        # Attempt to decode a bug number.  TEMP-nnn bugs (but not
        # TEMP-nnn-mmm bugs) are treated as bug references, too.
        bugnumber = 0
        fake_bug = False
        try:
            if obj[0:5] == 'FAKE-' or obj[0:5] == 'TEMP-':
                bugnumber = int(obj[5:])
                fake_bug = True
            else:
                bugnumber = int(obj)
        except ValueError:
            pass
        if bugnumber:
            buglist = list(self.db.getBugsFromDebianBug(c, bugnumber))
            if buglist:
                return self.page_debian_bug(url, bugnumber, buglist, fake_bug)
            if redirect:
                return RedirectResult(self.url_debian_bug(url, str(bugnumber)),
                                      permanent=False)

        if 'A' <= obj[0] <= 'Z':
            # Bug names start with a capital letter.
            return self.page_bug(url, obj, redirect)

        if self.db.isSourcePackage(c, obj):
            return RedirectResult(self.url_source_package(url, obj, full=True))

        return self.page_not_found(url, obj)

    def page_bug(self, url, name, redirect):
        # FIXME: Normalize CAN-* to CVE-* when redirecting.  Too many
        # people still use CAN.
        if redirect and name[0:4] == 'CAN-':
            name = 'CVE-' + name[4:]

        cursor = self.db.cursor()
        try:
            bug = bugs.BugFromDB(cursor, name)
        except ValueError:
            if redirect:
                if name[0:4] == 'CVE-':
                    return RedirectResult(self.url_cve(url, name),
                                          permanent=False)
            return self.page_not_found(url, name)
        if bug.name != name or redirect:
            # Show the normalized bug name in the browser address bar.
            return RedirectResult(url.scriptRelativeFull(bug.name))

        page = []

        def gen_header():
            yield B("Name"), bug.name

            nvd = self.db.getNVD(cursor, bug.name)

            if nvd and nvd.cve_desc:
                yield B("Description"), nvd.cve_desc
            elif bug.description:
                yield B("Description"), bug.description

            source = bug.name.split('-')[0]
            if source == 'CVE':
                source_xref = compose(self.make_cve_ref(url, bug.name, 'CVE'),
                                      " (at ",
                                      self.make_nvd_ref(url, bug.name,
                                                        'NVD'),
                                      "; ",
                                      self.make_cert_bug_ref(url, bug.name, 'CERT'),
                                      ", ",
                                      self.make_lwn_bug_ref(url, bug.name, 'LWN'),
                                      ", ",
                                      self.make_osssec_bug_ref(url, bug.name, 'oss-sec'),
                                      ", ",
                                      self.make_fulldisc_bug_ref(url, bug.name, 'fulldisc'),
                                      ", ",
                                      self.make_bugtraq_bug_ref(url, bug.name, 'bugtraq'),
                                      ", ",
                                      self.make_edb_bug_ref(url, bug.name, 'EDB'),
                                      ", ",
                                      self.make_metasploit_bug_ref(url, bug.name, 'Metasploit'),
                                      ", ",
                                      self.make_rhbug_ref(url, bug.name,
                                                        'Red Hat'),
                                      ", ",
                                      self.make_ubuntu_bug_ref(url, bug.name, 'Ubuntu'),
                                      ", ",
                                      self.make_gentoo_bug_ref(url, bug.name, 'Gentoo'),
                                      ", SUSE ",
                                      self.make_suse_bug_ref(url, bug.name, 'bugzilla'),
                                      "/",
                                      self.make_suse_cve_ref(url, bug.name, 'CVE'),
                                      ", ",
                                      self.make_mageia_bug_ref(url, bug.name, 'Mageia'),
                                      ", GitHub ",
                                      self.make_github_advisory_ref(url, bug.name, 'advisories'),
                                      "/",
                                      self.make_github_code_ref(url, bug.name, 'code'),
                                      "/",
                                      self.make_github_issues_ref(url, bug.name, 'issues'),
                                      ", ",
                                      self.make_web_search_bug_ref(url, bug.name, 'web search'),
                                      ", ",
                                      A(url.absolute('https://oss-security.openwall.org/wiki/vendors'), 'more'),
                                      ")")
            elif source == 'DSA':
                source_xref = self.make_dsa_ref(url, bug.name, 'Debian')
            elif source == 'DTSA':
                source_xref = 'Debian Testing Security Team'
            elif source == 'DLA':
                source_xref = self.make_dla_ref(url, bug.name, 'Debian LTS')
            elif source == 'TEMP':
                source_xref = (
        'Automatically generated temporary name.  Not for external reference.')
            else:
                source_xref = None

            if source_xref:
                yield B("Source"), source_xref

            xref = list(self.db.getBugXrefs(cursor, bug.name))
            if xref:
                yield B("References"), self.make_xref_list(url, xref)

            debian_bugs = bug.getDebianBugs(cursor)
            if debian_bugs:
                yield (B("Debian Bugs"),
                       self.make_debian_bug_list(url, debian_bugs))

# Disable table with fixed status per release.
#           if not bug.not_for_us:
#               for (release, status, reason) in bug.getStatus(cursor):
#                   if status == 'undetermined':
#                       reason = self.make_purple(reason)
#                   elif status != 'fixed':
#                       reason = self.make_red(reason)
#                   yield B('Debian/%s' % release), reason

        page.append(make_table(gen_header()))

        if bug.notes:

            def gen_source():
                old_pkg = ''
                for (package, release, version, vulnerable) \
                        in self.db.getSourcePackages(cursor, bug.name):
                    if package == old_pkg:
                        package = ''
                    else:
                        old_pkg = package
                        package = compose(
                            self.make_source_package_ref(url, package),
                            " (", self.make_pts_ref(url, package, 'PTS'), ")")
                    if vulnerable == 1:
                        vuln = self.make_red('vulnerable')
                        version = self.make_red(version)
                    elif vulnerable == 2:
                        vuln = self.make_purple('undetermined')
                        version = self.make_purple(version)
                    else:
                        vuln = 'fixed'

                    yield package, ', '.join(release), version, vuln

            page.append(make_table(gen_source(),
                title=H2('Vulnerable and fixed packages'),
                caption=("Source Package", "Release", "Version", "Status"),
                introduction=P('The table below lists information on source packages.')))

            def gen_data():
                notes_sorted = bug.notes[:]
                notes_sorted.sort(key=lambda n: (n.package, n.release or debian_support.internRelease('sid')))
                for n in notes_sorted:
                    if n.release:
                        rel = str(n.release)
                    else:
                        rel = '(unstable)'
                    urgency = str(n.urgency)
                    if urgency == 'end-of-life':
                        urgency = self.make_purple('end-of-life')
                    if n.fixed_version:
                        ver = str(n.fixed_version)
                        if ver == '0':
                            ver = '(not affected)'
                            urgency = ''
                    else:
                        ver = self.make_red('(unfixed)')
                    if urgency == 'not yet assigned':
                        urgency = ''

                    pkg = n.package
                    pkg_kind = n.package_kind
                    if pkg_kind == 'source':
                        pkg = self.make_source_package_ref(url, pkg)
                    elif pkg_kind == 'itp':
                        pkg_kind = 'ITP'
                        rel = ''
                        ver = ''
                        urgency = ''

                    bugs = n.bugs
                    bugs.sort()
                    bugs = make_list(
                        list(map(lambda x: self.make_debian_bug(url, x), bugs)))
                    if n.bug_origin:
                        origin = self.make_xref(url, n.bug_origin)
                    else:
                        origin = ''
                    yield (pkg, pkg_kind, rel, ver, urgency, origin, bugs)

            page.append(
                make_table(gen_data(),
                    caption=("Package", "Type", "Release", "Fixed Version",
                             "Urgency", "Origin", "Debian Bugs"),
                    introduction=P("The information below is based on the following data on fixed versions.")))

        if bug.comments:
            page.append(H2("Notes"))
            def gen_comments():
                for (t, c) in bug.comments:
                    yield c
            page.append(make_pre(gen_comments()))

        return self.create_page(url, bug.name, page)

    def page_debian_bug(self, url, bugnumber, buglist, fake_bug):
        if fake_bug:
            new_buglist = []
            for b in buglist:
                (bug_name, urgency, description) = b
                if bug_name[0:5] == 'FAKE-' or bug_name[0:5] == 'TEMP-':
                    new_buglist.append(b)
            if len(new_buglist) > 0:
                # Only replace the bug list if there are still fake
                # bug reports.
                buglist = new_buglist

        if len(buglist) == 1:
            # Single issue, redirect.
            return RedirectResult(url.scriptRelativeFull(buglist[0][0]))

        def gen():
            for (name, urgency, description) in buglist:
                if urgency == "unknown":
                    urgency = ""
                yield self.make_xref(url, name), urgency, description

        if fake_bug:
            intro = """The URL you used contained a non-stable name
based on a Debian bug number.  This name cannot be mapped to a specific
issue. """
        else:
            intro = ""

        return self.create_page(
            url, "Information related to Debian bug #%d" % bugnumber,
            [P(intro + "The following issues reference to Debian bug ",
               self.make_debian_bug(url, bugnumber), ":"),
             make_table(gen(),
                        caption=("Name", "Urgency", "Description"))])

    def page_not_found(self, url, query):
        return self.create_page(url, 'Not found',
                                [P('Your query ',
                                   CODE(query),
                                   ' matched no results.')],
                                status=404)

    def page_report(self, path, params, url):
        return self.create_page(
            url, 'Reporting discrepancies in the data',
            [P("""The data in this tracker is always in flux, as bugs are fixed and new
issues disclosed, the data contained herein is updated. We strive to
maintain complete and accurate state information, and appreciate any
updates in status, information or new issues."""),
             P("There are three ways that you can report updates to this information:"),
             make_numbered_list(
            [P("""IRC: We can be found at """,
               CODE("irc.oftc.net"),
               ", ",
               CODE("#debian-security"),
    """. If you have information to report, please go ahead and join
the channel and tell us.  Please feel free to state the issue,
regardless if there is someone who has acknowledged you. Many of us
idle on this channel and may not be around when you join, but we read
the backlog and will see what you have said. If you require a
response, do not forget to let us know how to get a hold of you."""),
             P("Mailing list: Our mailing list is: ",
               A("mailto:debian-security-tracker@lists.debian.org",
                 "debian-security-tracker@lists.debian.org")),
             P("""Helping out: We welcome people who wish to join us in tracking
issues. The process is designed to be easy to learn and participate,
please read our """,
               A("https://security-team.debian.org/security_tracker.html",
                 "Introduction"),
               """ to get familiar with how things work.  Join us on
our mailing list, and on IRC and request to be added to the Salsa """,
               A("https://salsa.debian.org/security-tracker-team/security-tracker/", "project"),
               """. We are really quite friendly. If you have a
question about how things work, don't be afraid to ask, we would like
to improve our documentation and procedures, so feedback is welcome.""")])])

    def page_source_package(self, path, params, url):
        if path == ():
            return self.create_page(
                url, "Object not found",
                [P("No source package was provided.")],
                status=404)

        pkg = path[0]
        data = security_db.getBugsForSourcePackage(self.db.cursor(), pkg)

        def gen_versions():
            for (release, version) in self.db.getSourcePackageVersions(
                    self.db.cursor(), pkg):
                yield release, version
        def gen_bug_list(lst):
            for bug in lst:
                yield self.make_xref(url, bug.bug), bug.description

        def format_summary_entry(per_release):
            if per_release is None:
                return self.make_purple('unknown')
            if per_release.vulnerable == 1:
                if per_release.state == 'no-dsa':
                    if per_release.reason:
                        text = 'vulnerable (no DSA, %s)' % per_release.reason
                    else:
                        text = 'vulnerable (no DSA)'
                    hint = per_release.comment
                    return self.make_mouseover((self.make_yellow(text),),
                                               text=hint)
                else:
                    return self.make_red('vulnerable')
            if per_release.vulnerable == 2:
                return self.make_purple('undetermined')
            assert per_release.vulnerable == 0
            return self.make_green('fixed')

        def gen_summary(bugs):
            for bug in bugs:
                status_row = tuple(
                    format_summary_entry(bug.releases.get(rel, None))
                    for rel in data.all_releases)
                yield (self.make_xref(url, bug.bug),) + status_row \
                    + (bug.description,)

        return self.create_page(
            url, 'Information on source package ' + pkg,
            [make_menu(lambda x: x,
                       (self.url_pts(url, pkg),
                        pkg + ' in the Package Tracking System'),
                       (self.url_debian_bug_pkg(url, pkg),
                        pkg + ' in the Bug Tracking System'),
                       (self.url_source_code(url, pkg),
                        pkg + ' source code'),
                       (self.url_testing_status(url, pkg),
                        pkg + ' in the testing migration checker')),
             make_table(gen_versions(), title=H2('Available versions'), caption=('Release', 'Version')),

             make_table(
                 gen_summary(data.open),
                 title=H2('Open issues'),
                 caption=('Bug',) + data.all_releases + ('Description',),
                 replacement='No known open issues.'
             ),


             make_table(
                 gen_summary(data.unimportant),
                 title=H2('Open unimportant issues'),
                 caption=('Bug',) + data.all_releases + ('Description',),
                 replacement='No known unimportant issues.'
             ),

             make_table(gen_bug_list(data.resolved),
                        title=H2('Resolved issues'),
                        caption=('Bug', 'Description'),
                        replacement='No known resolved issues.'),

             make_table(gen_bug_list(self.db.getDSAsForSourcePackage
                                     (self.db.cursor(), pkg)),
                        title=H2('Security announcements'),
                        caption=('DSA / DLA', 'Description'),
                        replacement='No known security announcements.')
             ])

    def page_status_release_stable_like(self, path, params, url):
        release = os.path.basename(url.path_info)

        bf = BugFilter(params)

        def gen():
            old_pkg_name = ''
            for (pkg_name, bug_name, archive, urgency, vulnerable, remote, no_dsa, no_dsa_reason) in \
                    self.db.cursor().execute(
                """SELECT package, bug, section, urgency, vulnerable, remote, no_dsa, no_dsa_reason
                FROM %s_status
                WHERE (bug LIKE 'CVE-%%' OR bug LIKE 'TEMP-%%')
                ORDER BY package, bug COLLATE version""" % release):
                if bf.urgencyFiltered(urgency, vulnerable):
                    continue
                if bf.remoteFiltered(remote):
                    continue
                if bf.nodsaFiltered(no_dsa):
                    continue
                if bf.ignoredFiltered(no_dsa_reason):
                    continue
                if bf.postponedFiltered(no_dsa_reason):
                    continue

                if pkg_name == old_pkg_name:
                    pkg_name = ''
                    title = None
                else:
                    old_pkg_name = pkg_name
                    title = None
                    if archive != 'main':
                        title = "%s (%s)" % (pkg_name, archive)

                if remote is None:
                    remote = '?'
                elif remote:
                    remote = 'yes'
                else:
                    remote = 'no'

                if urgency.startswith('high'):
                    urgency = self.make_red(urgency)
                elif vulnerable == 2:
                    urgency = self.make_purple(urgency)
                else:
                    if no_dsa:
                        urgency = urgency + '*'

                yield self.make_source_package_ref(url, pkg_name, title), self.make_xref(url, bug_name), urgency, remote

        return self.create_page(
            url, 'Vulnerable source packages in the %s suite' % release,
            [bf.actions(url), BR(),
             make_table(gen(), caption=("Package", "Bug", "Urgency", "Remote")),
             P('''If a "*" is included in the urgency field, no DSA is planned
                  for this vulnerability.'''),
             self.nvd_text])

    def page_status_release_testing(self, path, params, url):
        bf = BugFilter(params)

        def gen():
            old_pkg_name = ''
            for (pkg_name, bug_name, archive, urgency, vulnerable,
                 sid_vulnerable, ts_fixed, remote, no_dsa) \
                 in self.db.cursor().execute(
                """SELECT package, bug, section, urgency, vulnerable,
                unstable_vulnerable, testing_security_fixed, remote, no_dsa
                FROM testing_status
                ORDER BY package, bug COLLATE version"""):
                if bf.urgencyFiltered(urgency, vulnerable):
                    continue
                if bf.remoteFiltered(remote):
                    continue
                if bf.nodsaFiltered(no_dsa):
                    continue

                if pkg_name == old_pkg_name:
                    pkg_name = ''
                    title = None
                else:
                    old_pkg_name = pkg_name
                    title = None
                    if archive != 'main':
                        title = "%s (%s)" % (pkg_name, archive)

                if remote is None:
                    remote = '?'
                elif remote:
                    remote = 'yes'
                else:
                    remote = 'no'

                if ts_fixed:
                    status = 'fixed in testing-security'
                else:
                    if sid_vulnerable:
                        status = self.make_red('unstable is vulnerable')
                    else:
                        status = self.make_dangerous('fixed in unstable')

                if urgency.startswith('high'):
                    urgency = self.make_red(urgency)
                elif vulnerable == 2:
                    urgency = self.make_purple(urgency)

                yield (self.make_source_package_ref(url, pkg_name, title), self.make_xref(url, bug_name),
                       urgency, remote, status)

        return self.create_page(
            url, 'Vulnerable source packages in the testing suite',
            [make_menu(url.scriptRelative,
                       ("status/dtsa-candidates", "Candidates for DTSAs")),
             bf.actions(url), BR(),
             make_table(gen(), caption=("Package", "Bug", "Urgency", "Remote", 'Status')),
             self.nvd_text])

    def page_status_release_unstable_like(self, path, params, url,
                                          rel, title, subrel=""):
        bf = BugFilter(params,nonodsa=True,noignored=True,nopostponed=True)

        def gen():
            old_pkg_name = ''
            for (pkg_name, bug_name, section, urgency, vulnerable, remote) \
                    in self.db.cursor().execute(
                """SELECT DISTINCT sp.name, st.bug_name,
                sp.archive, st.urgency, st.vulnerable,
                (SELECT range_remote FROM nvd_data
                 WHERE cve_name = st.bug_name)
                FROM source_package_status AS st, source_packages AS sp
                WHERE st.vulnerable AND sp.rowid = st.package
                AND sp.release = ?  AND sp.subrelease = ''
                ORDER BY sp.name, st.bug_name COLLATE version""", (rel,)):
                if bf.urgencyFiltered(urgency, vulnerable):
                    continue
                if bf.remoteFiltered(remote):
                    continue

                if pkg_name == old_pkg_name:
                    pkg_name = ''
                    title = None
                else:
                    old_pkg_name = pkg_name
                    title = None
                    if section != 'main':
                        title = "%s (%s)" % (pkg_name, section)

                if remote is None:
                    remote = '?'
                elif remote:
                    remote = 'yes'
                else:
                    remote = 'no'

                if urgency.startswith('high'):
                    urgency = self.make_red(urgency)
                elif vulnerable == 2:
                    urgency = self.make_purple(urgency)

                yield self.make_source_package_ref(url, pkg_name, title), self.make_xref(url, bug_name), urgency, remote

        return self.create_page(
            url, title,
            [P("""Note that the list below is based on source packages.
            This means that packages are not listed here once a new,
            fixed source version has been uploaded to the archive, even
            if there are still some vulnerable binary packages present
            in the archive."""),
             bf.actions(url), BR(),
             make_table(gen(), caption=('Package', 'Bug', 'Urgency', 'Remote')),
             self.nvd_text])

    def page_status_release_unstable(self, path, params, url):
        return self.page_status_release_unstable_like(
            path, params, url,
            title='Vulnerable source packages in the unstable suite',
            rel='sid')

    def page_status_release_backports_like(self, path, params, url):
        release = os.path.basename(url.path_info)
        release = release.split("-")[0]

        return self.page_status_release_unstable_like(
            path, params, url,
            title='Vulnerable source packages among backports for ' + release,
            rel=config.get_release_codename(release, '-backports'))

    def page_status_dtsa_candidates(self, path, params, url):
        bf = BugFilter(params,nonodsa=True,noignored=True,nopostponed=True)

        def gen():
            old_pkg_name = ''
            for (pkg_name, bug_name, archive, urgency, vulnerable,
                 stable_later, remote) \
                    in self.db.cursor().execute(
                """SELECT package, bug, section, urgency, vulnerable,
                (SELECT testing.version_id < stable.version_id
                 FROM source_packages AS testing, source_packages AS stable
                 WHERE testing.name = testing_status.package
                 AND testing.release = ?
                 AND testing.subrelease = ''
                 AND testing.archive = testing_status.section
                 AND stable.name = testing_status.package
                 AND stable.release = ?
                 AND stable.subrelease = 'security'
                 AND stable.archive = testing_status.section),
                (SELECT range_remote FROM nvd_data
                 WHERE cve_name = bug)
                FROM testing_status
                WHERE (NOT unstable_vulnerable)
                AND (NOT testing_security_fixed)""",
                (config.get_release_codename('testing'), config.get_release_codename('stable'))):
                if bf.urgencyFiltered(urgency, vulnerable):
                    continue
                if bf.remoteFiltered(remote):
                    continue

                if pkg_name == old_pkg_name:
                    pkg_name = ''
                    migration = ''
                    title = None
                else:
                    old_pkg_name = pkg_name
                    title = None
                    migration = A(self.url_testing_status(url, pkg_name),
                                  "check")
                    if archive != 'main':
                        title = "%s (%s)" % (pkg_name, archive)

                if remote is None:
                    remote = '?'
                elif remote:
                    remote = 'yes'
                else:
                    remote = 'no'

                if urgency.startswith('high'):
                    urgency = self.make_red(urgency)
                elif vulnerable == 2:
                    urgency = self.make_purple(urgency)

                if stable_later:
                    notes = "(fixed in stable?)"
                else:
                    notes = ''

                yield (self.make_source_package_ref(url, pkg_name, title), migration, self.make_xref(url, bug_name),
                       urgency, remote, notes)

        return self.create_page(
            url, "Candidates for DTSAs",
            [P("""The table below lists packages which are fixed
in unstable, but unfixed in testing.  Use the testing migration
checker to find out why they have not entered testing yet."""),
             make_menu(url.scriptRelative,
                       ("status/release/testing",
                        "List of vulnerable packages in testing")),
             bf.actions(url), BR(),
             make_table(gen(),
                        caption=("Package", "Migration", "Bug", "Urgency",
                                 "Remote", ""))])

    def page_status_todo(self, path, params, url):
        hide_check = params.get('hide_check', False)
        if hide_check:
            flags = A(url.updateParamsDict({'hide_check' : None}),
                      'Show "check" TODOs')
        else:
            flags = A(url.updateParamsDict({'hide_check' : '1'}),
                  'Hide "check" TODOs')

        def gen():
            for (bug, description, note) in self.db.getTODOs(hide_check=hide_check):
                yield self.make_xref(url, bug), description, note
        return self.create_page(
            url, 'Bugs with TODO items',
            [P(flags), make_table(gen(), caption=('Bug', 'Description', 'Note'))])

    def page_status_undetermined(self, path, params, url):
        def gen():
            outrel = []
            old_bug = ''
            old_pkg = ''
            old_dsc = ''
            last_displayed = ''
            releases = config.get_supported_releases()
            for (pkg_name, bug_name, release, desc) in self.db.cursor().execute(
                    """SELECT DISTINCT sp.name, st.bug_name, sp.release,
                    bugs.description
                    FROM source_package_status AS st, source_packages AS sp, bugs
                    WHERE st.vulnerable == 2 AND sp.rowid = st.package
                    AND sp.release IN (""" + ",".join("?" * len(releases)) + """)
                    AND sp.subrelease = '' AND st.bug_name == bugs.name
                    ORDER BY sp.name, st.bug_name COLLATE version""", releases):

                if old_bug == '':
                    old_bug = bug_name
                    old_pkg = pkg_name
                    old_dsc = desc
                elif old_bug != bug_name:
                    if old_pkg == last_displayed:
                        to_display = ''
                    else:
                        to_display = old_pkg
                    yield to_display, self.make_xref(url, old_bug), old_dsc, ', '.join(outrel)
                    last_displayed = old_pkg
                    old_bug = bug_name
                    old_pkg = pkg_name
                    old_dsc = desc
                    outrel = []
                outrel.append( release )
            yield old_pkg, self.make_xref(url, old_bug), old_dsc, ', '.join(outrel)

        return self.create_page(url, 'Packages that may be vulnerable but need to be checked      (undetermined issues)',
            [P("""This page lists packages that may or may not be affected
            by known issues.  This means that some additional work needs to
            be done to determined whether the package is actually
            vulnerable or not.  This list is a good area for new
            contributors to make quick and meaningful contributions."""),
            make_table(gen(), caption=('Package', 'Bug', 'Description', 'Releases'))])

    def page_status_unimportant(self, path, params, url):
        def gen():
            outrel = []
            old_bug = ''
            old_pkg = ''
            old_dsc = ''
            old_name = ''
            last_displayed = ''
            releases = config.get_supported_releases()
            for (pkg_name, bug_name, release, desc) in self.db.cursor().execute(
                    """SELECT DISTINCT sp.name, st.bug_name, sp.release,
                    bugs.description
                    FROM source_package_status AS st, source_packages AS sp, bugs
                    WHERE st.vulnerable > 0 AND sp.rowid = st.package
                    AND sp.release IN (""" + ",".join("?" * len(releases)) +  """)
                    AND st.urgency == 'unimportant'
                    AND sp.subrelease = '' AND st.bug_name == bugs.name
                    ORDER BY sp.name, st.bug_name COLLATE version""", releases):

                if old_bug == '':
                    old_bug = bug_name
                    old_pkg = pkg_name
                    old_dsc = desc
                elif old_bug != bug_name:
                    if old_pkg == last_displayed:
                        to_display = ''
                    else:
                        to_display = old_pkg
                    yield to_display, self.make_xref(url, old_bug), old_dsc, ', '.join(outrel)
                    last_displayed = old_pkg
                    old_bug = bug_name
                    old_pkg = pkg_name
                    old_dsc = desc
                    outrel = []
                outrel.append( release )
            yield old_pkg, self.make_xref(url, old_bug), old_dsc, ', '.join(outrel)

        return self.create_page(url, 'Packages that have open unimportant issues',
            [P("""This page lists packages that are affected by issues
            that are considered unimportant from a security perspective.
            These issues are thought to be unexploitable or uneffective
            in most situations (for example, browser denial-of-services)."""),
            make_table(gen(), caption=('Package', 'Bug', 'Description', 'Releases'))])

    def page_status_itp(self, path, params, url):
        def gen():
            old_pkg = ''
            for pkg, bugs, debian_bugs in self.db.getITPs(self.db.cursor()):
                if pkg == old_pkg:
                    pkg = ''
                else:
                    old_pkg = pkg
                yield (pkg, self.make_xref_list(url, bugs),
                       self.make_debian_bug_list(url, debian_bugs))
        return self.create_page(
            url, "ITPs with potential security issues",
            [make_table(gen(), caption=("Package", "Issue", "Debian Bugs"),
                        replacement="No ITP bugs are currently known.")])

    def page_status_unreported(self, path, params, url):
        def gen():
            for (bug, packages) in self.db.getUnreportedVulnerabilities():
                pkgs = make_list([self.make_source_package_ref(url, pkg)
                                  for pkg in packages], ", ")
                yield self.make_xref(url, bug), pkgs
        return self.create_page(
            url, "Unfixed vulnerabilities in unstable without a filed bug",
            [P("""The list below contains vulnerabilities for which no matching
Debian bug has been filed, and there is still an unfixed package in sid."""),
             make_table(gen(), caption=("Bug", "Packages"))])

    def page_data_unknown_packages(self, path, params, url):
        def gen():
            for name, bugs in self.db.getUnknownPackages(self.db.cursor()):
                yield name, self.make_xref_list(url, bugs)
        return self.create_page(
            url, "Unknown packages",
            [P("""Sometimes, a package referenced in a bug report
cannot be found in the database.  This can be the result of a spelling
error, or a historic entry refers to a
package which is no longer in the archive."""),
             make_table(gen(), caption=("Package", "Bugs"),
        replacement="No unknown packages are referenced in the database.")])

    def page_data_missing_epochs(self, path, params, url):
        def gen():
            old_bug = ''
            old_pkg = ''
            for bug, pkg, ver1, ver2 in self.db.cursor().execute(
                """SELECT DISTINCT bug_name, n.package,
                n.fixed_version, sp.version
                FROM package_notes AS n, source_packages AS sp
                WHERE n.package_kind = 'source'
                AND n.fixed_version NOT LIKE '%:%'
                AND n.fixed_version <> '0'
                AND n.bug_origin = ''
                AND sp.name = n.package
                AND sp.version LIKE '%:%'
                ORDER BY bug_name COLLATE version, package"""):
                if bug == old_bug:
                    bug = ''
                else:
                    old_bug = bug
                    old_pkg = ''
                    bug = self.make_xref(url, bug)
                if pkg == old_pkg:
                    pkg = ''
                else:
                    old_pkg = pkg
                    pkg = self.make_source_package_ref(url, pkg)
                yield bug, pkg, ver1, ver2

        return self.create_page(
            url, "Missing epochs in package versions",
            [make_table(gen(),
                caption=("Bug", "Package", "Version 1", "Version 2"),
                replacement="No source package version with missing epochs.")])

    def page_data_latently_vulnerable(self, path, params, url):
        def gen():
            for pkg, bugs in self.db.cursor().execute(
                """SELECT package, string_set(bug_name)
                FROM package_notes AS p1
                WHERE release <> ''
                AND (bug_name LIKE 'CVE-%' OR bug_name LIKE 'TEMP-%')
                AND NOT EXISTS (SELECT 1 FROM package_notes AS p2
                                WHERE p2.bug_name = p1.bug_name
                                AND p2.package = p1.package
                                AND release = '')
                AND EXISTS (SELECT 1 FROM source_packages
                           WHERE name = p1.package AND release = 'sid')
                GROUP BY package
                ORDER BY package"""):
                pkg = self.make_source_package_ref(url, pkg)
                bugs = bugs.split(',')
                yield pkg, self.make_xref_list(url, bugs)

        def gen_unimportant():
            for pkg, bugs in self.db.cursor().execute(
                """SELECT package, string_set(bug_name)
                FROM package_notes AS p1
                WHERE release <> ''
                AND urgency <> 'unimportant'
                AND (bug_name LIKE 'CVE-%' OR bug_name LIKE 'TEMP-%')
                AND EXISTS (SELECT 1 FROM package_notes AS p2
                                WHERE p2.bug_name = p1.bug_name
                                AND p2.package = p1.package
                                AND release = '')
                AND NOT EXISTS (SELECT 1 FROM package_notes AS p2
                                WHERE p2.bug_name = p1.bug_name
                                AND p2.package = p1.package
                                AND urgency <> 'unimportant'
                                AND release = '')
                AND EXISTS (SELECT 1 FROM source_packages
                           WHERE name = p1.package AND release = 'sid')
                GROUP BY package
                ORDER BY package"""):
                pkg = self.make_source_package_ref(url, pkg)
                bugs = bugs.split(',')
                yield pkg, self.make_xref_list(url, bugs)

        return self.create_page(
            url, "Latently vulnerable packages in unstable",
            [P(
"""A package is latently vulnerable in unstable if it is vulnerable in
any release, and there is no package note for the same vulnerability
and package in unstable (and the package is still available in
unstable, of course)."""),
             make_table(gen(),
                caption=("Package", "Bugs"),
                replacement="No latently vulnerable packages were found."),
             P(
"""The next table lists issues which are marked unimportant for
unstable, but for which release-specific annotations exist which are
not unimportant."""),
             make_table(gen_unimportant(),
                caption=("Package", "Bugs"),
                replacement=
    "No packages with unimportant latent vulnerabilities were found."),
            ])

    def page_data_releases(self, path, params, url):
        def gen():
            for (rel, subrel, archive, sources, archs) \
                    in self.db.availableReleases():
                if sources:
                    sources = 'yes'
                else:
                    sources = 'no'
                if 'source' in archs:
                    archs.remove('source')
                yield rel, subrel, archive, sources, make_list(archs)
        return self.create_page(
            url, "Available releases",
            [P("""The security issue database is checked against
the Debian releases listed in the table below."""),
             make_table(gen(),
                        caption=("Release", "Subrelease", "Archive",
                                 "Sources", "Architectures"))])

    def page_data_funny_versions(self, path, params, url):
        def gen():
            for name, release, archive, version, source_version \
                in self.db.getFunnyPackageVersions():
                yield name, release, archive, source_version, version

        return self.create_page(
            url, "Version conflicts between source/binary packages",
            [P("""The table below lists source packages
            which have a binary package of the same name, but with a different
            version.  This means that extra care is necessary to determine
            the version of a package which has been fixed.  (Note that
            the bug tracker prefers source versions to binary versions
            in this case.)"""),
             make_table(gen(),
                        caption=("Package",
                                 "Release",
                                 "Archive",
                                 "Source Version",
                                 "Binary Version")),
             P("""Technically speaking, these version numbering is fine,
but it makes version-based bug tracking quite difficult for these packages."""),
             P("""There are many binary packages which are built from source
             packages with different version numbering schemes.  However, as
             long as none of the binary packages carries the same name as the
             source package, most confusion is avoided or can be easily
             explained.""")])

    def page_data_fake_names(self, path, params, url):
        def gen(v):
            for (bug, description) in self.db.getFakeBugs(vulnerability=v):
                yield self.make_xref(url, bug), description
        return self.create_page(
            url, "Automatically generated issue names",
            [P("""Some issues have not been assigned CVE names, but are still
tracked by this database.  In this case, the system automatically assigns
a unique name.  These names are not stable and can change when the database
is updated, so they should not be used in external references."""),
             P('''The automatically generated names come in two flavors:
the first kind starts with the string "''', CODE("TEMP-000000-"),
               '''".  This means that no Debian bug has been assigned to this
issue (or a bug has been created and is not recorded in this database).
In the second kind of names, there is a Debian bug for the issue, and the "''',
               CODE("000000"), '''"part of the name is replaced with the
Debian bug number.'''),
             make_table(gen(1),title=H2('With unfixed issues'), caption=("Bug", "Description")),
             make_table(gen(0),title=H2('The rest'), caption=("Bug", "Description")),
            ])

    def page_data_pts(self, path, params, url):
        data = []
        for pkg, bugs in self.db.cursor().execute(
                """SELECT package, COUNT(DISTINCT bug) FROM
                (SELECT package, bug, urgency FROM stable_status
                 UNION ALL SELECT DISTINCT sp.name, st.bug_name, st.urgency
                   FROM source_package_status AS st, source_packages AS sp
                   WHERE st.vulnerable AND st.urgency <> 'unimportant'
                   AND sp.rowid = st.package AND sp.release = 'sid'
                   AND sp.subrelease = '') x WHERE urgency <> 'unimportant'
                GROUP BY package ORDER BY package"""):
            data.append(pkg)
            data.append(':')
            data.append(str(bugs))
            data.append('\n')
        return BinaryResult(''.join(data),'application/octet-stream')

    def _get_json(self):
        """Helper method handling basic caching of the JSON data, to avoid
           overloading security-tracker.d.o. It'll return the cached
           version of this data unless it's been generated more than
           self.json_generation_interval seconds ago """

        if self.json_timestamp: # we've generated the JSON at least once
            delta = time.time() - self.json_timestamp
            if delta <= self.json_generation_interval:
                # not expired yet, serve the cached data
                return self.json_data

        # if we reached here, the data has expired; let's regenerate it
        from collections import defaultdict
        packages = []
        issues = defaultdict(list)
        descriptions = {}
        debianbugs = defaultdict(dict)
        remote = defaultdict(dict)
        releases = defaultdict(lambda: defaultdict(list))
        subreleases = defaultdict(lambda: defaultdict(list))
        repositories = defaultdict(lambda: defaultdict(list))
        version = defaultdict(lambda: defaultdict(dict))
        fixed_version = defaultdict(lambda: defaultdict(dict))
        status = defaultdict(lambda: defaultdict(dict))
        urgency = defaultdict(lambda: defaultdict(dict))
        nodsa = defaultdict(lambda: defaultdict(dict))
        nodsa_reason = defaultdict(lambda: defaultdict(dict))
        next_point_update = defaultdict(lambda: defaultdict(set))
        supported_releases = config.get_supported_releases()
        for (pkg, issue, desc, debianbug, release, subrelease, db_version, db_fixed_version, db_status, db_urgency, db_remote, db_nodsa, db_nodsa_reason, db_next_point_update) in self.db.cursor().execute(
                """SELECT sp.name, st.bug_name,
                (SELECT cve_desc FROM nvd_data
                WHERE cve_name = st.bug_name),
                (SELECT MIN(debian_cve.bug) FROM debian_cve
                WHERE debian_cve.bug_name = st.bug_name),
                sp.release, sp.subrelease,
                sp.version,
                (SELECT pn.fixed_version FROM package_notes AS pn
                WHERE pn.bug_name = st.bug_name
                AND pn.package = sp.name AND
                (pn.release = sp.release OR (pn.release = '' AND fixed_version != ''))),
                st.vulnerable, st.urgency,
                (SELECT range_remote FROM nvd_data
                WHERE cve_name = st.bug_name),
                (SELECT comment FROM package_notes_nodsa AS nd
                WHERE nd.package = sp.name AND nd.release = sp.release
                AND nd.bug_name = st.bug_name) AS nodsa,
                (SELECT reason FROM package_notes_nodsa AS nd
                WHERE nd.package = sp.name AND nd.release = sp.release
                AND nd.bug_name = st.bug_name) AS nodsa_reason,
                (SELECT next_point_update.release as next_point_update_release FROM next_point_update
                WHERE st.bug_name=next_point_update.cve_name) AS next_point_update_release
                FROM source_package_status AS st, source_packages AS sp, bugs
                WHERE sp.rowid = st.package AND st.bug_name = bugs.name
                AND ( st.bug_name LIKE 'CVE-%' OR st.bug_name LIKE 'TEMP-%' )
                AND sp.release IN (""" + ",".join("?" * len(supported_releases)) + """)
                ORDER BY sp.name, st.bug_name, sp.release, sp.subrelease""" , supported_releases):

            ### to ease debugging...:
            #if issue in ('CVE-2012-6656','CVE-2014-8738','CVE-2013-6673') :
            #    print pkg, issue, release, subrelease, db_version, db_fixed_version, db_status
            if pkg not in packages:
                packages.append(pkg)
            if issue not in issues[pkg]:
                issues[pkg].append(issue)
                descriptions[issue] = desc
                debianbugs[pkg][issue] = debianbug
                remote[pkg][issue] = db_remote
            if release not in releases[pkg][issue]:
                releases[pkg][issue].append(release)
            subreleases[pkg][issue].append(subrelease)
            if subrelease == '':
                repository = release
            else:
                repository = release+'-'+subrelease
            if repository not in repositories[pkg][issue]:
                repositories[pkg][issue].append(repository)
            version[pkg][issue][repository] = db_version
            fixed_version[pkg][issue][repository] = db_fixed_version
            status[pkg][issue][repository] = db_status
            urgency[pkg][issue][repository] = db_urgency
            if db_next_point_update:
                next_point_update[pkg][issue].add(db_next_point_update)
            if str(db_nodsa) != 'None':
                nodsa[pkg][issue][repository] = db_nodsa
            if str(db_nodsa_reason) != 'None':
                nodsa_reason[pkg][issue][repository] = db_nodsa_reason

        data = {}
        for pkg in packages:
            data[pkg] = {}
            for issue in issues[pkg]:
                description = None
                debianbug = None
                scope = None
                suites = {}

                if descriptions[issue]:
                    description = descriptions[issue]
                if debianbugs[pkg][issue] != None:
                    debianbug = debianbugs[pkg][issue]
                if str(remote[pkg][issue]) == 'None':
                    pass
                elif remote[pkg][issue] == 1:
                    scope = "remote"
                else:
                    scope = "local"
                for release in releases[pkg][issue]:
                    state = None
                    suite_fixed_version = None
                    suite_urgency = None
                    suite_nodsa = None
                    suite_nodsa_reason = None
                    suite_repositories = {}
                    winner=''
                    for suffix in ('','-security','-lts'):
                        subrelease=release+suffix
                        if subrelease in status[pkg][issue]:
                            if status[pkg][issue][subrelease] == 0:
                                # the issue is fixed, let's pick this subrelease and be done
                                winner=suffix
                                break
                            elif status[pkg][issue][subrelease] > 0 and winner == '':
                                # the issue ain't fixed, but at least exists.
                                # keep looking for a real winner...
                                winner=suffix
                    repository=release+winner
                    if status[pkg][issue][repository] == 0:
                        # 1 = vulnerable, 2 = undetermined
                        state = "resolved"
                        suite_fixed_version = fixed_version[pkg][issue][repository]
                    elif status[pkg][issue][repository] == 2:
                        state = "undetermined"
                    else:
                        state = "open"
                    suite_urgency = urgency[pkg][issue][repository]
                    if repository in nodsa[pkg][issue]:
                        suite_nodsa = nodsa[pkg][issue][repository]
                    if repository in nodsa_reason[pkg][issue]:
                        suite_nodsa_reason = nodsa_reason[pkg][issue][repository]
                    if pkg in next_point_update and \
                            issue in next_point_update[pkg] and \
                            release in next_point_update[pkg][issue]:
                        suite_next_point_update = True
                    else:
                        suite_next_point_update = None
                    for repository in repositories[pkg][issue]:
                        for suffix in ('','-security','-lts'):
                            subrelease=release+suffix
                            if subrelease in version[pkg][issue]:
                                suite_repositories[subrelease] = version[pkg][issue][subrelease]
                    suites[release] = { "status": state,
                                        "repositories": suite_repositories,
                                        "fixed_version" : suite_fixed_version,
                                        "urgency": suite_urgency,
                                        "nodsa": suite_nodsa,
                                        "nodsa_reason": suite_nodsa_reason,
                                        "next_point_update": suite_next_point_update
                                        }
                    clean_dict(suites[release])
                pkg_issue = { "description": description,
                              "debianbug": debianbug,
                              "scope": scope,
                              "releases": suites }
                clean_dict(pkg_issue)

                data[pkg][issue]=pkg_issue

        # store the JSON dump in memory, and update the generation
        # timestamp before returning
        new_data = json.dumps(data, separators=(',', ':'))
        self.json_timestamp = time.time()
        if new_data != self.json_data:
            self.json_data = new_data
            self.json_last_modified = self.json_timestamp
        return self.json_data

    def page_json(self, path, params, url):
        result = BinaryResult(self._get_json(),'application/json')
        result.headers['Last-Modified'] = email.utils.formatdate(self.json_last_modified, usegmt=True)
        return result

    def page_debsecan(self, path, params, url):
        obj = '/'.join(path)
        data = self.db.getDebsecan(obj)
        if data:
            return BinaryResult(data,'application/octet-stream')
        else:
            return self.create_page(
                url, "Object not found",
                [P("The requested debsecan object has not been found.")],
                status=404)

    def create_page(self, url, title, body, search_in_page=False, status=200):
        append = body.append
        append(HR())
        if not search_in_page:
            append(self.make_search_button(url))
            append(FOOTER(P(A(url.scriptRelative(""), "Home"),
                    " - ", A(url.absolute("https://www.debian.org/security/"),
                             "Debian Security"),
                    " - ", A(url.absolute("https://salsa.debian.org/security-tracker-team/security-tracker/blob/master/bin/tracker_service.py"),
                             "Source"),
                    " ", A(url.absolute("https://salsa.debian.org/security-tracker-team/security-tracker"), "(Git)"),
                    )))
        if search_in_page:
            on_load = "selectSearch()"
        else:
            on_load = None
        head_contents = compose(
            LINK(' ', href=url.scriptRelative("style.css")),
            SCRIPT(' ', src=url.scriptRelative("script.js")),
        ).toHTML()
        return HTMLResult(self.add_title(title, body,
                                         head_contents=head_contents,
                                         body_attribs={'onload': on_load}),
                          doctype=self.html_dtd(),
                          status=status)

    def make_search_button(self, url):
        return FORM("Search for package or bug name: ",
                    INPUT(type='text', name='query',
                          onkeyup="onSearch(this.value)",
                          onmousemove="onSearch(this.value)"),
                    INPUT(type='submit', value='Go'),
                    ' ',
                    A(url.scriptRelative("data/report"), "Reporting problems"),
                    method='get',
                    id='searchform',
                    action=url.scriptRelative(''))

    def url_cve(self, url, name):
        return url.absolute("https://www.cve.org/CVERecord",
                            id=name)
    def url_nvd(self, url, name):
        return url.absolute("https://nvd.nist.gov/vuln/detail/%s" % name)
    def url_cert_bug(self, url, name):
        return url.absolute("https://www.kb.cert.org/vuls/byid", searchview='', query=name)
    def url_lwn_bug(self, url, name):
        return url.absolute("https://lwn.net/Search/DoSearch", words=name)
    def url_osssec_bug(self, url, name):
        return url.absolute("https://marc.info/", l="oss-security", s=name)
    def url_fulldesc_bug(self, url, name):
        return url.absolute("https://marc.info/", l="full-disclosure", s=name)
    def url_bugtraq_bug(self, url, name):
        return url.absolute("https://marc.info/", l="bugtraq", s=name)
    def url_edb_bug(self, url, name):
        name = name[len('CVE-'):] if name.startswith('CVE-') else name
        return url.absolute("https://www.exploit-db.com/search/", action="search", cve=name)
    def url_metasploit_bug(self, url, name):
        return url.absolute("https://www.rapid7.com/db/search", q=name)
    def url_rhbug(self, url, name):
        return url.absolute("https://bugzilla.redhat.com/show_bug.cgi",
                            id=name)
    def url_ubuntu_bug(self, url, name):
        return url.absolute("https://people.canonical.com/~ubuntu-security/cve/%s" % name)
    def url_gentoo_bug(self, url, name):
        return url.absolute("https://bugs.gentoo.org/show_bug.cgi", id=name)
    def url_suse_bug(self, url, name):
        return url.absolute("https://bugzilla.suse.com/show_bug.cgi",
                            id=name)
    def url_suse_cve(self, url, name):
        return url.absolute("https://www.suse.com/security/cve/%s/" % name)
    def url_mageia_bug(self, url, name):
        return url.absolute("https://advisories.mageia.org/%s.html" % name)
    def url_github_advisory_bug(self, url, name):
        return url.absolute("https://github.com/advisories", query=name)
    def url_github_code_bug(self, url, name):
        return url.absolute("https://github.com/search", type="Code", q='"%s"' % name)
    def url_github_issues_bug(self, url, name):
        return url.absolute("https://github.com/search", type="Issues", q='"%s"' % name)
    def url_web_search_bug(self, url, name):
        return url.absolute("https://duckduckgo.com/html", q='"%s"' % name)

    def url_dsa(self, url, dsa, re_dsa=re.compile(r'^DSA-(\d+)(?:-\d+)?$')):
        match = re_dsa.match(dsa)
        if match:
            # We must determine the year because there is no generic URL.
            (number,) = match.groups()
            for (date,) in self.db.cursor().execute(
                "SELECT release_date FROM bugs WHERE name = ?", (dsa,)):
                (y, m, d) = date.split('-')
                return url.absolute("https://www.debian.org/security/%d/dsa-%d"
                                    % (int(y), int(number)))
        return None

    def url_dla(self, url, dla, re_dla=re.compile(r'^DLA-(\d+)(-\d+)?$')):
        match = re_dla.match(dla)
        if match:
            (number,revision) = match.groups()
            if revision == "-1":
                link = "dla-%d" % int(number)
            else:
                link = dla.lower()
            # We must determine the year because there is no generic URL.
            for (date,) in self.db.cursor().execute(
                "SELECT release_date FROM bugs WHERE name = ?", (dla,)):
                (y, m, d) = date.split('-')
                return url.absolute("https://www.debian.org/lts/security/%d/%s"
                                    % (int(y), link))
        return None

    def url_debian_bug(self, url, debian):
        return url.absolute("https://bugs.debian.org/cgi-bin/bugreport.cgi",
                            bug=str(debian))
    def url_debian_bug_pkg(self, url, debian):
        return url.absolute("https://bugs.debian.org/cgi-bin/pkgreport.cgi",
                            pkg=debian)
    def url_source_code(self, url, package):
        return url.absolute("https://sources.debian.org/src/%s/" % package)
    def url_pts(self, url, package):
        return url.absolute("https://tracker.debian.org/pkg/%s" % package)
    def url_testing_status(self, url, package):
        return url.absolute("https://qa.debian.org/excuses.php",
                            package=package)
    def url_source_package(self, url, package, full=False):
        if full:
            return url.scriptRelativeFull("source-package/" + package)
        else:
            return url.scriptRelative("source-package/" + package)

    def make_xref(self, url, name):
        return A(url.scriptRelative(name), name)

    def make_xref_list(self, url, lst, separator=', '):
        return make_list(list(map(lambda x: self.make_xref(url, x), lst)), separator)

    def make_debian_bug(self, url, debian):
        return A(self.url_debian_bug(url, debian), str(debian))
    def make_debian_bug_list(self, url, lst):
        return make_list(list(map(lambda x: self.make_debian_bug(url, x), lst)))

    def make_cve_ref(self, url, cve, name=None):
        if name is None:
            name = cve
        return A(self.url_cve(url, cve), name)

    def make_nvd_ref(self, url, cve, name=None):
        if name is None:
            name = cve
        return A(self.url_nvd(url, cve), name)

    def make_cert_bug_ref(self, url, cve, name=None):
        if name is None:
            name = cve
        return A(self.url_cert_bug(url, cve), name)

    def make_lwn_bug_ref(self, url, cve, name=None):
        if name is None:
            name = cve
        return A(self.url_lwn_bug(url, cve), name)

    def make_osssec_bug_ref(self, url, cve, name=None):
        if name is None:
            name = cve
        return A(self.url_osssec_bug(url, cve), name)

    def make_fulldisc_bug_ref(self, url, cve, name=None):
        if name is None:
            name = cve
        return A(self.url_fulldesc_bug(url, cve), name)

    def make_bugtraq_bug_ref(self, url, cve, name=None):
        if name is None:
            name = cve
        return A(self.url_bugtraq_bug(url, cve), name)

    def make_edb_bug_ref(self, url, cve, name=None):
        if name is None:
            name = cve
        return A(self.url_edb_bug(url, cve), name)

    def make_metasploit_bug_ref(self, url, cve, name=None):
        if name is None:
            name = cve
        return A(self.url_metasploit_bug(url, cve), name)

    def make_rhbug_ref(self, url, cve, name=None):
        if name is None:
            name = cve
        return A(self.url_rhbug(url, cve), name)

    def make_ubuntu_bug_ref(self, url, cve, name=None):
        if name is None:
            name = cve
        return A(self.url_ubuntu_bug(url, cve), name)

    def make_gentoo_bug_ref(self, url, cve, name=None):
        if name is None:
            name = cve
        return A(self.url_gentoo_bug(url, cve), name)

    def make_suse_bug_ref(self, url, cve, name=None):
        if name is None:
            name = cve
        return A(self.url_suse_bug(url, cve), name)

    def make_suse_cve_ref(self, url, cve, name=None):
        if name is None:
            name = cve
        return A(self.url_suse_cve(url, cve), name)

    def make_mageia_bug_ref(self, url, cve, name=None):
        if name is None:
            name = cve
        return A(self.url_mageia_bug(url, cve), name)

    def make_github_advisory_ref(self, url, cve, name=None):
        if name is None:
            name = cve
        return A(self.url_github_advisory_bug(url, cve), name)

    def make_github_code_ref(self, url, cve, name=None):
        if name is None:
            name = cve
        return A(self.url_github_code_bug(url, cve), name)

    def make_github_issues_ref(self, url, cve, name=None):
        if name is None:
            name = cve
        return A(self.url_github_issues_bug(url, cve), name)

    def make_web_search_bug_ref(self, url, cve, name=None):
        if name is None:
            name = cve
        return A(self.url_web_search_bug(url, cve), name)

    def make_dsa_ref(self, url, dsa, name=None):
        if name is None:
            name = dsa
        u = self.url_dsa(url, dsa)
        if u:
            return A(u, name)
        else:
            return name

    def make_dla_ref(self, url, dla, name=None):
        if name is None:
            name = dla
        u = self.url_dla(url, dla)
        if u:
            return A(u, name)
        else:
            return name

    def make_source_code_ref(self, url, pkg, name=None):
        if name is None:
            name = pkg
        return A(self.url_source_code(url, pkg), name)

    def make_pts_ref(self, url, pkg, name=None):
        if name is None:
            name = pkg
        return A(self.url_pts(url, pkg), name)

    def make_source_package_ref(self, url, pkg, title=None):
        if title is None:
            title = pkg
        return A(self.url_source_package(url, pkg), title)

    def make_red(self, contents):
        return SPAN(contents, _class="red")

    def make_yellow(self, contents):
        return SPAN(contents, _class="yellow")

    def make_purple(self, contents):
        return SPAN(contents, _class="purple")

    def make_green(self, contents):
        return SPAN(contents, _class="green")

    def make_mouseover(self, contents, text):
        return tag("SPAN", contents, title=text)

    def make_dangerous(self, contents):
        return SPAN(contents, _class="dangerous")

    def pre_dispatch(self):
        pass

if __name__ == "__main__":
    TrackerService(socket_name, db_name).run()

# nvd.py -- simplistic NVD parser
# Copyright (C) 2005 Florian Weimer <fw@deneb.enyo.de>
# Copyright (C) 2019 Salvatore Bonaccorso <carnil@debian.org>
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

"""This module parses the JSON files provided by the
National Vulnerability Database (NVD) <https://nvd.nist.gov/>
"""

import json

class _Parser:
    """Parser helper class."""

    def __init__(self):
        self.result = []

    def parse(self, file):
        cve_data=json.load(file)

        for entry in cve_data['CVE_Items']:
            # get CVE ID name
            if 'cve' not in entry:
                raise ValueError("No CVE entry present in CVE_Items")
            if 'CVE_data_meta' not in entry['cve']:
                raise ValueError("No CVE metadata entry present")
            if 'ID' not in entry['cve']['CVE_data_meta']:
                raise ValueError("No CVE ID present for entry")
            self.name=entry['cve']['CVE_data_meta']['ID']

            # get CVE description
            self.cve_desc=""
            try:
                self.cve_desc=entry['cve']['description']['description_data'][0].get('value')
            except KeyError:
                pass

            # get discovered date
            # TODO: re-implement or change database schema
            self.discovered=""

            # get publication date
            self.published=""
            try:
                self.published=entry.get('publishedDate')
            except KeyError:
                pass

            # get severity
            self.severity=""
            try:
                self.severity=entry['impact']['baseMetricV2'].get('severity')
            except KeyError:
                pass

            # initalize defaults
            self.range_local = self.range_remote = self.range_user_init = 0

            self.loss_avail = self.loss_conf = self.loss_int \
                = self.loss_sec_prot_user = self.loss_sec_prot_admin \
                = self.loss_sec_prot_other = 0

            # get range and loss values
            # TODO: re-implement or change database schema

            self.result.append((self.name,
                                self.cve_desc,
                                self.discovered,
                                self.published,
                                self.severity,
                                self.range_local,
                                self.range_remote,
                                self.range_user_init,
                                self.loss_avail,
                                self.loss_conf,
                                self.loss_int,
                                self.loss_sec_prot_user,
                                self.loss_sec_prot_admin,
                                self.loss_sec_prot_other))

def parse(file):
    """Parses the indicated file object.  Returns a list of tuples,
    containing the following elements:

    - CVE name
    - CVE description
    - discovery data (can be empty)
    - publication date
    - severity (can be empty)
    - local range flag
    - remote range flag
    - availability loss type flag
    - confidentiality loss type flag
    - integrity loss type flag
    - security protection (user) loss type flag
    - security protection (admin) loss type flag
    - security protection (other) loss type flag
    """

    p = _Parser()
    p.parse(file)
    return p.result

if __name__ == '__main__':
    import sys
    for name in sys.argv[1:]:
        parse(open(name))

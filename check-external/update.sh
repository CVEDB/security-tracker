#!/bin/sh

####################
#    Copyright (C) 2010 by Raphael Geissert <geissert@debian.org>
#
#
#    This file is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
#
#    This file is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this file.  If not, see <https://www.gnu.org/licenses/>.
####################

set -e

export LANG=C

check_list() {
    if grep -vE '^CVE-[12][0-9]{3}-[0-9]{4,}$' $1; then
	echo "$1 contains garbage (see above), aborting"
	exit 1
    fi
}

# Discontinued since October 2015, cf. #805079
## Red Hat provides a complete dump of their tracker, which includes
## unfixed issues.
## Note: The downloaded html files are Copyright by Red Hat, Inc.
## or as specified at the individual html files or elsewhere on redhat.com's website
#for year in $(seq 1999 $(date +%Y)); do
#    wget -O cve-$year.html https://www.redhat.com/security/data/cve/cve-$year.html
#done
#sed -rn '/CVE-[12][0-9]{2,}-/{s/^.+>(CVE-[12][0-9]{3}-[0-9]{4,})<.+$/\1/;T;p}' cve-*.html |
#    sort > cve.list
#check_list cve.list

# Fetch some CVE information directly from Red Hat Bugzilla
# This should be better done via a rewrite and using python-bugzilla
# but it is sufficient for now to get some additional CVE information
# from Red Hat source
wget -O redhat-bugzilla.html 'https://bugzilla.redhat.com/buglist.cgi?classification=Other&component=vulnerability&f1=alias&o1=regexp&product=Security%20Response&query_format=advanced&v1=^CVE-.*&order=priority%2Cbug_severity&limit=0'
# Some extra data is readily available as an xml file
wget -N https://www.redhat.com/security/data/metrics/cve-metadata-from-bugzilla.xml
cat redhat-bugzilla.html cve-metadata-from-bugzilla.xml |
perl -ne 'print "$1\n" while (s/(CVE-[12][0-9]{3}-[0-9]{4,})//);' | sort -u > cve.list
check_list cve.list

# List of issues fixed by each vendor, according to MITRE. Very
# incomplete, but it doesn't hurt to double check (including our own list)
# Note: The downloaded html files are Copyright by The MITRE Corporation
# or as specified at the individual html files or elsewhere on cve.mitre.org's website
for vendor in SUSE DEBIAN GENTOO FEDORA REDHAT UBUNTU; do
    wget -N http://cve.mitre.org/data/refs/refmap/source-$vendor.html
    sed -rn "/CVE-[12][0-9]{3}-/{s/^.+>($vendor:)?(CVE-[12][0-9]{3}-[0-9]{4,})<.+$/\2/;p}" source-$vendor.html |
	sort -u > $vendor.list
    check_list $vendor.list
done

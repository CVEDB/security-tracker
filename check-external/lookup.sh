#!/bin/bash

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

regex=
after=
source=cve

while [ $# -ge 1 ]; do
    case $1 in
	--after|-a)
	    [ $# -gt 1 ] || {
		echo "Missing argument for --after" >&2
		exit 1
	    }
	    shift
	    after="$1"
	;;
	--source|-s)
	    [ $# -gt 1 ] || {
		echo "Missing argument for --source" >&2
		exit 1
	    }
	    shift
	    source="$1"
	;;
	--help|-h)
	    echo "Usage: $(basename "$0") [--source|-s vendor] [--after|-a per-year-id] [regex]"
	    echo ; echo "Look for NFUs/TODOs/RESERVED in our tracker"
	    echo "which are recognised or fixed by another vendor"
	    echo "(requires you to run ./update.sh every now and then)"
	    echo ; echo "Possible vendors:"
	    echo -e "\tcve (for checking against Red Hat's tracker)"
	    echo "fixed issues only:"
	    echo -e "\tUBUNTU\n\tFEDORA\n\tetc (uppercase vendor name; check ./update)"
	    echo ; year="$(date +%Y)"
	    echo "Example (check ids of $year):"
	    echo -e "\t$(basename "$0") CVE-$year"
	    echo "Example (check ids after CVE-$year-0100):"
	    echo -e "\t$(basename "$0") --after 0100 CVE-$year"
	    echo "Example (check ids of $year fixed at Fedora):"
	    echo -e "\t$(basename "$0") --source FEDORA CVE-$year"
	    echo ; echo "Note: this is a hackish and slow implementation."
	    exit
	;;
	*)
	    regex="$1"
	;;
    esac
    shift
done

source+=.list
[ -f "$source" ] || {
    echo "CVE source list $source doesn't exist" >&2
    exit 1
}

for cve in $(< $source); do

    [[ $cve ]] || continue

    if [[ $regex ]]; then
	[[ $cve =~ $regex ]] || continue
    fi

    if [[ $after ]]; then
	[ "${cve#CVE-*-}" '>' "$after" ] || continue
    fi

    # Permanent exclusions can be added below
    o="$(grep -m1 -A2 -w ^$cve ../data/CVE/list | sed '1{d;q}')" || continue

    if [ -z "$o" ]; then
	echo "$cve: missing from list"
    fi

    extra=empty
    while read line; do
	if [[ $extra = empty ]]; then
	    [[ $line =~ TODO|NOT-FOR-US|RESERVED ]] || continue 2
	    o="$line"
	    extra=
	else
	    extra="$line"
	fi
    done <<< "$o"

    case $o in
	*NOT-FOR-US*)
	    tr "[:upper:]" "[:lower:]" <<< "${o#*NOT-FOR-US:}" |
	    grep -v redhat | grep -v 'red hat' | grep -v pre-dating |
	    grep -v realplayer | grep -v acroread |
	    grep -v adobe | grep -v acrobat | grep -vw opera |
	    grep -v 'real player' >/dev/null && echo "$cve: $o" || :
	;;
	*TODO:*)
	    echo "$cve: $o"
	;;
	*RESERVED*)
	    [[ $extra ]] && grep -qv ^CVE <<< "$extra" || \
	    echo "$cve: $o"
	;;
	*)
	    echo "Unrecognised match: $o" >&2
	;;
    esac
done

#!/bin/sh

####################
#    Copyright (C) 2014 by Raphael Geissert <geissert@debian.org>
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

set -eu

include_oldstable=false
turl="https://security-tracker.debian.org/tracker/status/release"

[ -f data/dsa-needed.txt ] || {
    echo "error: run this script from the top-level dir of the repo" >&2
    exit 1
}

tmpd="$(mktemp -d)"
cleanup() {
    rm -r "$tmpd"
}
trap cleanup EXIT

pkgs_print() {
    local pkg=$1
    local include_suffix=$2
    local suffix=$3

    if $include_suffix ; then
        printf "%s/%s\n--\n" "$pkg" "$suffix"
    else
        printf "%s\n--\n" "$pkg"
    fi
}

output=data/dsa-needed.txt
case "${1:-}" in
    --stdout)
        output=/dev/stdout
        ;;
    --cronjob-sectracker)
        output=/dev/stdout
        # see doc/soriano.txt
        turl='http://127.0.0.1:25648/tracker/status/release'
        ;;
    '')
        :
        ;;
    *)
        echo "error: unknown option '$1'" >&2
        exit 1
        ;;
esac

releases=stable
if $include_oldstable; then
    releases="$releases oldstable"
fi

for release in $releases; do
    HOME=$tmpd w3m $turl/$release > $tmpd/$release.txt
    touch $tmpd/toadd-$release.txt
    seen_marker=false
    while read line; do
    if ! $seen_marker; then
        case "$line" in
        *Package*Bug*)
            seen_marker=true
        ;;
        esac
    else
        case "$line" in
        [a-z]*)
            # a package
            pkg="$(echo "$line" | awk -F' ' '{ print $1 }')"
            if ! grep -qE "^$pkg(/$release)?( |\$)" data/dsa-needed.txt; then
            echo "$pkg" >> $tmpd/toadd-$release.txt
            fi
        ;;
        '')
            # end of the list of packages
            break
        ;;
        esac
    fi
    done < $tmpd/$release.txt
done

# Handle packages which need update in multiple releases
# These are added without /$release suffix
cat $tmpd/toadd-*.txt | sort | uniq -d |
while read pkg; do
    pkgs_print "$pkg" false false >> $output
    sed -ri "/^$pkg\$/d" $tmpd/toadd-*.txt
done

# Handle package which need update in distinct releases
# and that are added with /$release suffix
for release in $releases; do
    while read pkg; do
        pkgs_print "$pkg" "$include_oldstable" "$release" >> $output
    done < $tmpd/toadd-$release.txt
done

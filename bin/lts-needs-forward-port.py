#!/usr/bin/python3
#
# Copyright 2016 Guido Günther <agx@sigxcpu.org>
#
# This file is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 2 of the License, or
# (at your option) any later version.
#
# This file is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this file.  If not, see <https://www.gnu.org/licenses/>.

import argparse
import collections
import sys

from tracker_data import TrackerData

import setup_paths
import config

lts = config.get_supported_releases()[0]
next_lts = config.get_supported_releases()[1]
oldstable = config.get_release_codename('oldstable')

LIST_NAMES = (
    ('needs_fix_in_next_lts',
     ('Issues that are unfixed in {} but fixed in {}'
      ).format(next_lts, lts)),
    ('needs_review_in_next_lts',
     ('Issues that are no-dsa in {} but fixed in {}'
      ).format(next_lts, lts)),
    ('fixed_via_pu_in_oldstable',
     ('Issues that will be fixed via p-u in {}'
      ).format(oldstable)),
)


def main():
    def add_to_list(key, pkg, issue):
        assert key in [l[0] for l in LIST_NAMES]
        lists[key][pkg].append(issue)

    parser = argparse.ArgumentParser(
        description='Find discrepancies between suites')
    parser.add_argument('--skip-cache-update', action='store_true',
                        help='Skip updating the tracker data cache')
    parser.add_argument('--exclude', nargs='+', choices=[x[0] for x in LIST_NAMES],
                        help='Filter out specified lists')

    args = parser.parse_args()

    lists = collections.defaultdict(lambda: collections.defaultdict(lambda: []))
    tracker = TrackerData(update_cache=not args.skip_cache_update)

    for pkg in tracker.iterate_packages():
        for issue in tracker.iterate_pkg_issues(pkg):
            status_in_lts = issue.get_status(lts)
            status_in_next_lts = issue.get_status(next_lts)

            if status_in_lts.status in ('not-affected', 'open'):
                continue

            if status_in_lts.status == 'resolved':
                #  Package will be updated via the next oldstable
                #  point release
                #  FIXME: when lts == oldstable, this should look at the stable pu list
                if (issue.name in tracker.oldstable_point_update and
                    pkg in tracker.oldstable_point_update[issue.name]):
                    add_to_list('fixed_via_pu_in_oldstable', pkg, issue)
                    continue

                #  The security tracker marks "not-affected" as
                #  "resolved in version 0" (#812410)
                if status_in_lts.reason == 'fixed in 0':
                    continue

                if status_in_next_lts.status == 'open':
                    add_to_list('needs_fix_in_next_lts', pkg, issue)
                    continue

                if status_in_next_lts.status == 'ignored':
                    add_to_list('needs_review_in_next_lts', pkg, issue)
                    continue

    for key, desc in LIST_NAMES:
        if args.exclude is not None and key in args.exclude:
            continue
        if not len(lists[key]):
            continue
        print('{}:'.format(desc))
        for pkg in sorted(lists[key].keys()):
            cve_list = ' '.join(
                [i.name for i in sorted(lists[key][pkg],
                                        key=lambda i: i.name)])
            print('* {:20s} -> {}'.format(pkg, cve_list))
        print('')

if __name__ == '__main__':
    sys.exit(main())

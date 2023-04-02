# Tests for sectracker.regexpcase
# Copyright (C) 2009, 2010 Florian Weimer <fw@deneb.enyo.de>
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

import unittest

from sectracker.regexpcase import *

class TestRegexpCase(unittest.TestCase):
    def testempty(self):
        self.assertRaises(ValueError, RegexpCase, ())
        self.assertRaises(ValueError, RegexpCase, (), prefix="foo")
        self.assertRaises(ValueError, RegexpCase, (), suffix="foo")
        self.assertRaises(ValueError, RegexpCase, (), default="foo")
        self.assertRaises(ValueError, RegexpCase, (("two", 2)),
                                                   prefix="(f)oo")
        self.assertRaises(ValueError, RegexpCase, (("two", 2)),
                                                   suffix="(f)oo")

    def teststrings(self):
        rc = RegexpCase((("two", 2),
                         ("three", 3),
                         ("five", 5)))
        self.assertEqual(2, rc["two"])
        self.assertEqual(3, rc["three"])
        self.assertEqual(5, rc["five"])
        self.assertEqual(None, rc["seven"])
        self.assertEqual((None, None), rc.match("seven"))
        self.assertRaises(TypeError, rc.__call__, ())

    def testcallstrings(self):
        rc = RegexpCase((("(two)", lambda groups, x: (groups, x)),
                         ("three", lambda groups, x: (groups, x)),
                         ("f(i)v(e)", lambda groups, x : (groups, x))))
        self.assertEqual((("two",), -2), rc("two", -2))
        self.assertEqual(((), -3), rc("three", -3))
        self.assertEqual((tuple("ie"), -5), rc("five", -5))
        self.assertEqual(None, rc("seven", -1))
    def testcallstringsdefault(self):
        rc = RegexpCase([("f(i)v(e)", lambda groups, x : (groups, x))],
                        default=lambda key, x: (key, x))
        self.assertEqual(("seven", -1), rc("seven", -1))

unittest.main()

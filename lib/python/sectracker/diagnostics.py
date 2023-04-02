# sectracker.diagnostics -- keeping track of errors and warnings
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

from collections import namedtuple as _namedtuple

from helpers import isstring

Message = _namedtuple("Message", "file line level message")

def _checkfile(file):
    if not isstring(file):
        raise ValueError("file name is not a string: " + repr(file))
    return file

def _checkline(line):
    if not isinstance(line, int):
        raise ValueError("not a number: " + repr(line))
    if line <= 0:
        raise ValueError("line number must be positive: " + repr(line))
    return line

class Diagnostics:
    def __init__(self):
        self._messages = []
        self._file = None
        self._line = None

    def setlocation(self, file, line=1):
        if file is None and line is None:
            self._file = self._line = None
        else:
            self._file = _checkfile(file)
            self._line = _checkline(line)

    def error(self, message, file=None, line=None):
        self.record(file, line, "error", message)

    def warning(self, message, file=None, line=None):
        self.record(file, line, "warning", message)

    def record(self, file, line, level, message):
        if file is None:
            file = self._file
            if file is None:
                raise Excpetion("location has not been set")
        else:
            _checkfile(file)
        if line is None:
            line = self._line
            if line is None:
                raise Excpetion("location has not been set")
        else:
            _checkline(line)
        self._messages.append(Message(file, line, level, message))

    def file(self):
        if self._file is None:
            raise Excpetion("location has not been set")
        return self._file

    def line(self):
        if self._line is None:
            raise Excpetion("location has not been set")
        return self._line

    def messages(self):
        return tuple(self._messages)


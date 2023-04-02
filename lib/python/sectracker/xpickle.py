# sectracker.xpickle -- pickle helpers
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

import errno as _errno
import os as _os
import pickle as _pickle
import tempfile as _tempfile

EXTENSION = '.xpck'

def safeunlink(path):
    """Removes the file.
    No exception is thrown if the file does not exist."""
    try:
        _os.unlink(path)
    except OSError as e:
        if e.errno != _errno.ENOENT:
            raise e

def replacefile(path, action):
    """Calls the action to replace the file at path.

    The action is called with two arguments, the path to the temporary
    file, and an open file object for that temporary file.  On success,
    the temporary file is renmaed as the original file, atomically
    replacing it.  The return value is the value returned by the action."""
    t_fd, t_name = _tempfile.mkstemp(suffix='.tmp', dir=_os.path.dirname(path))
    try:
        t = _os.fdopen(t_fd, "wb")
        try:
            result = action(t_name, t)
        finally:
            t.close()
        _os.rename(t_name, path)
        t_name = None
    finally:
        if t_name is not None:
            safeunlink(t_name)
    return result
    
def _wraploader(typ, parser):
    # Format of the top-most object in the picke:
    #
    #   ((type, size, mtime, inode), payload)
    #
    # The first element is used to check for up-to-date-ness.

    def safeload(path):
        try:
            with open(path + EXTENSION, "rb") as f:
                return (_pickle.load(f), True)
        except (AttributeError, EOFError, IOError, _pickle.PickleError):
            return (None, False)

    def check(data, st):
        try:
            obj = data[1]
            if data[0] == (typ, st.st_size, st.st_mtime, st.st_ino):
                return (obj, True)
        except (IndexError, TypeError):
            pass
        return (None, False)

    def reparse(path, st):
        with open(path) as f:
            obj = parser(path, f)
        data = _pickle.dumps(
            ((typ, st.st_size, st.st_mtime, st.st_ino), obj), -1)
        replacefile(path + EXTENSION, lambda name, f: f.write(data))
        return obj

    def loader(path):
        st = _os.stat(path)
        xpck = path + EXTENSION
        data, success = safeload(path)
        if success:
            obj, success = check(data, st)
            if success:
                return obj
        return reparse(path, st)
    loader.__doc__ = parser.__doc__
    return loader

def loader(file_type):
    """Adds disk-based memoization to the annotated parser function.

    The function takes two arguments, the file name and a file object.
    file_type is an arbitrary string, also useful for versioninging."""
    return lambda f: _wraploader(file_type, f)

# helpers.py -- utility functions that don't belong elsewhere

def isstring(s):
    try:
        return isinstance(s, basestring)
    except NameError:
        return isinstance(s, str)

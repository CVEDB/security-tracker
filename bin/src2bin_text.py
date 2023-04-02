#!/usr/bin/env python2

import sys
import os
import fileinput

ca_path = '/etc/ssl/ca-debian'
if os.path.isdir(ca_path):
    os.environ['SSL_CERT_DIR'] = ca_path

default_url = 'https://packages.qa.debian.org/cgi-bin/soap-alpha.cgi'

def soappy_query(url, method, **kwargs):
    import SOAPpy

    ws = SOAPpy.SOAPProxy(url)
    return getattr(ws, method)(**kwargs)

def joinEN(words):
    if len(words) == 1: return words[0]
    if len(words) == 2: return ' and '.join(words)
    if len(words) >= 3: return ', '.join(words[:-1]+ ['and %s' % words[-1]])

def filterPkg(bins,rms):
    for rm in rms:
        bins = filter(lambda x: not x.endswith('-%s' % rm), bins)
    return list(bins)
    
def getBin(srcPkg):
    bins = soappy_query(default_url,'binary_names',source=srcPkg)
    if type(bins) == str: bins = [bins]
    return [ i for i in bins]

def word_wrap(string, width=80, ind1=0, ind2=0, prefix=''):
    """ word wrapping function.
        string: the string to wrap
        width: the column number to wrap at
        prefix: prefix each line with this string (goes before any indentation)
        ind1: number of characters to indent the first line
        ind2: number of characters to indent the rest of the lines
    """
    string = prefix + ind1 * " " + string
    newstring = ""
    while len(string) > width:
        # find position of nearest whitespace char to the left of "width"
        marker = width - 1
        while not string[marker].isspace():
            marker = marker - 1

        # remove line from original string and add it to the new string
        newline = string[0:marker] + "\n"
        newstring = newstring + newline
        string = prefix + ind2 * " " + string[marker + 1:]

    return newstring + string

def change(line, toRemove):
    srcPkg = line[35:-11]
    bins = filterPkg(getBin(srcPkg),toRemove)
    return joinEN(bins)

if __name__ == '__main__':
    exclude = []
    if '-x' in sys.argv:
       i = sys.argv.index('-x')
       exclude = sys.argv[i+1:]
       sys.argv = sys.argv[:i]
    for line in fileinput.input():
       if 'We recommend that you upgrade your' in line:
	 line = word_wrap("%s: %s.\n" % (line[:-2],change(line,exclude)),width=73)
       print(line)

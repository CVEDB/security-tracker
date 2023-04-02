#!/usr/bin/python2
import urllib2
import SOAPpy
import os
import string
import sys
import json

base_path=os.path.dirname(os.path.abspath(__file__))
db_file=os.path.join(base_path,'../data/security.db')
remove_pkgs=os.path.join(base_path,'../data/packages/removed-packages')

def setup_paths():
    check_file = 'lib/python/debian_support.py'
    path = os.getcwd()
    while 1:
        if os.path.exists("%s/%s" % (path, check_file)):
            sys.path = [path + '/lib/python'] + sys.path
            return path
        idx = string.rfind(path, '/')
        if idx == -1:
            raise ImportError("could not setup paths")
        path = path[0:idx]
os.chdir(setup_paths())

import security_db

try:
    db = security_db.DB(db_file)
    new_file = False
except security_db.SchemaMismatch:
    os.unlink(db_file)
    db = security_db.DB(db_file, verbose=True)
    new_file = True
    
debian_ca_bundle = '/etc/ssl/ca-debian/ca-certificates.crt'
if os.path.exists(debian_ca_bundle):
    os.environ['SSL_CERT_FILE'] = debian_ca_bundle

ws = SOAPpy.SOAPProxy('https://packages.qa.debian.org/cgi-bin/soap-alpha.cgi')

def checkInPTS(pkg):
    try:
       ws.versions(source=pkg)
    except SOAPpy.faultType:
       return False
    else:
       return True

def fromSources(pkg):
    try: 
       data = json.load(urllib2.urlopen('https://sources.debian.org/api/src/%s/latest/' %pkg))
    except urllib2.HTTPError as e:
       return []
    if 'error' in data: return []
    else: return data['pkg_infos']['suites']

def inExperimental(pkg):
    print pkg, "in experimental"

def removeIt(pkg):
    with open(remove_pkgs, 'a') as file:
         file.write(pkg+'\n')

pkgs=set([ i[0] for i in db.getUnknownPackages(db.cursor())])

for pkg in pkgs:
    suites = fromSources(pkg)
    if len(suites) >0:
       if 'experimental' in suites : inExperimental(pkg)
       else: removeIt(pkg)
    else:
       if checkInPTS(pkg): removeIt(pkg)
       else: print pkg #UNKNOWN

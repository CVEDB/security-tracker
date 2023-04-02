# inserts lib/python/ into sys.path

import os
import sys

def setup_path():
    dirname = os.path.dirname
    base = dirname(dirname(os.path.realpath(__file__)))
    sys.path.insert(0, os.path.join(base, "lib", "python"))

setup_path()

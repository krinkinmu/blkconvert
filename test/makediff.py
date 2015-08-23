#!/usr/bin/python

import sys

pr = -1
for line in sys.stdin:
    nx = int(line)
    if pr != -1:
        print nx - pr
    pr = nx

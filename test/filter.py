#!/usr/bin/python

import sys

threshold = 1000
for line in sys.stdin:
    if int(line) <= threshold:
        print line.strip()

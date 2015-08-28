#!/usr/bin/python

from collections import defaultdict
import sys

bucket = 1000
d = defaultdict(int)

for i in sys.stdin:
    diff = int(i)
    d[diff / bucket] += 1

for k, v in sorted(d.items()):
    print k, v

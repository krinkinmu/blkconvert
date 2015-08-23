#!/usr/bin/python

import sys

nums = sorted(map(int, sys.stdin.readlines()))
print 'avg:', sum(nums)/len(nums)
print 'mod:', nums[len(nums)/2]

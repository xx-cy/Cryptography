# -*- coding: cp936 -*-
'''n1 ��n2������ͬ��������'''
import re
import gmpy2

Data = []
for i in [1, 18]:
    with open('Frame' + str(i)) as fp:
        data = re.findall('(.{256})(.{256})(.{256})', fp.read().replace('\n', ''))
        Data += data

N = [int(n, 16) for n, e, c in Data]
C = [int(c, 16) for n, e, c in Data]
E = [int(e, 16) for n, e, c in Data]

p = gmpy2.gcd(N[0], N[1])

q1 = N[0] / p
q2 = N[1] / p

print 'p: ', p
print 'q1: ', q1
print 'q2: ', q2

print 'Frame1 m:', '{:x}'.format(pow(C[0], gmpy2.invert(E[0], (p - 1) * (q1 - 1)), p * q1)).decode('hex')[56:]
print 'Frame18 m:', '{:x}'.format(pow(C[1], gmpy2.invert(E[1], (p - 1) * (q2 - 1)), p * q2)).decode('hex')[56:]




# -*- coding: cp936 -*-
import re
import gmpy2


def CRT(items):
    N = reduce(lambda x, y: x * y, (i[1] for i in items))
    result = 0
    for a, n in items:
        m = N / n
        d, r, s = gmpy2.gcdext(n, m)
        if d != 1: raise Exception("Input not pairwise co-prime")
        result += a * s * m
    return result % N, N


Data = []
N = []
C = []
E = []
for i in [3, 8, 12, 16, 20]:
    with open('Frame' + str(i)) as fp:
        data = re.findall('(.{256})(.{256})(.{256})', fp.read().replace('\n', ''))
        Data += data

N = [int(n, 16) for n, e, c in Data]
C = [int(c, 16) for n, e, c in Data]
E = [int(e, 16) for n, e, c in Data]

# 读入e, n, c
n, c = N, C
e = E[0]
data = zip(c, n)

x, n = CRT(data)
print x, n
realnum = gmpy2.iroot(gmpy2.mpz(x), e)[0].digits()
print ' m: ' + '{:x}'.format(int(realnum)).decode('hex')[12:]

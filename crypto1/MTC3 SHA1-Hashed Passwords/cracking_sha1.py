import hashlib
import itertools
import datetime

start = datetime.datetime.now()
SHA1hash = "67ae1a64661ac8b4494666f58c4822408dd0a3e4"
testStr = [['Q', 'q'], ['W', 'w'], ['5', '%'], ['8', '('], ['=', '0'], ['I', 'i'], ['*', '+'], ['n', 'N']]


def sha1Encrypt(str):
    sha = hashlib.sha1(str.encode())
    encrypts = sha.hexdigest()
    return encrypts

#按照每个键按了一次进行暴力破解
liststr = "0" * 8
tempstr = ""
testPassword = list(liststr)
for a in range(0, 2):
    testPassword[0] = testStr[0][a]
    for b in range(0, 2):
        testPassword[1] = testStr[1][b]
        for c in range(0, 2):
            testPassword[2] = testStr[2][c]
            for d in range(0, 2):
                testPassword[3] = testStr[3][d]
                for e in range(0, 2):
                    testPassword[4] = testStr[4][e]
                    for f in range(0, 2):
                        testPassword[5] = testStr[5][f]
                        for g in range(0, 2):
                            testPassword[6] = testStr[6][g]
                            for h in range(0, 2):
                                testPassword[7] = testStr[7][h]
                                temp = "".join(testPassword)
                                for i in itertools.permutations(temp, 8):
                                    tempPw="".join(i)
                                    tempstr = sha1Encrypt(tempPw)
                                    if tempstr == SHA1hash:
                                        print("密码为:",tempPw)
                                        end = datetime.datetime.now()
                                        print("运行时间为:",end - start)
                                        exit(0)







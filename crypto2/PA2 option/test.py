# -*- coding: utf-8 -*-
from oracle import *
import re

CipherText = '9F0B13944841A832B2421B9EAF6D9836813EC9D944A5C8347A7CA69AA34D8DC0DF70E343C4000A2AE35874CE75E64C31'
div = 32  # AES每一块16字节
BLOCK = len(CipherText) / 32 - 1
CipherText = re.findall('.{' + str(div) + '}', CipherText)  # 将密文分为3组 第一组为IV

Oracle_Connect()
M = []
for b in range(BLOCK):  # 对 2 组密文分别求解
    print '破解密文', str(b + 1)
    IV = CipherText[b]
    Ivalue = []
    iv = '00000000000000000000000000000000'  # 初始化 iv
    iv = re.findall('.{2}', iv)[::-1]
    padding = 1
    for l in range(16):
        print "穷举Ivalue倒数第", str(l + 1), '字节'
        for ll in range(l):
            iv[ll] = hex(int(Ivalue[ll], 16) ^ padding)[2:].zfill(2)  # 更新 iv
        for n in range(256):  # 遍历 0x00-0xFF
            iv[l] = hex(n)[2:].zfill(2)
            # 将iv列表反转并与当前要解密的密文连接起来
            data = ''.join(iv[::-1]) + CipherText[b + 1]
            # 将字符串data16进制解码 用10进制保存在ctext中
            ctext = [(int(data[i:i + 2], 16)) for i in range(0, len(data), 2)]
            # 向服务器发送IV和要解密的密文和
            rc = Oracle_Send(ctext, 2)
            # Padding 正确时, 记录 Ivalue, 结束爆破
            if str(rc) == '1':
                Ivalue += [hex(n ^ padding)[2:].zfill(2)]
                break

        print '穷举出的IV为', ''.join(iv[::-1])
        print '穷举出的Ivalue为', ''.join(Ivalue[::-1])
        print '================================================================'

        padding += 1

    Ivalue = ''.join(Ivalue[::-1])

    # IV 与 Ivalue 异或求密文
    m = re.findall('[0-9a-f]+', str(hex(int(IV, 16) ^ int(Ivalue, 16))))[1].decode('hex')
    M += [m]

    print '密文', str(b + 1), '破解成功'
    print 'Ivalue' + str(b + 1), '为:', Ivalue
    print '密文' + str(b + 1), '解密后为:', m
    print '================================================================'

Oracle_Disconnect()

print '密文破解后为', ''.join(M)

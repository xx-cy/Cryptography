import hashlib
from Crypto.Cipher import AES
import base64

#奇偶校验函数
def odd_even_verify(x):
    k = []
    a = bin(int(x, 16))[2:]
    for i in range(0, len(a), 8):
        if (a[i:i + 7].count("1")) % 2 == 0:
            k.append(a[i:i + 7])
            k.append('1')
        else:
            k.append(a[i:i + 7])
            k.append('0')
    a1 = hex(int(''.join(k), 2))
    return a1[2:]


# 22-27位为到期日，？位置是第28位为校验位，根据参考文件的校验方法计算
a = [7, 3, 1] * 2
b = [1, 1, 1, 1, 1, 6]
c = 0
for i in range(0, 6):
    c = c + a[i] * b[i]
    d = c % 10
print("?位置的数字:", d)

c_text = '9MgYwmuPrjiecPMx61O6zIuy3MtIXQQ0E59T3xB6u0Gyf1gYs2i3K9Jxaa0zj4gTMazJuA\
          pwd6+jdyeI5iGHvhQyDHGVlAuYTgJrbFDrfB22Fpil2NfNnWFBTXyf7SDI'
c_text = base64.b64decode(c_text)

#根据参考文件找出机读区信息
mrz = "12345678<8<<<1110182<1111167<<<<<<<<<<<<<<<4"
v_no = mrz[:9]
v_no_verify = mrz[9]
birthday = mrz[13:19]
birthday_verify = mrz[19]
endday = mrz[21:27]
endday_verify = mrz[27]
message = v_no + v_no_verify + birthday + birthday_verify + endday + endday_verify
print("机读区信息:", message)

#根据参考文件的K_seed计算方法计算机读区sha1，取高16位
k_seed = hashlib.sha1(message.encode()).hexdigest()[:32]
print("K_seed:", k_seed)

#根据参考文件计算D
d = k_seed + '0' * 7 + '1'
print("D:", d)

#根据参考文件计算D的sha1
k = hashlib.sha1(bytes.fromhex(d)).hexdigest()
print("D的SHA1值为:", k)

#根据参考文件以及奇偶校验算出ka,kb
k_a = odd_even_verify(k[:16])
k_b = odd_even_verify(k[16:32])
print("Ka为:", k_a)
print("Kb为:", k_b)

#计算出key
key = k_a + k_b
print("Key为:", key)

#解密明文
IV = '0' * 32
m = AES.new(bytes.fromhex(key), AES.MODE_CBC, bytes.fromhex(IV))
print("解密后明文为:", m.decrypt(c_text).decode())




import string

# 使用穷举密钥法
# 1.选择密钥长度
# 2.确定密钥中每个字符的值(0x00-0xFF)
ciphertext = 'F96DE8C227A259C87EE1DA2AED57C93FE5DA36ED4EC87EF2C63AAE5B9A\
7EFFD673BE4ACF7BE8923CAB1ECE7AF2DA3DA44FCF7AE29235A24C963FF0DF3CA3599A\
70E5DA36BF1ECE77F8DC34BE129A6CF4D126BF5B9A7CFEDF3EB850D37CF0C63AA2509A\
76FF9227A55B9A6FE3D720A850D97AB1DD35ED5FCE6BF0D138A84CC931B1F121B44ECE\
70F6C032BD56C33FF9D320ED5CDF7AFF9226BE5BDE3FF7DD21ED56CF71F5C036A94D96\
3FF8D473A351CE3FE5DA3CB84DDB71F5C17FED51DC3FE8D732BF4D963FF3C727ED4AC8\
7EF5DB27A451D47EFD9230BF47CA6BFEC12ABE4ADF72E29224A84CDF3FF5D720A459D4\
7AF59232A35A9A7AE7D33FB85FCE7AF5923AA31EDB3FF7D33ABF52C33FF0D673A551D9\
3FFCD33DA35BC831B1F43CBF1EDF67F0DF23A15B963FE5DA36ED68D378F4DC36BF5B9A\
7AFFD121B44ECE76FEDC73BE5DD27AFCD773BA5FC93FE5DA3CB859D26BB1C63CED5CDF\
3FE2D730B84CDF3FF7DD21ED5ADF7CF0D636BE1EDB79E5D721ED57CE3FE6D320ED57D4\
69F4DC27A85A963FF3C727ED49DF3FFFDD24ED55D470E69E73AC50DE3FE5DA3ABE1EDF\
67F4C030A44DDF3FF5D73EA250C96BE3D327A84D963FE5DA32B91ED36BB1D132A31ED8\
7AB1D021A255DF71B1C436BF479A7AF0C13AA14794'


# 密文为16进制编码 密文中两个十六进制数对应一个字符
def hexDecode(text):
    cList = []
    for i in range(0, len(text), 2):
        cList.append(int(text[i:2 + i], 16))
    return cList


# 从0x00-0xFF验证每一位密钥
def keyfind(strGroup):
    # 由题目得知明文中包含大小写字母、标点符号和空格，但不包含数字
    possibleChars = string.ascii_letters + ',' + '.' + ' '
    testKeys = []
    trueKeys = []
    for i in range(0x00, 0xFF):
        testKeys.append(i)
        trueKeys.append(i)
    for i in testKeys:
        for j in strGroup:
            if chr(i ^ j) not in possibleChars:
                trueKeys.remove(i)
                break
    return trueKeys


# 密文中两个十六进制数对应一个字符
cipherList = hexDecode(ciphertext)
# 枚举密钥长度从1-13位
trueKeylen = 0
truevigenerekey = []
for keyLen in range(1, 14):
    vigenerelikeKey = []
    for i in range(0, keyLen):
        # 每隔一个keyLen取一个字符保存在strGroup中，strGroup中的所有字符都是由同一个密钥字符加密的
        strGroup = cipherList[i::keyLen]
        ansKeys = keyfind(strGroup)
        if not ansKeys:
            break
        else:
            vigenerelikeKey.insert(i, ansKeys)
    if vigenerelikeKey:
        trueKeylen = keyLen
        truevigenerekey = vigenerelikeKey
        print('枚举出的密钥长度为', keyLen)
        print('密钥为(十进制ASCII码表示)', vigenerelikeKey)

# 用密钥解密密文
plaintext = ''
for i in range(0, len(cipherList)):
    plaintext = plaintext + chr(cipherList[i] ^ truevigenerekey[i % trueKeylen][0])
print('解密后的明文为', plaintext)



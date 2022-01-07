import base64
import itertools

# 字母频率表
charfreq = {
    'a': 0.0651738, 'b': 0.0124248, 'c': 0.0217339,
    'd': 0.0349835, 'e': 0.1041442, 'f': 0.0197881,
    'g': 0.0158610, 'h': 0.0492888, 'i': 0.0558094,
    'j': 0.0009033, 'k': 0.0050529, 'l': 0.0331490,
    'm': 0.0202124, 'n': 0.0564513, 'o': 0.0596302,
    'p': 0.0137645, 'q': 0.0008606, 'r': 0.0497563,
    's': 0.0515760, 't': 0.0729357, 'u': 0.0225134,
    'v': 0.0082903, 'w': 0.0171272, 'x': 0.0013692,
    'y': 0.0145984, 'z': 0.0007836, ' ': 0.1918182
}

# 计算文本的分值：该分值是所有在输入字符串中出现的字符对应在字符频率表中的频率相加
def engScore(tbytes):
    score = 0
    for byte in tbytes:
        score += charfreq.get(chr(byte).lower(), 0)
    return score

# 字符串与密钥（同一个）异或函数
def charXor(tbytes, keyvalue):
    output = b''
    for char in tbytes:
        output += bytes([char ^ keyvalue])
    return output

# 密钥从0-255暴力破解函数
def singlecharXor(ciphertext):
    candidates = []
    for keyCandidates in range(256):
        plainCandidates = charXor(ciphertext, keyCandidates)
        candidateScore = engScore(plainCandidates)
        result = {
            'key': keyCandidates,
            'score': candidateScore,
            'plaintext': plainCandidates
        }
        candidates.append(result)
    return sorted(candidates, key=lambda c: c['score'], reverse=True)[0]

# 字符串与重复密钥异或函数
def repeatkeyXor(tbytes, key):
    output = b''
    i = 0
    for byte in tbytes:
        output += bytes([byte ^ key[i]])
        i = i + 1 if i < len(key) - 1 else 0
    return output

# 计算两个字符串的hamming距离
def hammingDistance(str1, str2):
    assert len(str1) == len(str2)
    dist = 0
    for x, y in zip(str1, str2):
        b = x ^ y  # 转换为二进制（以字符串形式表示，如“0b100000”，0b表示二进制）
        dist += sum([1 for bit in bin(b) if bit == '1'])
    return dist

def breakrepeatingkeyXor(binarydata):
    normalizedDistances = {}
    for keySize in range(2, 41):
        # 取出根据keySize划分出的4组数据
        group = [binarydata[i:i + keySize] for i in range(0, len(binarydata), keySize)][:4]
        distance = 0
        # 使用迭代器itertools中的combinations对4组中进行两两任意组合
        pairs = itertools.combinations(group, 2)
        for (x, y) in pairs:
            distance += hammingDistance(x, y)
        distance /= 6
        normalizedDistance = distance / keySize
        normalizedDistances[keySize] = normalizedDistance
    possiblekeySizes = sorted(normalizedDistances, key=normalizedDistances.get)[:3]
    print(possiblekeySizes)

    possiblePlaintexts = []
    for d in possiblekeySizes:
        key = b''
        for i in range(d):
            block = b''
            for j in range(i, len(binarydata), d):
                block += bytes([binarydata[j]])
            key += bytes([singlecharXor(block)['key']])
        possiblePlaintexts.append((repeatkeyXor(binarydata, key), key))
    return max(possiblePlaintexts, key=lambda k: engScore(k[0]))

def main():
    with open("ctext.txt") as fp:
        data = base64.b64decode(fp.read())
    result = breakrepeatingkeyXor(data)
    print("key = ", result[1].decode())
    print("长度= ", len(result[1].decode()))
    print(result[0].decode().rstrip())

if __name__ == "__main__":
    main()



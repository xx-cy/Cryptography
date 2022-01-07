#密文为十六进制字符串，应该先将其处理
ciphertexts = [
    "315c4eeaa8b5f8aaf9174145bf43e1784b8fa00dc71d885a804e5ee9fa40b16349c146fb778cdf2d3aff021dfff5b403b510d0d0455468aeb98622b137dae857553ccd8883a7bc37520e06e515d22c954eba5025b8cc57ee59418ce7dc6bc41556bdb36bbca3e8774301fbcaa3b83b220809560987815f65286764703de0f3d524400a19b159610b11ef3e",
    "234c02ecbbfbafa3ed18510abd11fa724fcda2018a1a8342cf064bbde548b12b07df44ba7191d9606ef4081ffde5ad46a5069d9f7f543bedb9c861bf29c7e205132eda9382b0bc2c5c4b45f919cf3a9f1cb74151f6d551f4480c82b2cb24cc5b028aa76eb7b4ab24171ab3cdadb8356f",
    "32510ba9a7b2bba9b8005d43a304b5714cc0bb0c8a34884dd91304b8ad40b62b07df44ba6e9d8a2368e51d04e0e7b207b70b9b8261112bacb6c866a232dfe257527dc29398f5f3251a0d47e503c66e935de81230b59b7afb5f41afa8d661cb",
    "32510ba9aab2a8a4fd06414fb517b5605cc0aa0dc91a8908c2064ba8ad5ea06a029056f47a8ad3306ef5021eafe1ac01a81197847a5c68a1b78769a37bc8f4575432c198ccb4ef63590256e305cd3a9544ee4160ead45aef520489e7da7d835402bca670bda8eb775200b8dabbba246b130f040d8ec6447e2c767f3d30ed81ea2e4c1404e1315a1010e7229be6636aaa",
    "3f561ba9adb4b6ebec54424ba317b564418fac0dd35f8c08d31a1fe9e24fe56808c213f17c81d9607cee021dafe1e001b21ade877a5e68bea88d61b93ac5ee0d562e8e9582f5ef375f0a4ae20ed86e935de81230b59b73fb4302cd95d770c65b40aaa065f2a5e33a5a0bb5dcaba43722130f042f8ec85b7c2070",
    "32510bfbacfbb9befd54415da243e1695ecabd58c519cd4bd2061bbde24eb76a19d84aba34d8de287be84d07e7e9a30ee714979c7e1123a8bd9822a33ecaf512472e8e8f8db3f9635c1949e640c621854eba0d79eccf52ff111284b4cc61d11902aebc66f2b2e436434eacc0aba938220b084800c2ca4e693522643573b2c4ce35050b0cf774201f0fe52ac9f26d71b6cf61a711cc229f77ace7aa88a2f19983122b11be87a59c355d25f8e4",
    "32510bfbacfbb9befd54415da243e1695ecabd58c519cd4bd90f1fa6ea5ba47b01c909ba764896cf606ef40c04afe1ac0aa81dd066592ded9f8774b529c7ea125d298e8883f5e9305f4b44f915cb2bd05af51373fd9b4af511039fa2d96f83414aaaf261bda2e97b170fb5cce2a53e675c154c0d9681596934777e2275b381ce2e40582afe67650b13e72287ff2270abcf73bb028932836fbdecfecee0a3b894473c1bbeb6b4913a536ce4f9b13f1efff71ea313c8661dd9a4ce",
    "315c4eeaa8b5f8bffd11155ea506b56041c6a00c8a08854dd21a4bbde54ce56801d943ba708b8a3574f40c00fff9e00fa1439fd0654327a3bfc860b92f89ee04132ecb9298f5fd2d5e4b45e40ecc3b9d59e9417df7c95bba410e9aa2ca24c5474da2f276baa3ac325918b2daada43d6712150441c2e04f6565517f317da9d3",
    "271946f9bbb2aeadec111841a81abc300ecaa01bd8069d5cc91005e9fe4aad6e04d513e96d99de2569bc5e50eeeca709b50a8a987f4264edb6896fb537d0a716132ddc938fb0f836480e06ed0fcd6e9759f40462f9cf57f4564186a2c1778f1543efa270bda5e933421cbe88a4a52222190f471e9bd15f652b653b7071aec59a2705081ffe72651d08f822c9ed6d76e48b63ab15d0208573a7eef027",
    "466d06ece998b7a2fb1d464fed2ced7641ddaa3cc31c9941cf110abbf409ed39598005b3399ccfafb61d0315fca0a314be138a9f32503bedac8067f03adbf3575c3b8edc9ba7f537530541ab0f9f3cd04ff50d66f1d559ba520e89a2cb2a83",
    "32510ba9babebbbefd001547a810e67149caee11d945cd7fc81a05e9f85aac650e9052ba6a8cd8257bf14d13e6f0a803b54fde9e77472dbff89d71b57bddef121336cb85ccb8f3315f4b52e301d16e9f52f904"
]

NUM_CIPHER = len(ciphertexts)#NUM_CIPHER=11
THRESHOLD_VALUE = 7#如果两两异或的结果为字母数大于7次，就认为该字符为空格,该值更改会影响最终结果

def strxor(a, b):
    #两个字符串的异或
    if len(a) > len(b):
        # 形成二元组，异或,返回新字符串
        return "".join([chr(ord(x) ^ ord(y)) for (x, y) in zip(a[:len(b)], b)])
    else:
        return "".join([chr(ord(x) ^ ord(y)) for (x, y) in zip(a, b[:len(a)])])

def letter_position(s):
    #返回给定字符串中给定字母的位置
    position = []
    for idx in range(len(s)):
        #考虑到空格异或为0的情况可能较多
        if (s[idx] >= 'A' and s[idx] <= 'Z') or (s[idx] >= 'a' and s[idx] <= 'z') or s[idx] == chr(0):
            position.append(idx)
    return position

def find_space(cipher):
    #寻找空字符
    space_position = {}
    space_possible = {}
    #双重循环，每一条密文均与其他密文异或
    for cipher_idx_1 in range(NUM_CIPHER):
        space_xor = []#用于保存可能空格符对应的位置
        c = ''.join([chr(int(d, 16)) for d in [cipher[cipher_idx_1][i:i + 2] for i in range(0, len(cipher[cipher_idx_1]), 2)]])
        for cipher_idx_2 in range(NUM_CIPHER):
            #将十六进制字符串处理成对应ascii字符（每两个字符代表一个ascii符号）
            e = ''.join([chr(int(d, 16)) for d in [cipher[cipher_idx_2][i:i+2] for i in range(0, len(cipher[cipher_idx_2]), 2)]])
            plain_xor = strxor(c, e)
            if cipher_idx_2 != cipher_idx_1:
                # 记录明文中可能空格符的位置
                space_xor.append(letter_position(plain_xor))
        space_possible[cipher_idx_1] = space_xor  #形成三维列表,新列表为11*10*n

    #进一步判断已记录的位置是否为空字符，其准确性受到文本数量的影响
    for cipher_idx_1 in range(NUM_CIPHER):
        spa = []
        for position in range(400):
            count = 0
            for cipher_idx_2 in range(NUM_CIPHER - 1):
                if position in space_possible[cipher_idx_1][cipher_idx_2]:
                    count += 1
            if count > THRESHOLD_VALUE:  # 如果异或后字母出现次数大于7次，认为明文中此处为空格
                spa.append(position)
        space_position[cipher_idx_1] = spa  #构成二维列表，11 * n
    return space_position

#计算获得对应密钥Key
def calculate_key(cipher):
    key = [0] * 200  #存放key
    space = find_space(cipher)
    #print(space)
    for cipher_idx_1 in range(NUM_CIPHER):
        for position in range(len(space[cipher_idx_1])):
            idx = space[cipher_idx_1][position] * 2 #十六进制，用2位表示
            a = cipher[cipher_idx_1][idx] + cipher[cipher_idx_1][idx + 1]
            key[space[cipher_idx_1][position]] = int(a ,16) ^ ord(' ') # 计算密钥，获得结果十进制(ascii码）

    key_str = ""#空串用于存放密钥
    for k in key:
        key_str += chr(k)#转化为
    return key_str  #获得密钥串

result = ""
key = calculate_key(ciphertexts)
key_hex = ''.join([hex(ord(c)).replace('0x', '') for c in key])#十六进制key
print("key=",key)
print("key_hex=",key_hex)

f = ''.join([chr(int(d, 16)) for d in [ciphertexts[10][i:i+2] for i in range(0, len(ciphertexts[10]), 2)]])
for letter in strxor(f,key):
         if (letter>=' ' and letter<='~ '):#打印从32-126的可见字符
             result+=letter
         else:
             result+='0'#不可打印字符用0代替，以区别空格符
print(result)


#打印所有密文对应的明文
for j in range(11):
    f = ''.join([chr(int(d, 16)) for d in [ciphertexts[j][i:i + 2] for i in range(0, len(ciphertexts[j]), 2)]])
    for letter in strxor(f,key):
         if (letter>=' ' and letter<='~ '):
             result+=letter
         else:
             result+='0'
    print(result)
    result = '' #将result清空，再次使用



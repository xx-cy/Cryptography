plaintext = 'The secret message is: When using a stream cipher, never use the key more than once'
ciphertext = '32510ba9babebbbefd001547a810e67149caee11d945cd7fc81a05e9f85aac650e9052ba6a8cd8257bf14d13e6f0a803b54fde9e77472dbff89d71b57bddef121336cb85ccb8f3315f4b52e301d16e9f52f904'
cipher8text = '315c4eeaa8b5f8bffd11155ea506b56041c6a00c8a08854dd21a4bbde54ce56801d943ba708b8a3574f40c00fff9e00fa1439fd0654327a3bfc860b92f89ee04132ecb9298f5fd2d5e4b45e40ecc3b9d59e9417df7c95bba410e9aa2ca24c5474da2f276baa3ac325918b2daada43d6712150441c2e04f6565517f317da9d3'

ciphertext_bytes = bytes.fromhex(ciphertext)
cipher8text_bytes = bytes.fromhex(cipher8text)
plaintext_bytes = plaintext.encode('utf-8')

key = []
for i in range(len(ciphertext_bytes)):
    key.append(ciphertext_bytes[i] ^ plaintext_bytes[i])
print("密钥为:(十进制ASCII码表示)", key)

plain8text = ''
for i in range(len(key)):
    plain8text += chr(cipher8text_bytes[i] ^ key[i])
print("第八组明文为:", plain8text)


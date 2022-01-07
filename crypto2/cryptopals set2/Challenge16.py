from Challenge10 import aes_cbc_encrypt, aes_cbc_decrypt
from Crypto import Random
from Crypto.Cipher import AES


class Oracle:

    def __init__(self):
        self._key = Random.new().read(AES.key_size[0])
        self._iv = Random.new().read(AES.block_size)
        self._prefix = "comment1=cooking%20MCs;userdata="
        self._suffix = ";comment2=%20like%20a%20pound%20of%20bacon"

    # 实现加密函数，添加前缀和后缀后，使用AES-128-CBC进行加密
    def encrypt(self, data):
        data = data.replace(';', '').replace('=', '')
        plaintext = (self._prefix + data + self._suffix).encode()
        return aes_cbc_encrypt(plaintext, self._key, self._iv)

    def decrypt(self, ciphertext):
        data = aes_cbc_decrypt(ciphertext, self._key, self._iv)
        return data

    # 实现解密函数，还会检查解密后的内容中是否有:admin = true;
    def decrypt_and_check_admin(self, ciphertext):
        data = aes_cbc_decrypt(ciphertext, self._key, self._iv)
        return b';admin=true;' in data


# 计算块长度。要找到一个块的长度，我们需要加密越来越长的明文，直到输出密文的大小也增加为止。
# 发生这种情况时，我们可以轻松地计算出块的长度，其值等于新的密文长度与其初始长度之间的差
def find_block_length(encryption_oracle):
    my_text = ''
    ciphertext = encryption_oracle(my_text)
    initial_len = len(ciphertext)
    new_len = initial_len

    while new_len == initial_len:
        my_text += 'A'
        ciphertext = encryption_oracle(my_text)
        new_len = len(ciphertext)

    return new_len - initial_len

#加密两个不同的明文字节，得到两个不同的密文，
# 计算两个密文间相同的长度，赋给common_length,确保其为块长度的整数倍。
def find_prefix_length(encryption_oracle, block_length):
    ciphertext_a = encryption_oracle('A')
    ciphertext_b = encryption_oracle('B')
    common_len = 0
    while ciphertext_a[common_len] == ciphertext_b[common_len]:
        common_len += 1
    common_len = int(common_len / block_length) * block_length
    #从1开始将越来越多的相同字节添加到明文中，分别加密，比较两个密文，直到它们有一个额外的相同块为止。
    # 如果找到了，这意味着通过添加i个字节，我们可以控制相同的输入（包括前缀）为块大小的整数倍，这样我们就可以得到前缀的长度了。
    for i in range(1, block_length + 1):
        ciphertext_a = encryption_oracle('A' * i + 'X')
        ciphertext_b = encryption_oracle('A' * i + 'Y')
        if ciphertext_a[common_len:common_len + block_length] == ciphertext_b[common_len:common_len + block_length]:
            return common_len + (block_length - i)


def cbc_bit_flip(encryption_oracle):
    #获得块长度
    block_length = find_block_length(encryption_oracle.encrypt)
    #获得前缀长度
    prefix_length = find_prefix_length(encryption_oracle.encrypt, block_length)
    #计算需要添加多少字节到前缀，才能使得其长度为块长度整数倍
    additional_prefix_bytes = (block_length - (prefix_length % block_length)) % block_length
    total_prefix_length = prefix_length + additional_prefix_bytes
    plaintext = "?admin?true"
    #接着计算要添加多少字节到明文才能使得其长度为块长度整数倍
    additional_plaintext_bytes = (block_length - (len(plaintext) % block_length)) % block_length
    #然后将明文加长1个块长度（用?填充），对其加密。
    final_plaintext = additional_plaintext_bytes * '?' + plaintext
    #使用异或的方法，我们可以通过更改明文之前的块的字节来生成所需的字节。
    ciphertext = encryption_oracle.encrypt(additional_prefix_bytes * '?' + final_plaintext)
    semicolon = ciphertext[total_prefix_length - 11] ^ ord('?') ^ ord(';')
    equals = ciphertext[total_prefix_length - 5] ^ ord('?') ^ ord('=')
    #最后将伪造的密文片段放在一起，组成完整的密文
    forced_ciphertext = ciphertext[:total_prefix_length - 11] + bytes([semicolon]) + \
                        ciphertext[total_prefix_length - 10: total_prefix_length - 5] + \
                        bytes([equals]) + ciphertext[total_prefix_length - 4:]

    return forced_ciphertext


def main():
    encryption_oracle = Oracle()
    forced_ciphertext = cbc_bit_flip(encryption_oracle)
    print(encryption_oracle.decrypt(forced_ciphertext))


if __name__ == '__main__':
    main()




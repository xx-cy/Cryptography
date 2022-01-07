import base64
from Challenge10 import aes_ecb_encrypt
from Challenge9 import pkcs7_unpad
import random
from Crypto import Random
from Challenge12 import count_aes_ecb_repetitions, find_length, ECBOracle


class HarderECBOracle(ECBOracle):

    def __init__(self, secret_padding):
        super(HarderECBOracle, self).__init__(secret_padding)
        self._random_prefix = Random.new().read(random.randint(0, 255))

    def encrypt(self, data):
        # 加密函数加密的内容就是随机前缀+可控字符串+未知字符串
        return aes_ecb_encrypt(self._random_prefix + data + self._secret_padding, self._key)


# 找到target-byte的一个字节。填充length_to_use个a，保证将块的最后一个字符设置为target-byte的第一个字符。
def get_next_byte(prefix_length, block_length, curr_decrypted_message, encryption_oracle):
    length_to_use = (block_length - prefix_length - (1 + len(curr_decrypted_message))) % block_length
    my_input = b'A' * length_to_use
    cracking_length = prefix_length + length_to_use + len(curr_decrypted_message) + 1
    real_ciphertext = encryption_oracle.encrypt(my_input)
    for i in range(256):
        fake_ciphertext = encryption_oracle.encrypt(my_input + curr_decrypted_message + bytes([i]))
        if fake_ciphertext[:cracking_length] == real_ciphertext[:cracking_length]:
            return bytes([i])
    return b''


def has_equal_block(ciphertext, block_length):
    for i in range(0, len(ciphertext) - 1, block_length):
        if ciphertext[i:i + block_length] == ciphertext[i + block_length:i + 2 * block_length]:
            return True

    return False


# 首先分别加密空消息和一个字符的消息，得到两个密文。比较这两个密文，
# 第一个不同的块就是前缀结束的块。然后需要精确定位是在前缀是在哪个位置结束的。
def find_prefix_length(encryption_oracle, block_length):
    ciphertext1 = encryption_oracle.encrypt(b'')
    ciphertext2 = encryption_oracle.encrypt(b'a')
    prefix_length = 0
    for i in range(0, len(ciphertext2), block_length):
        if ciphertext1[i:i + block_length] != ciphertext2[i:i + block_length]:
            prefix_length = i
            break
    # 加密“两个块长度+一个随机增量”长度大小的相同的字节，如果字节数足够了（在密文中找到了两个连续的相同块），我们就可以精确计算前缀在其最后一个块中结束的位置。
    # 其在最后一块中结束的位置为块长度-i
    for i in range(block_length):
        fake_input = bytes([0] * (2 * block_length + i))
        ciphertext = encryption_oracle.encrypt(fake_input)
        if has_equal_block(ciphertext, block_length):
            return prefix_length + block_length - i if i != 0 else prefix_length

    raise Exception('The oracle is not using ECB')


def byte_at_a_time_ecb_decryption_harder(encryption_oracle):
    block_length = find_length(encryption_oracle)
    ciphertext = encryption_oracle.encrypt(bytes([0] * 64))
    assert count_aes_ecb_repetitions(ciphertext) > 0
    prefix_length = find_prefix_length(encryption_oracle, block_length)
    mysterious_text_length = len(encryption_oracle.encrypt(b'')) - prefix_length
    secret_padding = b''
    for i in range(mysterious_text_length):
        secret_padding += get_next_byte(prefix_length, block_length, secret_padding, encryption_oracle)
    return secret_padding


def main():
    secret_padding = base64.b64decode("Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGF"
                                      "pciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IH"
                                      "RvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK")
    print(secret_padding)
    oracle = HarderECBOracle(secret_padding)
    discovered_secret_padding = byte_at_a_time_ecb_decryption_harder(oracle)
    print(pkcs7_unpad(discovered_secret_padding))


if __name__ == '__main__':
    main()




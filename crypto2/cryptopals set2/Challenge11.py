from Challenge10 import aes_ecb_encrypt, aes_cbc_encrypt
from random import randint
from Crypto.Cipher.AES import block_size
from Crypto import Random


def pad_bytes(bin_data):
    return Random.new().read(randint(5, 10))


def encrypt(plaintext):
    padded_plaintext = pad_bytes(plaintext)
    key = Random.new().read(block_size)
    if randint(0, 1) == 0:
        return "ECB", aes_ecb_encrypt(padded_plaintext, key)
    else:
        return "CBC", aes_cbc_encrypt(padded_plaintext, key, Random.new().read(block_size))


def main():
    input_data = input("请输入要加密的内容")
    input_data_bytes = input_data.encode()
    encryption_used, ciphertext = encrypt(input_data_bytes)
    print(encryption_used, ciphertext)


if __name__ == '__main__':
    main()

import base64
from Crypto.Cipher import AES
from Challenge9 import pkcs7_pad, pkcs7_unpad


def aes_ecb_decrypt(data, key):
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.decrypt(data)


def aes_ecb_encrypt(data, key):
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(pkcs7_pad(data, AES.block_size))


def xor_data(bin_data_1, bin_data_2):
    return bytes([b1 ^ b2 for b1, b2 in zip(bin_data_1, bin_data_2)])


def aes_cbc_encrypt(data, key, iv):
    ciphertext = b''
    prev = iv
    for i in range(0, len(data), AES.block_size):
        curr_plaintext_block = pkcs7_pad(data[i:i + AES.block_size], AES.block_size)
        block_cipher_input = xor_data(curr_plaintext_block, prev)
        encrypted_block = aes_ecb_encrypt(block_cipher_input, key)
        ciphertext += encrypted_block
        prev = encrypted_block
    return ciphertext


def aes_cbc_decrypt(data, key, iv, unpad=True):
    plaintext = b''
    prev = iv
    for i in range(0, len(data), AES.block_size):
        curr_ciphertext_block = data[i:i + AES.block_size]
        decrypted_block = aes_ecb_decrypt(curr_ciphertext_block, key)
        plaintext += xor_data(prev, decrypted_block)
        prev = curr_ciphertext_block
    return pkcs7_unpad(plaintext) if unpad else plaintext


def main():
    iv = b'\x00' * AES.block_size
    key = b'YELLOW SUBMARINE'
    with open("ch10.txt") as file:
        bin_data = base64.b64decode(file.read())
    print(aes_cbc_decrypt(bin_data, key, iv).decode().rstrip())


if __name__ == '__main__':
    main()

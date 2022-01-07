import base64
from Challenge10 import aes_ecb_encrypt
from Challenge9 import pkcs7_unpad
from Crypto import Random
from Crypto.Cipher import AES
from Crypto.Cipher.AES import block_size


class ECBOracle:
    def __init__(self, secret_padding):
        self._key = Random.new().read(AES.key_size[0])
        self._secret_padding = secret_padding

    def encrypt(self, data):
        return aes_ecb_encrypt(data + self._secret_padding, self._key)


def count_aes_ecb_repetitions(ciphertext):
    chunks = [ciphertext[i:i + block_size] for i in range(0, len(ciphertext), block_size)]
    number_of_duplicates = len(chunks) - len(set(chunks))
    return number_of_duplicates


def find_length(encryption_oracle):
    text = b''
    ciphertext = encryption_oracle.encrypt(text)
    initial_length = len(ciphertext)
    new_length = initial_length
    while new_length == initial_length:
        text += b'A'
        ciphertext = encryption_oracle.encrypt(text)
        new_length = len(ciphertext)
    return new_length - initial_length


def get_next_byte(block_length, curr_decrypted_message, encryption_oracle):
    length_to_use = (block_length - (1 + len(curr_decrypted_message))) % block_length
    prefix = b'A' * length_to_use
    cracking_length = length_to_use + len(curr_decrypted_message) + 1
    real_ciphertext = encryption_oracle.encrypt(prefix)
    for i in range(256):
        test_ciphertext = encryption_oracle.encrypt(prefix + curr_decrypted_message + bytes([i]))
        if test_ciphertext[:cracking_length] == real_ciphertext[:cracking_length]:
            return bytes([i])
    return b''


def byte_ecb_decryption(encryption_oracle):
    block_length = find_length(encryption_oracle)
    ciphertext = encryption_oracle.encrypt(bytes([0] * 64))
    assert count_aes_ecb_repetitions(ciphertext) > 0
    mysterious_text_length = len(encryption_oracle.encrypt(b''))
    secret_padding = b''
    for i in range(mysterious_text_length):
        secret_padding += get_next_byte(block_length, secret_padding, encryption_oracle)
    return secret_padding


def main():
    secret_padding = base64.b64decode("Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGF"
                                      "pciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IH"
                                      "RvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK")
    print(secret_padding)
    oracle = ECBOracle(secret_padding)
    discovered_secret_padding = byte_ecb_decryption(oracle)

    print(pkcs7_unpad(discovered_secret_padding))


if __name__ == '__main__':
    main()

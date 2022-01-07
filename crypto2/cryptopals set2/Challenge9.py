def pkcs7_pad(plaintext, block_size):
    if len(plaintext) == block_size:
        return plaintext
    ch = block_size - len(plaintext) % block_size
    return plaintext + bytes([ch] * ch)


def is_pkcs7_padded(bin_data):
    padding = bin_data[-bin_data[-1]:]
    return all(padding[b] == len(padding) for b in range(0, len(padding)))


def pkcs7_unpad(data):
    if not is_pkcs7_padded(data):
        return data
    padding_len = data[len(data) - 1]
    return data[:-padding_len]


def main():
    message = b"YELLOW SUBMARINE"
    b = pkcs7_pad(message, 20)
    print(b)


if __name__ == "__main__":
    main()

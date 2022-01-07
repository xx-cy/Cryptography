def is_pkcs7_padded(bin_data):
    padding = bin_data[-bin_data[-1]:]
    return all(padding[b] == len(padding) for b in range(0, len(padding)))


def pkcs7_unpad(data):
    if not is_pkcs7_padded(data):
        return data
    padding_len = data[len(data) - 1]
    return data[:-padding_len]


def main():
    assert is_pkcs7_padded(b'ICE ICE BABY\x04\x04\x04\x04') is True
    print(pkcs7_unpad(b'ICE ICE BABY\x04\x04\x04\x04'))
    assert is_pkcs7_padded(b'ICE ICE BABY\x05\x05\x05\x05') is False
    assert is_pkcs7_padded(b'ICE ICE BABY\x01\x02\x03\x04') is False
    assert is_pkcs7_padded(b'ICE ICE BABY') is False


if __name__ == '__main__':
    main()




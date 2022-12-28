# representations: bytes, hex (str), base64 (str)
# bytes->hex (str): (bytes_here).hex()
# bytes->base64(str): TODO
# hex->bytes: bytes.fromhex(...)
# hex->base64:same as hex->bytes->base64
# base64->bytes: TODO
# base64->hex: same as base64->bytes->hex

def bytes_to_base64(input_bytes: bytes) -> str:
    from base64 import b64encode
    b64_bytes = b64encode(input_bytes)
    return b64_bytes.decode('ascii')

def base64_to_bytes(input_base64: str) -> bytes:
    from base64 import b64decode
    b64_bytes = input_base64.encode('ascii')
    return b64decode(b64_bytes)

# Challenge 1
def hex_to_base64(input_hex: str) -> str:
    input_bytes = bytes.fromhex(input_hex)
    return bytes_to_base64(input_bytes)

def base64_to_hex(input_base64: str) -> str:
    input_bytes = base64_to_bytes(input_base64)
    return input_bytes.hex()

# xor two bytes, return bytes of xor
def xor_bytes(bytes1: bytes|bytearray, bytes2: bytes|bytearray) -> bytes:
    if len(bytes1) != len(bytes2):
        raise ValueError("Cannot xor unequal length bytes")
    xor_array = [b1^b2 for b1, b2 in zip(bytes1, bytes2)]
    return bytes(xor_array)

# xor two hex strings, return xor hex string
# Challenge 2
def xor_hex(hex1: str, hex2: str) -> str:
    bytes1 = bytes.fromhex(hex1)
    bytes2 = bytes.fromhex(hex2)
    return xor_bytes(bytes1, bytes2).hex()

# Challenge 5
def repeating_key_xor(plaintext: bytes, key: bytes) -> bytes:
    plaintext_len = len(plaintext)
    key_len = len(key)
    key_repeated = bytes()
    if plaintext_len%key_len == 0:
        key_repeated = key*(plaintext_len//key_len)
    else:
        key_repeated = key*((plaintext_len//key_len)+1)
        key_repeated = key_repeated[:plaintext_len]
    return xor_bytes(plaintext, key_repeated)

def hamming_distance(bytes1: bytes, bytes2: bytes) -> int:
    if len(bytes1) != len(bytes2):
        raise ValueError("Cannot compute hamming distance of unequal length bytes")
    return sum(list(map(
        int.bit_count,
        xor_bytes(bytes1, bytes2)
    )))

def pad_pkcs7(text: bytes, block_size: int) -> bytes:
    n_pad = block_size-(len(text)%block_size)
    if n_pad == 0:
        n_pad = block_size
    padded_text = bytearray(text)
    for _ in range(n_pad):
        padded_text.append(n_pad)
    return bytes(padded_text)

# Detect if text has pkcs7 padding. If it does, return text without padding
def strip_pkcs7(text: bytes, block_size: int) -> bytes:
    error = ValueError("Bad PKCS7 padding")
    if len(text)%block_size != 0:
        raise error
    last_byte = text[-1]
    # padding is always with 0x01 through 0x10. Second condition implies
    # not enough room in text for padding
    if last_byte > block_size or last_byte > len(text) or last_byte == 0:
        raise error
    for i in range(1, last_byte+1):
        if text[-i] != last_byte:
            raise error
    return text[:-last_byte]

def decrypt_aes_ecb(ciphertext: bytes, key: bytes) -> bytes:
    from Crypto.Cipher import AES
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.decrypt(ciphertext)

def encrypt_aes_ecb(plaintext: bytes, key: bytes, add_padding: bool = True) -> bytes:
    from Crypto.Cipher import AES
    if add_padding:
        plaintext = pad_pkcs7(plaintext, 16)
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(plaintext)

def detect_AES_128_ECB(ciphertext: bytes) -> bool:
    if len(ciphertext)%16 != 0:
        raise ValueError("Number of bytes must be multiple of 16")
    n_blocks = len(ciphertext)//16
    seen_blocks = set()
    for i in range(n_blocks):
        block = ciphertext[16*i:16*(i+1)]
        if block in seen_blocks:
            return True
        seen_blocks.add(block)
    return False
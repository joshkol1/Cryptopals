# from Utility.Set1Util import xor_bytes, encrypt_aes_ecb, decrypt_aes_ecb
import Utility.Set1Util as Set1Util

def encrypt_aes_cbc(plaintext: bytes, key: bytes, iv: bytes) -> bytes:
    plaintext = Set1Util.pad_pkcs7(plaintext, len(iv))
    n_blocks = len(plaintext)//len(iv)
    block_size = len(iv)
    ciphertext = bytearray()
    for i in range(n_blocks):
        block = plaintext[block_size*i:block_size*(i+1)]
        block_xor = Set1Util.xor_bytes(block, iv)
        encrypted_block = Set1Util.encrypt_aes_ecb(block_xor, key, False)
        ciphertext += encrypted_block
        iv = encrypted_block
    return bytes(ciphertext)

def decrypt_aes_cbc(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
    if len(ciphertext)%len(iv) != 0:
        raise ValueError("Number of bytes must be a multiple of IV length")
    n_blocks = len(ciphertext)//len(iv)
    block_size = len(iv)
    plaintext = bytearray()
    for i in range(n_blocks):
        block = ciphertext[block_size*i:block_size*(i+1)]
        block_xor = Set1Util.decrypt_aes_ecb(block, key)
        plaintext_block = Set1Util.xor_bytes(block_xor, iv)
        plaintext += plaintext_block
        iv = ciphertext[block_size*i:block_size*(i+1)]
    return bytes(plaintext)

# Generate "block_size" random bytes
def get_random_bytes(block_size: int = 16) -> bytes:
    from secrets import token_bytes
    return token_bytes(block_size)

def block_at_index(text: bytes, index: int, block_size: int) -> bytes:
    return text[block_size*index:block_size*(index+1)]
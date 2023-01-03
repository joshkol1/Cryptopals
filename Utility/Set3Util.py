import Utility.Set1Util as Set1Util
import Utility.Set2Util as Set2Util

def encrypt_aes_ctr(plaintext: bytes, key: bytes, nonce: int) -> bytes:
    counter = 0
    nonce_bytes = nonce.to_bytes(8, 'little', signed=False)
    n_blocks = len(plaintext)//16 if len(plaintext)%16 == 0 else len(plaintext)//16+1
    ciphertext = bytearray()
    for i in range(n_blocks):
        input = nonce_bytes + counter.to_bytes(8, 'little', signed=False)
        aes_output = Set1Util.encrypt_aes_ecb(input, key, False)
        cutoff = len(plaintext)%16 if i == n_blocks-1 else 16
        if cutoff <= 0:
            cutoff += 16
        ciphertext += Set1Util.xor_bytes(
            aes_output[:cutoff], 
            Set2Util.block_at_index(plaintext, i, 16)
        )
        counter += 1
    return bytes(ciphertext)

def decrypt_aes_ctr(plaintext: bytes, key: bytes, nonce: int) -> bytes:
    return encrypt_aes_ctr(plaintext, key, nonce)
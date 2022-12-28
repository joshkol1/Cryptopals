import Utility.Set1Util as Set1Util
import Utility.Set2Util as Set2Util
import random
from typing import Tuple

random_key = Set2Util.get_random_bytes()

plaintexts = [
    "MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=",
    "MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=",
    "MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==",
    "MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==",
    "MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl",
    "MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==",
    "MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==",
    "MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=",
    "MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=",
    "MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93"
]

def ch17_encrypt() -> Tuple[bytes, bytes]:
    index = random.randint(0, len(plaintexts)-1)
    plaintext_bytes = Set1Util.base64_to_bytes(plaintexts[index])
    iv = Set2Util.get_random_bytes()
    return Set2Util.encrypt_aes_cbc(plaintext_bytes, random_key, iv), iv

def has_valid_padding(ciphertext: bytes, iv: bytes) -> bool:
    plaintext_padded = Set2Util.decrypt_aes_cbc(ciphertext, random_key, iv)
    try:
        _ = Set1Util.strip_pkcs7(plaintext_padded, 16)
        return True
    except ValueError:
        return False

def padding_oracle_attack() -> bytes:
    # We know the IV and ciphertext, but not the key
    plaintext = bytearray()
    ciphertext, encryption_iv = ch17_encrypt()
    n_blocks = len(ciphertext)//16
    for block_index in range(n_blocks):
        ctext_block = Set2Util.block_at_index(ciphertext, block_index, 16)
        # need to figure out bits back to front
        zero_iv = bytearray(16)
        for i in range(15, -1, -1):
            base_iv = bytearray(zero_iv)
            for j in range(15, i, -1):
                # i=14 -> 0x02, i=13 -> 0x03, ..., i=0 -> 0x10
                base_iv[j] ^= (16-i)
            for j in range(256):
                base_iv[i] = j
                if not has_valid_padding(ctext_block, base_iv):
                    continue
                if i == 15:
                    base_iv[14] ^= 0xff
                    if not has_valid_padding(ctext_block, base_iv):
                        continue
                zero_iv[i] = j^(16-i)
                break
        plaintext += Set1Util.xor_bytes(zero_iv, encryption_iv)
        encryption_iv = bytes(ctext_block)
    return bytes(plaintext)

def main():
    plaintext_set = set([
        Set1Util.pad_pkcs7(Set1Util.base64_to_bytes(b64_text), 16)
    for b64_text in plaintexts])
    for _ in range(100):
        attack_plaintext = padding_oracle_attack()
        if attack_plaintext not in plaintext_set:
            print("Failure")
            break
    print("Success")
    return 0

if __name__ == "__main__":
    main()
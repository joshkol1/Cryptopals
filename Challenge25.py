import Utility.Set1Util as Set1Util
import Utility.Set2Util as Set2Util
import Utility.Set3Util as Set3Util
import random

random_ctr_key = Set2Util.get_random_bytes()

def get_file_plaintext() -> bytes:
    f = open("25.txt")
    b64_encoded = ""
    for line in f:
        b64_encoded += line
    ciphertext_bytes = Set1Util.base64_to_bytes(b64_encoded)
    return Set1Util.decrypt_aes_ecb(ciphertext_bytes, b'YELLOW SUBMARINE')

# replace plaintext with "new_text", starting at index "offset".
# return above encrypted under ctr with same key
def edit_text(ciphertext: bytes, key: bytes, offset: int, new_text: bytes) -> bytes:
    plaintext = Set3Util.decrypt_aes_ctr(ciphertext, key, 0)
    plaintext = plaintext[:offset] + new_text + plaintext[offset+len(new_text):]
    return Set3Util.encrypt_aes_ctr(plaintext, key, 0)

def edit_api(ciphertext: bytes, offset: int, new_text: bytes) -> bytes:
    return edit_text(ciphertext, random_ctr_key, offset, new_text)

# recover without the key, by using edit_api calls
def recover_plaintext(ciphertext: bytes) -> bytes:
    new_ciphertext = edit_api(ciphertext, 0, bytes(len(ciphertext)))
    return Set1Util.xor_bytes(ciphertext, new_ciphertext)

def main():
    ciphertext = Set3Util.encrypt_aes_ctr(get_file_plaintext(), random_ctr_key, 0)
    attack_plaintext = recover_plaintext(ciphertext)
    true_plaintext = Set3Util.decrypt_aes_ctr(ciphertext, random_ctr_key, 0)
    if attack_plaintext == true_plaintext:
        print("Plaintext recovered")
    return 0

if __name__ == "__main__":
    main()
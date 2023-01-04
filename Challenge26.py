import Utility.Set1Util as Set1Util
import Utility.Set2Util as Set2Util
import Utility.Set3Util as Set3Util
import re

prefix = "comment1=cooking MCs;userdata="
suffix = ";comment2= like a pound of bacon"

random_ctr_key = Set2Util.get_random_bytes()

def ch26_encode_string(user_data: str) -> bytes:
    user_data = re.sub(r'[;=]', "", user_data)
    plaintext = prefix+user_data+suffix
    return Set3Util.encrypt_aes_ctr(plaintext.encode('utf-8'), random_ctr_key, 0)

def ch26_contains_admin(encrypted: bytes) -> bool:
    decrypted = Set3Util.decrypt_aes_ctr(encrypted, random_ctr_key, 0)
    tokens = decrypted.split(b';')
    for token in tokens:
        token_split = token.split(b'=')
        if token_split[0] == b'admin' and token_split[1] == b'true':
            return True
    return False

def ch26_admin_ciphertext() -> bytes:
    ciphertext = bytearray(ch26_encode_string("\x00"*len(";admin=true")))
    admin_block = ciphertext[len(prefix):len(prefix)+len(";admin=true")]
    new_block = Set1Util.xor_bytes(admin_block, b';admin=true')
    ciphertext[len(prefix):len(prefix)+len(";admin=true")] = new_block
    return bytes(ciphertext)

def main():
    admin_ciphertext = ch26_admin_ciphertext()
    if ch26_contains_admin(admin_ciphertext):
        print("Admin token generated")
    return 0

if __name__ == "__main__":
    main()
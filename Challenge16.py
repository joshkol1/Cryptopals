import Utility.Set1Util as Set1Util
import Utility.Set2Util as Set2Util
import re

prefix = "comment1=cooking MCs;userdata="
suffix = ";comment2= like a pound of bacon"

random_key = Set2Util.get_random_bytes()
random_iv = Set2Util.get_random_bytes()

def ch16_encode_string(user_data: str) -> bytes:
    user_data = re.sub(r'[;=]', "", user_data)
    plaintext = prefix+user_data+suffix
    return Set2Util.encrypt_aes_cbc(plaintext.encode('utf-8'), random_key, random_iv)

def ch16_contains_admin(encrypted: bytes) -> bool:
    decrypted = Set2Util.decrypt_aes_cbc(encrypted, random_key, random_iv)
    print(decrypted)
    tokens = decrypted.split(b';')
    for token in tokens:
        token_split = token.split(b'=')
        if token_split[0] == b'admin' and token_split[1] == b'true':
            return True
    return False

def get_admin_ciphertext() -> bytes:
    prefix_length = len(prefix)
    trailing = 16-(prefix_length%16) if prefix_length%16 != 0 else 0
    zero_index = prefix_length//16+1 if prefix_length%16 != 0 else prefix_length//16
    ciphertext = ch16_encode_string("\x00"*(32+trailing))
    first_zero_block = Set2Util.block_at_index(ciphertext, zero_index, 16)
    new_first_block = Set1Util.xor_bytes(first_zero_block, b';admin=true;'+bytes([0]*4))
    admin_ciphertext = bytearray(ciphertext)
    admin_ciphertext[16*zero_index:16*(zero_index+1)] = new_first_block
    return bytes(admin_ciphertext)

def main():
    admin_ciphertext = get_admin_ciphertext()
    print(ch16_contains_admin(admin_ciphertext))
    return 0

if __name__ == "__main__":
    main()
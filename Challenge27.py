import Utility.Set1Util as Set1Util
import Utility.Set2Util as Set2Util
import re

prefix = "comment1=cooking MCs;userdata="
suffix = ";comment2= like a pound of bacon"

# use key as iv too
random_key = Set2Util.get_random_bytes()

def ch27_encode_string(user_data: str) -> bytes:
    user_data = re.sub(r'[;=]', "", user_data)
    for c in user_data:
        if ord(c) > 127:
            raise ValueError("User data not ascii compliant")
    plaintext = prefix+user_data+suffix
    return Set2Util.encrypt_aes_cbc(plaintext.encode('utf-8'), random_key, random_key)

def ch16_contains_admin(encrypted: bytes) -> bool:
    decrypted = Set2Util.decrypt_aes_cbc(encrypted, random_key, random_key)
    for c in decrypted:
        if c > 127:
            raise ValueError("Plaintext not complaint with ascii: {}".format(decrypted.decode("ISO-8859-1")))
    tokens = decrypted.split(b';')
    for token in tokens:
        token_split = token.split(b'=')
        if token_split[0] == b'admin' and token_split[1] == b'true':
            return True
    return False

def recover_key() -> bytes:
    encoded_bytes = ch27_encode_string("")
    first_block = Set2Util.block_at_index(encoded_bytes, 0, 16)
    atk_ciphertext = first_block + bytes(16) + first_block
    try:
        ch16_contains_admin(atk_ciphertext)
        return -1
    except ValueError as e:
        error_message = e.args[0]
        search_index = error_message.index("comment1=cooking")
        vuln_bytes = error_message.encode("ISO-8859-1")[search_index:]
        return Set1Util.xor_bytes(vuln_bytes[:16], vuln_bytes[-16:])

def main():
    key = recover_key()
    if key == random_key:
        print("Key recovered")
    return 0

if __name__ == "__main__":
    main()
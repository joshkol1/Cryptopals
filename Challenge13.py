import Utility.Set1Util as Set1Util
import Utility.Set2Util as Set2Util
import re
from dataclasses import dataclass
from typing import Tuple

global_key = Set2Util.get_random_bytes()

@dataclass
class UserProfile:
    email: str = ""
    uid: int = 10
    role: str = "user"

def kv_to_profile(kv_encoding: str) -> UserProfile:
    tokens = kv_encoding.split("&")
    profile = UserProfile()
    for token in tokens:
        token_split = token.split("=")
        field_value = token_split[1]
        match token_split[0]:
            case "email":
                profile.email = field_value
            case "uid":
                profile.uid = int(field_value)
            case "role":
                profile.role = field_value
    return profile

def profile_to_kv(profile: UserProfile) -> str:
    return "email={}&uid={}&role={}".format(profile.email, profile.uid, profile.role)

def profile_for(email: str) -> UserProfile:
    email = re.sub(r'[&=]', "", email)
    return UserProfile(email, 10, "user")

def encrypt_profile(profile: UserProfile, key: bytes) -> bytes:
    kv_string = profile_to_kv(profile)
    return Set1Util.encrypt_aes_ecb(kv_string.encode(), key)

def decrypt_profile(encrypted_profile: bytes, key: bytes) -> UserProfile:
    decrypted = Set1Util.decrypt_aes_ecb(encrypted_profile, key)
    decrypted = Set1Util.strip_pkcs7(decrypted, 16)
    kv_string = decrypted.decode('utf-8')
    return kv_to_profile(kv_string)

# Goal: generate ciphertext which, when decoded, yields role=admin profile
def generate_admin_profile() -> bytes:
    prefix_length = len("email=&uid=10&role=")
    email_length = 16-(prefix_length%16) if prefix_length%16 != 0 else 16
    email = "A"*email_length
    encoded_prefix = encrypt_profile(profile_for(email), global_key)
    encoded_prefix = encoded_prefix[:-16] # cut off encoded pkcs7 padding
    suffix_payload = "AAAAAAAAAAadmin" + "\x0b"*11
    encoded_suffix = encrypt_profile(profile_for(suffix_payload), global_key)[16:32]
    admin_profile_encrypted = encoded_prefix + encoded_suffix
    return admin_profile_encrypted

def main():
    admin_profile_encrypted = generate_admin_profile()
    admin_profile = decrypt_profile(admin_profile_encrypted, global_key)
    print(admin_profile)
    return 0

if __name__ == "__main__":
    main()
import Utility.Set1Util as Set1Util
import Utility.Set2Util as Set2Util
import random
from typing import Tuple, Callable

# randomly encrypt under ECB or CBC with equal chance
def encryption_oracle(text: bytes) -> Tuple[bytes, int]:
    prefix_length = random.randint(5, 10)
    suffix_length = random.randint(5, 10)
    prefix = Set2Util.get_random_bytes(prefix_length)
    suffix = Set2Util.get_random_bytes(suffix_length)
    text = prefix + text + suffix
    text = Set2Util.pad_pkcs7(text, 16)
    aes_key = Set2Util.get_random_bytes(16)
    encryption_mode = random.randint(0, 1) # 0 is ECB, 1 is CBC
    if encryption_mode == 0:
        return Set1Util.encrypt_aes_ecb(text, aes_key), 0
    else:
        random_iv = Set2Util.get_random_bytes(16)
        return Set2Util.encrypt_aes_cbc(text, aes_key, random_iv), 1

# return 0 if using ECB, 1 if using CBC
def detection_oracle(
    aes_encryption_oracle: Callable[[bytes], Tuple[bytes, ...]]
) -> int:
    # idea: if using ECB, same ciphertext block will encrypt to same thing
    # --> feed in many repeated blocks, if CBC then very low chance of collision
    plaintext = bytes([0x41]*100)
    ciphertext, _ = aes_encryption_oracle(plaintext)
    detected_encryption_mode = 1
    if Set1Util.detect_AES_128_ECB(ciphertext):
        detected_encryption_mode = 0
    return detected_encryption_mode

def main():
    return 0

if __name__ == "__main__":
    main()
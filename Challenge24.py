from Utility.MersenneTwister import MT19937
import Utility.Set1Util as Set1Util
import Utility.Set2Util as Set2Util
import Utility.Set3Util as Set3Util
import random
from typing import Tuple
import time

def mt_stream_encrypt(plaintext: bytes, seed: int) -> bytes:
    rng = MT19937(seed)
    keystream = bytearray()
    while len(keystream) < len(plaintext):
        word = rng.get()
        keystream += bytes([
            (word&0xFF000000)>>24,
            (word&0xFF0000)>>16,
            (word&0xFF00)>>8,
            word&0xFF
        ])
    keystream = keystream[:len(plaintext)]
    return Set1Util.xor_bytes(plaintext, keystream)

def mt_stream_decrypt(ciphertext: bytes, seed: int) -> bytes:
    return mt_stream_encrypt(ciphertext, seed)

# return MT stream encrypted bytes and 16-bit seed
def get_ciphertext() -> Tuple[bytes, int]:
    random_prefix = Set2Util.get_random_bytes(random.randint(10, 20))
    seed = random.randint(1, 0x10000)
    return mt_stream_encrypt(random_prefix+b'AAAAAAAAAAAAAA', seed), seed

def find_key(ciphertext: bytes) -> int:
    for seed in range(1, 0x10000):
        plaintext = mt_stream_decrypt(ciphertext, seed)
        if plaintext.endswith(b'AAAAAAAAAAAAAA'):
            return seed
    return -1

def get_reset_token() -> Tuple[bytes, int]:
    random_prefix = Set2Util.get_random_bytes(random.randint(10, 20))
    random_suffix = Set2Util.get_random_bytes(random.randint(10, 20))
    tstamp = Set3Util.get_timestamp()
    return mt_stream_encrypt(random_prefix+b'reset'+random_suffix, tstamp), tstamp

def was_time_seeded(encrypted_token: bytes) -> Tuple[bool, int]:
    current_time = Set3Util.get_timestamp()
    for tstamp in range(current_time, current_time-1000, -1):
        potential_token = mt_stream_decrypt(encrypted_token, tstamp)
        if b'reset' in potential_token:
            return True, tstamp
    return False, -1

def main():
    ciphertext, seed = get_ciphertext()
    seed_guess = find_key(ciphertext)
    if seed_guess == seed:
        print("16-bit seed recovered")
    token, tstamp = get_reset_token()
    time.sleep(10)
    was_seeded, guess_tstamp = was_time_seeded(token)
    if was_seeded and tstamp == guess_tstamp:
        print("Timestamp seed recovered")
    return 0

if __name__ == "__main__":
    main()
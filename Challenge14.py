import Utility.Set1Util as Set1Util
import Utility.Set2Util as Set2Util
import random
from typing import Tuple

random_key = Set2Util.get_random_bytes()
random_prefix = Set2Util.get_random_bytes(random.randint(1, 100))

base64_suffix = (
    "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg"
    "aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq"
    "dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg"
    "YnkK"
)

# ecb(random_prefix || plaintext || suffix, random_key)
def ch14_ecb_encryptor(plaintext: bytes) -> bytes:
    decoded_suffix = Set1Util.base64_to_bytes(base64_suffix)
    plaintext = random_prefix + plaintext + decoded_suffix
    return Set1Util.encrypt_aes_ecb(plaintext, random_key)

def get_length_info() -> Tuple[int, int]:
    previous_length = -1
    prefix_suffix_length = -1
    block_size = -1
    for null_bytes in range(200):
        payload = bytes(null_bytes)
        ciphertext = ch14_ecb_encryptor(payload)
        if previous_length >= 0 and len(ciphertext) != previous_length:
            block_size = len(ciphertext)-previous_length
            prefix_suffix_length = previous_length-null_bytes
            break
        previous_length = len(ciphertext)
    return block_size, prefix_suffix_length

def get_zero_block_index(block_size: int) -> int:
    ctext_with_zeros = ch14_ecb_encryptor(bytes(3*block_size))
    n_blocks = len(ctext_with_zeros)//block_size
    zero_block_index = -1
    for i in range(n_blocks-1):
        first_block = Set2Util.block_at_index(
            ctext_with_zeros, i, block_size
        )
        second_block = Set2Util.block_at_index(
            ctext_with_zeros, i+1, block_size
        )
        if first_block == second_block:
            zero_block_index = i
            break
    return zero_block_index

# Same goal: get the suffix
def ch14_ecb_byte_cracker() -> bytes:
    # same technique as 12 to get prefix+suffix length
    block_size, prefix_suffix_length = get_length_info()
    # now need to find length of prefix. 
    zero_block_index = get_zero_block_index(block_size)
    match_block = Set2Util.block_at_index(
        ch14_ecb_encryptor(bytes(block_size)), zero_block_index-1, block_size
    )
    prefix_length = -1
    for null_bytes in range(block_size-1, 0, -1):
        ciphertext = ch14_ecb_encryptor(bytes(null_bytes))
        last_block = Set2Util.block_at_index(ciphertext, zero_block_index-1, block_size)
        if last_block != match_block:
            trailing = block_size-(null_bytes+1)
            prefix_length = trailing+block_size*(zero_block_index-1)
            break
    if prefix_length == -1:
        # two cases: prefix is 0 or block_size-1 mod block_size
        ciphertext = ch14_ecb_encryptor(bytes(block_size*2))
        first_block = Set2Util.block_at_index(
            ciphertext, zero_block_index, block_size
        )
        second_block = Set2Util.block_at_index(
            ciphertext, zero_block_index+1, block_size
        )
        if first_block == second_block:
            prefix_length = zero_block_index*block_size
        else:
            prefix_length = zero_block_index*block_size-1
    suffix_length = prefix_suffix_length-prefix_length
    # need to pad out the prefix and only look at blocks after that. 
    # same technique as challenge 12
    if prefix_length%block_size != 0:
        prefix_padding = bytes(block_size-(prefix_length%block_size))
        ignore_blocks = prefix_length//block_size+1
    else:
        prefix_padding = bytes()
        ignore_blocks = prefix_length//block_size
    discovered = bytearray()
    for i in range(suffix_length):
        block_index = i//block_size+ignore_blocks
        a_bytes = block_size-(i%block_size)-1
        payload = prefix_padding+bytes([0x41]*a_bytes)+discovered
        a_output = ch14_ecb_encryptor(prefix_padding+bytes([0x41]*a_bytes))
        a_block = Set2Util.block_at_index(a_output, block_index, block_size)
        for j in range(255):
            guess = payload + bytes([j])
            guess_output = ch14_ecb_encryptor(guess)
            guess_block = Set2Util.block_at_index(guess_output, block_index, block_size)
            if guess_block == a_block:
                discovered.append(j)
                break
    return bytes(discovered)

def main():
    suffix = ch14_ecb_byte_cracker()
    print(suffix.decode('utf-8'))
    return 0

if __name__ == "__main__":
    main()
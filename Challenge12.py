import Utility.Set1Util as Set1Util
import Utility.Set2Util as Set2Util

key = Set2Util.get_random_bytes()

base64_suffix = (
    "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg"
    "aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq"
    "dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg"
    "YnkK"
)

def ch12_ecb_encryptor(plaintext: bytes) -> bytes:
    decoded_suffix = Set1Util.base64_to_bytes(base64_suffix)
    plaintext += decoded_suffix
    return Set1Util.encrypt_aes_ecb(plaintext, key)

def ch12_ecb_byte_cracker() -> bytes:
    # figure out block size by feeding repeating blocks
    # jump in ciphertext size is block size, due to padding
    previous_length = -1
    suffix_length = -1
    block_size = -1
    for a_bytes in range(200):
        payload = bytes([0x41]*a_bytes)
        ciphertext = ch12_ecb_encryptor(payload)
        if previous_length >= 0 and len(ciphertext) != previous_length:
            block_size = len(ciphertext)-previous_length
            # previous_length must have 1 byte of padding
            # payload is size a_bytes-1 (previous payload)
            # thus suffix length is (previous_length-1)-(a_bytes-1)
            suffix_length = previous_length-a_bytes
            break
        previous_length = len(ciphertext)
    # make sure we detect ECB usage by feeding repeating blocks
    detect_ecb_ciphertext = ch12_ecb_encryptor(bytes([0x41]*200))
    assert Set1Util.detect_AES_128_ECB(detect_ecb_ciphertext)
    # TODO: crack ECB with payloads
    # we know unknown message length, this is equal to iterations required
    discovered = bytearray()
    for i in range(suffix_length):
        block_index = i//block_size
        a_bytes = block_size-(i%block_size)-1
        payload = bytes([0x41]*a_bytes)+discovered
        a_output = ch12_ecb_encryptor(bytes([0x41]*a_bytes))
        a_block = a_output[
            block_index*block_size:(block_index+1)*block_size
        ]
        for j in range(255):
            guess = payload+bytes([j])
            guess_output = ch12_ecb_encryptor(guess)
            guess_block = guess_output[
                block_index*block_size:(block_index+1)*block_size
            ]
            if guess_block == a_block:
                discovered.append(j)
                break
    return bytes(discovered)

def main():
    print(ch12_ecb_byte_cracker().decode('utf-8'))
    return 0

if __name__ == "__main__":
    main()
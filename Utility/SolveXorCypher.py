import Utility.Set1Util as Set1Util
import Utility.PlaintextScores as PlaintextScores
import math
from typing import Tuple
from typing import List

# Take in xor-encrypted string (must be valid hex string)
# Return plaintext, chi2 score, and key
def solveSingleCharacterXor(hex_ciphertext: str) -> Tuple[bytes, float, int]:
    ciphertext_bytes = bytes.fromhex(hex_ciphertext)
    n_bytes = len(ciphertext_bytes)
    min_chi2 = math.inf
    decrypted = bytes([0]*n_bytes)
    key = -1
    for i in range(256):
        key_bytes = bytes([i]*n_bytes)
        plaintext = Set1Util.xor_bytes(ciphertext_bytes, key_bytes)
        percent_letters = PlaintextScores.getAlphabetPercent(plaintext)
        if percent_letters >= 0.85:
            plaintext_chi2 = PlaintextScores.getChi2(plaintext)
            if plaintext_chi2 < min_chi2:
                min_chi2 = plaintext_chi2
                decrypted = plaintext
                key = i
    return decrypted, min_chi2, key

def chunkBytes(raw_bytes: bytes, chunk_size: int) -> List[bytes]:
    n_chunks = len(raw_bytes)//chunk_size
    return [raw_bytes[i*chunk_size:(i+1)*chunk_size] for i in range(n_chunks)]

def getBestBlockSize(
    hex_bytes: bytes, min_block_size: int, max_block_size: int
) -> int:
    best_edit_distance = math.inf
    best_block_size = -1
    for block_size in range(min_block_size, max_block_size+1):
        bytes_blocks = chunkBytes(hex_bytes, block_size)
        block_pairs = len(bytes_blocks)//2
        edit_distance = 0
        while len(bytes_blocks) >= 2:
            chunks_edit_distance = Set1Util.hamming_distance(
                bytes_blocks[0], bytes_blocks[1]
            )/block_size
            edit_distance += chunks_edit_distance
            bytes_blocks.pop(0)
            bytes_blocks.pop(0)
        edit_distance /= block_pairs
        if edit_distance < best_edit_distance:
            best_edit_distance = edit_distance
            best_block_size = block_size
    return best_block_size

def solveRepeatingKeyXor(
    hex_ciphertext: str, min_key_length: int, max_key_length: int
) -> Tuple[bytes, bytes]: 
    ciphertext_bytes = bytes.fromhex(hex_ciphertext)
    best_block_size = getBestBlockSize(
        ciphertext_bytes, min_key_length, max_key_length
    )
    n_blocks = len(ciphertext_bytes)//best_block_size
    trailing_bytes = len(ciphertext_bytes)%best_block_size
    true_key = bytearray([0]*best_block_size)
    for index in range(best_block_size):
        transposed = bytearray([
            ciphertext_bytes[best_block_size*i+index] for i in range(n_blocks)
        ])
        if index < trailing_bytes:
            transposed.append(ciphertext_bytes[n_blocks*best_block_size+index])
        _, _, key = solveSingleCharacterXor(transposed.hex())
        true_key[index] = key
    plaintext = Set1Util.repeating_key_xor(ciphertext_bytes, bytes(true_key))
    return plaintext, bytes(true_key)
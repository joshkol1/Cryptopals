import Utility.Set1Util as Set1Util
import Utility.Set2Util as Set2Util
from Utility.MersenneTwister import MT19937

def encrypt_aes_ctr(plaintext: bytes, key: bytes, nonce: int) -> bytes:
    counter = 0
    nonce_bytes = nonce.to_bytes(8, 'little', signed=False)
    n_blocks = len(plaintext)//16 if len(plaintext)%16 == 0 else len(plaintext)//16+1
    ciphertext = bytearray()
    for i in range(n_blocks):
        input = nonce_bytes + counter.to_bytes(8, 'little', signed=False)
        aes_output = Set1Util.encrypt_aes_ecb(input, key, False)
        cutoff = len(plaintext)%16 if i == n_blocks-1 else 16
        if cutoff <= 0:
            cutoff += 16
        ciphertext += Set1Util.xor_bytes(
            aes_output[:cutoff], 
            Set2Util.block_at_index(plaintext, i, 16)
        )
        counter += 1
    return bytes(ciphertext)

def decrypt_aes_ctr(plaintext: bytes, key: bytes, nonce: int) -> bytes:
    return encrypt_aes_ctr(plaintext, key, nonce)

# run unix shell command "date +%s" to get current unix time
def get_timestamp() -> int:
    import subprocess
    tstamp_cmd = ["date", "+%s"]
    proc = subprocess.Popen(tstamp_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        output, _ = proc.communicate(timeout=15)
    except subprocess.TimeoutExpired:
        proc.kill()
        _, _ = proc.communicate()
        return -1
    return int(output.decode().strip())

def rng_same(rng1: MT19937, rng2: MT19937, iterations: int = 10000) -> bool:
    for _ in range(iterations):
        v1 = rng1.get()
        v2 = rng2.get()
        if v1 != v2:
            return False
    return True
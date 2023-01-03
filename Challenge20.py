import Utility.Set1Util as Set1Util
import Utility.Set2Util as Set2Util
import Utility.Set3Util as Set3Util
import Utility.SolveXorCypher as SolveXorCypher

random_key = Set2Util.get_random_bytes()

def main():
    ciphertexts = []
    f = open("20.txt")
    for line in f:
        plaintext = Set1Util.base64_to_bytes(line)
        ciphertexts.append(
            Set3Util.encrypt_aes_ctr(plaintext, random_key, 0)
        )
    max_length = max([len(c) for c in ciphertexts])
    decoded = [bytearray() for _ in range(len(ciphertexts))]
    for i in range(max_length):
        index_bytes = bytearray()
        used_items = []
        for j, ctext in enumerate(ciphertexts):
            if i < len(ctext):
                index_bytes.append(ctext[i])
                used_items.append(j)
        ptext, _, _ = SolveXorCypher.solveSingleCharacterXor(index_bytes.hex())
        assert len(ptext) == len(used_items)
        for j in range(len(ptext)):
            decoded[used_items[0]].append(ptext[j])
            used_items.pop(0)
    for ptext in decoded:
        print(ptext.decode('utf-8'))
        print()
    return 0

if __name__ == "__main__":
    main()
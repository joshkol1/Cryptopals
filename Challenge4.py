import math
import Utility.SolveXorCypher as SolveXorCypher

def main():
    f = open('4.txt')
    best_chi2 = math.inf
    encrypted_line = ""
    english_bytes = bytes()
    xor_key = -1
    for xor_line in f:
        xor_line = xor_line.strip()
        plaintext, chi2, key = SolveXorCypher.solveSingleCharacterXor(xor_line)
        if chi2 < best_chi2:
            best_chi2 = chi2
            encrypted_line = xor_line
            english_bytes = plaintext
            xor_key = key
    print("Xor-encrypted line: {}".format(encrypted_line))
    print("Plaintext: {}".format(english_bytes))
    print("Chi2 score: {}".format(best_chi2))
    print("Key: {}".format(chr(xor_key)))
    return 0

if __name__ == "__main__":
    main()
import Utility.SolveXorCypher as SolveXorCypher

def main():
    ciphertext = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
    plaintext_bytes, chi2, key = SolveXorCypher.solveSingleCharacterXor(ciphertext)
    print("Plaintext: {}".format(plaintext_bytes))
    print("Chi2 score: {}".format(chi2))
    print("Key: {}".format(chr(key)))
    return 0

if __name__ == "__main__":
    main()
import Utility.Set1Util as Set1Util

def main():
    f = open('8.txt')
    for line in f:
        ciphertext_hex = line.strip()
        ciphertext = bytes.fromhex(ciphertext_hex)
        if Set1Util.detect_AES_128_ECB(ciphertext):
            print("hex: {}".format(ciphertext_hex))
            print("bytes: {}".format(str(ciphertext)))
            print()
    return 0

if __name__ == "__main__":
    main()
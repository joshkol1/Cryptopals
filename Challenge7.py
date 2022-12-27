import Utility.Set1Util as Set1Util

def main():
    base64_text = ""
    f = open('7.txt')
    for line in f:
        base64_text += line.strip()
    ciphertext_bytes = Set1Util.base64_to_bytes(base64_text)
    key = b'YELLOW SUBMARINE'
    plaintext = Set1Util.decrypt_aes_ecb(ciphertext_bytes, key)
    print(plaintext.decode('ascii'))
    return 0

if __name__ == "__main__":
    main()
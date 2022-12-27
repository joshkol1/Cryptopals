import Utility.Set1Util as Set1Util
import Utility.Set2Util as Set2Util
from Crypto.Cipher import AES

def main():
    base64_text = ""
    f = open('10.txt')
    for line in f:
        base64_text += line.strip()
    ciphertext = Set1Util.base64_to_bytes(base64_text)
    key = b'YELLOW SUBMARINE'
    iv = bytes([0]*16)
    # Check against library implementation of CBC mode decryption
    plaintext = Set2Util.decrypt_aes_cbc(ciphertext, key, iv)
    print("Plaintext: {}".format(plaintext))
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    true_plaintext = cipher.decrypt(ciphertext)
    if plaintext == true_plaintext:
        print("Successful AES-128 CBC mode decryption")
    # Same thing for CBC mode encryption. remember to remove padding
    plaintext = Set1Util.strip_pkcs7(plaintext, 16)
    encrypted = Set2Util.encrypt_aes_cbc(plaintext, key, iv)
    encrypted_base64 = Set1Util.bytes_to_base64(encrypted)
    if encrypted_base64 == base64_text:
        print("Successful AES-128 CBC mode encryption")
    return 0

if __name__ == "__main__":
    main()
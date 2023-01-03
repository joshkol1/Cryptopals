import Utility.Set1Util as Set1Util
import Utility.Set3Util as Set3Util


def main():
    plaintext = Set1Util.base64_to_bytes(
        "L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ=="
    )
    print(Set3Util.decrypt_aes_ctr(plaintext, b'YELLOW SUBMARINE', 0))
    return 0

if __name__ == "__main__":
    main()
import Utility.Set1Util as Set1Util

def main():
    text = b'YELLOW SUBMARINE'
    block_size = 20
    print("Text: {}".format(text))
    print("Block size: {}".format(block_size))
    padded = Set1Util.pad_pkcs7(text, block_size)
    print("Padded text: {}".format(padded))
    return 0

if __name__ == "__main__":
    main()
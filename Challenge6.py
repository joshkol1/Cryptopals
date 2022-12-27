import Utility.Set1Util as Set1Util
import Utility.SolveXorCypher as SolveXorCypher
import colorama

def main():
    colorama.init(autoreset=True)
    base64_text = ""
    f = open('6.txt')
    for line in f:
        base64_text += line.strip()
    hex_bytes = Set1Util.base64_to_bytes(base64_text)
    hex_text = hex_bytes.hex()
    plaintext, key = SolveXorCypher.solveRepeatingKeyXor(hex_text, 2, 40)
    print("Key: "+colorama.Back.RED+key.decode('ascii'))
    print()
    print(plaintext.decode('ascii'))
    return 0

if __name__ == "__main__":
    main()
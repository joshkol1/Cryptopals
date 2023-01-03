import math

CHAR_FREQUENCY = [
    0.08167, 0.01492, 0.02782, 0.04253, 0.12702, 0.02228, 0.02015,  # A-G
    0.06094, 0.06966, 0.00153, 0.00772, 0.04025, 0.02406, 0.06749,  # H-N
    0.07507, 0.01929, 0.00095, 0.05987, 0.06327, 0.09056, 0.02758,  # O-U
    0.00978, 0.02360, 0.00150, 0.01974, 0.00074                     # V-Z
]

def getChi2(text: bytes) -> float:
    frequency = [0]*26
    ignored = 0
    for c in text:
        if c >= ord('a') and c <= ord('z'):
            frequency[c-ord('a')] += 1
        elif c >= ord('A') and c <= ord('Z'):
            frequency[c-ord('A')] += 1
        elif c >= ord(' ') and c <= ord('~'): # Punctuation
            ignored += 1
        elif c == 9 or c == 10 or c == 13: # spacing
            ignored += 1
        else:
            return math.inf
    chi2 = 0
    n_chars = len(text)-ignored
    if n_chars <= 0:
        return math.inf
    for i in range(26):
        observed = frequency[i]
        expected = n_chars*CHAR_FREQUENCY[i]
        difference = observed-expected
        chi2 += difference*difference/expected
    return chi2

def getAlphabetPercent(text: bytes) -> float:
    good_chars = 0
    for c in text:
        if c >= ord('a') and c <= ord('z'):
            good_chars += 1
        elif c >= ord('A') and c <= ord('Z'):
            good_chars += 1
        # count spaces and newlines too, these are frequent
        elif c == ord(' ') or c == ord('\n'):
            good_chars += 1
    return good_chars/len(text)
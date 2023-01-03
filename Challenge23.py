from Utility.MersenneTwister import MT19937
import Utility.Set3Util as Set3Util
import random

def inverse_temper(mt_output: int) -> int:
    # First inverse transform
    first_18 = mt_output&0xFFFFC000
    first_14 = mt_output&0xFFFC0000
    mt_output = first_18|((first_14>>18)^(mt_output&0x00003FFF))
    # Second inverse transform
    inv = mt_output&0x00007FFF
    shift_and = 0
    for _ in range(2):
        shift_and = (inv<<15)&0xEFC60000
        inv = mt_output^shift_and
    mt_output = inv
    # Third inverse transform
    inv = mt_output&0x0000007F
    shift_and = 0
    for _ in range(4):
        shift_and = (inv<<7)&0x9D2C5680
        inv = mt_output^shift_and
    mt_output = inv
    # Fourth inverse transform
    inv = mt_output&0xFFE00000
    shift = 0
    for _ in range(2):
        shift = inv>>11
        inv = mt_output^shift
    mt_output = inv
    return mt_output

def clone_mt19937(rng: MT19937) -> MT19937:
    rng_sample = [inverse_temper(rng.get()) for _ in range(624)]
    rng_clone = MT19937()
    rng_clone._mt = rng_sample
    return rng_clone

def main():
    rng = MT19937(random.randint(0, 0xFFFFFFFF))
    rng_clone = clone_mt19937(rng)
    if Set3Util.rng_same(rng, rng_clone):
        print("MT19937 clone successful")
    return 0

if __name__ == "__main__":
    main()
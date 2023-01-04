from Utility.MersenneTwister import MT19937
import Utility.Set3Util as Set3Util
import random

def main():
    timestamp = Set3Util.get_timestamp()
    rng = MT19937(timestamp)
    rng_output = rng.get()
    # simulate passage of time
    min_wait_seconds = 40
    max_wait_seconds = 1000
    wait_seconds = random.randint(40, 1000)
    later_timestamp = timestamp+wait_seconds
    for ts in range(later_timestamp-min_wait_seconds+10, later_timestamp-max_wait_seconds-10, -1):
        later_rng = MT19937(ts)
        later_output = later_rng.get()
        if later_output == rng_output and Set3Util.rng_same(rng, later_rng):
            print("True seed: {}".format(timestamp))
            print("Detected seed: {}".format(ts))
            break
    return 0

if __name__ == "__main__":
    main()
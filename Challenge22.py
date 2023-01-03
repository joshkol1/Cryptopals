from Utility.MersenneTwister import MT19937
import subprocess
import random

# run unix shell command "date +%s" to get current unix time
def get_timestamp() -> int:
    tstamp_cmd = ["date", "+%s"]
    proc = subprocess.Popen(tstamp_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        output, _ = proc.communicate(timeout=15)
    except subprocess.TimeoutExpired:
        proc.kill()
        _, _ = proc.communicate()
        return -1
    return int(output.decode().strip())

def rng_same(rng1: MT19937, rng2: MT19937, iterations: int = 10000) -> bool:
    for _ in range(iterations):
        v1 = rng1.get()
        v2 = rng2.get()
        if v1 != v2:
            return False
    return True

def main():
    timestamp = get_timestamp()
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
        if later_output == rng_output and rng_same(rng, later_rng):
            print("True seed: {}".format(timestamp))
            print("Detected seed: {}".format(ts))
            break
    return 0

if __name__ == "__main__":
    main()
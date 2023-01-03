class MT19937:
    W, N, M, R = 32, 624, 397, 31
    A = 0x9908B0DF
    U, D = 11, 0xFFFFFFFF
    S, B = 7, 0x9D2C5680
    T, C = 15, 0xEFC60000
    L = 18
    F = 1812433253
    LOWER_MASK = (1<<R)-1
    UPPER_MASK = (~LOWER_MASK)&((1<<W)-1)

    def __init__(self, mt_seed: int = 0):
        self.mt = [0]*MT19937.N
        self.index = 0
        self.seed(mt_seed)

    def seed(self, mt_seed: int = 0) -> None:
        self.index = MT19937.N
        self.mt[0] = mt_seed
        for i in range(1, MT19937.N):
            self.mt[i] = (MT19937.F*(self.mt[i-1]^(self.mt[i-1]>>(MT19937.W-2)))+i)&((1<<MT19937.W)-1)

    def get(self) -> int:
        if self.index >= MT19937.N:
            self.twist()
        y = self.mt[self.index]
        y ^= ((y>>MT19937.U)&MT19937.D)
        y ^= ((y<<MT19937.S)&MT19937.B)
        y ^= ((y<<MT19937.T)&MT19937.C)
        y ^= (y>>MT19937.L)
        self.index += 1
        return y&((1<<MT19937.W)-1)
    
    def twist(self) -> None:
        for i in range(MT19937.N):
            x = (self.mt[i]&MT19937.UPPER_MASK)|(self.mt[(i+1)%MT19937.N]&MT19937.LOWER_MASK)
            xA = x>>1
            if x%2 != 0:
                xA ^= MT19937.A
            self.mt[i] = self.mt[(i+MT19937.M)%MT19937.N]^xA
        self.index = 0
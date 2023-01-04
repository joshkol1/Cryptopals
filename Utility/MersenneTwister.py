W, N, M, R = 32, 624, 397, 31
A = 0x9908B0DF
U, D = 11, 0xFFFFFFFF
S, B = 7, 0x9D2C5680
T, C = 15, 0xEFC60000
L = 18
F = 1812433253
LOWER_MASK = (1<<R)-1
UPPER_MASK = (~LOWER_MASK)&((1<<W)-1)

class MT19937:
    def __init__(self, mt_seed: int = 5489):
        self._mt = [0]*N
        self._index = 0
        self.seed(mt_seed)

    def seed(self, mt_seed: int = 0) -> None:
        self._index = N
        self._mt[0] = mt_seed
        for i in range(1, N):
            self._mt[i] = (F*(self._mt[i-1]^(self._mt[i-1]>>(W-2)))+i)&((1<<W)-1)

    def get(self) -> int:
        if self._index >= N:
            self._twist()
        y = self._mt[self._index]
        y ^= ((y>>U)&D)
        y ^= ((y<<S)&B)
        y ^= ((y<<T)&C)
        y ^= (y>>L)
        self._index += 1
        return y&((1<<W)-1)
    
    def _twist(self) -> None:
        for i in range(N):
            x = (self._mt[i]&UPPER_MASK)|(self._mt[(i+1)%N]&LOWER_MASK)
            xA = x>>1
            if x%2 != 0:
                xA ^= A
            self._mt[i] = self._mt[(i+M)%N]^xA
        self._index = 0
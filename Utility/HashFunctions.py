from abc import ABC, abstractmethod

class HashFunction(ABC):
    def __init__(self, data: bytes|bytearray = None):
        self._data = bytearray() if data is None else bytearray(data)

    def update(self, data: bytes|bytearray) -> None:
        self._data += data

    def clear(self) -> None:
        self._data = bytearray()

    def copy(self) -> None:
        return HashFunction(bytearray(self._data))
    
    @abstractmethod
    def digest(self) -> bytes:
        pass

    @abstractmethod
    def hexdigest(self) -> str:
        pass

class SHA1(HashFunction):
    def __init__(self, data: bytes|bytearray = None):
        super().__init__(data)

    def digest(self) -> bytes:
        h0 = 0x67452301
        h1 = 0xEFCDAB89
        h2 = 0x98BADCFE
        h3 = 0x10325476
        h4 = 0xC3D2E1F0

        msg_length = len(self._data)*8
        

        return 0

    def hexdigest(self) -> str:
        return self.digest().hex()

class MD4(HashFunction):
    def __init__(self, data: bytes|bytearray = None):
        super().__init__(data)

    def digest(self) -> bytes:
        return 0

    def hexdigest(self) -> str:
        return self.digest().hex()
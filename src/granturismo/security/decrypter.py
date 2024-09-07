from enum import Enum
from salsa20 import Salsa20_xor
from granturismo.utils import ntoh


class GT_Version(Enum):
    GT6 = 6
    GT7 = 7


# https://github.com/Nenkai/PDTools/blob/85f11a67489346c62273ca2f70708b4ed3b44279/PDTools.Crypto/SimulationInterface/SimulatorInterfaceCryptorGT7.cs#L15
class Decrypter(object):
    def __init__(self, gt: GT_Version = GT_Version.GT7):
        if gt == GT_Version.GT6:
            self._KEY = b"Simulator Interface Packet ver 0"  # ".0" -> only 32-bits
            self._BYTE_ORDER = "big"
            self._IV_MASK = 0xDEADBEAF
            self._GT_ID = 0x30533647
        elif gt == GT_Version.GT7:
            self._KEY = b"Simulator Interface Packet GT7 v"  # "er 0.0" -> only 32-bits
            self._BYTE_ORDER = "little"
            self._IV_MASK = 0xDEADBEAF
            self._GT_ID = 0x47375330
        else:
            raise NotImplementedError(
                "GTA versions other than GT6 and GT7 are not implemented"
            )

    def decrypt(self, buffer: bytearray) -> bytearray:
        iv1 = int.from_bytes(ntoh(buffer[64:68]), byteorder=self._BYTE_ORDER)
        iv2 = iv1 ^ self._IV_MASK

        iv = bytearray()
        iv.extend(iv2.to_bytes(4, "little"))
        iv.extend(iv1.to_bytes(4, "little"))

        return Salsa20_xor(bytes(buffer), bytes(iv), self._KEY)

"""Decryption of Gran Turismo 7 telemetry datagrams.

GT7 obfuscates each UDP packet with Salsa20.  The 32-byte key is a fixed
ASCII string baked into the game; the 8-byte nonce is derived per packet from
a 32-bit seed stored at byte offset 0x40 of the *encrypted* payload.  These
facts come from the public reverse-engineering of the protocol (see the
project README for attribution) and are reimplemented here from scratch.
"""

from __future__ import annotations

from granturismo.security import salsa20

# First 32 bytes of the game's "Simulator Interface Packet GT7 ver 0.0" string.
_KEY = b"Simulator Interface Packet GT7 v"

# The seed lives at this offset in the encrypted packet ...
_SEED_OFFSET = 0x40
# ... and the second nonce word is the seed XOR'd with this constant.
_NONCE_MASK = 0xDEADBEEF


class Decrypter:
    """Stateless decrypter for GT7 telemetry packets."""

    @staticmethod
    def decrypt(buffer: bytes) -> bytes:
        """Return the plaintext telemetry packet for an encrypted ``buffer``."""
        seed = int.from_bytes(buffer[_SEED_OFFSET:_SEED_OFFSET + 4], "little")
        nonce = ((seed ^ _NONCE_MASK).to_bytes(4, "little")
                 + seed.to_bytes(4, "little"))
        return salsa20.xor(bytes(buffer), nonce, _KEY)

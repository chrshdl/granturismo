import os

from granturismo.security import salsa20
from granturismo.security.decrypter import (
    _KEY,
    _NONCE_MASK,
    _SEED_OFFSET,
    Decrypter,
)


def test_decrypt_uses_seed_derived_nonce():
    # Build an arbitrary "encrypted" datagram; the decrypter must derive its
    # nonce from the 32-bit seed at offset 0x40 and XOR with the GT7 key.
    cipher = os.urandom(0x128)

    seed = int.from_bytes(cipher[_SEED_OFFSET:_SEED_OFFSET + 4], "little")
    nonce = (seed ^ _NONCE_MASK).to_bytes(4, "little") + seed.to_bytes(4, "little")
    expected = salsa20.xor(cipher, nonce, _KEY)

    assert Decrypter.decrypt(cipher) == expected


def test_decrypt_round_trips_a_crafted_packet():
    # Craft a plaintext whose ciphertext carries a chosen seed at 0x40, so the
    # full encrypt -> decrypt cycle reproduces the original plaintext.
    seed = 0x12345678
    nonce = (seed ^ _NONCE_MASK).to_bytes(4, "little") + seed.to_bytes(4, "little")

    plaintext = bytearray(os.urandom(0x128))
    keystream_at_seed = salsa20.xor(bytes(0x128), nonce, _KEY)[_SEED_OFFSET:_SEED_OFFSET + 4]
    # ensure cipher[0x40:0x44] == seed so the decrypter recovers the same nonce
    plaintext[_SEED_OFFSET:_SEED_OFFSET + 4] = bytes(
        s ^ k for s, k in zip(seed.to_bytes(4, "little"), keystream_at_seed)
    )

    cipher = salsa20.xor(bytes(plaintext), nonce, _KEY)
    assert cipher[_SEED_OFFSET:_SEED_OFFSET + 4] == seed.to_bytes(4, "little")
    assert Decrypter.decrypt(cipher) == bytes(plaintext)

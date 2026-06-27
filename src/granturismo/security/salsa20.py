"""A small, dependency-free Salsa20 stream cipher.

Salsa20 was designed by Daniel J. Bernstein and placed in the public domain;
this module is an independent pure-Python implementation of the 20-round
variant with a 256-bit key and 64-bit nonce, which is what Gran Turismo 7's
telemetry stream uses.

Only the keystream/XOR primitive needed by :mod:`granturismo.security` is
exposed.  Encryption and decryption are the same operation for a stream
cipher, so :func:`xor` serves both directions.
"""

from __future__ import annotations

import struct

_MASK32 = 0xFFFFFFFF
_BLOCK = 64  # Salsa20 emits 64 keystream bytes per counter block

# "expand 32-byte k" split into four little-endian words, placed at the
# diagonal of the state matrix.
_SIGMA = (0x61707865, 0x3320646E, 0x79622D32, 0x6B206574)


def _rotl(value: int, shift: int) -> int:
    value &= _MASK32
    return ((value << shift) | (value >> (32 - shift))) & _MASK32


def _core(state: list[int]) -> bytes:
    """Run the 20-round Salsa20 core over a 16-word ``state``.

    Returns the 64-byte keystream block (state + scrambled state).
    """
    x = list(state)

    # The quarter-round, unrolled.  Each `step` mutates one word in place.
    def step(dst: int, a: int, b: int, rot: int) -> None:
        x[dst] ^= _rotl((x[a] + x[b]) & _MASK32, rot)

    for _ in range(10):  # 10 double-rounds == 20 rounds
        # column round
        step(4, 0, 12, 7);  step(8, 4, 0, 9);  step(12, 8, 4, 13);  step(0, 12, 8, 18)
        step(9, 5, 1, 7);  step(13, 9, 5, 9);  step(1, 13, 9, 13);  step(5, 1, 13, 18)
        step(14, 10, 6, 7);  step(2, 14, 10, 9);  step(6, 2, 14, 13);  step(10, 6, 2, 18)
        step(3, 15, 11, 7);  step(7, 3, 15, 9);  step(11, 7, 3, 13);  step(15, 11, 7, 18)
        # row round
        step(1, 0, 3, 7);  step(2, 1, 0, 9);  step(3, 2, 1, 13);  step(0, 3, 2, 18)
        step(6, 5, 4, 7);  step(7, 6, 5, 9);  step(4, 7, 6, 13);  step(5, 4, 7, 18)
        step(11, 10, 9, 7);  step(8, 11, 10, 9);  step(9, 8, 11, 13);  step(10, 9, 8, 18)
        step(12, 15, 14, 7);  step(13, 12, 15, 9);  step(14, 13, 12, 13);  step(15, 14, 13, 18)

    out = [(x[i] + state[i]) & _MASK32 for i in range(16)]
    return struct.pack("<16I", *out)


def _keystream_block(key_words: tuple[int, ...], nonce_words: tuple[int, int],
                     counter: int) -> bytes:
    state = [
        _SIGMA[0], key_words[0], key_words[1], key_words[2],
        key_words[3], _SIGMA[1], nonce_words[0], nonce_words[1],
        counter & _MASK32, (counter >> 32) & _MASK32, _SIGMA[2], key_words[4],
        key_words[5], key_words[6], key_words[7], _SIGMA[3],
    ]
    return _core(state)


def xor(message: bytes, nonce: bytes, key: bytes) -> bytes:
    """XOR ``message`` with the Salsa20 keystream for ``key``/``nonce``.

    :param message: bytes to encrypt or decrypt (any length).
    :param nonce: 8-byte nonce.
    :param key: 32-byte key.
    :return: the transformed bytes, same length as ``message``.
    """
    if len(key) != 32:
        raise ValueError(f"key must be 32 bytes, got {len(key)}")
    if len(nonce) != 8:
        raise ValueError(f"nonce must be 8 bytes, got {len(nonce)}")

    key_words = struct.unpack("<8I", key)
    nonce_words = struct.unpack("<2I", nonce)

    out = bytearray(len(message))
    for offset in range(0, len(message), _BLOCK):
        block = _keystream_block(key_words, nonce_words, offset // _BLOCK)
        chunk = message[offset:offset + _BLOCK]
        for i, byte in enumerate(chunk):
            out[offset + i] = byte ^ block[i]
    return bytes(out)

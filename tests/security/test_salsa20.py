import os

from granturismo.security import salsa20


def test_known_answer_vector():
    # Salsa20/20 keystream for an all-zero 256-bit key and all-zero nonce.
    # This is the canonical ECRYPT test vector (set 1, vector 0, first block).
    keystream = salsa20.xor(bytes(64), bytes(8), bytes(32))
    assert keystream.hex() == (
        "9a97f65b9b4c721b960a672145fca8d4"
        "e32e67f9111ea979ce9c4826806aeee6"
        "3de9c0da2bd7f91ebcb2639bf989c625"
        "1b29bf38d39a9bdce7c55f4b2ac12a39"
    )


def test_xor_round_trips():
    key, nonce = os.urandom(32), os.urandom(8)
    message = os.urandom(296)
    cipher = salsa20.xor(message, nonce, key)
    assert cipher != message
    assert salsa20.xor(cipher, nonce, key) == message


def test_rejects_bad_key_and_nonce_sizes():
    for bad in (b"short", os.urandom(31), os.urandom(33)):
        try:
            salsa20.xor(b"data", os.urandom(8), bad)
        except ValueError:
            pass
        else:
            raise AssertionError("expected ValueError for bad key length")
    try:
        salsa20.xor(b"data", os.urandom(7), os.urandom(32))
    except ValueError:
        pass
    else:
        raise AssertionError("expected ValueError for bad nonce length")

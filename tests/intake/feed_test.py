import socket
import struct

import pytest

from granturismo import Feed
from granturismo.intake.feed import SocketNotBoundError
from tests.helpers import build_packet_buffer, encrypt_packet


def _send(cipher: bytes) -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.sendto(cipher, ("127.0.0.1", Feed.BIND_PORT))


def test_get_before_start_raises():
    feed = Feed("127.0.0.1")
    with pytest.raises(SocketNotBoundError):
        feed.get_latest(timeout=0)


def test_receives_and_decodes_a_packet():
    with Feed("127.0.0.1") as feed:
        _send(encrypt_packet(bytes(build_packet_buffer())))
        packet = feed.get_latest(timeout=2.0)
        assert packet is not None
        assert packet.packet_id == 12345
        assert packet.car_id == 42


def test_latest_wins_keeps_only_freshest():
    with Feed("127.0.0.1") as feed:
        # send three packets with ascending packet_ids in quick succession
        for pid in (100, 200, 300):
            buf = build_packet_buffer()
            struct.pack_into("<I", buf, 112, pid)
            _send(encrypt_packet(bytes(buf)))
        # drain to the newest; allow a moment for all to arrive
        latest = None
        for _ in range(50):
            pkt = feed.get_latest(timeout=0.1)
            if pkt is not None:
                latest = pkt
        assert latest is not None
        assert latest.packet_id == 300


def test_get_nowait_returns_none_when_idle():
    with Feed("127.0.0.1") as feed:
        assert feed.get_nowait() is None


def test_garbage_datagram_is_ignored():
    with Feed("127.0.0.1") as feed:
        _send(b"not a valid packet")          # undecryptable / wrong length
        assert feed.get_latest(timeout=0.3) is None
        _send(encrypt_packet(bytes(build_packet_buffer())))
        assert feed.get_latest(timeout=2.0) is not None

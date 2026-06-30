"""Live telemetry feed from a Gran Turismo 7 console.

A :class:`Feed` opens a UDP socket, keeps the console streaming by sending a
periodic heartbeat, and decodes incoming datagrams into
:class:`~granturismo.model.Packet` objects on a background thread.  Only the
most recent packet is retained ("latest wins"), since stale telemetry is
useless.

Typical use::

    with Feed("192.168.1.50") as feed:
        while True:
            packet = feed.get_latest(timeout=0.05)
            if packet is not None:
                ...
"""

from __future__ import annotations

import random
import socket
import threading
import time
from typing import Optional

from granturismo.model import Packet
from granturismo.security import Decrypter


class SocketNotBoundError(Exception):
    """Raised when a packet is requested before :meth:`Feed.start`."""


class Feed:
    # The console listens for heartbeats here and streams telemetry back to us.
    HEARTBEAT_PORT = 33739
    BIND_PORT = 33740
    HEARTBEAT_MESSAGE = b"C"
    HEARTBEAT_INTERVAL = 10.0  # seconds; the console stops streaming without it
    _RECV_BUFFER = 0x128       # GT7 packets are 296 bytes
    _SOCKET_TIMEOUT = 1.0      # lets the receiver notice shutdown promptly

    def __init__(self, addr: str):
        """:param addr: IP address of the PlayStation to stream from."""
        if not isinstance(addr, str):
            raise TypeError("addr must be a string")
        self._addr = addr

        self._sock: Optional[socket.socket] = None
        self._decrypter = Decrypter()
        self._stop = threading.Event()

        # Single-slot "latest packet" mailbox guarded by a condition.
        self._cond = threading.Condition()
        self._latest: Optional[Packet] = None
        self._fresh = False  # True when a packet has arrived since last consume

        self._heartbeat_thread: Optional[threading.Thread] = None
        self._receiver_thread: Optional[threading.Thread] = None

    # -- lifecycle ---------------------------------------------------------

    def start(self) -> "Feed":
        if self._sock is not None:
            return self
        self._stop.clear()
        self._sock = self._open_socket()
        self._heartbeat_thread = threading.Thread(
            target=self._heartbeat_loop, name="gt-heartbeat", daemon=True)
        self._receiver_thread = threading.Thread(
            target=self._receive_loop, name="gt-receiver", daemon=True)
        self._heartbeat_thread.start()
        self._receiver_thread.start()
        return self

    def close(self) -> None:
        """Stop the background threads and release the socket."""
        self._stop.set()
        # Wake any consumer blocked in get()/get_latest().
        with self._cond:
            self._cond.notify_all()
        if self._sock is not None:
            try:
                self._sock.close()
            except OSError:
                pass
        for thread in (self._heartbeat_thread, self._receiver_thread):
            if thread is not None and thread.is_alive():
                thread.join(timeout=2.0)
        self._sock = None

    def __enter__(self) -> "Feed":
        return self.start()

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.close()

    # -- consumer API ------------------------------------------------------

    def get(self) -> Optional[Packet]:
        """Block until a packet is available and return the most recent one.

        Returns ``None`` if the feed is closed while waiting.
        """
        self._require_started()
        with self._cond:
            while not self._fresh and not self._stop.is_set():
                self._cond.wait(timeout=self._SOCKET_TIMEOUT)
            self._fresh = False
            return self._latest

    def get_latest(self, timeout: Optional[float] = None) -> Optional[Packet]:
        """Return the freshest packet, waiting up to ``timeout`` seconds.

        Returns ``None`` on timeout or if the feed is closed.
        """
        self._require_started()
        deadline = None if timeout is None else time.monotonic() + timeout
        with self._cond:
            while not self._fresh and not self._stop.is_set():
                remaining = None if deadline is None else deadline - time.monotonic()
                if remaining is not None and remaining <= 0:
                    return None
                self._cond.wait(timeout=remaining)
            self._fresh = False
            return self._latest

    def get_nowait(self) -> Optional[Packet]:
        """Return the freshest packet if one has arrived, else ``None``."""
        with self._cond:
            if not self._fresh:
                return None
            self._fresh = False
            return self._latest

    # -- internals ---------------------------------------------------------

    def _require_started(self) -> None:
        if self._sock is None:
            raise SocketNotBoundError(
                "Feed not started; call start() or use it as a context manager")

    def _publish(self, packet: Packet) -> None:
        with self._cond:
            self._latest = packet
            self._fresh = True
            self._cond.notify_all()

    def _receive_loop(self) -> None:
        while not self._stop.is_set():
            try:
                data, _ = self._sock.recvfrom(self._RECV_BUFFER)
            except socket.timeout:
                continue
            except OSError:
                break  # socket closed during shutdown
            received_time = time.time()
            try:
                plaintext = self._decrypter.decrypt(data)
                packet = Packet.from_bytes(plaintext, received_time)
            except Exception:
                continue  # malformed or undecryptable datagram; skip it
            self._publish(packet)

    def _heartbeat_loop(self) -> None:
        backoff = 0.5
        backoff_max = 30.0
        while not self._stop.is_set():
            try:
                self._sock.sendto(
                    self.HEARTBEAT_MESSAGE, (self._addr, self.HEARTBEAT_PORT))
            except OSError:
                # Network hiccup (e.g. no route to host): back off and retry.
                jitter = 0.9 + 0.2 * random.random()
                self._stop.wait(min(backoff, backoff_max) * jitter)
                backoff = min(backoff * 2.0, backoff_max)
                continue
            backoff = 0.5
            self._stop.wait(self.HEARTBEAT_INTERVAL)

    @classmethod
    def _open_socket(cls) -> socket.socket:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if hasattr(socket, "SO_REUSEPORT"):
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        sock.settimeout(cls._SOCKET_TIMEOUT)
        sock.bind(("", cls.BIND_PORT))
        return sock

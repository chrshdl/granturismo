import signal
import socket
import threading
import time
from collections import deque
from queue import Empty, Queue

from granturismo.model import Packet
from granturismo.security import Decrypter


class SocketNotBoundError(Exception):
    pass


class ReadError(Exception):
    pass


class UnknownStatusError(Exception):
    pass


class Feed(object):
    _HEARTBEAT_PORT = 33739
    _BIND_PORT = 33740
    _BUFFER_LEN = 0x128  # in bytes
    _HEARTBEAT_DELAY = 10  # in seconds
    _HEARTBEAT_MESSAGE = b"A"

    def __init__(self, addr: str):
        """
        Initialize the telemetry listener.
        This will spawn a background thread to send heartbeat signals to the PlayStation. Be sure to call `.stop()` when
        you are done using this object.
        :param addr: Address to the PlayStation so we can send a heartbeat
        """
        self._recv_times = deque()  # timestamps of received packets
        self._last_log = time.monotonic()  # last time we printed stats

        # set this first so that if we fail to connect to socket we wont fail the closing functions
        self._terminate_event = threading.Event()

        if not isinstance(addr, str):
            raise TypeError("`addr` must be a string")

        self._addr = addr
        self._sock: socket.socket = None
        self._sock_bounded = False
        self._decrypter: Decrypter = False

        # setup signal handlers so we can make sure we close the socket and kill daemon threads properly
        for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGQUIT, signal.SIGABRT):

            def kill(*args):
                self._terminate_event.set()
                signal.getsignal(sig)()

            signal.signal(sig, kill)

        self._packet_queue = Queue()
        self._packet_lock = threading.Lock()
        self._heartbeat_thread = threading.Thread(
            target=self._send_heartbeat, name="HeartbeatThread"
        )
        self._receiver_thread = threading.Thread(
            target=self._get, name="ReceiverThread"
        )

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def __delete__(self, instance):
        self.close()

    def __del__(self):
        self.close()

    def start(self):
        # connect to socket
        self._sock = self._init_sock_()
        self._sock_bounded = True
        self._decrypter = Decrypter()

        # start heartbeat thread
        self._heartbeat_thread.start()
        self._receiver_thread.start()
        return self

    def close(self):
        """
        Kills the background process which sends heartbeats to the PlayStation. If this is not called, your program will not
        gracefully terminate.
        :return: None
        """
        self._terminate_event.set()
        if self._heartbeat_thread.is_alive():
            self._heartbeat_thread.join()

    def get(self) -> Packet:
        """
        Waits for the next packet to be sent from PlayStation, decrypts, and unpacks it into a Packet object.
        :return: Packet containing latest telemetry data
        """
        if not self._sock_bounded:
            raise SocketNotBoundError(
                "Not started. Call `.start` or `with Listener(your_ip_addr)` before calling `.get`"
            )

        self._packet_lock.acquire()
        if not self._packet_queue.empty():
            packet = self._packet_queue.get_nowait()
            self._packet_queue.task_done()
            self._packet_lock.release()
            return packet
        else:
            self._packet_lock.release()
            return self._packet_queue.get(block=True)

    def get_latest(self, timeout: float | None = None) -> Packet | None:
        """
        Wait (with timeout) for at least one packet,
        then empty the queue and return the most recent one.
        """
        if not self._sock_bounded:
            raise SocketNotBoundError(
                "Not started. Call `.start` or `with Feed(your_ip_addr)` before calling `.get_latest`"
            )
        try:
            if timeout is None:
                pkt = self._packet_queue.get(block=True)
            else:
                pkt = self._packet_queue.get(block=True, timeout=timeout)
        except Empty:
            return None
        # Discard all newer packets, so we always end up with the freshest
        while True:
            try:
                pkt = self._packet_queue.get_nowait()
            except Empty:
                break
        return pkt

    def get_nowait(self) -> Packet | None:
        """
        Returns the latest Packet from the queue if available, or None if the queue is empty.
        Never blocks.
        """
        self._packet_lock.acquire()
        try:
            if not self._packet_queue.empty():
                packet = self._packet_queue.get_nowait()
                self._packet_queue.task_done()
                return packet
            else:
                return None
        finally:
            self._packet_lock.release()

    def _get(self) -> None:
        error_count = 0
        while not self._terminate_event.is_set():
            try:
                data, _ = self._sock.recvfrom(Feed._BUFFER_LEN)

                # measure how many packets in last 20 ms
                now_mono = time.monotonic()
                self._recv_times.append(now_mono)

                window = 0.020
                while self._recv_times and now_mono - self._recv_times[0] > window:
                    self._recv_times.popleft()

                packets_last_20ms = len(self._recv_times)

                # log every 0.5 s
                if now_mono - self._last_log >= 0.5:
                    print(f"≈{packets_last_20ms} packets in the last 20 ms")
                    self._last_log = now_mono
                # end measurement

                received_time = time.time()
                if self._terminate_event.is_set():
                    break

                data = self._decrypter.decrypt(data)
                packet = Packet.from_bytes(data, received_time)

                self._packet_lock.acquire()
                try:
                    if not self._packet_queue.empty():
                        self._packet_queue.get_nowait()
                        self._packet_queue.task_done()
                    self._packet_queue.put_nowait(packet)
                finally:
                    self._packet_lock.release()
                error_count = 0
            except Exception:
                error_count += 1
                if error_count > 5:
                    # small backoff if repeatedly erroring
                    time.sleep(0.1)

    def _send_heartbeat(self) -> None:
        while not self._terminate_event.is_set():
            self._sock.sendto(
                self._HEARTBEAT_MESSAGE, (self._addr, self._HEARTBEAT_PORT)
            )
            self._terminate_event.wait(self._HEARTBEAT_DELAY)
        self._sock.close()
        self._sock_bounded = False

    @staticmethod
    def _init_sock_() -> socket.socket:
        # Create a datagram socket
        sock = socket.socket(
            socket.AF_INET,  # Internet
            socket.SOCK_DGRAM,
        )  # UDP
        # Enable immediate reuse of IP address
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        # Bind the socket to the port
        sock.bind(("", Feed._BIND_PORT))

        return sock

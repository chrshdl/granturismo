import socket
import time
import threading
import signal
from granturismo.model import Packet
from granturismo.security import Decrypter
from queue import Queue

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
  _HEARTBEAT_DELAY = 10 # in seconds
  _HEARTBEAT_MESSAGE = b'A'

  def __init__(self, addr: str):
    """
    Initialize the telemetry listener.
    This will spawn a background thread to send heartbeat signals to the PlayStation. Be sure to call `.stop()` when
    you are done using this object.
    :param addr: Address to the PlayStation so we can send a heartbeat
    """
    # set this first so that if we fail to connect to socket we wont fail the closing functions
    self._terminate_event = threading.Event()

    if not isinstance(addr, str):
      raise TypeError('`addr` must be a string')

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

    # return self

  def close(self):
    """
    Kills the background process which sends heartbeats to the PlayStation. If this is not called, your program will not
    gracefully terminate.
    :return: None
    """
    self._terminate_event.set()

  def get(self) -> Packet:
    if not self._terminate_event.is_set():
      try:
        data, _ = self._sock.recvfrom(Feed._BUFFER_LEN)
        received_time = time.time()

        # breaking early so unit tests don't throw annoying error
        if self._terminate_event.is_set():
          return

      except Exception as e:
        raise ReadError(f'Failed to read message on port {self._BIND_PORT}: {e}')

      data = self._decrypter.decrypt(data)
      packet = Packet.from_bytes(data, received_time)
      return packet

  def send_heartbeat(self) -> None:
    if not self._terminate_event.is_set():
        self._sock.sendto(self._HEARTBEAT_MESSAGE, (self._addr, self._HEARTBEAT_PORT))
    else:
        self._sock.close()
        self._sock_bounded = False

  @staticmethod
  def _init_sock_() -> socket.socket:
    # Create a datagram socket
    sock = socket.socket(socket.AF_INET,  # Internet
                         socket.SOCK_DGRAM)  # UDP
    # Enable immediate reuse of IP address
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.settimeout(Feed._HEARTBEAT_DELAY)
    # Bind the socket to the port
    sock.bind(('', Feed._BIND_PORT))

    return sock

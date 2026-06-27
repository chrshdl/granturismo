"""Stream live suspension heights to the terminal.

Usage: python3 examples/stream_suspension.py <playstation-ip>
"""

import curses
import datetime as dt
import sys
import time

from granturismo import Feed
from granturismo.model import Wheels

stdscr = curses.initscr()


def report_suspension(wheels: Wheels) -> None:
    now = dt.datetime.fromtimestamp(time.time()).isoformat()
    stdscr.addstr(0, 0, f"[{now}] Suspension Height")
    stdscr.addstr(1, 0, f"\t{wheels.front_left.suspension_height:.3f}    "
                        f"{wheels.front_right.suspension_height:.3f}")
    stdscr.addstr(2, 0, f"\t{wheels.rear_left.suspension_height:.3f}    "
                        f"{wheels.rear_right.suspension_height:.3f}")
    stdscr.refresh()


if __name__ == "__main__":
    ip_address = sys.argv[1]
    try:
        with Feed(ip_address) as feed:
            while True:
                packet = feed.get_latest(timeout=1.0)
                if packet is None:
                    continue
                if not packet.flags.loading_or_processing and not packet.flags.paused:
                    report_suspension(packet.wheels)
    finally:
        curses.echo()
        curses.nocbreak()
        curses.endwin()

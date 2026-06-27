"""Grab a single telemetry packet and print it.

Usage: python3 examples/quickstart.py <playstation-ip>
"""

import sys

from granturismo import Feed

if __name__ == "__main__":
    ip_address = sys.argv[1]
    with Feed(ip_address) as feed:
        print(feed.get())

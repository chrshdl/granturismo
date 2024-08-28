from granturismo import Feed
import sys

from granturismo.security.decrypter import GT_Version

if __name__ == '__main__':
  ip_address = sys.argv[1]
  with Feed(ip_address, GT_Version.GT7) as feed:
    print(feed.get())

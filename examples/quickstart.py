from granturismo import Feed, GT_Version
import sys

if __name__ == '__main__':
  ip_address = sys.argv[1]
  with Feed(ip_address, GT_Version.GT7) as feed:
    print(feed.get())

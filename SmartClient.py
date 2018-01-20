#!/usr/bin/python3

import sys
import ssl
import socket
#import hpack?

print(sys.argv)

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(("www.python.org", 80))
s.sendall("GET http://www/python/org HTTP/1.0 \n\n")
print s.recv(4096)
s.close()

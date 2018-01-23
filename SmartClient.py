#.recv(4096)!/usr/bin/python3
import re
import sys
import ssl
import socket
#import hpack?

if(len(sys.argv) < 2):
	print("Please add url as command line argument")
	sys.exit()

url = sys.argv[1]
matchhttp = "^http://"
matchhttps = "^https://"
urlstatus = 0

if (re.match(matchhttp, url)):
	urlstatus = 1
elif(re.match(matchhttps, url)):
	urlstatus = 2

print(urlstatus)	

'''
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(("www.python.org", 80))
s.sendall("GET http://www/python/org HTTP/1.0 \n\n")
print s.recv(4096)
s.close()
'''

#!/usr/bin/python3
import re
import sys
import ssl
import socket
#import hpack?

def getInfo(info):
	match = re.search("HTTP/([12].[01]) (\d\d\d)", info)
	if(match):
		print(match.group(1))
		print(match.group(2))
		return match.group(1), match.group(2)
	else:
		print("yikes")

'''
def parseUrl(url):
	matchhttp = "^http://" #regular expression to check what is at the beggingin of the url
	matchhttps = "^https://" #as above
	urlstatus = 0 #0 is nothing, 1 is http://, 2 is https://

	if (re.match(matchhttp, url)): #check if http at begginging of url
		urlstatus = 1
	elif(re.match(matchhttps, url)): #check if https at begginging of url
		urlstatus = 2
	return url, urlstatus
'''

def connectHTTPS(url):
	print("connectHTTPS")
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
	ssls = ssl.wrap_socket(s, ssl_version = ssl.PROTOCOL_SSLv23)
	IP = socket.gethostbyname(url)
	ssls.connect((IP, 443))
	ssls.write(("GET / HTTP/1.1\r\nHost: " + url +"\r\nConnection: close\r\n\r\n").encode('latin-1'))
	responce = ssls.recv(4096).decode('latin-1')
	ssls.close()
	return responce

def connectHTTP(url):
	print("connectHTTP")
'''
def connect(url, port):

	print("connect")
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
	ssls = ssl.wrap_socket(s, ssl.PROTOCOL_TLSv1, "ADH-AES256-SHA")
	IP = socket.gethostbyname(url)
	ssls.connect((IP, 443))
	ssls.sendall("HEAD https://" + url + "  HTTP/1.1 \n\n")
	print ssls.recv(4096)

	ssls.close()

	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
	s.connect((url, port))
	s.sendall("HEAD http://" + url + "  HTTP/1.1 \n\n")
	print s.recv(4096)

	s.close()
'''

if(len(sys.argv) < 2): #make sure that we are given a command line argument
	print("Please add url as command line argument")
	sys.exit()

#url, urlstatus = parseUrl(sys.argv[1]) #the command line argument should be a url
url = sys.argv[1]
print(url)
results = connectHTTPS(url)
print(results)
getInfo(results)

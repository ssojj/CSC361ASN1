#!/usr/bin/python3
#coded on python 3.6.4

#Author: Joss Vrooman, V00813897
#CSC361 Assignment 1

import re
import sys
import ssl
import socket

#--General----------------------------------------------------------------------------------------------------------------------------------------------------------

#on redirect find info on https vs http and the status code
def getNewLocation(info):
	match = re.search("Location: (https?)://([^/]*)/", info)
	if(match):
		return match.group(1), match.group(2)
	else:
		print("Error in getNewLocation")

#fetches the response code and the HTTP version from the response
def getInfo(info):
	match = re.search("HTTP/([12].[01]) (\d\d\d)", info)
	if(match):
		return match.group(1), match.group(2)
	else:
		print("Error in getInfo")

#--HTTPS----------------------------------------------------------------------------------------------------------------------------------------------------------

#Find if the server supports https
def findHTTPS(url):
	try:
		for i in range(10):
			results = connectHTTPS(url) 
			version, reCo = getInfo(results) #finds the http version and response code
			if (reCo == '302' or reCo == '301' or reCo == '505'): #on redirect code
				list = getNewLocation(results)#find redirect
				url = list[1]#and try again
			elif(reCo == '200'):#on okay we know they support https
				return True
			else:#on error
				print("Unexpected response code: " + reCo) 
				sys.exit()
	except:
		print("Error connecting on HTTPS: " + url)#//
		return False

#try to connect https 1.1
def connectHTTPS(url):
	#build socket
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
	#wrap soccket
	ssls = ssl.wrap_socket(s, ssl_version = ssl.PROTOCOL_SSLv23)
	IP = socket.gethostbyname(url)
	ssls.connect((IP, 443))
	#send request
	ssls.write(("GET / HTTP/1.1\r\nHost: " + url +"\r\nConnection: close\r\n\r\n").encode('latin-1'))
	responce = ssls.recv(4096).decode('latin-1')
	ssls.close()
	return responce		

#--HTTP Version----------------------------------------------------------------------------------------------------------------------------------------------------------

#connect on HTTP on given version
def connectHTTP(url, version):
	#build socket
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
	s.connect((url, 80))
	#send request
	s.sendall(("GET / HTTP/"+version+ "\r\nHost: " + url +"\r\nConnection: close\r\n\r\n").encode('latin-1'))
	responce = s.recv(4096).decode('latin-1')
	s.close()
	return responce	

#finds highest HTTP version to use	
def findVersion(url, httpsStatus):
	try: #try http 2.0
		for i in range(10):
			results = connectHTTPS(url)
			version, reCo = getInfo(results) #finds the http version and response code
			if (reCo == '302' or reCo == '301' or reCo == '505'): #on redirect code
				list = getNewLocation(results)#find redirect
				url = list[1]#and try again
				continue
			elif(reCo != '200'):#
				print("Unexpected response code: " + reCo) 
				sys.exit()
			
			if(checkHTTP2(url)):
				return('2.0')
			else:
				break
	except:
		pass
		#print("Error in findVersion: 2.0")
	
	try:#try HTTP 1.1
		for i in range(10):
			if(httpsStatus):
				results = connectHTTPS(url)
			else:
				results = connectHTTP(url, '1.1')
			version, reCo = getInfo(results)
			if (reCo == '302' or reCo == '301' or reCo == '505'): #on redirect code
				list = getNewLocation(results)#find redirect
				url = list[1]#and try again
				continue
			elif(reCo != '200'):#
				print("Unexpected response code: " + reCo) 
				sys.exit()
			if(version == '1.1'):
				return '1.1'
	except:
		pass
		#print("Error in findVersion: 1.1")
		
	try:#try HTTP 1.0
		for i in range(10):
			results = connectHTTP(url, '1.0')
			version, reCo = getInfo(results)
			if (reCo == '302' or reCo == '301' or reCo == '505'): #on redirect code
				list = getNewLocation(results)#find redirect
				url = list[1]#and try again
				continue
			elif(reCo != '200'):#
				print("Unexpected response code: " + reCo) 
				sys.exit()
			if(version == '1.0'):
				return '1.0'
		print("To many redirects")
	except:
		pass
		#print("Error in findVersion: oops3")	
		
	return "Unable to connect and determine HTTP version"
	

#--Cookies----------------------------------------------------------------------------------------------------------------------------------------------------------

#gets cookies from spot depending on if server accepts
#https and http version
def getCookies(url, httpsStatus, version):
	if(httpsStatus):#https
		for i in range(10):
			results = connectHTTPS(url) 
			version, reCo = getInfo(results) #finds the http version and response code
			if (reCo == '302' or reCo == '301'): #on redirect code
				list = getNewLocation(results)#find redirect
				url = list[1]#and try again
			elif(reCo == '200'):#on okay we know they support https
				break
			else:
				print("Unexpected response code: " + reCo) 
				sys.exit()
	else:#http
		for i in range(10):
			results = connectHTTP(url, version)
			version, reCo = getInfo(results)
			if (reCo == '302' or reCo == '301'): #on redirect code
				list = getNewLocation(results)#find redirect
				url = list[1]#and try again
				continue
			elif(reCo == '200'):#
				break;
			elif(reCo == '505'):
				version = '1.0'
			else:
				print("Unexpected response code: " + reCo) 
				sys.exit()
	
	
	#return only the stuff we want
	match = re.findall("Set-Cookie: (.*)", results)
	
	return match

#find the name and key of a cookie
def parseNameKey(cookie):
	match = re.search("([^=]*)=([^;]*);", cookie)
	return match.group(1), match.group(2)

#find the domain of a cookie
#note that not every cookie has a domain
#so its in a seperate function
def parseDomain(cookie):
	match = re.search("[Dd]omain=(.*);?", cookie)
	return match.group(1)
		
#--HTTP2----------------------------------------------------------------------------------------------------------------------------------------------------------
#PLEASE NOTE:
#This is not my work anything below this until the main
#method was taken from
#https://python-hyper.org/projects/h2/en/stable/negotiating-http2.html
#and all credit should go to them for this code	
def negotiate_tls(tcp_conn, context, url):
    """
    Given an established TCP connection and a HTTP/2-appropriate TLS context,
    this function:

    1. wraps TLS around the TCP connection.
    2. confirms that HTTP/2 was negotiated and, if it was not, throws an error.
    """
    # Note that SNI is mandatory for HTTP/2, so you *must* pass the
    # server_hostname argument.
    tls_conn = context.wrap_socket(tcp_conn, server_hostname=url)

    # Always prefer the result from ALPN to that from NPN.
    # You can only check what protocol was negotiated once the handshake is
    # complete.
    negotiated_protocol = tls_conn.selected_alpn_protocol()
    if negotiated_protocol is None:
        negotiated_protocol = tls_conn.selected_npn_protocol()

    if negotiated_protocol != "h2":
        return False

    return True
		
def checkHTTP2(url):
	# Step 1: Set up your TLS context.
    context = get_http2_ssl_context()

    # Step 2: Create a TCP connection.
    connection = establish_tcp_connection(url)

    # Step 3: Wrap the connection in TLS and validate that we negotiated HTTP/2
    return negotiate_tls(connection, context, url)
		
def establish_tcp_connection(url):
    """
    This function establishes a client-side TCP connection. How it works isn't
    very important to this example. For the purpose of this example we connect
    to localhost.
    """
    return socket.create_connection((url, 443))


def get_http2_ssl_context():
    """
    This function creates an SSLContext object that is suitably configured for
    HTTP/2. If you're working with Python TLS directly, you'll want to do the
    exact same setup as this function does.
    """
    # Get the basic context from the standard library.
    ctx = ssl.create_default_context(purpose=ssl.Purpose.SERVER_AUTH)

    # RFC 7540 Section 9.2: Implementations of HTTP/2 MUST use TLS version 1.2
    # or higher. Disable TLS 1.1 and lower.
    ctx.options |= (
        ssl.OP_NO_SSLv2 | ssl.OP_NO_SSLv3 | ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1
    )

    # RFC 7540 Section 9.2.1: A deployment of HTTP/2 over TLS 1.2 MUST disable
    # compression.
    ctx.options |= ssl.OP_NO_COMPRESSION

    # RFC 7540 Section 9.2.2: "deployments of HTTP/2 that use TLS 1.2 MUST
    # support TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256". In practice, the
    # blacklist defined in this section allows only the AES GCM and ChaCha20
    # cipher suites with ephemeral key negotiation.
    ctx.set_ciphers("ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20")

    # We want to negotiate using NPN and ALPN. ALPN is mandatory, but NPN may
    # be absent, so allow that. This setup allows for negotiation of HTTP/1.1.
    ctx.set_alpn_protocols(["h2", "http/1.1"])

    try:
        ctx.set_npn_protocols(["h2", "http/1.1"])
    except NotImplementedError:
        print("BAD@get_http2_ssl_context")
	
    return ctx

#--MAIN---------------------------------------------------------------------------------------------------------------------------------------------------------
#The following is my (Joss Vrooman) code	
if(len(sys.argv) < 2): #make sure that we are given a command line argument
	print("Please add url as command line argument")
	sys.exit() 	

url = sys.argv[1]#url
httpsStatus = findHTTPS(url)#find if HTTPS is supported
print("Website: " + url)
if(httpsStatus):
	print("Support of HTTPS: True")
else:
	print("Support of HTTPS: False")
version = findVersion(url, httpsStatus)#find the HTTP version
print("HTTP Version: HTTP/" + version)
#if HTTP is supported find cookies
if(version == '2.0' or version == '1.1' or version == '1.0'):
	#find cookies
	cookies = getCookies(url, httpsStatus, version)
	print("List of Cookies:")
	#for each cookie find the name key and domain 
	#and make it look nice
	for i in cookies:
		name, key = parseNameKey(i)
		domain = "";
		try:
			domain = parseDomain(i)
		except:
			pass
		if(name and key and domain):
			print("Name: " + name + "; Key: " + key + "; Domain: " + domain)
		else:
			print("Name: " + name + "; Key: " + key)
	

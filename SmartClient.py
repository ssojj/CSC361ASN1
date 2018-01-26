#!/usr/bin/python3
import re
import sys
import ssl
import socket
#import h2
#import hpack?

#NOTES
#
#Need to handle statues codes: 505, 404, 301, 302, 200

#--General----------------------------------------------------------------------------------------------------------------------------------------------------------

#if we need to connect somewhere else
def getNewLocation(info):
	match = re.search("Location: (https?)://(.*)/", info)
	if(match):
		print("new location:" + match.group(1) + " " + match.group(2))
		return match.group(1), match.group(2)
	else:
		print("yikes2")

#fetches the response code and the HTTP version from the response
def getInfo(info):
	match = re.search("HTTP/([12].[01]) (\d\d\d)", info)
	if(match):
		print("new Info:" + match.group(1) + " " + match.group(2))
		return match.group(1), match.group(2)
	else:
		print("yikes")

def connectHTTP(url):
	print("connectHTTP")

#--HTTPS----------------------------------------------------------------------------------------------------------------------------------------------------------

#Find if the server supports https
def findHTTPS(url):
	try:
		for i in range(10):
			results = connectHTTPS(url) 
			#print(results)#//
			version, reCo = getInfo(results) #finds the http version and response code
			if (reCo == '302' or reCo == '301'): #on redirect code
				list = getNewLocation(results)#find redirect
				url = list[1]#and try again
			elif(reCo == '200'):#on okay we know they support https
				return True
			else:
				print("Unexpected response code: " + reCo) 
				sys.exit()
	except:
		print("Error connecting on HTTPS: " + url)#//
		return False

#try to connect https 1.1
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

#--HTTP Version----------------------------------------------------------------------------------------------------------------------------------------------------------

def findVersion(url):
	try:
		for i in range(10):
			results = connectHTTPS(url)
			version, reCo = getInfo(results) #finds the http version and response code
			if (reCo == '302' or reCo == '301'): #on redirect code
				list = getNewLocation(results)#find redirect
				url = list[1]#and try again
				continue
			elif(reCo != '200'):#
				print("Unexpected response code: " + reCo) 
				sys.exit()
			
			if(checkHTTP2(url)):
				return(2.0)
			else:
				break
	except Exception as e:
		print(e)
		print("oops")
		
	

#--Cookies----------------------------------------------------------------------------------------------------------------------------------------------------------



#--H2?----------------------------------------------------------------------------------------------------------------------------------------------------------
		
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
	
if(len(sys.argv) < 2): #make sure that we are given a command line argument
	print("Please add url as command line argument")
	sys.exit()

url = sys.argv[1]
print(url)
if(findHTTPS(url)):
	print("HTTPS true")
else:
	print("HTTPS false")
if(findVersion(url)):
	print("H2 TRUE")
else:
	print("H2 FALSE")

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
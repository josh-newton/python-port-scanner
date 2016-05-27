#!/usr/bin/python
import argparse
import socket
from socket import *

def connScan(tgtHost, tgtPort):
	try:
		connSkt = socket(AF_INET, SOCK_STREAM)
		connSkt.connect((tgtHost, tgtPort))
		connSkt.send('Hello\r\n')
		results = connSkt.recv(200)
		print '[+] %d open'% tgtPort
		# print '[+] ' + str(results)
	except:
		print '[-] %d closed'% tgtPort

def portScan(tgtHost, tgtPorts):
	try:
		tgtIP = gethostbyname(tgtHost)
	except:
		print '[-] Cannot resolve "%s": unknown host'%tgtHost
		return
	try:
		tgtName = gethostbyaddr(tgtIP)
		print '\n[+] Scan results for: ' + tgtName[0]
	except:
		print '\n[+] Scan results for: ' + tgtIP
	setdefaulttimeout(1)
	for tgtPort in tgtPorts:
		connScan(tgtHost, int(tgtPort))

def main():
	parser = argparse.ArgumentParser('%prog -H <target host> -p <target ports>')
	parser.add_argument('-H', dest='tgtHost', help='Specify target host')
	parser.add_argument('-p', dest='tgtPort', help='Specify target port[s] separated by comma')
	args = parser.parse_args()

	tgtHost = args.tgtHost
	tgtPorts = str(args.tgtPort).split(',')

	if (tgtHost == None):
		print '[-] You must specify a target host and port[s]'
		exit(0)
	elif (tgtPorts[0] == 'None'):
		# ftp, ssh, smtp, http, altHttp, pop3, imap, sql, irc, https
		tgtPorts = ['21', '22', '25', '80', '8080', '110', '143', '156', '194','443']

	# If '*' wildcard is used
	if(tgtHost[-2:] == '.*'):
		# chop off the '*'
		tgtHost = tgtHost[:-1]
		# Scan each ip address up to .254
		for x in range(254):
			host = tgtHost + str(x)
			portScan(host, tgtPorts)
	else:
		portScan(tgtHost, tgtPorts)

if __name__ == '__main__':
	main()

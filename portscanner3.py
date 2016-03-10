#! /usr/bin/python
# reference code adapted from: http://www.pythonforbeginners.com/code-snippets-source-code/port-scanner-in-python
# reference code adapted from: http://www.secdev.org/projects/scapy/build_your_own_tools.html
# reference code adapted from: http://securitylair.wordpress.com/2014/02/21/simple-port-scanner-in-python-with-scapy-2
# code primarily intended for use in command prompt on Kali Linux operating system

# first see if user wants to use ICMP protocol in their scan
from logging import getLogger, ERROR
getLogger("scapy.runtime").setLevel(ERROR)
from scapy.all import *
import sys
import time
import logging

# Have the user identify the target remote host
ip    = raw_input("Enter a remote host to scan: ")

# see if user wants to perform icmp echo scan
icmpChoice	= raw_input("Do you want to use ICMP echo protocol for your scan (y/n)?: ")

# icmp tests if the host is up
if icmpChoice == "y":
	icmp = IP(dst=ip)/ICMP()
	resp = sr1(icmp, timeout=10)
	if resp == None:
		print "Remote host %s is not responding to icmp." % ip
	else:
		print "Remote host %s is up." % ip	

# see if user wants to perform typical TCP protocol scan
TCPChoice	= raw_input("Do you want to use TCP protocol for your scan (y/n)?: ")

# if user doesn't want TCP protocol, then exit the script
if TCPChoice == "n":
	print "Scan terminated."
	sys.exit()

# if user does want TCP protocol, we perform that scan with the rest of our code
import socket
import subprocess
import sys
from datetime import datetime

# Have the user identify the continuous range of ports to scan
desiredPortLow = 2
desiredPortHigh = 1
while desiredPortLow > desiredPortHigh:
	desiredPortLow 	= raw_input("  Enter the lowest port number of the desired range of ports to scan (0-65535): ")
	desiredPortHigh = raw_input("  Enter the highest port number of the desired range of ports to scan (0-65535): ")
	if desiredPortLow > desiredPortHigh:
		print "The lowest port number must be less than or equal to the highest port."

remoteServerIP  = socket.gethostbyname(ip)

#  Tell the user that remote host is being scanned
print "Scanning of", remoteServerIP, "in progress..."

# Check what time the scan started
t1 = datetime.now()

# Range function specifies ports previously input by the user
# Socket function was imported at start of this code
# syntax for socket function is socket.socket([family[, type[, proto]]])
# family is AF_INET address for a pair (host, port) where port is integer and host is string of IP address or hostname in domain notation 
# type default is SOCK_STREAM
# If socket function returns a zero, it means port is open
try:
    for port in range(int(desiredPortLow),int(desiredPortHigh)): 
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        result = sock.connect_ex((remoteServerIP, port))
        if result == 0:
            print "Port {}: 	 Open".format(port)
        sock.close()

# the following is to handle various types of errors
		
# if scan is taking too long, want to be able to interrupt it
except KeyboardInterrupt:
    print "You pressed Ctrl+C"
    sys.exit()

# if scan gets a gaierror give error message an exit
except socket.gaierror:
    print 'Hostname could not be resolved. Exiting'
    sys.exit()

# if couldn't connect to server for whatever reason, give error message
except socket.error:
    print "Couldn't connect to server"
    sys.exit()

# notify the user that if no ports were listed as open, than the range scanned had no open ports
print ("If no ports were listed as open above, then the range of ports scanned (%d to %d) had no open ports") % (int(desiredPortLow), int(desiredPortHigh))
	
# the following is to report on how long the scan took
# Get the time after the scan is complete
t2 = datetime.now()

# See how long it took to run the scan
totalScanTime =  t2 - t1

# Printing the information to screen
print 'Time to complete the scan (Hours:Minutes:Seconds): ', totalScanTime
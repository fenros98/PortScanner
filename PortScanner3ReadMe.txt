portscanner3.py Read Me
by username fenros98 on github
10MAR2016

This python code allows a user to scan ports on a remote host computer.

Note that such a scan should only be performed if you have written permission by the owner of that host machine.

The code was primarily written for use in the command prompt on Kali Linux operating system.  It probably will not work on Windows 10 machines unless additional software is installed so that Scapy can be imported.  However, the ICMP portion of the code can be removed and it works on Windows 10.

To use the program, open a Kali Linux command prompt and navigate so the current directory is where this code file is located.
Then type "python portscanner3.py" and press enter to activate the code.

The main inputs required of the user are as follows:
	A single remote host ip address
	Whether or not you want to perform ICMP echo on that remote host
	Whether or not you want to perform TCP protocol scan on that remote host
	What continuous range of ports you want to scan
	
The main outputs the program returns are:
	Whether or not the host is up based on the ICMP scan of remote host
	Any ports that are open on the remote host based on the TCP scan
	The time it took to perform the TCP scan for the entire specified range of ports on the remote host
	
Future areas for improving the code would include:
	Allowing entry of multiple remote host addresses at once as a range (e.g. 192.168.100.0-255)
	Allowing remote host to be identified using subnet
	Incorporating traceroute into the scans
	Exporting the results as a PDF or HTML
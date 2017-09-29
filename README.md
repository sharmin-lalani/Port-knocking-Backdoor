# Port-knocking-Backdoor
A Linux backdoor that is activated using a “port knocking” scheme

backdoor.cpp:

It is a hidden backdoor service that passively scans incoming packets.
When a client makes connection attempts on a prespecified sequence of closed ports, it fetches a Linux command from a preconfigured remote server and executes it.

Command execution syntax: `backdoor <path-to-config-file> <URL>`

The configuration file will contain the port sequence (one number per line). 
After the program has received the correct packets in the correct order that match the port-knocking sequence 
it makes a request to the URL parameter, fetches a linux command and executes it in the local system.

Note: run the program as root to get access to raw sockets.

knocker.c:

The configuration file will contain the port sequence (one per line) 
and the IP address should be the target IPv4 address that runs the backdoor service.

Command execution syntax: `knocker <path-to-config-file> <backdoor-IP>`

The primary purpose of port knocking is to prevent an attacker 
from scanning a system for potentially exploitable services by doing a port scan.
Unless the attacker sends the correct knock sequence, the protected ports will appear closed.

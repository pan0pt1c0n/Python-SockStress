Proof of Concept on my blog at:
http://www.pan0pt1c0n.net/sockstress-denial-of-service-with-python-2/

		***Basic Usage***
Usage - ./sock_stress.py [Target-IP] [Port Number] [Threads]
Example - ./sock_stress.py 10.0.0.5 21 20
Example will perform a 20x multi-threaded sock-stress DoS attack
against the FTP (port 21) service on 10.0.0.5

		***NOTE***
Make sure you target a port that responds when a connection is made


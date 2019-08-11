#!/bin/bash

#example sender/receiver:
#ik wil netflix film kijken
#host1: source     /netflix
#host2: destination/ikke
#host1: sent path mesg
#host2: sent resv mesg
#host1: als resv mesg aankomt: set TOS byte op session
#host1: sent CONF mesg als CONF boolean = 1
(sleep 0.5; echo 'write host1/rsvpHost.session ID 1, DST 192.168.11.1, PORT 2222') | telnet localhost 10001
#setup session
(sleep 0.5; echo 'write host2/rsvpHost.session ID 1, DST 192.168.11.1, PORT 2222') | telnet localhost 10004
#setup session
(sleep 0.5; echo 'write host1/rsvpHost.sender ID 1, SRC 192.168.10.1, PORT 7') | telnet localhost 10001
#sent path messages
sleep 10; (sleep 0.5; echo 'write host2/rsvpHost.reserve ID 1, CONF 1') | telnet localhost 10004 #sent reserve messages
#als resv message aankomt: set TOS byte
sleep 10; (sleep 0.5; echo 'write host1/rsvpHost.release ID 1') | telnet localhost 10001
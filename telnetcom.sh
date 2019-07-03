#!/bin/sh

echo 'Start bash script for sending packages'

(sleep 0.5; echo 'write host1/host.session ID 1, DST 192.168.11.1, PORT 24'; sleep 0.5; echo 'write host1/host.sender ID 1, SRC 192.168.10.1, PORT 24'; sleep 0.5; echo 'quit') | telnet localhost 10001
(sleep 0.5; echo 'write host2/host.session ID 1, DST 192.168.10.1, PORT 24'; sleep 0.5; echo 'write host2/host.reserve ID 1, CONF 1'; sleep 0.5; echo 'quit') | telnet localhost 10004

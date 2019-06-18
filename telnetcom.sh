#!/bin/sh

echo 'Start bash script for sending packages'

(sleep 0.5; echo 'write host1/host.session SID 1, DST_ADDR 192.168.11.1, DST_PORT 24'; sleep 0.5; echo 'write host1/host.sender SID 1, ADDR 192.168.10.1, PORT 24'; sleep 0.5; echo 'quit') | telnet localhost 10001
(sleep 0.5; echo 'write host2/host.session SID 1, DST_ADDR 192.168.10.1, DST_PORT 24'; sleep 0.5; echo 'write host2/host.sender SID 1, ADDR 192.168.11.1, PORT 24'; sleep 0.5; echo 'quit') | telnet localhost 10004

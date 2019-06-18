#!/bin/sh

sudo ./scripts/start_click.sh &
telnet localhost 10001 &
write host1/host.session SID 1, DST_ADDR 192.168.11.1, DST_PORT 24 &
write host1/host.sender SID 1, ADDR 192.168.10.1, PORT 24 &
write host2/host.session SID 2, DST_ADDR 192.168.10.1, DST_PORT 24 &
write host2/host.sender SID 2, ADDR 192.168.11.1, PORT 24 &

wait
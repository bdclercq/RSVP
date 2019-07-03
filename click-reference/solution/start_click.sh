#!/bin/sh

cd /home/student/click-reference/solution/

./glue.bin &
./host1.bin & # port 10001
./router1.bin & # port 10002
./router2.bin & # port 10003
./host2.bin & # 10004

wait

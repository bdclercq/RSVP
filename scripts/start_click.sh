#!/bin/sh

cd /home/student/click/scripts/

../userlevel/click glue.click &
../userlevel/click -p 10001 host1.click &
../userlevel/click -p 10002 router1.click &
../userlevel/click -p 10003 router2.click &
../userlevel/click -p 10004 host2.click &

wait

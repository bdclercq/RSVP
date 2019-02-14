#!/bin/sh

# tunctl is provided by package uml-utilities
for i in `seq 0 6`; do
	tunctl && ip link set dev tap$i up
done

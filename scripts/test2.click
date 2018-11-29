AddressInfo(host1_address 192.168.10.1/24 00:00:00:00:10:01);
AddressInfo(host2_address 192.168.11.1/24 00:00:00:00:11:01);

rsvpsource::RSVPSource(host1_address, host2_address);

rsvpsource -> IPEncap(PROTO 46, SRC host1_address, DST host2_address) -> EtherEncap(0x0800, 1:1:1:1:1:1, 2:2:2:2:2:2) -> ToDump(test2.pcap);
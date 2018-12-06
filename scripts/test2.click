AddressInfo(host1_address 192.168.10.1/24 00:00:00:00:10:01);
AddressInfo(host2_address 192.168.11.1/24 00:00:00:00:11:01);

rsvpsource::RSVPSource();
osource::ICMPPingSource(host1_address, host2_address, INTERVAL 0.2, LIMIT 20);

osource -> rsvpsource -> EtherEncap(0x0800, 1:1:1:1:1:1, 2:2:2:2:2:2) -> ToDump(test2.pcap);
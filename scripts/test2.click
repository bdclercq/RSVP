AddressInfo(host1_address 192.168.10.1/24 00:00:00:00:10:01);
AddressInfo(host2_address 192.168.11.1/24 00:00:00:00:11:01);

src::RSVPHost(host1_address:ip);
osource::ICMPPingSource(host1_address, host2_address, INTERVAL 0.2, LIMIT 20);
//-> RSVPNode(157.154.20.1) -> RSVPHost(host2_address:ip)
osource -> src -> ToDump(test2.pcap);
// !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
// ! DO NOT CHANGE THIS FILE: Any changes will be removed prior to the project defense. !
// !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!

require(library routers/definitions.click)
require(library routers/bandwidthlimiter.click)
require(library routers/host.click)

FromHost(tap0) 
	-> host1_rx_tee :: Tee(2)
	-> host1 :: Host(host1_address, router1_lan_address)
	-> host1link :: BandwidthLimiter(1000kbps)
	-> host1_tx_tee :: Tee(2)
	-> ToHost(tap0);
host1[1] -> Discard;

host1_tx_tee[1]
	-> Classifier(12/0800)
	-> host1_tx_qos_cl :: IPClassifier(ip tos 0, -)
	-> host1_tx_be_ctr :: AverageCounter
	-> Discard;

host1_tx_qos_cl[1]
	-> host1_tx_qos_ctr :: AverageCounter
	-> Discard;

host1_rx_tee[1]
	-> HostEtherFilter(host1_address:eth)
	-> Classifier(12/0800)
	-> host1_rx_qos_cl :: IPClassifier(ip tos 0, -)
	-> host1_rx_be_ctr :: AverageCounter
	-> Discard;

host1_rx_qos_cl[1]
	-> host1_rx_qos_ctr :: AverageCounter
	-> Discard;




// Traffic generators
// QoS traffic
RatedSource(LENGTH 83, RATE 300)
	-> DynamicUDPIPEncap(host1_address:ip, 7, host2_address:ip, 2222)
	-> EtherEncap(0x0800, host1_address:eth, host1_address:eth)
	-> host1;

// Best Effort traffic
RatedSource(LENGTH 83, RATE 500)
        -> DynamicUDPIPEncap(host1_address:ip, 7, host2_address:ip, 3333)
        -> EtherEncap(0x0800, host1_address:eth, host1_address:eth)
        -> host1;

// Best Effort traffic
RatedSource(LENGTH 83, RATE 500)
        -> DynamicUDPIPEncap(host1_address:ip, 8, host2_address:ip, 4444)
        -> EtherEncap(0x0800, host1_address:eth, host1_address:eth)
        -> host1;

// !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
// ! DO NOT CHANGE THIS FILE: Any changes will be removed prior to the project defense. !
// !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!

require(library routers/definitions.click)
require(library routers/bandwidthlimiter.click)
require(library routers/router.click)

FromHost(tap5)
	-> router2 :: Router(router2_lan_address, router2_wan_address, global_router_address)
	-> BandwidthLimiter(1000kbps)
	-> router2_tx_tee :: Tee(2)
	-> ToHost(tap5);

FromHost(tap4)
	-> [1]router2[1] 
	-> BandwidthLimiter(1000kbps)
	-> router2_rx_tee :: Tee(2)
	-> ToHost(tap4);


// Again count the traffic, but this time on router2
router2_rx_tee[1]
	-> HostEtherFilter(router2_lan_address:eth)
	-> Classifier(12/0800)
	-> MarkIPHeader(14)
	-> router2_rx_qos_cl :: IPClassifier(ip tos 0, -)
	-> router2_rx_be_ctr :: AverageCounter
	-> Discard;
router2_rx_qos_cl[1]
	-> router2_rx_qos_ctr :: AverageCounter
	-> Discard;
router2_tx_tee[1]
	-> router2_tx_qos_cl :: IPClassifier(ip tos 0, -)
	-> router2_tx_be_ctr :: AverageCounter
	-> Discard;
router2_tx_qos_cl[1]
	-> router2_tx_qos_ctr :: AverageCounter
	-> Discard;
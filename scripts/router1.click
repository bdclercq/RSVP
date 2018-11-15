// !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
// ! DO NOT CHANGE THIS FILE: Any changes will be removed prior to the project defense. !
// !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!

require(library routers/definitions.click)
require(library routers/bandwidthlimiter.click)
require(library routers/router.click)

FromHost(tap1)
	-> router1 :: Router(router1_lan_address, router1_wan_address, global_router_address)
	-> BandwidthLimiter(1000kbps)
	-> ToHost(tap1);

FromHost(tap2) 
	-> [1]router1[1] 
	-> BandwidthLimiter(1000kbps)
	-> ToHost(tap2);

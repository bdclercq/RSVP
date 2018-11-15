// !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
// ! DO NOT CHANGE THIS FILE: Any changes will be removed prior to the project defense. !
// !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!

require(library routers/definitions.click)
require(library routers/bandwidthlimiter.click)
require(library routers/host.click)

FromHost(tap6)
	-> host2 :: Host(host2_address, router2_lan_address)
	-> ToHost(tap6);

host2[1] -> Discard;

// !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
// ! DO NOT CHANGE THIS FILE: Any changes will be removed prior to the project defense. !
// !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!

require(library routers/definitions.click)
require(library routers/globalrouter.click)

global_router :: GlobalRouter(global_router_address);

network1::ListenEtherSwitch;
cloud::ListenEtherSwitch;
network2::ListenEtherSwitch;


FromDevice(tap0) -> [0]network1[0] -> Queue  -> ToDevice(tap0);
FromDevice(tap1) -> [1]network1[1] -> Queue -> ToDevice(tap1);

FromDevice(tap2) -> [0]cloud[0] -> Queue -> ToDevice(tap2);
FromDevice(tap3) -> [1]cloud[1] -> Queue -> ToDevice(tap3);
FromDevice(tap4) -> [2]cloud[2] -> Queue -> ToDevice(tap4);

FromDevice(tap5) -> [0]network2[0] -> Queue -> ToDevice(tap5);
FromDevice(tap6) -> [1]network2[1] -> Queue -> ToDevice(tap6);


network1[2] -> ToDump(network1.pcap);
cloud[3]    -> ToDump(cloud.pcap);
network2[2] -> ToDump(network2.pcap);


FromHost(tap3) -> global_router -> ToHost(tap3);

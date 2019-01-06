// Output configuration: 
//
// Packets for the network are put on output 0
// Packets for the host are put on output 1
elementclass Host {
	$address, $gateway |

        dest :: RSVPDest();
        src :: RSVPSource();
        tee :: Tee(2);

	// Shared IP input path
	ip1 :: Strip(14)
		-> CheckIPHeader
        -> tee;

        tee[0]
            -> dest
            -> rt;

        tee[1]
            -> src
            -> rt;
 
        rt :: StaticIPLookup(
			$address:ip/32 0,
			$address:ipnet 1,
			0.0.0.0/0 $gateway 1)
		-> [1]output;

	rt[1]
		-> ipgw :: IPGWOptions($address)
		-> FixIPSrc($address)
		-> ttl :: DecIPTTL
		-> frag :: IPFragmenter(1500)
        -> qos_classifier :: IPClassifier(ip dscp = 1, -)
        -> qos_queue :: Queue
        -> [0]scheduler :: PrioSched
        // For classifying
        qos_classifier[1]
            -> be_queue :: Queue
            -> [1]scheduler
        // For scheduling
        scheduler
            -> LinkUnqueue(0, 1000)
		-> arpq :: ARPQuerier($address)
		-> output;

	ipgw[1]	-> ICMPError($address, parameterproblem)
		-> output;

	ttl[1]	-> ICMPError($address, timeexceeded)
		-> output;

	frag[1]	-> ICMPError($address, unreachable, needfrag)
		-> output;

	// incoming packets
	input	-> HostEtherFilter($address)
		-> in_cl :: Classifier(12/0806 20/0001, 12/0806 20/0002, 12/0800)
		-> arp_res :: ARPResponder($address)
		-> output;

	in_cl[1]
		-> [1]arpq;

	in_cl[2]
		-> ip;
}

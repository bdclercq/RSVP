// Output configuration: 
//
// Packets for the network are put on output 0
// Packets for the host are put on output 1
elementclass Host {
	$address, $gateway |

	    printer :: Print("RSVP", -1, CONTENTS ASCII);

        host :: RSVPHost($address:ip); //Het is miss handig da ge aan uw element $address kunt meegeven dan weet
                            // dan weet uw host zijn eigen ip adres

        rt :: StaticIPLookup(
                $address:ip/32 0,
                $address:ipnet 1,
                0.0.0.0/0 $gateway 1)
            -> [1]output;

	// Shared IP input path
	ip :: Strip(14) // ETHERNET HEADER WORDT VERWIJDERD
		-> CheckIPHeader // kijkt wa parameters na in de ip-header
                -> host // onze host heeft 2 inputs, 1 voor rsvp-pakketten en 1 voor de rest
                        // dit moet je zelf weten wat handiger is voor u :)
                -> printer
                -> rt;

	rt[1]
	    //-> EtherEncap(0x0800, $address:ether, $gateway)
		-> ipgw :: IPGWOptions($address)
		-> FixIPSrc($address)
		-> ttl :: DecIPTTL
		-> frag :: IPFragmenter(1500)
                -> qos_classifier :: IPClassifier(ip dscp > 0, -) // > 0 is beter want 1 klopt niet
                -> qos_queue :: Queue
                -> [0]scheduler :: PrioSched; // PUNT KOMMA NA ELKE BLOK!!!

        // For classifying
        qos_classifier[1]
                -> be_queue :: Queue
                -> [1]scheduler; // PUNT KOMMA NA ELKE BLOK!!!

        // For scheduling
        scheduler[0]
                -> LinkUnqueue(0, 1000) // Ik heb dit anders gedaan, maar dit zou ook kunnen
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
	    -> IPPrint
		-> in_cl :: Classifier(12/0806 20/0001,     // ARP request
		                        12/0806 20/0002,    // ARP reply
		                        12/0800)            // IP
		-> arp_res :: ARPResponder($address)
		-> output;

	in_cl[1]
		-> [1]arpq;

	in_cl[2]
		-> ip;
}
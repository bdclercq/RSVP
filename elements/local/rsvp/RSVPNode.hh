//
// Created by student on 11/13/18.
//

#ifndef CLICK_RSVPNODE_HH
#define CLICK_RSVPNODE_HH

#include <click/element.hh>
#include <click/timer.hh>
#include <click/string.hh>
#include <click/hashmap.hh>
#include "RSVPObject.hh"
#include "RSVPState.hh"


CLICK_DECLS

class RSVPNode: public Element{
private:
    IPAddress lan_address;
    IPAddress wan_address;
    uint16_t in_port;
    uint16_t out_port;
    HashMap<int, RSVPState> sessions;

    Timer _timer;
    uint16_t _lifetime;
    unsigned K = 3;
    int _tos_value = 184;

public:
    RSVPNode();
    ~RSVPNode();

    const char *class_name() const { return "RSVPNode"; }
    const char *port_count() const { return "3/1"; }
    const char *processing() const { return PUSH; }

    int configure(Vector<String>&, ErrorHandler*);

    /// Push along packets and react in a correct way.
    void push(int, Packet* p);

    /// Run timer to check if states are still valid.
    void run_timer(Timer *);

    Packet* make_packet(Packet* p, bool isLan);
    Packet* make_path_tear(Packet* p, bool isLan);
    Packet* make_reservation(Packet* p, bool conf, bool isLan, IPAddress next_hop);
    Packet* make_confirm(Packet* p, bool isLan, IPAddress next_hop);
};

CLICK_ENDDECLS
#endif //CLICK_RSVPNODE_HH

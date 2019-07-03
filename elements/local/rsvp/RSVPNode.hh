//
// Created by student on 11/13/18.
//

#ifndef CLICK_RSVPNODE_HH
#define CLICK_RSVPNODE_HH

#include <click/element.hh>
#include <click/timer.hh>
#include <click/hashmap.hh>
#include "RSVPObject.hh"
#include "RSVPState.hh"


CLICK_DECLS

class RSVPNode: public Element{
private:
    IPAddress address;
    uint16_t in_port;
    uint16_t out_port;
    HashMap<int, RSVPState> sessions;

    Timer _timer;
    uint16_t _lifetime;
    unsigned K = 3;

public:
    RSVPNode();
    ~RSVPNode();

    const char *class_name() const { return "RSVPNode"; }
    const char *port_count() const { return "1/1"; }
    const char *processing() const { return PUSH; }

    int configure(Vector<String>&, ErrorHandler*);

    void push(int, Packet* p);
    void run_timer(Timer *);
};

CLICK_ENDDECLS
#endif //CLICK_RSVPNODE_HH

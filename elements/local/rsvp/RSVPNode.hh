//
// Created by student on 11/13/18.
//

#ifndef CLICK_RSVPNODE_HH
#define CLICK_RSVPNODE_HH

#include <click/element.hh>
#include "PathState.hh"

CLICK_DECLS

class RSVPNode: public Element{
private:
    IPAddress address;
    uint16_t in_port;
    uint16_t out_port;
    PathState pState;

public:
    RSVPNode();
    ~RSVPNode();

    const char *class_name() const { return "RSVPNode"; }
    const char *port_count() const { return "0-1/0-1"; }
    const char *processing() const { return PUSH; }

    int configure(Vector<String>&, ErrorHandler*);

    void push(int, Packet* p);
};

CLICK_ENDDECLS
#endif //CLICK_RSVPNODE_HH

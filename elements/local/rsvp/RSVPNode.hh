//
// Created by student on 11/13/18.
//

#ifndef CLICK_RSVPNODE_HH
#define CLICK_RSVPNODE_HH

#include <click/element.hh>
#include <click/vector.hh>
#include "PathState.hh"

CLICK_DECLS

class RSVPNode: public Element{
private:
    IPAddress address;
    uint16_t in_port;
    uint16_t out_port;
    Vector<PathState> pstates;

    Vector<Packet*> priority;
    Vector<Packet*> best_effort;

public:
    RSVPNode();
    ~RSVPNode();

    const char *class_name() const { return "RSVPNode"; }
    const char *port_count() const { return "1/1"; }
    const char *processing() const { return PUSH; }

    int configure(Vector<String>&, ErrorHandler*);

    void push(int, Packet* p);
};

CLICK_ENDDECLS
#endif //CLICK_RSVPNODE_HH

//
// Created by student on 11/13/18.
//

#ifndef CLICK_RSVPNODE_HH
#define CLICK_RSVPNODE_HH

#include <click/element.hh>
#include<click/timer.hh>
#include <map>
#include "RSVPObject.hh"
#include "PathState.hh"
#include "ResvState.hh"

CLICK_DECLS

class RSVPNode: public Element{
private:
    IPAddress address;
    uint16_t in_port;
    uint16_t out_port;
    std::map<SessionInfo, PathState> pstates;
    std::map<SessionInfo, ResvState> rstates;

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

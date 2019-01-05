//
// Created by student on 11/16/18.
//

#ifndef RSVP_RSVPDEST_HH
#define RSVP_RSVPDEST_HH

#include <click/vector.hh>
#include <click/element.hh>
#include<click/string.hh>
#include<click/timer.hh>
#include <map>
#include "PathState.hh"
#include "ResvState.h"
#include "RSVPObject.hh"

CLICK_DECLS

class RSVPDest: public Element{
private:
    IPAddress address;
    IPAddress dst;
    uint16_t in_port;
    uint16_t out_port;

    // Map <address, port> pairs to session IDs
    std::map<int, std::pair<IPAddress, uint16_t>> sessions;
    std::map<SessionInfo, PathState> pstates;
    std::map<SessionInfo, ResvState> rstates;

    uint32_t _generator = 0;
    PathState state;

public:
    RSVPDest();
    ~RSVPDest();

    const char *class_name() const { return "RSVPDest"; }
    const char *port_count() const { return "1/1"; }
    const char *processing() const { return PUSH; }

    int configure(Vector<String>&, ErrorHandler*);

    void push(int, Packet* p);
    Packet* make_packet(Packet* p);
    void setRSVP(IPAddress src, IPAddress dst);
    void addSession(int, IPAddress, uint16_t);
    void add_handlers();
};

CLICK_ENDDECLS


#endif //RSVP_RSVPDEST_HH

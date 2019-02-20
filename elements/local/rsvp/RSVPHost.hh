//
// Created by student on 11/15/18.
//

#ifndef CLICK_RSVPHOST_HH
#define CLICK_RSVPHOST_HH

#include <click/element.hh>
#include <click/vector.hh>
#include<click/string.hh>
#include<click/timer.hh>
#include <map>
#include "PathState.hh"
#include "ResvState.h"
#include "RSVPObject.hh"

CLICK_DECLS

class RSVPHost : public Element {
private:
    IPAddress _own_address;
    IPAddress address;
    bool tos = false;
    uint16_t port;
    PathState pState;

    // Map <address, port> pairs to session IDs
    std::map<int, std::pair<IPAddress, uint16_t>> sessions;
    std::map<SessionInfo, PathState> pstates;
    std::map<SessionInfo, ResvState> rstates;

    uint32_t _generator = 0;
//    Timer _timer;

public:
    RSVPHost();

    ~RSVPHost();

    const char *class_name() const { return "RSVPHost"; }

    const char *port_count() const { return "0-1/1"; }

    const char *processing() const { return PUSH; }

    int configure(Vector <String> &, ErrorHandler *);

    IPAddress getOwnAddress(){return _own_address;}

    void push(int, Packet *p);

    static int push_packet(Element *e);

//    int push_packet();
    Packet *make_packet(Packet *p);

    Packet *make_reservation(Packet *p);

    void setRSVP(IPAddress src, uint16_t port);

    void addSession(int, IPAddress, uint16_t);

    int tearPath(int);

    void add_handlers();
};

CLICK_ENDDECLS

#endif //CLICK_RSVPHOST_HH

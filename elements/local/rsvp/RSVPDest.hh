//
// Created by student on 11/16/18.
//

#ifndef RSVP_RSVPDEST_HH
#define RSVP_RSVPDEST_HH
#include<click/string.hh>
#include "RSVPMessage.hh"
#include "PathState.hh"

CLICK_DECLS

class RSVPDest: public Element{
private:
    IPAddress address;
    IPAddress dst;
    uint16_t in_port;
    uint16_t out_port;

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
};

CLICK_ENDDECLS


#endif //RSVP_RSVPDEST_HH

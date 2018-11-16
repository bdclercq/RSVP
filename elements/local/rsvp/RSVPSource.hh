//
// Created by student on 11/15/18.
//

#ifndef CLICK_RSVPSOURCE_HH
#define CLICK_RSVPSOURCE_HH

#include "RSVPMessage.hh"
#include "PathState.hh"

CLICK_DECLS

class RSVPSource: public Element{
private:
    IPAddress address;
    IPAddress dst;
    uint16_t in_port;
    uint16_t out_port;
    PathState pState;

public:
    RSVPSource();
    ~RSVPSource();

    const char *class_name() const { return "RSVPSource"; }
    const char *port_count() const { return "0-1/0-1"; }
    const char *processing() const { return PUSH; }

    int configure(Vector<String>&, ErrorHandler*);

    void push(int, Packet* p);
    Packet* make_packet(Packet* p);
};

CLICK_ENDDECLS

#endif //CLICK_RSVPSOURCE_HH

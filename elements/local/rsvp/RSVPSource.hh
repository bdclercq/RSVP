//
// Created by student on 11/15/18.
//

#ifndef CLICK_RSVPSOURCE_HH
#define CLICK_RSVPSOURCE_HH

#include <click/element.hh>
#include <click/vector.hh>
#include<click/string.hh>
#include<click/timer.hh>
#include "PathState.hh"
#include "RSVPObject.hh"

CLICK_DECLS

class RSVPSource : public Element {
private:
    IPAddress address;
    IPAddress dst;
    bool tos = false;
    uint16_t in_port;
    uint16_t out_port;
    PathState pState;

    uint32_t _generator = 0;
//    Timer _timer;

    bool hasIntegrity = false;
    bool hasPolicy = false;
public:
    RSVPSource();

    ~RSVPSource();

    const char *class_name() const { return "RSVPSource"; }

    const char *port_count() const { return "0-1/1"; }

    const char *processing() const { return PUSH; }

    int configure(Vector <String> &, ErrorHandler *);

    void push(int, Packet *p);

    static int push_packet(Element *e);

//    int push_packet();
    Packet *make_packet(Packet *p);

    void setRSVP(IPAddress src, IPAddress dst);



    void add_handlers();
};
//static int setRSVPHandler(const String &conf, Element *e, void *thunk, ErrorHandler *errh);
CLICK_ENDDECLS

#endif //CLICK_RSVPSOURCE_HH

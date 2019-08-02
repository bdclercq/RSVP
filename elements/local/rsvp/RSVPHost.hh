//
// Created by student on 11/15/18.
//

#ifndef CLICK_RSVPHOST_HH
#define CLICK_RSVPHOST_HH

#include <click/element.hh>
#include <click/vector.hh>
#include <click/string.hh>
#include <click/timer.hh>
#include <click/hashmap.hh>
#include "RSVPState.hh"
#include "RSVPObject.hh"

CLICK_DECLS

class RSVPHost : public Element {
private:
    IPAddress _own_address;
    IPAddress _address;
    bool confirmation = false;
    uint16_t _own_port;
    uint16_t _port;

    // Map <address, port> pairs to session IDs
    HashMap<int, RSVPState> sessions;

    Timer _timer;
    uint16_t _lifetime;
    uint64_t _identification;

    int _tos_value = 184;

public:
    RSVPHost();

    ~RSVPHost();

    const char *class_name() const { return "RSVPHost"; }

    const char *port_count() const { return "0-1/1"; }

    const char *processing() const { return PUSH; }

    int configure(Vector <String> &, ErrorHandler *);

    void run_timer(Timer*);

    IPAddress getOwnAddress(){return _own_address;}

    void push(int, Packet *p);

    static int push_packet(Element *e);

//    int push_packet();
    Packet *make_packet();

    Packet *make_path_tear(HashMap<int, RSVPState>::Pair*);

    Packet *make_resv_tear(HashMap<int, RSVPState>::Pair*);

    void make_reservation(RSVPState);

    void send_confirmation(RSVPState);

    void setRSVP(int sid, IPAddress src, uint16_t port);

    void addSession(int, IPAddress, uint16_t);

    void addReservation(int, bool);

    void tearPath(int);

    void add_handlers();
};

CLICK_ENDDECLS

#endif //CLICK_RSVPHOST_HH

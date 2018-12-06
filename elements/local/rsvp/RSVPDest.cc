//
// Created by student on 11/15/18.
//

#include <click/config.h>
#include <click/confparse.hh>
#include <click/error.hh>
#include <click/args.hh>
#include <clicknet/ip.h>
#include <clicknet/udp.h>
#include <clicknet/ether.h>

#include "RSVPDest.hh"

CLICK_DECLS

RSVPDest::RSVPDest() {}

int RSVPDest::configure(Vector <String> &conf, ErrorHandler *errh) {
    if (Args(conf, this, errh)
                .read_mp("ADDR", address)
                .read_mp("INPORT", in_port)
                .read_mp("DST", dst)
                .read_mp("OUTPORT", out_port)
                .complete() < 0)
        return -1;

    click_chatter("RSVPDest initialized with ");
    click_chatter(address.unparse().c_str());
    click_chatter(String(in_port).c_str());
    click_chatter(dst.unparse().c_str());
    click_chatter(String(out_port).c_str());
    return 0;
}

RSVPDest::~RSVPDest() {}

Packet* RSVPDest::make_packet(Packet* p) {


}

void RSVPDest::push(int, Packet *p) {
    click_chatter("Pushing packet at RSVPDest %i-%s-%i", in_port, address.unparse().c_str(), out_port);

    Packet* q = make_packet(p);

    output(0).push(q);
}

CLICK_ENDDECLS
EXPORT_ELEMENT(RSVPDest)
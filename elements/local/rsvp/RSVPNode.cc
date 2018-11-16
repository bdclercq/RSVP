//
// Created by student on 11/13/18.
//

#include <click/config.h>
#include <click/confparse.hh>
#include <click/error.hh>
#include <click/args.hh>
#include "RSVPNode.hh"

CLICK_DECLS

RSVPNode::RSVPNode() {}

int RSVPNode::configure(Vector <String> &conf, ErrorHandler *errh) {
    if (Args(conf, this, errh)
                .read_mp("ADDR", address)
                .read_mp("INPORT", in_port)
                .read_mp("OUTPORT", out_port)
                .complete() < 0)
        return -1;

    return 0;
}

RSVPNode::~RSVPNode() {}

void RSVPNode::push(int, Packet *p) {
    click_chatter("Pushing packet at RSVPNode %i-%i-%i", in_port, address, out_port);
    output(0).push(p);
}

CLICK_ENDDECLS
EXPORT_ELEMENT(RSVPNode)
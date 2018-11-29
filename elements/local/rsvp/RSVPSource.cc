//
// Created by student on 11/15/18.
//

#include <click/config.h>
#include <click/confparse.hh>
#include <click/error.hh>
#include <click/args.hh>
#include <clicknet/ip.h>
#include <clicknet/ether.h>

#include "RSVPSource.hh"

CLICK_DECLS

RSVPSource::RSVPSource() {}

int RSVPSource::configure(Vector <String> &conf, ErrorHandler *errh) {
    if (Args(conf, this, errh)
                .read_mp("ADDR", address)
//                .read_mp("INPORT", in_port)
                .read_mp("DST", dst)
//                .read_mp("OUTPORT", out_port)
                .complete() < 0)
        return -1;

    click_chatter("RSVPSource initialized with ");
    click_chatter(address.unparse().c_str());
//    click_chatter(String(in_port).c_str());
    click_chatter(dst.unparse().c_str());
//    click_chatter(String(out_port).c_str());
    return 0;
}

RSVPSource::~RSVPSource() {}

Packet* RSVPSource::make_packet() {

    click_chatter("Creating packet at source");

    WritablePacket* q = WritablePacket::make(sizeof(CommonHeader));

    if (q == 0)
        return 0;

    auto q2 = addCommonHeader(q);

    return q2;
}

WritablePacket* RSVPSource::addCommonHeader(WritablePacket *p) {
    CommonHeader ch;
//    ch->send_ttl = ;
    ch.msg_type = 1;
    ch.version_flags = 16;
    ch.length = sizeof(CommonHeader);
    ch.checksum = 0;

    memcpy(p->end_data(), &ch, sizeof(ch));
    return p->put(sizeof(ch));
}

int RSVPSource::push_packet(Element* e) {
    RSVPSource * rsvpSource = (RSVPSource *)e;
    rsvpSource->push(0, rsvpSource->make_packet());
    return 0;
}

void RSVPSource::push(int, Packet *p) {
    click_chatter("Pushing packet at RSVPSource %s", address.unparse().c_str());

//    Packet* q = make_packet(p);

    output(0).push(p);
}

void RSVPSource::add_handlers() {
    add_write_handler("push_packet", &push_packet, (void *) 0);
}

CLICK_ENDDECLS
EXPORT_ELEMENT(RSVPSource)
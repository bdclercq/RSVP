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

    click_chatter("Creating path message");

    click_ip* p_ip = (click_ip*)p->data();

    int headroom = sizeof(click_ether) + 4;
    int p_size = sizeof(click_ip) + sizeof(CommonHeader) + sizeof(PathMessageHeader);
    WritablePacket* q = Packet::make(headroom, 0, p_size, 0);

    if (q == 0)
        return 0;

    memset(q->data(), '\0', p_size);

    click_chatter("Setting fields of Path Header");

    uint16_t ipid = ((_generator) % 0xFFFF) + 1;

    //ip fields
    click_ip* ip = (click_ip*)q->data();
    ip->ip_v = 4;
    ip->ip_hl = sizeof(click_ip) >> 2;
    ip->ip_len = htons(q->length());
    ip->ip_id = ipid;
    ip->ip_p = IP_PROTO_RSVP;
    ip->ip_src = p_ip->ip_src;
    ip->ip_dst = p_ip->ip_dst;
    ip->ip_tos = 32;
    ip->ip_off = 1;
    ip->ip_ttl = p_ip->ip_ttl;
    ip->ip_sum = click_in_cksum((unsigned char*) ip, sizeof(click_ip));

    q->set_dst_ip_anno(ip->ip_dst);

    CommonHeader* ch = (CommonHeader*)(ip+1);

    ch->send_ttl = ip->ip_ttl;
    ch->msg_type = 1;
    ch->version_flags = 16;
    ch->length = sizeof(CommonHeader);
    ch->checksum = click_in_cksum((unsigned char*) ch, sizeof(CommonHeader));


    PathMessageHeader* ph = (PathMessageHeader*)(ch+1);

    // Set Session
    ph->session.dest_addr = ip->ip_dst;
    ph->session.protocol_id = ip->ip_id;
    ph->session.flags = 1;
    ph->session.dstport = 0;

    // Set SenderTemplate
    ph->STemp.src = ip->ip_src;
    ph->STemp.srcPort = 0;

    // Set SenderTSpec
    ph->STSpec.version.data = 0;
    ph->STSpec.total_length = p_size;
    ph->STSpec.service = 1;
    ph->STSpec.service_length = p_size;
    ph->STSpec.r = 1;
    ph->STSpec.b = 2;
    ph->STSpec.p = p_size;
    ph->STSpec.m = p_size;
    ph->STSpec.M = p_size;

    return q;
}

void RSVPDest::push(int, Packet *p) {
    click_chatter("Pushing packet at RSVPDest %i-%s-%i", in_port, address.unparse().c_str(), out_port);

    Packet* q = make_packet(p);

    output(0).push(q);
}

CLICK_ENDDECLS
EXPORT_ELEMENT(RSVPDest)
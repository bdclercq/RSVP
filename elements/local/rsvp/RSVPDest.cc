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
//                .read_mp("ADDR", address)
//                .read_mp("INPORT", in_port)
//                .read_mp("DST", dst)
//                .read_mp("OUTPORT", out_port)
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

    click_ip* iph = (click_ip*)(p->data());
    CommonHeader* prev_ch = (CommonHeader*)(iph+1);
    Session* prev_session = (Session*)(prev_ch+1);
    RSVP_HOP* prev_rsvp_hop = (RSVP_HOP*)(prev_session+1);

    // Set path state
    state.HOP_addr = prev_rsvp_hop->addr;
    state.HOP_LIH = prev_rsvp_hop->LIH;
    state.session_dst = prev_session->dest_addr;
    state.session_flags = prev_session->flags;
    state.session_PID = prev_session->protocol_id;
    state.out_port = prev_session->dstport;

    int headroom = sizeof(click_ether) + 4;
    int packetsize = sizeof(click_ip) + sizeof(CommonHeader) + sizeof(Session)
                     + sizeof(RSVP_HOP) + sizeof(Time_Value)+ sizeof(Style);

    int tailroom = 0;

    WritablePacket *q = WritablePacket::make(headroom, 0, packetsize, tailroom);

    if (q == 0)
        return 0;

    memset(q->data(), '\0', packetsize);

    uint16_t ipid = ((_generator) % 0xFFFF) + 1;

    click_ip *ip = (click_ip *) q->data();
    ip->ip_v = 4;
    ip->ip_hl = sizeof(click_ip) >> 2;
    ip->ip_len = htons(q->length());
    ip->ip_id = htons(ipid);
    ip->ip_p = IP_PROTO_RSVP;
    ip->ip_src = iph->ip_dst;
    ip->ip_dst = iph->ip_src;
    ip->ip_tos = 1;
    ip->ip_off = 0;
    ip->ip_ttl = 64;
    ip->ip_sum = click_in_cksum((unsigned char *) ip, sizeof(click_ip));

    q->set_dst_ip_anno(ip->ip_dst);

    CommonHeader *ch = (CommonHeader *) (ip + 1);
    ch->version_flags = 16;
    ch->msg_type = 2;
    ch->length = htons(8 + 12 + 12 + 8 + 8);
    ch->checksum = 0;

//    click_chatter("Add session to Resv Message");
    Session *session = (Session *) (ch + 1);
    session = prev_session;
//    session->Class = 1;
//    session->C_type = 1;
//    session->length = htons(12);        // (64 body + 16 length + 8 class + 8 ctype) / 8
//    session->dest_addr = iph->ip_src;
//    session->protocol_id = ip->ip_p;
//    session->flags = 0;
//    session->dstport = htons(0);

//    click_chatter("Add HOP to Resv Message");
    RSVP_HOP *hop = (RSVP_HOP *) (session + 1);
    hop->Class = 3;
    hop->C_type = 1;
    hop->addr = iph->ip_dst;
    hop->LIH = 0;
    hop->length = htons(12);            // (64 body + 16 length + 8 class + 8 ctype) / 8

//    click_chatter("Add time to Resv Message");
    Time_Value* time_value = (Time_Value*)(hop+1);
    time_value->length = htons(8);      // (32 body + 16 length + 8 class + 8 ctype) / 8
    time_value->C_type = 1;
    time_value->Class = 5;
    time_value->period = htons(1);

//    click_chatter("Add style to Resv Message");
    Style* style = (Style*)(time_value+1);
    style->length = htons(8);           // (32 body + 16 length + 8 class + 8 ctype) / 8
    style->C_type = 1;
    style->Class = 8;
    style->flags = 0;
    style->reserved_options = 0;
    style->available_options = 0;

    return q;
}

void RSVPDest::push(int, Packet *p) {
    click_chatter("Pushing packet at RSVPDest %i-%s-%i", in_port, address.unparse().c_str(), out_port);

    Packet* q = make_packet(p);

    output(0).push(q);
}

CLICK_ENDDECLS
EXPORT_ELEMENT(RSVPDest)
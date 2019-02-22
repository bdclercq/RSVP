//
// Created by student on 11/15/18.
//

#include <click/config.h>
#include <click/confparse.hh>
#include <click/error.hh>
#include <click/args.hh>
#include <clicknet/ip.h>
#include <clicknet/ether.h>

#include "RSVPHost.hh"

CLICK_DECLS

RSVPHost::RSVPHost() {}

int RSVPHost::configure(Vector <String> &conf, ErrorHandler *errh) {
    if (Args(conf, this, errh)
                .read_mp("ADDR", _own_address)
//                .read_mp("INPORT", in_port)
//                .read_mp("DST", dst)
//                .read_mp("OUTPORT", out_port)
                .complete() < 0)
        return -1;

    click_chatter("RSVPHost initialized with ");
    click_chatter(_own_address.unparse().c_str());
//    click_chatter(String(in_port).c_str());
//    click_chatter(dst.unparse().c_str());
//    click_chatter(String(out_port).c_str());
    return 0;
}

RSVPHost::~RSVPHost() {}

Packet *RSVPHost::make_packet(Packet *p) {

    click_chatter("Creating packet at host");

    if (sessions.size() == 0){
        return p;
    }

    click_ip *iph = (click_ip * )(p->data());

    int headroom = sizeof(click_ether) + 4;
    int packetsize = sizeof(click_ip) + sizeof(CommonHeader) + sizeof(Session)
                     + sizeof(RSVP_HOP) + sizeof(Time_Value)+ sizeof(Sendertemplate) +
                     sizeof(SenderTSpec);

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
    ip->ip_src = _own_address;
    ip->ip_dst = _address;
    ip->ip_tos = 184;
    ip->ip_off = 0;
    ip->ip_ttl = 250;

    q->set_dst_ip_anno(_address);
    q->set_ip_header(ip, ip->ip_hl);

    CommonHeader *ch = (CommonHeader *) (ip + 1);
    ch->version_flags = 16;
    ch->msg_type = 1;
    ch->length = htons(8 + 12 + 12 + 8 + 12 + 36);
    ch->checksum = 0;

    Session *session = (Session *) (ch + 1);
    session->Class = 1;
    session->C_type = 1;
    session->length = htons(12);        // (64 body + 16 length + 8 class + 8 ctype) / 8
    session->dest_addr = _address;
    session->protocol_id = ip->ip_p;
    session->flags = 0;
    session->dstport = htons(0);

    RSVP_HOP *hop = (RSVP_HOP *) (session + 1);
    hop->Class = 3;
    hop->C_type = 1;
    hop->addr = _own_address;
    hop->LIH = 0;
    hop->length = htons(12);            // (64 body + 16 length + 8 class + 8 ctype) / 8

    Time_Value* time_value = (Time_Value*)(hop+1);
    time_value->length = htons(8);      // (32 body + 16 length + 8 class + 8 ctype) / 8
    time_value->C_type = 1;
    time_value->Class = 5;
    time_value->period = htons(1);

    Sendertemplate* sendertemplate = (Sendertemplate*)(time_value+1);
    sendertemplate->length = htons(12); // (64 body + 16 length + 8 class + 8 ctype) / 8
    sendertemplate->Class = 11;
    sendertemplate->C_type = 1;
    sendertemplate->src = _own_address;
    sendertemplate->reserved = htons(0);
    sendertemplate->srcPort = htons(_own_port);

    SenderTSpec* spec = (SenderTSpec*)(sendertemplate+1);
    spec->length = htons(36);           // (256 body + 16 length + 8 class + 8 ctype) / 8
    spec->Class = 12;
    spec->C_type = 2;
    spec->version = htons(4096);
    spec->total_length = htons(7);
    spec->service = 1;
    spec->reserved = 0;
    spec->service_length = htons(6);
    spec->param_id = 127;
    spec->param_flags = 0;
    spec->param_length = htons(5);
    spec->r = htonl((8+12+12+8+12+36)*8);
    spec->b = htonl(10*(8+12+8+12+12+36)*8);
    spec->p = htonl(UINT32_MAX);
    spec->m = htonl(74);
    spec->M = htonl(74);

    ip->ip_sum = click_in_cksum((unsigned char *) ip, sizeof(click_ip));

    return q;
}

Packet *RSVPHost::make_reservation(Packet *p) {
    click_ip* iph = (click_ip*)(p->data());
    CommonHeader* prev_ch = (CommonHeader*)(iph+1);
    Session* prev_session = (Session*)(prev_ch+1);
    RSVP_HOP* prev_rsvp_hop = (RSVP_HOP*)(prev_session+1);

    // Set path state
    pState.HOP_addr = prev_rsvp_hop->addr;
    pState.HOP_LIH = prev_rsvp_hop->LIH;
    pState.session_dst = prev_session->dest_addr;
    pState.session_flags = prev_session->flags;
    pState.session_PID = prev_session->protocol_id;
    pState.out_port = prev_session->dstport;

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
    ip->ip_src = _own_address;
    ip->ip_dst = _address;
    ip->ip_tos = 184;
    ip->ip_off = 0;
    ip->ip_ttl = 250;

    q->set_dst_ip_anno(_address);

    CommonHeader *ch = (CommonHeader *) (ip + 1);
    ch->version_flags = 16;
    ch->msg_type = 2;
    ch->length = htons(8 + 12 + 12 + 8 + 8);
    ch->checksum = 0;

//    click_chatter("Add session to Resv Message");
    Session *session = (Session *) (ch + 1);
    session = prev_session;

//    click_chatter("Add HOP to Resv Message");
    RSVP_HOP *hop = (RSVP_HOP *) (session + 1);
    hop->Class = 3;
    hop->C_type = 1;
    hop->addr = _address;
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

    ip->ip_sum = click_in_cksum((unsigned char *) ip, sizeof(click_ip));

    return q;

}

void RSVPHost::push(int, Packet *p) {

    if (tos){
        Packet *q = make_packet(p);
        click_chatter("Pushing packet at RSVPHost %s to %s", _own_address.unparse().c_str(), _address.unparse().c_str());
        output(0).push(q);
    } else{
        output(0).push(p);
    }
}

int RSVPHost::tearPath(int sid) {
    // Send path tear message
    tos = false;

    std::pair<IPAddress, uint16_t> entry = sessions[sid];

    int headroom = sizeof(click_ether) + 4;
    int packetsize = sizeof(click_ip) + sizeof(CommonHeader) + sizeof(Session)
                     + sizeof(RSVP_HOP) + sizeof(Sendertemplate) +
                     sizeof(SenderTSpec);

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
    ip->ip_src = _own_address;
    ip->ip_dst = entry.first;
    ip->ip_tos = 1;
    ip->ip_off = 0;
    ip->ip_ttl = 64;
    ip->ip_sum = click_in_cksum((unsigned char *) ip, sizeof(click_ip));

    q->set_dst_ip_anno(_address);

    CommonHeader *ch = (CommonHeader *) (ip + 1);
    ch->version_flags = 16;
    ch->msg_type = 5;
    ch->length = htons(8 + 12 + 12 + 12 + 36);
    ch->checksum = 0;

    Session *session = (Session *) (ch + 1);
    session->Class = 1;
    session->C_type = 1;
    session->length = htons(12);        // (64 body + 16 length + 8 class + 8 ctype) / 8
    session->dest_addr = entry.first;
    session->protocol_id = ip->ip_p;
    session->flags = 0;
    session->dstport = htons(entry.second);

    RSVP_HOP *hop = (RSVP_HOP *) (session + 1);
    hop->Class = 3;
    hop->C_type = 1;
    hop->addr = entry.first;
    hop->LIH = 0;
    hop->length = htons(12);            // (64 body + 16 length + 8 class + 8 ctype) / 8

    Sendertemplate* sendertemplate = (Sendertemplate*)(hop+1);
    sendertemplate->length = htons(12); // (64 body + 16 length + 8 class + 8 ctype) / 8
    sendertemplate->Class = 11;
    sendertemplate->C_type = 1;
    sendertemplate->src = _own_address;
    sendertemplate->reserved = htons(0);
    sendertemplate->srcPort = htons(_own_port);

    SenderTSpec* spec = (SenderTSpec*)(sendertemplate+1);
    spec->length = htons(36);           // (256 body + 16 length + 8 class + 8 ctype) / 8
    spec->Class = 12;
    spec->C_type = 2;
    spec->version = htons(4096);
    spec->total_length = htons(7);
    spec->service = 1;
    spec->reserved = 0;
    spec->service_length = htons(6);
    spec->param_id = 127;
    spec->param_flags = 0;
    spec->param_length = htons(5);
    spec->r = htonl((8+12+12+8+12+36)*8);
    spec->b = htonl(10*(8+12+8+12+12+36)*8);
    spec->p = htonl(UINT32_MAX);
    spec->m = htonl(74);
    spec->M = htonl(74);

    sessions.erase(sid);
    output(0).push(q);
}

void RSVPHost::setRSVP(IPAddress src, uint16_t port) {
    _own_address = src;
    _own_port = port;
    tos = true;
}

void RSVPHost::addSession(int sid, IPAddress address, uint16_t port) {
    sessions[sid] = std::pair<IPAddress, uint16_t>(address, port);
    _address = address;
    _port = port;
    //tos = true;
}

static int setRSVPHandler(const String &conf, Element* e, void *thunk, ErrorHandler *errh) {
    RSVPHost* rsvphost = (RSVPHost*)e;
    IPAddress address;
    uint16_t port;
    int sid;
    Vector<String> vec;
    cp_argvec(conf, vec);
    if (Args(vec, e, errh)
                .read_mp("SID", sid)
                .read_mp("ADDR", address)
                .read_mp("PORT", port)
                .complete() < 0)
        return -1;
    rsvphost->setRSVP(address, port);
    return 0;
}

static int setSession(const String &conf, Element* e, void *thunk, ErrorHandler *errh) {
    RSVPHost* rsvphost = (RSVPHost*)e;
    IPAddress address;
    uint16_t dst;
    int sid;
    Vector<String> vec;
    cp_argvec(conf, vec);
    if (Args(vec, e, errh)
                .read_mp("SID", sid)
                .read_mp("DST_ADDR", address)
                .read_mp("DST_PORT", dst)
                .complete() < 0)
        return -1;
    rsvphost->addSession(sid, address, dst);
    return 0;
}

static int release(const String &conf, Element* e, void *thunk, ErrorHandler *errh) {
    RSVPHost* rsvphost = (RSVPHost*)e;
    IPAddress address;
    IPAddress dst;
    int sid;
    Vector<String> vec;
    cp_argvec(conf, vec);
    if (Args(vec, e, errh)
                .read_mp("SID", sid)
                .complete() < 0)
        return -1;
    rsvphost->tearPath(sid);
    return 0;
}

enum{OWN_ADDR};

String read_handler(Element *e, void *thunk){
    RSVPHost* rsvphost = (RSVPHost*)e;
    switch ((intptr_t)thunk) {
        case OWN_ADDR:
            return String((rsvphost->getOwnAddress()).unparse().c_str());
        default:
            return "<error>";
    }
    click_chatter((rsvphost->getOwnAddress()).unparse().c_str());
}

void RSVPHost::add_handlers() {
    add_write_handler("sender", &setRSVPHandler, (void*) 0);
    add_write_handler("session", &setSession, (void*) 0);
    add_write_handler("release", &release, (void*) 0);
    add_read_handler("getOwnAddress", read_handler, OWN_ADDR);
}

CLICK_ENDDECLS
EXPORT_ELEMENT(RSVPHost)
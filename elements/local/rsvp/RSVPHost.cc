//
// Created by student on 11/15/18.
//

#include <click/config.h>
#include <click/confparse.hh>
#include <click/error.hh>
#include <click/args.hh>
#include <clicknet/ip.h>
#include <clicknet/ether.h>
#include <clicknet/udp.h>

#include "RSVPHost.hh"

CLICK_DECLS

RSVPHost::RSVPHost() : _timer(this), _lifetime(1000) {}

/////////////////////////////////////////////////////////////////////////

int RSVPHost::configure(Vector <String> &conf, ErrorHandler *errh) {
    if (Args(conf, this, errh)
                .read_mp("ADDR", _own_address)
//                .read_mp("INPORT", in_port)
//                .read_mp("DST", dst)
//                .read_mp("OUTPORT", out_port)
                .complete() < 0)
        return -1;


    _timer.initialize(this);
    _timer.schedule_after_msec(1000);

//    click_chatter("RSVPHost initialized with %s %u", _own_address.unparse().c_str(), _own_port);

    return 0;
}

/////////////////////////////////////////////////////////////////////////

RSVPHost::~RSVPHost() {}

/////////////////////////////////////////////////////////////////////////

void RSVPHost::run_timer(Timer *) {
    click_chatter("run timer");

    for (HashMap<int, RSVPState>::iterator it = sessions.begin(); it != sessions.end(); it++){
        if ((it.value().src_address == _own_address && it.value().src_port == _own_port)){
            click_chatter("Creating and pushing Path message at %s", _own_address.unparse().c_str());
            Packet* q = make_packet();
            output(0).push(q);
        }
        if (it.value().lifetime > 0) {
            click_chatter("Decreasing lifetime %u for session %i at host %s", it.value().lifetime, it.key(), _own_address.unparse().c_str());
            uint32_t lt = it.value().lifetime;
            lt--;
            it.value().lifetime = lt;
        }
        if (it.value().lifetime <= 0) {
            click_chatter("Erasing state %i for %s", it.key(), it.value().session_dst.unparse().c_str());
            sessions.remove(it.key());
        }
    }

    click_chatter("reschedule");
    _timer.reschedule_after_msec(1000);
    click_chatter("done");
}

/////////////////////////////////////////////////////////////////////////

// Path message
Packet *RSVPHost::make_packet() {

    click_chatter("Creating packet at host %s", _own_address.unparse().c_str());

    int headroom = sizeof(click_ether) + 4;
    int packetsize = sizeof(click_ip) +
            sizeof(CommonHeader) +
            sizeof(Session) +
            sizeof(RSVP_HOP) +
            sizeof(Time_Value)+
            sizeof(Sendertemplate) +
            sizeof(SenderTSpec);

    int tailroom = 0;

//    click_ip* p_ip = (click_ip*)p->data();

    WritablePacket *q = WritablePacket::make(headroom, 0, packetsize, tailroom);

    if (q == 0) {
        click_chatter("Error with creating Path message: returning empty packet");
        return 0;
    }

    memset(q->data(), '\0', packetsize);

    uint16_t ipid = ((_generator) % 0xFFFF) + 1;

    click_ip *ip = (click_ip *) q->data();
    ip->ip_v = 4;
    ip->ip_hl = sizeof(click_ip) >> 2;
    ip->ip_len = htons(q->length());
    ip->ip_id = 0;
    ip->ip_p = 46;
    ip->ip_src = _own_address;
    ip->ip_dst = _address;
    ip->ip_tos = _tos_value;
    ip->ip_off = 0;
    ip->ip_ttl = 250;
    ip->ip_sum = 0;

    q->set_dst_ip_anno(_address);
    q->set_ip_header(ip, ip->ip_hl);

    CommonHeader *ch = (CommonHeader *) (ip + 1);
    ch->version_flags = 16;
    ch->msg_type = 1;
    ch->length = htons(8 + 12 + 12 + 8 + 12 + 36);
    ch->send_ttl = 100;
    ch->checksum = 0;

    Session *session = (Session *) (ch + 1);
    session->Class = 1;
    session->C_type = 1;
    session->length = htons(12);        // (64 body + 16 length + 8 class + 8 ctype) / 8
    session->dest_addr = _address;
    session->protocol_id = 17;
    session->flags = 0;
    session->dstport = htons(_port);

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
    time_value->period = htonl(10000);

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
    spec->version = 0;
    spec->total_length = htons(7);
    spec->service = 1;
    spec->reserved = 0;
    spec->service_length = htons(6);
    spec->param_id = 127;
    spec->param_flags = 0;
    spec->param_length = htons(5);
    spec->r = htonl(1176256512);
    spec->b = htonl(1148846080);
    spec->p = htonl(1176256512);
    spec->m = htonl(packetsize);
    spec->M = htonl(15*packetsize);

    ip->ip_sum = click_in_cksum((unsigned char *) ip, sizeof(click_ip));
    ch->checksum = click_in_cksum((unsigned char *) q->data(), q->length());

    return q;
}

/////////////////////////////////////////////////////////////////////////

// Path tear message
Packet *RSVPHost::make_path_tear(HashMap<int, RSVPState>::Pair* entry) {

    int headroom = sizeof(click_ether) + 4;
    int packetsize = sizeof(click_ip)
                    + sizeof(CommonHeader)
                    + sizeof(Session)
                    + sizeof(RSVP_HOP)
                    + sizeof(Sendertemplate)
                    + sizeof(SenderTSpec);

    int tailroom = 0;

    WritablePacket *q = WritablePacket::make(headroom, 0, packetsize, tailroom);

    if (q == 0){
        click_chatter("Path tear problem");
        return 0;
    }

    memset(q->data(), '\0', packetsize);

    click_ip *ip = (click_ip *) q->data();
    ip->ip_v = 4;
    ip->ip_hl = sizeof(click_ip) >> 2;
    ip->ip_len = htons(q->length());
    ip->ip_id = 0;
    ip->ip_p = 46;
    ip->ip_src = _own_address;
    ip->ip_dst = entry->value.session_dst;
    click_chatter("Path tear IP dst: %s", entry->value.session_dst.unparse().c_str());
    ip->ip_tos = _tos_value;
    ip->ip_off = 0;
    ip->ip_ttl = 64;
    ip->ip_sum = 0;

    q->set_dst_ip_anno(entry->value.session_dst);
    q->set_ip_header(ip, ip->ip_hl);

    CommonHeader *ch = (CommonHeader *) (ip + 1);
    ch->version_flags = 16;
    ch->msg_type = 5;
    ch->length = htons(8 + 12 + 12 + 12 + 36);
    ch->send_ttl = 127;
    ch->checksum = 0;

    Session *session = (Session *) (ch + 1);
    session->Class = 1;
    session->C_type = 1;
    session->length = htons(12);        // (64 body + 16 length + 8 class + 8 ctype) / 8
    session->dest_addr = entry->value.session_dst;
    session->protocol_id = 17;
    session->flags = 0;
    session->dstport = htons(entry->value.dst_port);

    RSVP_HOP *hop = (RSVP_HOP *) (session + 1);
    hop->Class = 3;
    hop->C_type = 1;
    hop->addr = _own_address;
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
    spec->version = 0;
    spec->total_length = htons(7);
    spec->service = 1;
    spec->reserved = 0;
    spec->service_length = htons(6);
    spec->param_id = 127;
    spec->param_flags = 0;
    spec->param_length = htons(5);
    spec->r = htonl(1176256512);
    spec->b = htonl(1148846080);
    spec->p = htonl(spec->r*spec->b);
    spec->m = htonl(packetsize);
    spec->M = htonl(15*packetsize);

    ip->ip_sum = click_in_cksum((unsigned char *) ip, sizeof(click_ip));
    ch->checksum = click_in_cksum((unsigned char *) q->data(), q->length());

    return q;

}

/////////////////////////////////////////////////////////////////////////

//Resv tear message
Packet *RSVPHost::make_resv_tear(HashMap<int, RSVPState>::Pair* entry) {

    int headroom = sizeof(click_ether) + 4;
    int packetsize = sizeof(click_ip)
                     + sizeof(CommonHeader)
                     + sizeof(Session)
                     + sizeof(RSVP_HOP)
                     + sizeof(Style)
                     + sizeof(Flowspec)
                     + sizeof(Filterspec);

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
    ip->ip_p = 46;
    ip->ip_src = _own_address;
    ip->ip_dst = entry->value.src_address;
    ip->ip_tos = _tos_value;
    ip->ip_off = 0;
    ip->ip_ttl = 64;
    ip->ip_sum = 0;

    q->set_dst_ip_anno(entry->value.src_address);
    q->set_ip_header(ip, ip->ip_hl);

    CommonHeader *ch = (CommonHeader *) (ip + 1);
    ch->version_flags = 16;
    ch->msg_type = 6;
    ch->length = htons(8 + 12 + 12 + 12 + 36);
    ch->send_ttl = 127;
    ch->checksum = 0;

    Session *session = (Session *) (ch + 1);
    session->Class = 1;
    session->C_type = 1;
    session->length = htons(12);        // (64 body + 16 length + 8 class + 8 ctype) / 8
    session->dest_addr = entry->value.src_address;
    session->protocol_id = 17;
    session->flags = 0;
    session->dstport = htons(entry->value.src_port);

    RSVP_HOP *hop = (RSVP_HOP *) (session + 1);
    hop->Class = 3;
    hop->C_type = 1;
    hop->addr = _own_address;
    hop->LIH = 0;
    hop->length = htons(12);            // (64 body + 16 length + 8 class + 8 ctype) / 8

    Style *style = (Style*)(hop+1);
    style->length = htons(8);           // (32 body + 16 length + 8 class + 8 ctype) / 8
    style->C_type = 1;
    style->Class = 8;
    style->flags = 0;
    style->reserved_options1 = 0;
    style->reserved_options2 = 0;
    style->fixed_filter = 10;

    Flowspec* flowspec = (Flowspec*)(style+1);
    flowspec->length = htons(36);
    flowspec->C_type = 2;
    flowspec->Class = 9;
    flowspec->version = 4;
    flowspec->res = 12;
    flowspec->total_length = htons(7);
    flowspec->service = 5;
    flowspec->service_length = htons(6);
    flowspec->param_id = 127;
    flowspec->param_flags = 0;
    flowspec->param_length = htons(5);
    flowspec->r = htonl(1176256512);
    flowspec->b = htonl(1148846080);
    flowspec->p = htonl(1148846080);
    flowspec->m = htonl(100);
    flowspec->M = htonl(1500);

    Filterspec* filterspec = (Filterspec*)(flowspec+1);
    filterspec->length = htons(12);
    filterspec->Class = 10;
    filterspec->C_type = 1;
    filterspec->src = _own_address;
    filterspec->reserved = 0;
    filterspec->srcPort = htons(_own_port);

    ip->ip_sum = click_in_cksum((unsigned char *) ip, sizeof(click_ip));

    return q;

}

/////////////////////////////////////////////////////////////////////////

// Resv message
void RSVPHost::make_reservation(RSVPState rsvpState) {

    click_chatter("Making Resv message at %s", _own_address.unparse().c_str());

    if (sessions.size() == 0){
        click_chatter("No sessions registered: returning packet");
        return;
    }

    int headroom = sizeof(click_ether) + 4;
    int packetsize = sizeof(click_ip) +
            sizeof(CommonHeader) +
            sizeof(Session) +
            sizeof(RSVP_HOP) +
            sizeof(Time_Value) +
            sizeof(Style)+
            sizeof(Flowspec)+
            sizeof(Filterspec);

    if (rsvpState.confRequested){
        packetsize += sizeof(Resvconfirm);
    }

    int tailroom = 0;

    WritablePacket *q = WritablePacket::make(headroom, 0, packetsize, tailroom);

    if (q == 0) {
        click_chatter("Error with creating Resv message: returning empty packet");
        return;
    }

    memset(q->data(), '\0', packetsize);

    uint16_t ipid = ((_generator) % 0xFFFF) + 1;

    click_ip *ip = (click_ip *) q->data();
    ip->ip_v = 4;
    ip->ip_hl = sizeof(click_ip) >> 2;
    ip->ip_len = htons(q->length());
    ip->ip_id = 0;
    ip->ip_p = 46;
    ip->ip_src = _own_address;
    ip->ip_dst = rsvpState.HOP_addr;
    ip->ip_tos = _tos_value;
    ip->ip_off = 0;
    ip->ip_ttl = 126;

    q->set_dst_ip_anno(rsvpState.HOP_addr);
    q->set_ip_header(ip, ip->ip_hl);

    CommonHeader *ch = (CommonHeader *) (ip + 1);
    ch->version_flags = 16;
    ch->msg_type = 2;
    if (rsvpState.confRequested){
        ch->length = htons(12 + 12 + 8 + 8 + 8 + 8 + 36 + 12);
    }
    else{
        ch->length = htons(12 + 12 + 8 + 8 + 8 + 36 + 12);
    }
    ch->send_ttl = 127;
    ch->checksum = 0;

//    click_chatter("Add session to Resv Message");
    Session *session = (Session *) (ch + 1);
    session->Class = 1;
    session->C_type = 1;
    session->length = htons(12);        // (64 body + 16 length + 8 class + 8 ctype) / 8
    session->dest_addr = _address;
    session->protocol_id = 17;
    session->flags = 0;
    session->dstport = htons(_port);

//    click_chatter("Add HOP to Resv Message");
    RSVP_HOP *hop = (RSVP_HOP *) (session + 1);
    hop->Class = 3;
    hop->C_type = 1;
    hop->addr = _own_address;
    hop->LIH = 0;
    hop->length = htons(12);            // (64 body + 16 length + 8 class + 8 ctype) / 8

//    click_chatter("Add time to Resv Message");
    Time_Value* time_value = (Time_Value*)(hop+1);
    time_value->length = htons(8);      // (32 body + 16 length + 8 class + 8 ctype) / 8
    time_value->C_type = 1;
    time_value->Class = 5;
    time_value->period = htonl(10000);

    Style* style;

    if (rsvpState.confRequested){
        Resvconfirm* resvconfirm = (Resvconfirm*)(time_value+1);
        resvconfirm->C_type = 1;
        resvconfirm->Class = 15;
        resvconfirm->length = htons(8);     // (32 body + 16 length + 8 class + 8 ctype) / 8
        resvconfirm->receiveraddr = _own_address;

        //    click_chatter("Add style to Resv Message");
        style = (Style*)(resvconfirm+1);
        style->length = htons(8);           // (32 body + 16 length + 8 class + 8 ctype) / 8
        style->C_type = 1;
        style->Class = 8;
        style->flags = 0;
        style->reserved_options1 = 0;
        style->reserved_options2 = 0;
        style->fixed_filter = 10;
    }
    else{
        //    click_chatter("Add style to Resv Message");
        style = (Style*)(time_value+1);
        style->length = htons(8);           // (32 body + 16 length + 8 class + 8 ctype) / 8
        style->C_type = 1;
        style->Class = 8;
        style->flags = 0;
        style->reserved_options1 = 0;
        style->reserved_options2 = 0;
        style->fixed_filter = 10;
    }

    Flowspec* flowspec = (Flowspec*)(style+1);
    flowspec->length = htons(36);
    flowspec->C_type = 2;
    flowspec->Class = 9;
    flowspec->version = htons(1);
    flowspec->res = 12;
    flowspec->total_length = htons(7);
    flowspec->service = 5;
    flowspec->service_length = htons(6);
    flowspec->param_id = 127;
    flowspec->param_flags = 0;
    flowspec->param_length = htons(5);
    flowspec->r = htonl(1176256512);
    flowspec->b = htonl(1148846080);
    flowspec->p = htonl(flowspec->r*flowspec->b);
    flowspec->m = htonl(packetsize);
    flowspec->M = htonl(15*packetsize);

    Filterspec* filterspec = (Filterspec*)(flowspec+1);
    filterspec->length = htons(12);
    filterspec->Class = 10;
    filterspec->C_type = 1;
    filterspec->src = rsvpState.src_address;
    filterspec->reserved = 0;
    filterspec->srcPort = htons(rsvpState.src_port);

    ip->ip_sum = click_in_cksum((unsigned char *) ip, sizeof(click_ip));
    ch->checksum = click_in_cksum((unsigned char *) q->data(), q->length());

    output(0).push(q);

}

/////////////////////////////////////////////////////////////////////////

// Confirmation message
void RSVPHost::send_confirmation(RSVPState entry) {
    int headroom = sizeof(click_ether) + 4;
    int packetsize = sizeof(click_ip) +
                     sizeof(CommonHeader) +
                     sizeof(Session) +
                     sizeof(ErrorSpec) +
                     sizeof(Resvconfirm)+
                     sizeof(Style) +
                     sizeof(Flowspec) +
                     sizeof(Filterspec);

    int tailroom = 0;

//    click_ip* p_ip = (click_ip*)p->data();

    WritablePacket *q = WritablePacket::make(headroom, 0, packetsize, tailroom);

    if (q == 0) {
        click_chatter("Error with creating Resv_confirm message: returning empty packet");
        return;
    }

    memset(q->data(), '\0', packetsize);


    click_ip *ip = (click_ip *) q->data();
    ip->ip_v = 4;
    ip->ip_hl = sizeof(click_ip) >> 2;
    ip->ip_len = htons(q->length());
    ip->ip_id = 0;
    ip->ip_p = 46;
    ip->ip_src = _own_address;
    ip->ip_dst = entry.dst_HOP_addr;
    ip->ip_tos = _tos_value;
    ip->ip_off = 0;
    ip->ip_ttl = 126;

    q->set_dst_ip_anno(entry.dst_HOP_addr);
    q->set_ip_header(ip, ip->ip_hl);

    CommonHeader *ch = (CommonHeader *) (ip + 1);
    ch->version_flags = 16;
    ch->msg_type = 7;
    ch->length = htons(12 + 12 + 8 + 8 + 8 + 36 + 12);
    ch->send_ttl = 127;
    ch->checksum = 0;

//    click_chatter("Add session to Resv Message");
    Session *session = (Session *) (ch + 1);
    session->Class = 1;
    session->C_type = 1;
    session->length = htons(12);        // (64 body + 16 length + 8 class + 8 ctype) / 8
    session->dest_addr = _address;
    session->protocol_id = 17;
    session->flags = 0;
    session->dstport = htons(_port);

    ErrorSpec* errorSpec = (ErrorSpec*)(session+1);
    errorSpec->length = htons(12);
    errorSpec->Class = 6;
    errorSpec->C_type = 1;
    errorSpec->address = _own_address;
    errorSpec->flags = 0;
    errorSpec->error_code = 0;
    errorSpec->error_value = 0;

    Resvconfirm* resvconfirm = (Resvconfirm*)(errorSpec+1);
    resvconfirm->C_type = 1;
    resvconfirm->Class = 15;
    resvconfirm->length = htons(8);     // (32 body + 16 length + 8 class + 8 ctype) / 8
    resvconfirm->receiveraddr = _address;

    Style* style = (Style*)(resvconfirm+1);
    style->length = htons(8);           // (32 body + 16 length + 8 class + 8 ctype) / 8
    style->C_type = 1;
    style->Class = 8;
    style->flags = 0;
    style->reserved_options1 = 0;
    style->reserved_options2 = 0;
    style->fixed_filter = 10;

    Flowspec* flowspec = (Flowspec*)(style+1);
    flowspec->length = htons(36);
    flowspec->C_type = 2;
    flowspec->Class = 9;
    flowspec->version = 4;
    flowspec->res = 12;
    flowspec->total_length = htons(7);
    flowspec->service = 5;
    flowspec->service_length = htons(6);
    flowspec->param_id = 127;
    flowspec->param_flags = 0;
    flowspec->param_length = htons(5);
    flowspec->r = htonl(1176256512);
    flowspec->b = htonl(1148846080);
    flowspec->p = htonl(flowspec->r*flowspec->b);
    flowspec->m = htonl(packetsize);
    flowspec->M = htonl(15*packetsize);

    Filterspec* filterspec = (Filterspec*)(flowspec+1);
    filterspec->length = htons(12);
    filterspec->Class = 10;
    filterspec->C_type = 1;
    filterspec->src = _own_address;
    filterspec->reserved = 0;
    filterspec->srcPort = htons(_own_port);

    ip->ip_sum = click_in_cksum((unsigned char *) ip, sizeof(click_ip));
    ch->checksum = click_in_cksum((unsigned char *) q->data(), q->length());

    output(0).push(q);
}

/////////////////////////////////////////////////////////////////////////

void RSVPHost::push(int, Packet *p) {

    // If RSVP is enabled, determine what to do
    if (sessions.size() > 0){
        click_ip* iph = (click_ip*)(p->data());
        click_chatter("Received packet with protocol %d", iph->ip_p);
        /// IP protocol 46: RSVP
        if (iph->ip_p == 46){
            click_chatter("RSVP packet found");
            char *ipc = (char*)(iph);
            ipc += (iph->ip_hl)*4;
            CommonHeader* ch = (CommonHeader*)(ipc);
            click_chatter("Packet has message type %d", ch->msg_type);
            // Path message meant for this host: reply with Resv message and update states
            if (ch->msg_type == 1 && _own_address==iph->ip_dst){
                click_chatter("Path message found");
                click_chatter("Pushing Resv message at %s %u", _own_address.unparse().c_str(), _own_port);
                for (auto it = sessions.begin(); it!= sessions.end(); it++){
                    click_chatter("Entry: %s %u", it.value().session_dst.unparse().c_str(), it.value().dst_port);
                    if (it.value().session_dst == _own_address){
                        Session *s = (Session*)(ch+1);
                        RSVP_HOP* hop = (RSVP_HOP*)(s+1);
                        Time_Value* t = (Time_Value*)(hop+1);
                        Sendertemplate* stemp = (Sendertemplate*)(t+1);
                        it.value().HOP_addr = hop->addr;
                        it.value().src_address = stemp->src;
                        it.value().src_port = htons(stemp->srcPort);
                        click_chatter("HOP address: %s", hop->addr.unparse().c_str());
                        make_reservation(it.value());
                    }
                }
            }
            if (ch->msg_type == 2 && _own_address==iph->ip_dst){
                click_chatter("Resv message found");
                for (auto it = sessions.begin(); it != sessions.end(); it++){
                    if (it.value().src_address == _own_address && it.value().src_port == _own_port){
                        Session *s = (Session*)(ch+1);
                        RSVP_HOP* hop = (RSVP_HOP*)(s+1);
//                        Time_Value* t = (Time_Value*)(hop+1);
//                        Style* style;
//                        if (it.value().confRequested){
//                            Resvconfirm* resvconfirm = (Resvconfirm*)(t+1);
//                            style = (Style*)(resvconfirm+1);
//                        }
//                        else{
//                            style = (Style*)(t+1);
//                        }
//                        Flowspec* flowspec = (Flowspec*)(style+1);
//                        Filterspec* filterspec = (Filterspec*)(flowspec+1);
                        it.value().dst_HOP_addr = hop->addr;
//                        it.value().src_address = filterspec->src;
//                        it.value().src_port = htons(filterspec->srcPort);
                        send_confirmation(it.value());
                    }
                }
            }
            if (ch->msg_type == 3){
                click_chatter("Received Path error message");
            }
            if(ch->msg_type == 4){
                click_chatter("Received Resv error message");
            }
            if(ch->msg_type == 5){
                click_chatter("Received Path tear message");
//                for (HashMap<int, RSVPState>::iterator it = sessions.begin(); it != sessions.end(); it++){
//                    if (it.value().)
//                    click_chatter("Erasing state %i for %s", it.key(), it.value().session_dst.unparse().c_str());
//                    sessions.remove(it.key());
//                }
            }
            if(ch->msg_type == 6){
                click_chatter("Received Resv tear message");
            }
            if(ch->msg_type == 7){
                click_chatter("Received Confirm  message");
            }
            // Pass the packet to the next hop and update states
            else{
                click_chatter("Host received path message meant for other host");
                output(0).push(p);
            }

        }
        /// IP protocol 17: UDP
        else if (iph->ip_p == 17){
            click_ip *iph = (click_ip * )(p->data());
            IPAddress src = iph->ip_src;
            IPAddress dst = iph->ip_dst;
            for (auto it = sessions.begin(); it != sessions.end(); it++){
                if (src == it.value().src_address && dst == it.value().session_dst && it.value().reserveActive){
                    const click_udp *udph = p->udp_header();
                    uint16_t src_port = ntohs(udph->uh_sport);
                    uint16_t dst_port = ntohs(udph->uh_dport);
                    if (src_port == it.value().src_port && dst_port == it.value().dst_port){
                        iph->ip_tos = _tos_value;
                        iph->ip_sum = click_in_cksum((unsigned char *) iph, sizeof(click_ip));
                    }
                }
            }
            output(0).push(p);
        }

        else
            output(0).push(p);
    }
    // Else just pass along the packet
    else{
        click_chatter("RSVP not enabled for host %s", _own_address.unparse().c_str());
        output(0).push(p);
    }
}

/////////////////////////////////////////////////////////////////////////

// Handler to start sending RSVP packets
static int setRSVPHandler(const String &conf, Element* e, void *thunk, ErrorHandler *errh) {
    RSVPHost* rsvphost = (RSVPHost*)e;
    IPAddress address;
    uint16_t port;
    int sid;
    Vector<String> vec;
    cp_argvec(conf, vec);
    if (Args(vec, e, errh)
                .read_mp("ID", sid)
                .read_mp("SRC", address)
                .read_mp("PORT", port)
                .complete() < 0)
        return -1;
    rsvphost->setRSVP(sid, address, port);
    return 0;
}

// Start sending RSVP packets
void RSVPHost::setRSVP(int sid, IPAddress src, uint16_t port) {
    click_chatter("Session sender added");
    HashMap<int, RSVPState>::Pair* entry = sessions.find_pair(sid);
    if (entry != NULL){
        entry->value.src_port = port;
        entry->value.src_address = src;
        entry->value.refreshValue = Timestamp::recent();
        entry->value.lifetime = 10000;
        entry->value.refreshPeriod = 10000;
        entry->value.sessionReady = true;
    }
    else{
        RSVPState rsvpState;
        rsvpState.src_address = src;
        rsvpState.src_port = port;
        rsvpState.refreshValue = Timestamp::recent();
        rsvpState.lifetime = 10000;
        rsvpState.refreshPeriod = 10000;
        rsvpState.sessionReady = true;
        sessions.insert(sid, rsvpState);
    }

    _own_address = src;
    _own_port = port;
}

/////////////////////////////////////////////////////////////////////////

// Handler to add a session
static int setSession(const String &conf, Element* e, void *thunk, ErrorHandler *errh) {
    RSVPHost* rsvphost = (RSVPHost*)e;
    IPAddress address;
    uint16_t dst;
    int sid;
    Vector<String> vec;
    cp_argvec(conf, vec);
    if (Args(vec, e, errh)
                .read_mp("ID", sid)
                .read_mp("DST", address)    //DST_addr
                .read_mp("PORT", dst)       //DST_port
                .complete() < 0)
        return -1;
    rsvphost->addSession(sid, address, dst);
    return 0;
}

// Add a session
void RSVPHost::addSession(int sid, IPAddress dst_address, uint16_t dst_port) {
    click_chatter("Created session %i", sid);
    HashMap<int, RSVPState>::Pair* entry = sessions.find_pair(sid);
    if (entry != NULL){
        entry->value.dst_port = dst_port;
        entry->value.session_dst = dst_address;
        entry->value.refreshValue = Timestamp::recent();
        entry->value.lifetime = 10000;
        entry->value.refreshPeriod = 10000;
    }
    else{
        RSVPState rsvpState;
        rsvpState.dst_port = dst_port;
        rsvpState.session_dst = dst_address;
        rsvpState.refreshValue = Timestamp::recent();
        rsvpState.lifetime = 10000;
        rsvpState.refreshPeriod = 10000;
        sessions.insert(sid, rsvpState);
    }

    _address = dst_address;
    _port = dst_port;
}

/////////////////////////////////////////////////////////////////////////

// Handler to make a reservation
static int reserve(const String &conf, Element* e, void *thunk, ErrorHandler *errh) {
    RSVPHost* rsvphost = (RSVPHost*)e;
    bool confirmation;
    int sid;
    Vector<String> vec;
    cp_argvec(conf, vec);
    if (Args(vec, e, errh)
                .read_mp("ID", sid)
                .read_mp("CONF", confirmation)
                .complete() < 0)
        return -1;
    rsvphost->addReservation(sid, confirmation);
    return 0;
}

// Add a session
void RSVPHost::addReservation(int sid, bool confirmation) {
    click_chatter("Making reservation for %i", sid);
    HashMap<int, RSVPState>::Pair* entry = sessions.find_pair(sid);
    if (entry == NULL){
        click_chatter("No session found");
    }
    else{
        entry->value.refreshValue = Timestamp::recent();
        entry->value.latestRefresh = Timestamp::recent();
        entry->value.lifetime = 10000;
        entry->value.refreshPeriod = 10000;
        entry->value.confRequested = confirmation;
        entry->value.reserveActive = true;
        make_reservation(entry->value);
    }
}

/////////////////////////////////////////////////////////////////////////

// Handler to release a connection
static int release(const String &conf, Element* e, void *thunk, ErrorHandler *errh) {
    RSVPHost* rsvphost = (RSVPHost*)e;
    IPAddress address;
    IPAddress dst;
    int sid;
    Vector<String> vec;
    cp_argvec(conf, vec);
    if (Args(vec, e, errh)
                .read_mp("ID", sid)
                .complete() < 0)
        return -1;
    rsvphost->tearPath(sid);
    return 0;
}

// Release a connection
void RSVPHost::tearPath(int sid) {
    // Send tear message

    click_chatter("Removing session for %i", sid);
    HashMap<int, RSVPState>::Pair* entry = sessions.find_pair(sid);

    if(entry != NULL){
        if (entry->value.src_address == _own_address){
            // Path Tear
            Packet* q = make_path_tear(entry);
            click_chatter("Sending path tear");
            output(0).push(q);
        }
        else if (entry->value.session_dst == _own_address){
            // Resv Tear
            Packet* q = make_resv_tear(entry);
            output(0).push(q);
        }
    }

    sessions.remove(sid);
}

/////////////////////////////////////////////////////////////////////////

enum{OWN_ADDR};

// Reads the address of the host
String read_handler(Element *e, void *thunk){
    RSVPHost* rsvphost = (RSVPHost*)e;
    switch ((intptr_t)thunk) {
        case OWN_ADDR:
            return String((rsvphost->getOwnAddress()).unparse().c_str());
        default:
            return "<error>";
    }
}

/////////////////////////////////////////////////////////////////////////

void RSVPHost::add_handlers() {
    add_write_handler("sender", &setRSVPHandler, (void*) 0);
    add_write_handler("session", &setSession, (void*) 0);
    add_write_handler("release", &release, (void*) 0);
    add_write_handler("reserve", &reserve, (void*) 0);
    add_read_handler("getOwnAddress", read_handler, OWN_ADDR);
}

CLICK_ENDDECLS
EXPORT_ELEMENT(RSVPHost)
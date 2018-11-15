//
// Created by student on 11/15/18.
//

#include "RSVPSource.hh"

CLICK_DECLS

RSVPSource::RSVPSource() {}

int RSVPSource::configure(Vector <String> &, ErrorHandler *) {
    if (Args(conf, this, errh)
                .read_mp("ADDR", address)
                .read_mp("INPORT", in_port)
                .read_mp("OUTPORT", out_port)
                .complete() < 0)
        return -1;

    return 0;
}

RSVPSource::~RSVPSource() {}

void RSVPSource::push(int, Packet *p) {
    click_chatter("Pushing packet at RSVPSource %i-%i-%i", in_port, address, out_port);

    int headroom = sizeof(click_ip) + sizeof(CommonHeader);
    int p_size = sizeof(PathMessage);
    WritablePacket* q = Packet::make(headroom, 0, p_size, 0);

    if (q == 0)
        return 0;

    memset(q->data(), '\0', p_size);

    uint16_t ipid = ((_sequence) % 0xFFFF) + 1;

    //ip fields
    click_ip* ip = (click_ip*)q->data();
    ip->ip_v = 4;
    ip->ip_hl = sizeof(click_ip) >> 2;
    ip->ip_len = htons(q->length());
    ip->ip_id = htons(ipid);
    ip->ip_p = IP_PROTO_UDP;
    ip->ip_src = address;
    ip->ip_dst = dst;
    ip->ip_tos = 0;
    ip->ip_off = 0;
    ip->ip_ttl = 65;
    ip->ip_sum = click_in_cksum((unsigned char*) ip, sizeof(click_ip));

    q->set_dst_ip_anno(ip->ip_dst);

    CommonHeader* ch = (CommonHeader*)(ip+1);

    ch->send_ttl = ip->ip_ttl;
    ch->msg_type = 1;
    ch->version_flags = 16;
    ch->length = 0;
    ch->checksum = click_in_cksum((uint16_t) ch, sizeof(CommonHeader));

    output(0).push(q);
}

CLICK_ENDDECLS
EXPORT_ELEMENT(RSVPSource)
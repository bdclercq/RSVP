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

#include "RSVPSource.hh"

CLICK_DECLS

RSVPSource::RSVPSource() {}

int RSVPSource::configure(Vector <String> &conf, ErrorHandler *errh) {
    if (Args(conf, this, errh)
                .read_mp("ADDR", address)
                .read_mp("INPORT", in_port)
                .read_mp("DST", dst)
                .read_mp("OUTPORT", out_port)
                .complete() < 0)
        return -1;

    click_chatter("RSVPSource initialized with ");
    click_chatter(address.unparse().c_str());
    click_chatter(String(in_port).c_str());
    click_chatter(dst.unparse().c_str());
    click_chatter(String(out_port).c_str());
    return 0;
}

RSVPSource::~RSVPSource() {}

Packet* RSVPSource::make_packet(Packet* p) {

    click_chatter("Creating packet at source");

    int headroom = sizeof(click_ether) + 4;
    int p_size = sizeof(click_ip) + sizeof(click_udp) + sizeof(CommonHeader) + sizeof(PathMessageHeader);
    WritablePacket* q = Packet::make(headroom, 0, p_size, 0);

    if (q == 0)
        return 0;

    memset(q->data(), '\0', p_size);

    click_chatter("Setting fields of packet");

    //ip fields
    click_ip* ip = (click_ip*)q->data();
    ip->ip_v = 4;
    ip->ip_len = htons(q->length());
    ip->ip_src = address;
    ip->ip_dst = dst;
    ip->ip_tos = 0;
    ip->ip_sum = click_in_cksum((unsigned char*) ip, sizeof(click_ip));

    q->set_dst_ip_anno(ip->ip_dst);

    click_udp* udp = (click_udp*)(ip + 1);
    udp->uh_sport = htons(in_port);
    udp->uh_dport = htons(out_port);
    udp->uh_ulen = htons(q->length() - sizeof(click_ip));

    CommonHeader* ch = (CommonHeader*)(udp+1);

    ch->send_ttl = ip->ip_ttl;
    ch->msg_type = 1;
    ch->version_flags = 16;
    ch->length = 0;
    ch->checksum = 0;   //TODO fix checksum

    udp->uh_sum = click_in_cksum_pseudohdr(click_in_cksum((unsigned char*)udp, p_size - sizeof(click_ip)), ip, p_size - sizeof(click_ip));


    return q;
}

void RSVPSource::push(int, Packet *p) {
    click_chatter("Pushing packet at RSVPSource %i-%s-%i", in_port, address.unparse().c_str(), out_port);

    Packet* q = make_packet(p);

    output(0).push(q);
}

CLICK_ENDDECLS
EXPORT_ELEMENT(RSVPSource)
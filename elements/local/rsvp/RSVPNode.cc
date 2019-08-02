//
// Created by student on 11/13/18.
//

#include <click/config.h>
#include <click/confparse.hh>
#include <click/error.hh>
#include <click/args.hh>
#include <clicknet/ip.h>
#include <clicknet/ether.h>
#include <clicknet/udp.h>
#include "RSVPNode.hh"
#include "RSVPObject.hh"

CLICK_DECLS

RSVPNode::RSVPNode() : _timer(this), _lifetime(1000) {}

/////////////////////////////////////////////////////////////////////////

int RSVPNode::configure(Vector <String> &conf, ErrorHandler *errh) {
    if (Args(conf, this, errh)
                .read_mp("LAN_ADDR", lan_address)
                .read_mp("WAN_ADDR", wan_address)
                .read_mp("LAN_WAN", lan_wan)
//                .read_mp("OUTPORT", out_port)
                .complete() < 0)
        return -1;

    click_chatter("lan_wan = %i", lan_wan);

    _timer.initialize(this);
    _timer.schedule_after_msec(1000);

    return 0;
}

/////////////////////////////////////////////////////////////////////////

RSVPNode::~RSVPNode() {}

/////////////////////////////////////////////////////////////////////////

void RSVPNode::run_timer(Timer *timer) {
//    click_chatter("run timer");

    for (HashMap<int, RSVPState>::iterator it = sessions.begin(); it != sessions.end(); it++) {
        if (it.value().lifetime > 0) {
            uint32_t lt = it.value().lifetime;
            lt--;
            it.value().lifetime = lt;
        }
        if (it.value().lifetime <= 0) {
//            click_chatter("Erasing state %i for %s", it.key(), it.value().session_dst.unparse().c_str());
            sessions.remove(it.key());
        }
    }

//    click_chatter("reschedule");
    _timer.reschedule_after_msec(1000);
//    click_chatter("done");
}
/////////////////////////////////////////////////////////////////////////

// Path message
Packet *RSVPNode::make_packet(Packet* p) {



    int headroom = sizeof(click_ether) + 4;
    int packetsize = sizeof(click_ip) +
                     sizeof(RouterOption) +
                     sizeof(CommonHeader) +
                     sizeof(Session) +
                     sizeof(RSVP_HOP) +
                     sizeof(Time_Value)+
                     sizeof(Sendertemplate) +
                     sizeof(SenderTSpec);

    int tailroom = 0;

    WritablePacket *q = WritablePacket::make(headroom, 0, packetsize, tailroom);

    if (q == 0) {
        click_chatter("Error with creating Path message: returning empty packet");
        return 0;
    }

    memset(q->data(), '\0', packetsize);

    click_ip* iph = (click_ip*)(p->data());
    click_chatter("Old length = %d", ntohs(iph->ip_len));
    click_ip *ip = (click_ip *) q->data();
    ip->ip_v = 4;
    ip->ip_hl = sizeof(click_ip) + sizeof(RouterOption) >> 2;
    ip->ip_len = htons(q->length());
    ip->ip_id = iph->ip_id;
    ip->ip_p = iph->ip_p;
    ip->ip_src = iph->ip_src;
    ip->ip_dst = iph->ip_dst;
    ip->ip_tos = iph->ip_tos;
    ip->ip_off = iph->ip_off;
    ip->ip_ttl = iph->ip_ttl;
    ip->ip_sum = 0;

    q->set_ip_header(ip, ip->ip_hl);
    q->set_dst_ip_anno(iph->ip_dst);

    RouterOption* oldRO = (RouterOption*)(iph+1);
    RouterOption* RO = (RouterOption*)(ip+1);
    *RO = *oldRO;

    CommonHeader* oldch = (CommonHeader *) (oldRO + 1);
    CommonHeader *ch = (CommonHeader *) (RO + 1);
    *ch = *oldch;
    ch->checksum = 0;

    Session* oldsession = (Session*)(oldch+1);
    Session *session = (Session *) (ch + 1);
    *session = *oldsession;

    RSVP_HOP *oldhop = (RSVP_HOP *) (oldsession + 1);
    RSVP_HOP *hop = (RSVP_HOP *) (session + 1);
    *hop = *oldhop;            // (64 body + 16 length + 8 class + 8 ctype) / 8
    if (lan_wan == 0) {
        click_chatter("lan_wan == 0");
        hop->addr = wan_address;
    }
        // If wan, send to lan
    else if (lan_wan == 1) {
        click_chatter("lan_wan == 1");
        hop->addr = lan_address;
    }

    Time_Value* oldtime_value = (Time_Value*)(oldhop+1);
    Time_Value* time_value = (Time_Value*)(hop+1);
    *time_value = *oldtime_value;

    Sendertemplate* oldsendertemplate = (Sendertemplate*)(oldtime_value+1);
    Sendertemplate* sendertemplate = (Sendertemplate*)(time_value+1);
    *sendertemplate = *oldsendertemplate;

    SenderTSpec* oldspec = (SenderTSpec*)(oldsendertemplate+1);
    SenderTSpec* spec = (SenderTSpec*)(sendertemplate+1);
    *spec = *oldspec;

    ip->ip_sum = click_in_cksum((unsigned char *) ip, sizeof(click_ip)+ sizeof(RouterOption));
    ch->checksum = click_in_cksum((unsigned char *) q->data(), q->length());

    return q;
}

/////////////////////////////////////////////////////////////////////////

void RSVPNode::push(int, Packet *p) {

    click_ip *iph = (click_ip * )(p->data());
    /// IP protocol 46: RSVP
    if (iph->ip_p == 46) {
        click_chatter("RSVP packet found");
        char* ipc = (char*)(iph);
        ipc += (iph->ip_hl)*4;
        CommonHeader* ch = (CommonHeader*)(ipc);
        // Path message meant for this host: reply with Resv message and update states
        if (ch->msg_type == 1) {
            RouterOption *ro = (RouterOption *) (iph + 1);
            ch = (CommonHeader *) (ro + 1);
            Session *s = (Session *) (ch + 1);
            RSVP_HOP *hop = (RSVP_HOP *) (s + 1);
            Time_Value *t = (Time_Value *) (hop + 1);
            click_chatter("Path message found");
            /// Get source and destination IP from IP header and save as session source and destination
            bool found = false;
            Sendertemplate *sendertemplate = (Sendertemplate *) (t + 1);
            for (auto it = sessions.begin(); it != sessions.end(); it++) {
                if (it.value().session_dst == iph->ip_dst and it.value().src_address == sendertemplate->src and
                    it.value().src_port == sendertemplate->srcPort and it.value().dst_port == s->dstport and
                    it.value().session_PID == s->protocol_id) {
                    found = true;
                    if (ch->msg_type == 1)
                        it.value().HOP_addr = hop->addr;
                    else if (ch->msg_type == 2)
                        it.value().dst_HOP_addr = hop->addr;
                    it.value().latestRefresh = Timestamp::recent();
                    it.value().lifetime = (K + 0.5) + 1.5 * t->period;
                    it.value().refreshPeriod = t->period;
                    it.value().sessionReady = true;
                }
            }
            if (!found) {
                static int sid = 0;
                RSVPState rsvpState;
                if (ch->msg_type == 1)
                    rsvpState.HOP_addr = hop->addr;
                else if (ch->msg_type == 2)
                    rsvpState.dst_HOP_addr = hop->addr;
                rsvpState.session_dst = iph->ip_dst;
                rsvpState.src_address = sendertemplate->src;
                rsvpState.src_port = sendertemplate->srcPort;
                rsvpState.dst_port = s->dstport;
                rsvpState.session_PID = s->protocol_id;
                rsvpState.refreshValue = Timestamp::recent();
                rsvpState.lifetime = 10000;
                rsvpState.refreshPeriod = t->period;
                rsvpState.sessionReady = true;
                sessions.insert(sid++, rsvpState);
            }

            output(0).push(make_packet(p));
        }
        else if (ch->msg_type == 2) {
            ch = (CommonHeader *) (iph + 1);
            Session *s = (Session *) (ch + 1);
            RSVP_HOP *hop = (RSVP_HOP *) (s + 1);
            Time_Value *t = (Time_Value *) (hop + 1);
            click_chatter("Resv message found");
            /// Get source and destination IP from IP header and save as session source and destination
            bool found = false;
            Sendertemplate *sendertemplate = (Sendertemplate *) (t + 1);
            for (auto it = sessions.begin(); it != sessions.end(); it++) {
                if (it.value().session_dst == iph->ip_dst and it.value().src_address == sendertemplate->src and
                    it.value().src_port == sendertemplate->srcPort and it.value().dst_port == s->dstport and
                    it.value().session_PID == s->protocol_id) {
                    found = true;
                    if (ch->msg_type == 1)
                        it.value().HOP_addr = hop->addr;
                    else if (ch->msg_type == 2)
                        it.value().dst_HOP_addr = hop->addr;
                    it.value().latestRefresh = Timestamp::recent();
                    it.value().lifetime = (K + 0.5) + 1.5 * t->period;
                    it.value().refreshPeriod = t->period;
                    it.value().sessionReady = true;
                }
            }
            if (!found) {
                static int sid = 0;
                RSVPState rsvpState;
                if (ch->msg_type == 1)
                    rsvpState.HOP_addr = hop->addr;
                else if (ch->msg_type == 2)
                    rsvpState.dst_HOP_addr = hop->addr;
                rsvpState.session_dst = iph->ip_dst;
                rsvpState.src_address = sendertemplate->src;
                rsvpState.src_port = sendertemplate->srcPort;
                rsvpState.dst_port = s->dstport;
                rsvpState.session_PID = s->protocol_id;
                rsvpState.refreshValue = Timestamp::recent();
                rsvpState.lifetime = 10000;
                rsvpState.refreshPeriod = t->period;
                rsvpState.sessionReady = true;
                sessions.insert(sid++, rsvpState);
            }
            if (lan_wan == 0) {
                click_chatter("lan_wan == 0");
                hop->addr = wan_address;
            }
                // If wan, send to lan
            else if (lan_wan == 1) {
                click_chatter("lan_wan == 1");
                hop->addr = lan_address;
            }
            iph->ip_sum = click_in_cksum((unsigned char *) iph, sizeof(click_ip));
            ch->checksum = click_in_cksum((unsigned char *) p->data(), p->length());
            output(0).push(p);
        }
        else if (ch->msg_type == 3) {
            click_chatter("Received Path error message");
            // Update hop address
            /// RFC p25: error messages are simply sent upstream [...] and do not change state
            output(0).push(p);
        }
        else if (ch->msg_type == 4) {
            click_chatter("Received Resv error message");
            // Update hop address
            /// RFC p25: error messages are simply sent upstream [...] and do not change state
            output(0).push(p);
        }
        else if (ch->msg_type == 5) {
            click_chatter("Received Path tear message");
            /// Remove path and dependent reservation state
            // Remove session and update hop
            output(0).push(p);
        }
        else if (ch->msg_type == 6) {
            click_chatter("Received Resv tear message");
            /// Remove reservation state
            // Update hop
            output(0).push(p);
        }
        else if (ch->msg_type == 7) {
            click_chatter("Received Confirm  message");
            // Update hop
            output(0).push(p);
        }
        else {
            click_chatter("Message with unknown message type received:%d", ch->msg_type);
            output(0).push(p);
        }

    }
        /// IP protocol 17: UDP
    else if (iph->ip_p == 17) {
        click_ip *iph = (click_ip * )(p->data());
        IPAddress src = iph->ip_src;
        IPAddress dst = iph->ip_dst;
        for (auto it = sessions.begin(); it != sessions.end(); it++) {
            if (src == it.value().src_address && dst == it.value().session_dst && it.value().reserveActive) {
                const click_udp *udph = p->udp_header();
                uint16_t src_port = ntohs(udph->uh_sport);
                uint16_t dst_port = ntohs(udph->uh_dport);
                if (src_port == it.value().src_port && dst_port == it.value().dst_port) {
                    iph->ip_tos = _tos_value;
                    iph->ip_sum = click_in_cksum((unsigned char *) iph, sizeof(click_ip));
                }
            }
        }
        output(0).push(p);
    }

    else {
        output(0).push(p);
    }


}

CLICK_ENDDECLS
EXPORT_ELEMENT(RSVPNode)
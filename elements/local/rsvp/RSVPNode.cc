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

RSVPNode::RSVPNode() : _timer(this), _lifetime(10000) {}

/////////////////////////////////////////////////////////////////////////

int RSVPNode::configure(Vector <String> &conf, ErrorHandler *errh) {
    if (Args(conf, this, errh)
                .read_mp("LAN_ADDR", lan_address)
                .read_mp("WAN_ADDR", wan_address)
//                .read_mp("OUTPORT", out_port)
                .complete() < 0)
        return -1;

    click_chatter("Router initialized with LAN %s and WAN %s", lan_address.unparse().c_str(),
                  wan_address.unparse().c_str());


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
Packet *RSVPNode::make_packet(Packet *p, bool isLan) {

    int headroom = sizeof(click_ether) + 4;
    int packetsize = sizeof(click_ip) +
                     sizeof(RouterOption) +
                     sizeof(CommonHeader) +
                     sizeof(Session) +
                     sizeof(RSVP_HOP) +
                     sizeof(Time_Value) +
                     sizeof(Sendertemplate) +
                     sizeof(SenderTSpec);

    int tailroom = 0;

    WritablePacket *q = WritablePacket::make(headroom, 0, packetsize, tailroom);

    if (q == 0) {
        click_chatter("Error with creating Path message: returning empty packet");
        return 0;
    }

    memset(q->data(), '\0', packetsize);

    click_ip *iph = (click_ip * )(p->data());
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
    q->set_dst_ip_anno(ip->ip_dst);

    RouterOption *oldRO = (RouterOption *) (iph + 1);
    RouterOption *RO = (RouterOption *) (ip + 1);
    *RO = *oldRO;

    CommonHeader *oldch = (CommonHeader *) (oldRO + 1);
    CommonHeader *ch = (CommonHeader *) (RO + 1);
    *ch = *oldch;
    ch->checksum = 0;

    Session *oldsession = (Session *) (oldch + 1);
    Session *session = (Session *) (ch + 1);
    *session = *oldsession;

    RSVP_HOP *oldhop = (RSVP_HOP *) (oldsession + 1);
    RSVP_HOP *hop = (RSVP_HOP *) (session + 1);
    *hop = *oldhop;            // (64 body + 16 length + 8 class + 8 ctype) / 8
    if (isLan) {
        click_chatter("Going from LAN to WAN");
        hop->addr = wan_address;
    }
        // If wan, send to lan
    else {
        click_chatter("Going from WAN to LAN");
        hop->addr = lan_address;
    }

    Time_Value *oldtime_value = (Time_Value *) (oldhop + 1);
    Time_Value *time_value = (Time_Value *) (hop + 1);
    *time_value = *oldtime_value;

    Sendertemplate *oldsendertemplate = (Sendertemplate *) (oldtime_value + 1);
    Sendertemplate *sendertemplate = (Sendertemplate *) (time_value + 1);
    *sendertemplate = *oldsendertemplate;

    SenderTSpec *oldspec = (SenderTSpec *) (oldsendertemplate + 1);
    SenderTSpec *spec = (SenderTSpec *) (sendertemplate + 1);
    *spec = *oldspec;

    ip->ip_sum = click_in_cksum((unsigned char *) ip, sizeof(click_ip) + sizeof(RouterOption));
    ch->checksum = click_in_cksum((unsigned char *) q->data(), q->length());

    return q;
}

/////////////////////////////////////////////////////////////////////////

// Resv message
Packet *RSVPNode::make_reservation(Packet *p, bool conf, bool isLan, IPAddress next_hop) {

    int headroom = sizeof(click_ether) + 4;
    int packetsize = sizeof(click_ip) +
                     sizeof(CommonHeader) +
                     sizeof(Session) +
                     sizeof(RSVP_HOP) +
                     sizeof(Time_Value) +
                     sizeof(Style) +
                     sizeof(Flowspec) +
                     sizeof(Filterspec);

    if (conf) {
        packetsize += sizeof(Resvconfirm);
    }

    int tailroom = 0;

    WritablePacket *q = WritablePacket::make(headroom, 0, packetsize, tailroom);

    if (q == 0) {
        click_chatter("Error with creating Resv message: returning empty packet");
        return q;
    }

    memset(q->data(), '\0', packetsize);

    click_ip *iph = (click_ip * )(p->data());
    click_ip *ip = (click_ip *) q->data();
    ip->ip_v = 4;
    ip->ip_hl = sizeof(click_ip) >> 2;
    ip->ip_len = htons(q->length());
    ip->ip_id = iph->ip_id;
    ip->ip_p = iph->ip_p;

    if (isLan) {
        ip->ip_src = wan_address;
    }
        // If wan, send to lan
    else {
        ip->ip_src = lan_address;
    }
    click_chatter("source: from %s to %s", IPAddress(iph->ip_src).unparse().c_str(), IPAddress(ip->ip_src).unparse().c_str());
    ip->ip_dst = next_hop;
    click_chatter("destination is %s", next_hop.unparse().c_str());

    ip->ip_tos = iph->ip_tos;
    ip->ip_off = iph->ip_off;
    ip->ip_ttl = iph->ip_ttl;
    ip->ip_sum = 0;

    q->set_ip_header(ip, ip->ip_hl);
    q->set_dst_ip_anno(ip->ip_dst);

    CommonHeader *oldch = (CommonHeader *) (iph + 1);
    CommonHeader *ch = (CommonHeader *) (ip + 1);
    *ch = *oldch;
    ch->checksum = 0;

    Session *oldsession = (Session *) (oldch + 1);
    Session *session = (Session *) (ch + 1);
    *session = *oldsession;

    RSVP_HOP *oldhop = (RSVP_HOP *) (oldsession + 1);
    RSVP_HOP *hop = (RSVP_HOP *) (session + 1);
    *hop = *oldhop;            // (64 body + 16 length + 8 class + 8 ctype) / 8
    if (isLan) {
        click_chatter("Setting HOP to %s", wan_address.unparse().c_str());
        hop->addr = wan_address;
    }
        // If wan, send to lan
    else {
        click_chatter("Setting HOP to %s", lan_address.unparse().c_str());
        hop->addr = lan_address;
    }

    Time_Value *oldtime_value = (Time_Value *) (oldhop + 1);
    Time_Value *time_value = (Time_Value *) (hop + 1);
    *time_value = *oldtime_value;

    Style *style;
    Style *oldstyle;

    if (conf) {
        Resvconfirm *oldresvconfirm = (Resvconfirm *) (oldtime_value + 1);
        Resvconfirm *resvconfirm = (Resvconfirm *) (time_value + 1);
        *resvconfirm = *oldresvconfirm;

        //    click_chatter("Add style to Resv Message");
        oldstyle = (Style *) (oldresvconfirm + 1);
        style = (Style *) (resvconfirm + 1);
        *style = *oldstyle;
    } else {
        //    click_chatter("Add style to Resv Message");
        oldstyle = (Style *) (oldtime_value + 1);
        style = (Style *) (time_value + 1);
        *style = *oldstyle;
    }

    Flowspec *oldflowspec = (Flowspec *) (oldstyle + 1);
    Flowspec *flowspec = (Flowspec *) (style + 1);
    *flowspec = *oldflowspec;

    Filterspec *oldfilterspec = (Filterspec *) (oldflowspec + 1);
    Filterspec *filterspec = (Filterspec *) (flowspec + 1);
    *filterspec = *oldfilterspec;

    ip->ip_sum = click_in_cksum((unsigned char *) ip, sizeof(click_ip));
    ch->checksum = click_in_cksum((unsigned char *) q->data(), q->length());

    return q;

}

/////////////////////////////////////////////////////////////////////////
void RSVPNode::push(int input, Packet *p) {

    /// IP protocol 46: RSVP
    if (input == 0) {
        /// LAN packets
        click_ip *iph = (click_ip * )(p->data());
        char *ipc = (char *) (iph);
        ipc += (iph->ip_hl) * 4;
        CommonHeader *ch = (CommonHeader *) (ipc);
        // Path message meant for this host: reply with Resv message and update states
        if (ch->msg_type == 1) {
            RouterOption *ro = (RouterOption *) (iph + 1);
            ch = (CommonHeader *) (ro + 1);
            Session *s = (Session *) (ch + 1);
            RSVP_HOP *hop = (RSVP_HOP *) (s + 1);
            Time_Value *t = (Time_Value *) (hop + 1);
            click_chatter("Path message found on input 0...");
            click_chatter("%i sessions registered...", sessions.size());
            /// Get source and destination IP from IP header and save as session source and destination
            bool found = false;
            Sendertemplate *sendertemplate = (Sendertemplate *) (t + 1);
            for (auto it = sessions.begin(); it != sessions.end(); it++) {
                if (it.value().session_dst == s->dest_addr and
                    it.value().src_address == sendertemplate->src and
                    it.value().src_port == sendertemplate->srcPort and
                    it.value().dst_port == s->dstport and
                    it.value().session_PID == s->protocol_id) {

                    found = true;
                    it.value().HOP_addr = hop->addr;
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
                rsvpState.session_dst = s->dest_addr;
                rsvpState.src_address = sendertemplate->src;
                rsvpState.src_port = sendertemplate->srcPort;
                rsvpState.dst_port = s->dstport;
                rsvpState.session_PID = s->protocol_id;
                rsvpState.refreshValue = Timestamp::recent();
                rsvpState.lifetime = (K + 0.5) + 1.5 * t->period;
                rsvpState.refreshPeriod = t->period;
                rsvpState.sessionReady = true;
                rsvpState.conf_address = 0;
                rsvpState.gotResv = false;
                click_chatter("Add state");
                sessions.insert(sid++, rsvpState);
            }
            click_chatter("Forward message...");
            output(0).push(make_packet(p, true));
        } else if (ch->msg_type == 2) {
            ch = (CommonHeader *) (iph + 1);
            Session *s = (Session *) (ch + 1);
            RSVP_HOP *hop = (RSVP_HOP *) (s + 1);
            Time_Value *t = (Time_Value *) (hop + 1);
            click_chatter("Resv message found on input 0...");
            click_chatter("%i sessions registered...", sessions.size());
            /// Get source and destination IP from IP header and save as session source and destination
            bool conf = false;
            Style *style;
            Resvconfirm *resvconfirm;
            if (ntohs(ch->length) == 104) {
                resvconfirm = (Resvconfirm *) (t + 1);
                style = (Style *) (resvconfirm + 1);
                conf = true;
            }
            else {
                style = (Style *) (t + 1);
            }
            Flowspec *flowspec = (Flowspec *) (style + 1);
            Filterspec *filterspec = (Filterspec *) (flowspec + 1);
            for (auto it = sessions.begin(); it != sessions.end(); it++) {
                if (it.value().session_dst == s->dest_addr and
                    it.value().src_address == IPAddress(filterspec->src) and
                    it.value().src_port == filterspec->srcPort and
                    it.value().dst_port == s->dstport and
                    it.value().session_PID == s->protocol_id){
                    click_chatter("Resv message belongs to a session...");
                    if (ntohs(ch->length) == 104) {
                        it.value().conf_address = resvconfirm->receiveraddr;
                    }
                    /// Found the session to which the Resv message belongs
                    it.value().dst_HOP_addr = hop->addr;
                    it.value().session_flags = style->flags;
                    it.value().session_style = style->fixed_filter;
                    it.value().r = flowspec->r;
                    it.value().b = flowspec->b;
                    it.value().p = flowspec->p;
                    it.value().m = flowspec->m;
                    it.value().M = flowspec->M;
                    it.value().gotResv = true;

                    click_chatter("Forward message...");
                    output(0).push(make_reservation(p, conf, true, it.value().HOP_addr));
                }
            }

        } else if (ch->msg_type == 3) {
            click_chatter("Received Path error message");
            // Update hop address
            /// RFC p25: error messages are simply sent upstream [...] and do not change state
            output(0).push(p);
        } else if (ch->msg_type == 4) {
            click_chatter("Received Resv error message");
            // Update hop address
            /// RFC p25: error messages are simply sent upstream [...] and do not change state
            output(0).push(p);
        } else if (ch->msg_type == 5) {
            click_chatter("Received Path tear message");
            /// Remove path and dependent reservation state
            // Remove session and update hop
            output(0).push(p);
        } else if (ch->msg_type == 6) {
            click_chatter("Received Resv tear message");
            /// Remove reservation state
            // Update hop
            output(0).push(p);
        } else if (ch->msg_type == 7) {
            click_chatter("Received Confirm  message");
            // Update hop
            output(0).push(p);
        } else {
            click_chatter("Message with unknown message type received:%d", ch->msg_type);
            output(0).push(p);
        }

    }
    else if (input == 1){
        /// WAN packets
        click_ip *iph = (click_ip * )(p->data());
        char *ipc = (char *) (iph);
        ipc += (iph->ip_hl) * 4;
        CommonHeader *ch = (CommonHeader *) (ipc);
        // Path message meant for this host: reply with Resv message and update states
        if (ch->msg_type == 1) {
            RouterOption *ro = (RouterOption *) (iph + 1);
            ch = (CommonHeader *) (ro + 1);
            Session *s = (Session *) (ch + 1);
            RSVP_HOP *hop = (RSVP_HOP *) (s + 1);
            Time_Value *t = (Time_Value *) (hop + 1);
            click_chatter("Path message found on input 1...");
            click_chatter("%i sessions registered...", sessions.size());
            /// Get source and destination IP from IP header and save as session source and destination
            bool found = false;
            Sendertemplate *sendertemplate = (Sendertemplate *) (t + 1);
            for (auto it = sessions.begin(); it != sessions.end(); it++) {
                if (it.value().session_dst == s->dest_addr and
                    it.value().src_address == sendertemplate->src and
                    it.value().src_port == sendertemplate->srcPort and
                    it.value().dst_port == s->dstport and
                    it.value().session_PID == s->protocol_id) {

                    found = true;
                    it.value().HOP_addr = hop->addr;
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
                rsvpState.session_dst = s->dest_addr;
                rsvpState.src_address = sendertemplate->src;
                rsvpState.src_port = sendertemplate->srcPort;
                rsvpState.dst_port = s->dstport;
                rsvpState.session_PID = s->protocol_id;
                rsvpState.refreshValue = Timestamp::recent();
                rsvpState.lifetime = (K + 0.5) + 1.5 * t->period;
                rsvpState.refreshPeriod = t->period;
                rsvpState.sessionReady = true;
                rsvpState.conf_address = 0;
                rsvpState.gotResv = false;
                click_chatter("Add state");
                sessions.insert(sid++, rsvpState);
            }
            click_chatter("Forward message...");
            output(0).push(make_packet(p, false));
        } else if (ch->msg_type == 2) {
            ch = (CommonHeader *) (iph + 1);
            Session *s = (Session *) (ch + 1);
            RSVP_HOP *hop = (RSVP_HOP *) (s + 1);
            Time_Value *t = (Time_Value *) (hop + 1);
            click_chatter("Resv message found on input 1...");
            click_chatter("%i sessions registered...", sessions.size());
            /// Get source and destination IP from IP header and save as session source and destination
            bool conf = false;
            Style *style;
            Resvconfirm *resvconfirm;
            if (ntohs(ch->length) == 104) {
                resvconfirm = (Resvconfirm *) (t + 1);
                style = (Style *) (resvconfirm + 1);
                conf = true;
            }
            else {
                style = (Style *) (t + 1);
            }
            Flowspec *flowspec = (Flowspec *) (style + 1);
            Filterspec *filterspec = (Filterspec *) (flowspec + 1);
            for (auto it = sessions.begin(); it != sessions.end(); it++) {
                if (it.value().session_dst == s->dest_addr and
                    it.value().src_address == IPAddress(filterspec->src) and
                    it.value().src_port == filterspec->srcPort and
                    it.value().dst_port == s->dstport and
                    it.value().session_PID == s->protocol_id ){
                    //and not it.value().gotResv) {
                    click_chatter("Resv message belongs to a session...");
                    if (ntohs(ch->length) == 104) {
                        it.value().conf_address = resvconfirm->receiveraddr;
                    }
                    /// Found the session to which the Resv message belongs
                    it.value().dst_HOP_addr = hop->addr;
                    it.value().session_flags = style->flags;
                    it.value().session_style = style->fixed_filter;
                    it.value().r = flowspec->r;
                    it.value().b = flowspec->b;
                    it.value().p = flowspec->p;
                    it.value().m = flowspec->m;
                    it.value().M = flowspec->M;
                    it.value().gotResv = true;

                    click_chatter("Forward message...");
                    output(0).push(make_reservation(p, conf, false, it.value().HOP_addr));
                }
            }
        } else if (ch->msg_type == 3) {
            click_chatter("Received Path error message");
            // Update hop address
            /// RFC p25: error messages are simply sent upstream [...] and do not change state
            output(0).push(p);
        } else if (ch->msg_type == 4) {
            click_chatter("Received Resv error message");
            // Update hop address
            /// RFC p25: error messages are simply sent upstream [...] and do not change state
            output(0).push(p);
        } else if (ch->msg_type == 5) {
            click_chatter("Received Path tear message");
            /// Remove path and dependent reservation state
            // Remove session and update hop
            output(0).push(p);
        } else if (ch->msg_type == 6) {
            click_chatter("Received Resv tear message");
            /// Remove reservation state
            // Update hop
            output(0).push(p);
        } else if (ch->msg_type == 7) {
            click_chatter("Received Confirm  message");
            // Update hop
            output(0).push(p);
        } else {
            click_chatter("Message with unknown message type received:%d", ch->msg_type);
            output(0).push(p);
        }
    }
        /// IP protocol 17: UDP
    else if (input == 2) {
        output(0).push(p);
    }


}

CLICK_ENDDECLS
EXPORT_ELEMENT(RSVPNode)
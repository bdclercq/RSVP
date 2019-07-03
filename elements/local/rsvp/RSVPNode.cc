//
// Created by student on 11/13/18.
//

#include <click/config.h>
#include <click/confparse.hh>
#include <click/error.hh>
#include <click/args.hh>
#include "RSVPNode.hh"
#include "RSVPObject.hh"

CLICK_DECLS

RSVPNode::RSVPNode() : _timer(this), _lifetime(1000) {}

/////////////////////////////////////////////////////////////////////////

int RSVPNode::configure(Vector <String> &conf, ErrorHandler *errh) {
    if (Args(conf, this, errh)
                .read_mp("ADDR", address)
//                .read_mp("INPORT", in_port)
//                .read_mp("OUTPORT", out_port)
                .complete() < 0)
        return -1;

    _timer.initialize(this);
    _timer.schedule_after_msec(1000);

    return 0;
}

/////////////////////////////////////////////////////////////////////////

RSVPNode::~RSVPNode() {}

/////////////////////////////////////////////////////////////////////////

void RSVPNode::run_timer(Timer * timer) {

//    click_chatter("run timer");
//    for (auto it = pstates.begin(); it != pstates.end();) {
//        PathState pstate = (*it).second;
//        uint16_t lt = ntohs(pstate._lifetime);
//        if (lt > 0) {
//            lt--;
//            pstate._lifetime = htons(lt);
//            (*it).second = pstate;
//            ++it;
//        }
//        else {
//            pstates.erase(it);
//        }
//    }

//    click_chatter("reschedule");
    _timer.reschedule_after_msec(1000);
//    click_chatter("done");
}

/////////////////////////////////////////////////////////////////////////

void RSVPNode::push(int, Packet *p) {
    //click_chatter("Processing packet...");
    click_ip* iph = (click_ip*)(p->data());
    // Packet is RSVP
    if (iph->ip_p == 46){
        CommonHeader* ch = (CommonHeader*)(iph+1);
        Session* session = (Session*)(ch+1);
        RSVP_HOP* rsvp_hop = (RSVP_HOP*)(session+1);
        Time_Value* time_value = (Time_Value*)(rsvp_hop+1);
        Sendertemplate* sendertemplate = (Sendertemplate*)(time_value+1);
        SenderTSpec* senderTSpec = (SenderTSpec*)(sendertemplate+1);

//        SessionInfo si;
//        si.dest_addr = session->dest_addr;
//        si.dstport = session->dstport;
        // If packet is a Path or Resv Message, update states
        if (ch->msg_type == 1 ){
            // Path message
            // Address in state is previous address

//            PathState state;
//
//            state.session_dst = session->dest_addr;
//            state.session_flags = session->flags;
//            state.session_PID = session->protocol_id;
//            state.out_port = session->dstport;
//            state.HOP_addr = rsvp_hop->addr;
//            state.HOP_LIH = rsvp_hop->LIH;
//
//            state._lifetime = (K+0.5)*1.5*time_value->period;

//            pstates[si] = state;
            // Update address in HOP for next node
            rsvp_hop->LIH = rsvp_hop->addr;
            rsvp_hop->addr = address;
            output(0).push(p);
        }
        else if(ch->msg_type == 2){
            // Resv message
            // Address in state is address for next hop

//            ResvState state;
//
//            state.session_dst = session->dest_addr;
//            state.session_flags = session->flags;
//            state.session_PID = session->protocol_id;
//            state.out_port = session->dstport;
//            state.HOP_addr = rsvp_hop->addr;
//            state.HOP_LIH = rsvp_hop->LIH;
//
//            rstates[si] = state;
            // Update address in HOP for comparison in next node
//        rsvp_hop->addr = pathState.HOP_addr;
            output(0).push(p);
        }
            // If packet is path tear message
        else if(ch->msg_type == 5){

//            pstates.erase(si);
            output(0).push(p);
        }
            // In all other cases: just pass the packet
        else{
            output(0).push(p);
        }
    }
    else{
        output(0).push(p);
    }
}

CLICK_ENDDECLS
EXPORT_ELEMENT(RSVPNode)
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

RSVPNode::RSVPNode() {}

int RSVPNode::configure(Vector <String> &conf, ErrorHandler *errh) {
    if (Args(conf, this, errh)
                .read_mp("ADDR", address)
//                .read_mp("INPORT", in_port)
//                .read_mp("OUTPORT", out_port)
                .complete() < 0)
        return -1;

    return 0;
}

RSVPNode::~RSVPNode() {}

void RSVPNode::push(int, Packet *p) {
    //click_chatter("Processing packet...");
    click_ip* iph = (click_ip*)(p->data());
    CommonHeader* ch = (CommonHeader*)(iph+1);
    Session* session = (Session*)(ch+1);
    RSVP_HOP* rsvp_hop = (RSVP_HOP*)(session+1);

    Session s = *session;
    SessionInfo si;
    si.dest_addr = session->dest_addr;
    si.dstport = session->dstport;
    // If packet is a Path or Resv Message, update states
    if (ch->msg_type == 1 ){
        // Path message
        // Address in state is previous address

        PathState state;

        state.session_dst = session->dest_addr;
        state.session_flags = session->flags;
        state.session_PID = session->protocol_id;
        state.out_port = session->dstport;
        state.HOP_addr = rsvp_hop->addr;
        state.HOP_LIH = rsvp_hop->LIH;

        pstates[si] = state;
        // Update address in HOP for next node
        rsvp_hop->addr = address;
        output(0).push(p);
    }
    else if(ch->msg_type == 2){
        // Resv message
        // Address in state is address for next hop

        ResvState state;

        state.session_dst = session->dest_addr;
        state.session_flags = session->flags;
        state.session_PID = session->protocol_id;
        state.out_port = session->dstport;
        state.HOP_addr = rsvp_hop->addr;
        state.HOP_LIH = rsvp_hop->LIH;

        rstates[si] = state;
        // Update address in HOP for comparison in next node
//        rsvp_hop->addr = pathState.HOP_addr;
        output(0).push(p);
    }
    // If packet is path tear message
    else if(ch->msg_type == 5){

        pstates.erase(si);
        output(0).push(p);
    }
    // In all other cases: just pass the packet
    else{
        output(0).push(p);
    }



}

CLICK_ENDDECLS
EXPORT_ELEMENT(RSVPNode)
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
    click_chatter("Pushing packet at RSVPNode %i-%i-%i", in_port, address, out_port);

    click_ip* iph = (click_ip*)(p->data());
    CommonHeader* ch = (CommonHeader*)(iph+1);
    Session* session = (Session*)(ch+1);
    RSVP_HOP* rsvp_hop = (RSVP_HOP*)(session+1);

    // If packet is a Path or Resv Message
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
        pstates.push_back(state);
        // Update address in HOP for next node
        rsvp_hop->addr = address;
        output(0).push(p);
    }
    else if(ch->msg_type == 2){
        // Resv message
        // Address in state is address for next hop
        PathState state;
        state.session_dst = session->dest_addr;
        state.session_flags = session->flags;
        state.session_PID = session->protocol_id;
        state.out_port = session->dstport;
        state.HOP_addr = rsvp_hop->addr;
        state.HOP_LIH = rsvp_hop->LIH;
        pstates.push_back(state);
        // Update address in HOP for comparison in next node
        rsvp_hop->addr = address;
        output(0).push(p);
    }
    else{
        // Packet isn't a Path or Rev message
        // First task is to check whether QoS is required
        if (iph->ip_tos != 0){
            // QoS is requested
            // Now we need to check if it should come through this node
            bool has_session = false;
            for (auto state : pstates){
                if (session->dest_addr == state.session_dst and session->dstport == state.out_port){
                    has_session = true;
                }
            }
            if (has_session){
                priority.push_back(p);
            }
            else{
                best_effort.push_back(p);
            }

        }
        else{
            best_effort.push_back(p);
        }
        Packet* q;
        // Select packet to push
        if (priority.size()==0){
            q = best_effort.front();
            best_effort.pop_front();
        }
        else{
            q = priority.front();
            priority.pop_front();
        }
        output(0).push(q);
    }



}

CLICK_ENDDECLS
EXPORT_ELEMENT(RSVPNode)
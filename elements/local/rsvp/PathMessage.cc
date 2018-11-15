//
// Created by student on 11/7/18.
//

#include "PathMessage.hh"

CLICK_DECLS

PathMessage::PathMessage(IPAddress addr, PathMessage pm){
    ch = pm.ch;
    ch.send_ttl -= 1;
    integrity = pm.integrity;
    session = pm.session;
    hop = pm.hop;
    hop.addr = addr;
    time = pm.time;
    PD = pm.PD;
    STemp = pm.STemp;
    STSpec = pm.STSpec;
    ad = pm.ad;
    src = pm.src;
    dest = pm.dest;
}

CLICK_ENDDECLS
EXPORT_ELEMENT(PathMessage)
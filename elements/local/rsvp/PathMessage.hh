//
// Created by student on 11/7/18.
//

#ifndef CLICK_PATHMESSAGE_HH
#define CLICK_PATHMESSAGE_HH

#include "RSVPMessage.hh"
#include "RSVPObject.hh"

CLICK_DECLS

class PathMessage{
private:
    CommonHeader ch;
    Integrity integrity;    // Optional
    Session session;
    RSVP_HOP hop;           // Contains previous HOP address and LIH
    TimeValues time;
    Vector<PolicyData> PD;  // Optional
    Sendertemplate STemp;
    SenderTSpec STSpec;
    IPAddress src;
    IPAddress dest;
    uint16_t in_port;
    uint16_t out_port;
public:
    PathMessage(){};
    PathMessage(IPAddress addr, PathMessage pm);
    ~PathMessage(){};
};

CLICK_ENDDECLS
#endif //CLICK_PATHMESSAGE_HH

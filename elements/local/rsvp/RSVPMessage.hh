//
// Created by student on 11/7/18.
//

#ifndef CLICK_RSVPMESSAGE_HH
#define CLICK_RSVPMESSAGE_HH

#include <click/vector.hh>
#include <click/element.hh>
#include "RSVPObject.hh"

CLICK_DECLS

struct PathMessageHeader{
    CommonHeader ch;
    Integrity integrity;    // Optional
    Session session;
    RSVP_HOP hop;           // Contains previous HOP address and LIH
    Vector<PolicyData> PD;  // Optional
    Sendertemplate STemp;
    SenderTSpec STSpec;
};

struct ResvMessageHeader{
    Integrity integrity;    // Optional
    Session session;
    RSVP_HOP hop;           // Contains previous HOP address and LIH

    Vector<PolicyData> PD;  // Optional

};

CLICK_ENDDECLS

#endif //CLICK_RSVPMESSAGE_HH

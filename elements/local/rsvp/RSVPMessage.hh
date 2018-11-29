//
// Created by student on 11/7/18.
//

#ifndef CLICK_RSVPMESSAGE_HH
#define CLICK_RSVPMESSAGE_HH

#include <click/vector.hh>
#include <click/element.hh>
#include "RSVPObject.hh"

CLICK_DECLS

struct CommonHeader{
    uint8_t version_flags = 16; // version = 1, no flags
    uint8_t msg_type;   // 1 = path, 2 = resv, 3 = patherr, 4 = resverr, 5 = pathtear, 6 = resvtear, 7 = resvconf
    uint16_t checksum;
    uint8_t send_ttl;   // IP TTL with which message was sent
    uint16_t length;
    Vector<void*> objects;
};

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

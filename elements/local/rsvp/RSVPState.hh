//
// Created by student on 7/3/19.
//

#ifndef RSVP_RSVPSTATE_HH
#define RSVP_RSVPSTATE_HH

#include <click/timestamp.hh>

struct RSVPState{
    bool confRequested;
    bool sessionReady;
    bool reserveActive;

    IPAddress src_address;
    uint16_t src_port;

    IPAddress session_dst;
    uint16_t dst_port;

    uint8_t session_flags = 0;
    uint8_t session_style = 10;
    uint8_t session_PID = 17;

    IPAddress HOP_addr;
    IPAddress dst_HOP_addr;
    IPAddress HOP_LIH = 0;

    uint32_t lifetime = 10000;         // Lifetime in ms
    uint32_t refreshPeriod = 10000;

    Timestamp refreshValue;
    Timestamp latestRefresh;
};

#endif //RSVP_RSVPSTATE_HH

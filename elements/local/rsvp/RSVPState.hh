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
    bool gotResv;

    IPAddress src_address;
    uint16_t src_port;

    IPAddress session_dst;
    uint16_t dst_port;

    IPAddress conf_address = 0;

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

    uint32_t r = 10000;                 // Bucket rate
    uint32_t b = 1000;                 // Bucket size
    uint32_t p = r*b;    // Peak rate
    uint32_t m = 100;                 // Minimal policed unit
    uint32_t M = 2^15;                 // Maximum packet size, 1500 in reference

};

#endif //RSVP_RSVPSTATE_HH

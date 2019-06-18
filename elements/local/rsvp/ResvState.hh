//
// Created by student on 1/4/19.
//

#ifndef RSVP_RESVSTATE_H
#define RSVP_RESVSTATE_H

struct ResvState{
    IPAddress session_dst;
    uint8_t session_flags;
    uint8_t session_PID;
    uint16_t out_port;
    IPAddress HOP_addr;
    IPAddress HOP_LIH;
};

#endif //RSVP_RESVSTATE_H

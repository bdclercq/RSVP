//
// Created by student on 11/14/18.
//

#ifndef CLICK_PATHSTATE_HH
#define CLICK_PATHSTATE_HH

struct PathState{
    IPAddress session_dst;
    uint8_t session_flags;
    uint8_t session_PID;
    uint16_t out_port;
    IPAddress HOP_addr;
    IPAddress HOP_LIH;

    uint16_t _lifetime;
};

#endif //CLICK_PATHSTATE_HH

//
// Created by student on 11/14/18.
//

#ifndef CLICK_PATHSTATE_HH
#define CLICK_PATHSTATE_HH

struct PathState{
    IPAddress src;
    IPAddress dst;
    uint16_t in_port;
    uint16_t out_port;
};

#endif //CLICK_PATHSTATE_HH

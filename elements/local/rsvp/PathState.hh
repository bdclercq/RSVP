//
// Created by student on 11/14/18.
//

#ifndef CLICK_PATHSTATE_HH
#define CLICK_PATHSTATE_HH

class PathState{
private:
    IPAddress src;
    IPAddress dst;
    uint16_t in_port;
    uint16_t out_port;
public:
    PathState(){}
    PathState(IPAddress s, IPAddress d, uint16_t i, uint16_t o){src=s;dst=d;in_port=i;out_port=o;}
    ~PathState(){}
};

#endif //CLICK_PATHSTATE_HH

//
// Created by student on 11/7/18.
//

#ifndef CLICK_RSVPOBJECT_HH
#define CLICK_RSVPOBJECT_HH

CLICK_DECLS

struct uint24_t{
    unsigned int data : 24;
};

struct uint4_t{
    unsigned int data : 4;
};

struct SessionInfo{
    uint32_t dest_addr;
    uint16_t dstport;

    bool operator<(const SessionInfo s) const{
        return s.dest_addr<dest_addr && s.dstport<dstport;
    }
};

struct CommonHeader{
    uint8_t version_flags = 16; // version = 1, no flags
    uint8_t msg_type;   // 1 = path, 2 = resv, 3 = patherr, 4 = resverr, 5 = pathtear, 6 = resvtear, 7 = resvconf
    uint16_t checksum;
    uint8_t send_ttl;   // IP TTL with which message was sent
    uint16_t length;
};

struct Session{
    uint16_t length;     // Minimum length of 4
    uint8_t Class = 1;
    uint8_t C_type = 1;

    IPAddress dest_addr;
    uint8_t protocol_id;
    uint8_t flags;
    uint16_t dstport;

    bool operator==(Session s) const {
        if(s.length==length && s.Class==Class && s.C_type==C_type && s.dest_addr==dest_addr
            && s.protocol_id==protocol_id && s.flags==flags && s.dstport==dstport)
            return true;
        else
            return false;
    }

};

struct RSVP_HOP{
    uint16_t length;     // Minimum length of 4
    uint8_t Class = 3;
    uint8_t C_type = 1;

    IPAddress addr;
    IPAddress LIH;  // Logical Interface Handle
};

struct Time_Value{
    uint16_t length;
    uint8_t Class = 5;
    uint8_t C_type = 1;

    uint32_t period;
};

//struct Integrity{
//    uint16_t length = 4;     // Minimum length of 4
//    uint8_t Class = 4;
//    uint8_t C_type = 1;
//};

struct Scope{
    uint16_t length = 4;     // Minimum length of 4
    uint8_t Class = 7;
    uint8_t C_type = 1;

    Vector<uint32_t> addresses;
};

struct Style{
    uint16_t length = 4;     // Minimum length of 4
    uint8_t Class = 8;
    uint8_t C_type = 1;

    uint8_t flags;
    uint8_t reserved_options1;
    uint8_t reserved_options2;
    uint8_t fixed_filter;
};

struct Flowspec{
    uint16_t length = 36;     // Minimum length of 4
    uint8_t Class = 9;
    uint8_t C_type = 2;

    // See RFC2210
    uint8_t version;
    uint8_t res;
    uint16_t total_length;
    uint8_t service = 5;
    unsigned zero : 1;
    unsigned res2 : 7;
    uint16_t service_length;
    uint8_t param_id = 127;
    uint8_t param_flags = 0;
    uint16_t param_length = 0;
    uint32_t r;                 // Bucket rate
    uint32_t b;                 // Bucket size
    uint32_t p = UINT32_MAX;    // Peak rate
    uint32_t m;                 // Minimal policed unit
    uint32_t M;                 // Maximum packet size
};

struct Filterspec{
    uint16_t length = 4;     // Minimum length of 4
    uint8_t Class = 10;
    uint8_t C_type = 1;

    uint32_t src;
    uint16_t reserved;
    uint16_t srcPort;
};

struct Sendertemplate{
    uint16_t length = 4;     // Minimum length of 4
    uint8_t Class = 11;
    uint8_t C_type = 1;

    IPAddress src;
    uint16_t reserved;
    uint16_t srcPort;
};

struct SenderTSpec{
    uint16_t length = 4;     // Minimum length of 4
    uint8_t Class = 12;
    uint8_t C_type = 2;

    // See RFC2210
    uint16_t version;
    uint16_t total_length;
    uint8_t service = 1;
    uint8_t reserved;
    uint16_t service_length;
    uint8_t param_id = 127;
    uint8_t param_flags = 0;
    uint16_t param_length = 5;
    uint32_t r = 10000;                 // Bucket rate
    uint32_t b = 1000;                 // Bucket size
    uint32_t p = r*b;    // Peak rate
    uint32_t m = 100;                 // Minimal policed unit
    uint32_t M = 2^15;                 // Maximum packet size, 1500 in reference

};

//struct PolicyData{
//    uint16_t length = 4;     // Minimum length of 4
//    uint8_t Class = 14;
//    uint8_t C_type = 1;
//};

struct Resvconfirm{
    uint16_t length = 12;     // Minimum length of 4
    uint8_t Class = 15;
    uint8_t C_type = 1;

    uint32_t receiveraddr;
};

CLICK_ENDDECLS
#endif //CLICK_RSVPOBJECT_HH

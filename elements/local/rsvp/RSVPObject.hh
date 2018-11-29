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

struct Session{
    uint16_t length = 4;     // Minimum length of 4
    uint16_t id_type = 257; // ID = 1, ctype = 1

    IPAddress dest_addr;
    uint8_t protocol_id;
    uint8_t flags;
    uint16_t dstport;
};

struct RSVP_HOP{
    uint16_t length = 4;     // Minimum length of 4
    uint16_t id_type = 769; // ID = 1, ctype = 1

    IPAddress addr;
    IPAddress LIH;  // Logical Interface Handle
};

struct Integrity{
    uint16_t length = 4;     // Minimum length of 4
    uint16_t id_type = 1024; // ID = 1, ctype = 1
};

struct Scope{
    uint16_t length = 4;     // Minimum length of 4
    uint16_t id_type = 1793; // ID = 1, ctype = 1

    Vector<IPAddress> addresses;
};

struct Style{
    uint16_t length = 4;     // Minimum length of 4
    uint16_t id_type = 2049; // ID = 1, ctype = 1

    uint8_t flags;
    uint24_t options;
};

struct Flowspec{
    uint16_t length = 4;     // Minimum length of 4
    uint16_t id_type = 2305; // ID = 1, ctype = 1

    // See RFC2210
    uint4_t version;
    uint16_t total_length;
    uint8_t service = 5;
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
    uint16_t id_type = 2561; // ID = 1, ctype = 1

    IPAddress src;
    uint16_t srcPort;
};

struct Sendertemplate{
    uint16_t length = 4;     // Minimum length of 4
    uint16_t id_type = 2817; // ID = 1, ctype = 1

    IPAddress src;
    uint16_t srcPort;
};

struct SenderTSpec{
    uint16_t length = 4;     // Minimum length of 4
    uint16_t id_type = 3074; // ID = 1, ctype = 1

    // See RFC2210
    uint4_t version;
    uint16_t total_length;
    uint8_t service = 1;
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

struct PolicyData{
    uint16_t length = 4;     // Minimum length of 4
    uint16_t id_type = 3585; // ID = 1, ctype = 1

};

struct Resvconfirm{
    uint16_t length = 4;     // Minimum length of 4
    uint16_t id_type = 3841; // ID = 1, ctype = 1

    IPAddress receiveraddr;
};

CLICK_ENDDECLS
#endif //CLICK_RSVPOBJECT_HH

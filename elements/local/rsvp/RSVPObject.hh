//
// Created by student on 11/7/18.
//

#ifndef CLICK_RSVPOBJECT_HH
#define CLICK_RSVPOBJECT_HH

CLICK_DECLS

class Session{
private:
    IPAddress dest_addr;
    Vector<uint32_t> data;
    uint16_t length = 4;     // Minimum length of 4
    uint16_t id_type = 257; // ID = 1, ctype = 1
    uint8_t protocol_id;
    uint8_t flags;
    uint16_t dstport;
public:
    void addData(uint32_t w){data.push_back(w);}
    Session(){}
    Session(uint16_t l, IPAddress da, uint8_t p, uint8_t f, uint16_t dp){length=l;dest_addr=da;protocol_id=p;flags=f;dstport=dp;}
    ~Session(){}
};

class RSVP_HOP{
private:
    Vector<uint32_t> data;
    uint16_t length = 4;     // Minimum length of 4
    uint16_t id_type = 769; // ID = 3, ctype = 1
    IPAddress addr;
    IPAddress LIH;  // Logical Interface Handle
public:
    void addData(uint32_t w){data.push_back(w);}
    RSVP_HOP(){}
    RSVP_HOP(uint16_t l, IPAddress a, IPAddress lh){length=l;addr=a;LIH=lh;}
    ~RSVP_HOP(){}
};

class Integrity{
private:
    Vector<uint32_t> data;
    uint16_t length = 4;     // Minimum length of 4
    uint16_t id_type = 1024; // ID = 4
public:
    void addData(uint32_t w){data.push_back(w);}
    Integrity(){}
    Integrity(uint16_t l){length=l;}
    ~Integrity(){}
};

class TimeValues{
private:
    Vector<uint32_t> data;
    uint16_t length = 4;     // Minimum length of 4
    uint16_t id_type = 1281; // ID = 5, ctype = 1
    uint32_t refPer;  // Refresh period in ms
public:
    void addData(uint32_t w){data.push_back(w);}
    TimeValues(){}
    TimeValues(uint16_t l, uint32_t r){length=l;refPer=r;}
    ~TimeValues(){}
};

class ErrorSpec{
private:
    Vector<uint32_t> data;
    uint16_t length = 4;     // Minimum length of 4
    IPAddress ENA;  // Error Node Address
    uint16_t id_type = 1537; // ID = 6, ctype = 1
    uint8_t flags;
    uint8_t EC;  // Error code
    uint16_t EV;  // Error value
public:
    void addData(uint32_t w){data.push_back(w);}
    ErrorSpec(){}
    ErrorSpec(uint16_t l, IPAddress addr, uint8_t f, uint8_t ec, uint16_t ev){length=l;ENA=addr; flags=f;EC=ec;EV=ev;}
    ~ErrorSpec(){}
};

class Scope{
private:
    Vector<uint32_t> data;
    uint16_t length = 4;     // Minimum length of 4
    Vector<IPAddress> addresses;
    uint16_t id_type = 1793; // ID = 7, ctype = 1
public:
    void addData(uint32_t w){data.push_back(w);}
    Scope(){}
    Scope(uint16_t l){length=l;}
    void addAddr(IPAddress addr){addresses.push_back(addr);}
    ~Scope(){}
};

class Style{
private:
    Vector<uint32_t> data;
    uint16_t length = 4;     // Minimum length of 4
    uint16_t id_type = 2049; // ID = 8, ctype = 1
    uint8_t flags;
    uint24_t options;
public:
    void addData(uint32_t w){data.push_back(w);}
    Style(){}
    Style(uint16_t l, uint8_t f, uint2
    _t o){length=l;flags=f;options=o;}
    ~Style(){}
};

class Flowspec{
private:
    Vector<uint32_t> data;
    uint16_t length = 4;     // Minimum length of 4
    uint16_t id_type = 2305; // ID = 9, ctype = 1
public:
    void addData(uint32_t w){data.push_back(w);}
    Flowspec(){}
    Flowspec(uint16_t l){length=l;}
    ~Flowspec(){}
};

class Filterspec{
private:
    Vector<uint32_t> data;
    uint16_t length = 4;     // Minimum length of 4
    uint16_t id_type = 2561; // ID = 10, ctype = 1
    IPAddress src;
    uint16_t srcPort;
public:
    void addData(uint32_t w){data.push_back(w);}
    Filterspec(){}
    Filterspec(uint16_t l, IPAddress addr, uint16_t port){length=l;src=addr;srcPort=port;}
    ~Filterspec(){}
};

class Sendertemplate{
private:
    Vector<uint32_t> data;
    uint16_t length = 4;     // Minimum length of 4
    uint16_t id_type = 2817; // ID = 11, ctype = 1
    IPAddress src;
    uint16_t srcPort;
public:
    void addData(uint32_t w){data.push_back(w);}
    Sendertemplate(){}
    Sendertemplate(uint16_t l, IPAddress addr, uint16_t port){length=l;src=addr;srcPort=port;}
    ~Sendertemplate(){}
};

class SenderTSpec{
private:
    Vector<uint32_t> data;
    uint16_t length = 4;     // Minimum length of 4
    uint16_t id_type = 3074; // ID = 12, ctype = 2
    // See RFC2210
public:
    void addData(uint32_t w){data.push_back(w);}
    SenderTSpec(){}
    SenderTSpec(uint16_t l){length=l;}
    ~SenderTSpec(){}
};

class ADSpec{
private:
    Vector<uint32_t> data;
    uint16_t length = 4;     // Minimum length of 4
    uint16_t id_type = 3330; // ID = 13, ctype = 2
public:
    void addData(uint32_t w){data.push_back(w);}
    ADSpec(){}
    ADSpec(uint16_t l){length=l;}
    ~ADSpec(){}
};

class PolicyData{
private:
    Vector<uint32_t> data;
    uint16_t length = 4;     // Minimum length of 4
    uint16_t id_type = 3585; // ID = 14, ctype = 1
public:
    void addData(uint32_t w){data.push_back(w);}
    PolicyData(){}
    PolicyData(uint16_t l){length=l;}
    ~PolicyData(){}
};

class Resvconfirm{
private:
    Vector<uint32_t> data;
    uint16_t length = 4;     // Minimum length of 4
    uint16_t id_type = 3841; // ID = 15, ctype = 1
    IPAddress receiveraddr;
public:
    void addData(uint32_t w){data.push_back(w);}
    Resvconfirm(){}
    Resvconfirm(uint16_t l, IPAddress addr){length=l;receiveraddr=addr;}
    ~Resvconfirm(){}
};

CLICK_ENDDECLS
#endif //CLICK_RSVPOBJECT_HH

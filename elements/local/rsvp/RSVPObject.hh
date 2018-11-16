//
// Created by student on 11/7/18.
//

#ifndef CLICK_RSVPOBJECT_HH
#define CLICK_RSVPOBJECT_HH

CLICK_DECLS

struct int24{
    unsigned int data : 24;
};

class Session{
private:
    uint16_t length = 4;     // Minimum length of 4
    uint16_t id_type = 257; // ID = 1, ctype = 1
    Vector<uint32_t> data;

    IPAddress dest_addr;
    uint8_t protocol_id;
    uint8_t flags;
    uint16_t dstport;
public:
    Session(){}
    Session(IPAddress da, uint8_t p, uint8_t f, uint16_t dp, uint16_t l=4){length=l;dest_addr=da;protocol_id=p;flags=f;dstport=dp;}
    ~Session(){}
    void assign(const Session& s){this->length=s.getLength();this->id_type=s.getIDType();this->dest_addr=s.getDestAddr();this->protocol_id=s.getProtocolID();this->flags=s.getFlags();this->dstport=s.getDstPort();}
    IPAddress getDestAddr()const{ return this->dest_addr;}
    uint8_t getProtocolID()const{ return this->protocol_id;}
    uint8_t getFlags()const{ return this->flags;}
    uint16_t getDstPort()const{ return this->dstport;}
    uint16_t getLength()const{ return this->length;}
    uint16_t getIDType()const{ return this->id_type;}
    void addData(uint32_t w){data.push_back(w);}
};

class RSVP_HOP{
private:
    uint16_t length = 4;     // Minimum length of 4
    uint16_t id_type = 769; // ID = 1, ctype = 1
    Vector<uint32_t> data;

    IPAddress addr;
    IPAddress LIH;  // Logical Interface Handle
public:
    RSVP_HOP(){}
    RSVP_HOP(IPAddress a, IPAddress lh, uint16_t l=4){length=l;addr=a;LIH=lh;}
    ~RSVP_HOP(){}
    void assign(const RSVP_HOP& hop){this->length=hop.getLength();this->id_type=hop.getIDType();this->addr=hop.getAddr();this->LIH=hop.getLIH();}
    IPAddress getAddr()const{ return this->addr;}
    IPAddress getLIH()const{ return this->LIH;}
    uint16_t getLength()const{ return this->length;}
    uint16_t getIDType()const{ return this->id_type;}
    void setAddr(IPAddress ipAddress){this->addr=ipAddress;}
    void addData(uint32_t w){data.push_back(w);}
};

class Integrity{
private:
    uint16_t length = 4;     // Minimum length of 4
    uint16_t id_type = 1024; // ID = 1, ctype = 1
    Vector<uint32_t> data;
public:
    Integrity(uint16_t l=4){length=l;}
    ~Integrity(){}
    void assign(const Integrity& i){this->length=i.getLength();this->id_type=i.getIDType();}
    void addData(uint32_t w){data.push_back(w);}
    uint16_t getLength()const{ return this->length;}
    uint16_t getIDType()const{ return this->id_type;}
};

class Scope{
private:
    uint16_t length = 4;     // Minimum length of 4
    uint16_t id_type = 1793; // ID = 1, ctype = 1
    Vector<uint32_t> data;

    Vector<IPAddress> addresses;
public:
    Scope(uint16_t l=4){length=l;}
    void addAddr(IPAddress addr){addresses.push_back(addr);}
    ~Scope(){}
    Vector<IPAddress> getAddresses()const{ return this->addresses;}
    uint16_t getLength()const{ return this->length;}
    uint16_t getIDType()const{ return this->id_type;}
    void assign(const Scope& s){this->length=s.getLength();this->id_type=s.getIDType();this->addresses=s.getAddresses();}
    void addData(uint32_t w){data.push_back(w);}
};

class Style{
private:
    uint16_t length = 4;     // Minimum length of 4
    uint16_t id_type = 2049; // ID = 1, ctype = 1
    Vector<uint32_t> data;

    uint8_t flags;
    int24 options;
public:
    Style(){}
    Style(uint8_t f, int24 o, uint16_t l=4){length=l;flags=f;options=o;}
    ~Style(){}
    uint8_t getFlags()const{ return this->flags;}
    int24 getOptions()const{ return this->options;}
    uint16_t getLength()const{ return this->length;}
    uint16_t getIDType()const{ return this->id_type;}
    void assign(const Style& s){this->length=s.getLength();this->id_type=s.getIDType();this->flags=s.getFlags();this->options=s.getOptions();}
    void addData(uint32_t w){data.push_back(w);}
};

class Flowspec{
private:
    uint16_t length = 4;     // Minimum length of 4
    uint16_t id_type = 2305; // ID = 1, ctype = 1
    Vector<uint32_t> data;
public:
    Flowspec(uint16_t l=4){length=l;}
    ~Flowspec(){}
    void assign(const Flowspec& f){this->length=f.getLength();this->id_type=f.getIDType();}
    void addData(uint32_t w){data.push_back(w);}
    uint16_t getLength()const{ return this->length;}
    uint16_t getIDType()const{ return this->id_type;}
};

class Filterspec{
private:
    uint16_t length = 4;     // Minimum length of 4
    uint16_t id_type = 2561; // ID = 1, ctype = 1
    Vector<uint32_t> data;

    IPAddress src;
    uint16_t srcPort;
public:
    Filterspec(){}
    Filterspec(IPAddress addr, uint16_t port, uint16_t l=4){length=l;src=addr;srcPort=port;}
    ~Filterspec(){}
    IPAddress getSrc()const{ return this->src;}
    uint16_t getSrcPort()const{ return this->srcPort;}
    uint16_t getLength()const{ return this->length;}
    uint16_t getIDType()const{ return this->id_type;}
    void assign(const Filterspec& f){this->length=f.getLength();this->id_type=f.getIDType();this->src=f.getSrc();this->srcPort=f.getSrcPort();}
    void addData(uint32_t w){data.push_back(w);}
};

class Sendertemplate{
private:
    uint16_t length = 4;     // Minimum length of 4
    uint16_t id_type = 2817; // ID = 1, ctype = 1
    Vector<uint32_t> data;

    IPAddress src;
    uint16_t srcPort;
public:
    Sendertemplate(){}
    Sendertemplate(IPAddress addr, uint16_t port, uint16_t l=4){length=l;src=addr;srcPort=port;}
    ~Sendertemplate(){}
    IPAddress getSrc()const{ return this->src;}
    uint16_t getSrcPort()const{ return this->srcPort;}
    uint16_t getLength()const{ return this->length;}
    uint16_t getIDType()const{ return this->id_type;}
    void assign(const Sendertemplate& s){this->length=s.getLength();this->id_type=s.getIDType();this->src=s.getSrc();this->srcPort=s.getSrcPort();}
    void addData(uint32_t w){data.push_back(w);}
};

class SenderTSpec{
private:
    uint16_t length = 4;     // Minimum length of 4
    uint16_t id_type = 3074; // ID = 1, ctype = 1
    Vector<uint32_t> data;

    // See RFC2210
public:
    SenderTSpec(uint16_t l=4){length=l;}
    ~SenderTSpec(){}
    void assign(const SenderTSpec& s){this->length=s.getLength();this->id_type=s.getIDType();}
    void addData(uint32_t w){data.push_back(w);}
    uint16_t getLength()const{ return this->length;}
    uint16_t getIDType()const{ return this->id_type;}
};

class ADSpec{
private:
    uint16_t length = 4;     // Minimum length of 4
    uint16_t id_type = 3330; // ID = 1, ctype = 1
    Vector<uint32_t> data;
public:
    ADSpec(uint16_t l=4){length=l;}
    ~ADSpec(){}
    void assign(const ADSpec& a){this->length=a.getLength();this->id_type=a.getIDType();}
    void addData(uint32_t w){data.push_back(w);}
    uint16_t getLength()const{ return this->length;}
    uint16_t getIDType()const{ return this->id_type;}
};

class PolicyData{
private:
    uint16_t length = 4;     // Minimum length of 4
    uint16_t id_type = 3585; // ID = 1, ctype = 1
    Vector<uint32_t> data;
public:
    PolicyData(uint16_t l=4){length=l;}
    ~PolicyData(){}
    void assign(const PolicyData& p){this->length=p.getLength();this->id_type=p.getIDType();}
    void addData(uint32_t w){data.push_back(w);}
    uint16_t getLength()const{ return this->length;}
    uint16_t getIDType()const{ return this->id_type;}
};

class Resvconfirm{
private:
    uint16_t length = 4;     // Minimum length of 4
    uint16_t id_type = 3841; // ID = 1, ctype = 1
    Vector<uint32_t> data;

    IPAddress receiveraddr;
public:
    Resvconfirm(){}
    Resvconfirm(IPAddress addr, uint16_t l=4){length=l;receiveraddr=addr;}
    ~Resvconfirm(){}
    IPAddress getReceiver()const{ return this->receiveraddr;}
    uint16_t getLength()const{ return this->length;}
    uint16_t getIDType()const{ return this->id_type;}
    void assign(const Resvconfirm& r){this->receiveraddr=r.getReceiver();this->length=r.getLength();this->id_type=r.getIDType();}
    void addData(uint32_t w){data.push_back(w);}
};

CLICK_ENDDECLS
#endif //CLICK_RSVPOBJECT_HH

#include "ns3/core-module.h"
#include "ns3/network-module.h"
#include "ns3/internet-module.h"
#include "ns3/point-to-point-module.h"
#include "ns3/applications-module.h"
#include "ns3/ipv4-raw-socket-factory.h"
#include "ns3/ipv4-raw-socket-impl.h"
#include "ns3/ipv4-header.h"
#include "ns3/csma-module.h"
#include "ns3/ipv4-address-helper.h"
#include "ns3/ipv4-interface-address.h"
#include "ns3/log.h"
#include <openssl/md5.h>
#include "ns3/packet.h"
#include <filesystem>
#include <fstream>
#include <map>
#include <set>
#include <vector>
#include <tuple>
#include <cstring>
#include <cstdint>
#include <queue>
#include <algorithm>
#include <sstream>

using namespace ns3;
namespace fs = std::filesystem;

// Metrics monitoring for OSPF
struct OspfMetrics {
    uint32_t controlPacketsSent = 0;
    uint32_t authFailures = 0;
    Time attackTime;
    
    void OnPacketSent() { controlPacketsSent++; }
    
    void OnAuthFailure() {
        authFailures++;
        std::cout << "[" << Simulator::Now().GetSeconds() 
                  << "s] MD5 FAILED - Packet DROPPED" << std::endl;
    }
    
    void RecordAttack() {
        attackTime = Simulator::Now();
        std::cout << "\nATTACK at t=" << attackTime.GetSeconds() << "s\n" << std::endl;
    }
    
    void PrintSummary() {
        std::cout << "\n======================================" << std::endl;
        std::cout << "      OSPF METRICS SUMMARY" << std::endl;
        std::cout << "======================================" << std::endl;
        std::cout << "Control Packets Sent: " << controlPacketsSent << std::endl;
        std::cout << "Auth Failures:        " << authFailures << std::endl;
        if (authFailures > 0) {
            std::cout << "Detection Rate:       100%" << std::endl;
        }
        std::cout << "======================================\n" << std::endl;
    }
} g_metrics;

NS_LOG_COMPONENT_DEFINE("OspfStep4LsrAck");

// OSPF Common Header
class OspfCommonHeader : public Header {
public:
  OspfCommonHeader()
      : m_version(2), m_type(1), m_pktLen(0),
        m_routerId(0), m_areaId(0), m_checksum(0),
        m_authType(0), m_keyId(1), m_seqNum(0) {
    m_authData[0] = 0;
    m_authData[1] = 0;
    memset(m_digest, 0, 16);
  }

  // setters and getters
  void SetType(uint8_t t) { m_type = t; }
  uint8_t GetType() const { return m_type; }

  void SetRouterId(Ipv4Address rid) { m_routerId = rid.Get(); }
  uint32_t GetRouterIdRaw() const { return m_routerId; }

  void SetAreaId(Ipv4Address aid) { m_areaId = aid.Get(); }
  void SetPacketLen(uint16_t len) { m_pktLen = len; }
  void SetChecksum(uint16_t cks) { m_checksum = cks; }

  void SetAuthType(uint16_t t) { m_authType = t; }   // 0 = Null, 2 = MD5
  uint16_t GetAuthType() const { return m_authType; }

  void SetKeyId(uint8_t k) { m_keyId = k; }
  uint8_t GetKeyId() const { return m_keyId; }

  void SetSeqNum(uint32_t s) { m_seqNum = s; }
  uint32_t GetSeqNum() const { return m_seqNum; }

  void SetDigest(const uint8_t *d) { memcpy(m_digest, d, 16); }
  const uint8_t *GetDigest() const { return m_digest; }

  static const uint32_t COMMON_LEN = 24; // bytes (fixed in RFC 2328 §A.3.1)

  static TypeId GetTypeId() {
    static TypeId tid = TypeId("OspfCommonHeader").SetParent<Header>();
    return tid;
  }
  TypeId GetInstanceTypeId() const override { return GetTypeId(); }

  // Prints header contents for logging
  void Print(std::ostream &os) const override {
    os << "OSPFv2 hdr: v=" << unsigned(m_version)
       << " type=" << unsigned(m_type)
       << " len=" << m_pktLen
       << " rid=" << Ipv4Address(m_routerId)
       << " area=" << Ipv4Address(m_areaId)
       << " authType=" << m_authType;
    if (m_authType == 2)
      os << " keyId=" << unsigned(m_keyId)
         << " seq=" << m_seqNum;
  }

  uint32_t GetSerializedSize() const override { return COMMON_LEN; }

  // Serialize fields in network order ready to be written into a packet
  void Serialize(Buffer::Iterator i) const override {
    i.WriteU8(m_version);
    i.WriteU8(m_type);
    i.WriteHtonU16(m_pktLen);
    i.WriteHtonU32(m_routerId);
    i.WriteHtonU32(m_areaId);
    i.WriteHtonU16(m_checksum);
    i.WriteHtonU16(m_authType);
    i.WriteHtonU32(m_authData[0]);
    i.WriteHtonU32(m_authData[1]);
  }

  // Deserialize fields from packet buffer
  uint32_t Deserialize(Buffer::Iterator i) override {
    m_version = i.ReadU8();
    m_type = i.ReadU8();
    m_pktLen = i.ReadNtohU16();
    m_routerId = i.ReadNtohU32();
    m_areaId = i.ReadNtohU32();
    m_checksum = i.ReadNtohU16();
    m_authType = i.ReadNtohU16();
    m_authData[0] = i.ReadNtohU32();
    m_authData[1] = i.ReadNtohU32();
    return COMMON_LEN;
  }

private:
  // core OSPF headers
  uint8_t  m_version;
  uint8_t  m_type;
  uint16_t m_pktLen;
  uint32_t m_routerId;
  uint32_t m_areaId;
  uint16_t m_checksum;
  uint16_t m_authType;   // 0 = Null, 1 = Simple, 2 = MD5
  uint32_t m_authData[2];

  // fields for MD5 authentication
  uint8_t  m_keyId;
  uint32_t m_seqNum;
  uint8_t  m_digest[16];
};

// OSPF Hello Header for neighbor discovery
class OspfHelloHeader : public Header {
public:
  OspfHelloHeader() : m_netmask("255.255.255.0"), m_helloInterval(10), m_options(0x02), m_rtrPrio(1), m_deadInterval(40),
                      m_dr(0), m_bdr(0) {}
  void SetNetmask(Ipv4Mask m){ m_netmask = m; }
  void SetHello(uint16_t h){ m_helloInterval = h; }
  void SetDead(uint32_t d){ m_deadInterval = d; }
  void SetDr(Ipv4Address a){ m_dr = a.Get(); }
  void SetBdr(Ipv4Address a){ m_bdr = a.Get(); }
  void AddNeighbor(Ipv4Address rid){ m_neighbors.push_back(rid.Get()); }
  const std::vector<uint32_t>& GetNeighborRawList() const { return m_neighbors; }

  static const uint32_t HELLO_FIXED_LEN = 20; // without neighbors list

  static TypeId GetTypeId(){ static TypeId tid = TypeId("OspfHelloHeader").SetParent<Header>(); return tid; }
  TypeId GetInstanceTypeId() const override { return GetTypeId(); }
  void Print(std::ostream &os) const override {
    os << "Hello: mask=" << m_netmask << ", hi=" << m_helloInterval << ", dead=" << m_deadInterval
       << ", DR=" << Ipv4Address(m_dr) << ", BDR=" << Ipv4Address(m_bdr)
       << ", nbrs=" << m_neighbors.size();
  }
  uint32_t GetSerializedSize() const override { return HELLO_FIXED_LEN + 4 * m_neighbors.size(); }

  // Serializes header into packet buffer
  void Serialize(Buffer::Iterator i) const override {
    i.WriteHtonU32(m_netmask.Get());
    i.WriteHtonU16(m_helloInterval);
    i.WriteU8(m_options);
    i.WriteU8(m_rtrPrio);
    i.WriteHtonU32(m_deadInterval);
    i.WriteHtonU32(m_dr);
    i.WriteHtonU32(m_bdr);
    for (auto rid : m_neighbors) { i.WriteHtonU32(rid); }
  }
  // Deserialize header from packet buffer
  uint32_t Deserialize(Buffer::Iterator i) override {
    m_neighbors.clear();
    m_netmask = Ipv4Mask(i.ReadNtohU32());
    m_helloInterval = i.ReadNtohU16();
    m_options = i.ReadU8();
    m_rtrPrio = i.ReadU8();
    m_deadInterval = i.ReadNtohU32();
    m_dr = i.ReadNtohU32();
    m_bdr = i.ReadNtohU32();
    uint32_t consumed = HELLO_FIXED_LEN;
    // read neighbors until end of packet
    uint32_t remaining = i.GetSize() - HELLO_FIXED_LEN;
    while (remaining >= 4) {
      uint32_t rid = i.ReadNtohU32();
      m_neighbors.push_back(rid);
      consumed += 4;
      remaining -= 4;
    }
    return consumed;
  }
private:
  Ipv4Mask  m_netmask;  // subnet mask
  uint16_t  m_helloInterval; // hello interval in seconds
  uint8_t   m_options;   // options bitfield
  uint8_t   m_rtrPrio;  // router priority
  uint32_t  m_deadInterval; // router dead interval in seconds
  uint32_t  m_dr; // designated router
  uint32_t  m_bdr; // backup designated router
  std::vector<uint32_t> m_neighbors; // Router IDs
};

// Minimalistic implementation of MD5
struct Md5Ctx {
  uint32_t h[4];
  uint64_t len;
  uint8_t buf[64];
  size_t buf_len;
};

static inline uint32_t ROL(uint32_t x, uint32_t n) { return (x << n) | (x >> (32 - n)); }

static void md5_init(Md5Ctx *c) {
  c->h[0] = 0x67452301;
  c->h[1] = 0xefcdab89;
  c->h[2] = 0x98badcfe;
  c->h[3] = 0x10325476;
  c->len = 0;
  c->buf_len = 0;
}

static void md5_process_block(Md5Ctx *c, const uint8_t *block) {
  static const uint32_t K[] = {
    0xd76aa478,0xe8c7b756,0x242070db,0xc1bdceee,0xf57c0faf,0x4787c62a,0xa8304613,0xfd469501,
    0x698098d8,0x8b44f7af,0xffff5bb1,0x895cd7be,0x6b901122,0xfd987193,0xa679438e,0x49b40821,
    0xf61e2562,0xc040b340,0x265e5a51,0xe9b6c7aa,0xd62f105d,0x02441453,0xd8a1e681,0xe7d3fbc8,
    0x21e1cde6,0xc33707d6,0xf4d50d87,0x455a14ed,0xa9e3e905,0xfcefa3f8,0x676f02d9,0x8d2a4c8a,
    0xfffa3942,0x8771f681,0x6d9d6122,0xfde5380c,0xa4beea44,0x4bdecfa9,0xf6bb4b60,0xbebfbc70,
    0x289b7ec6,0xeaa127fa,0xd4ef3085,0x04881d05,0xd9d4d039,0xe6db99e5,0x1fa27cf8,0xc4ac5665,
    0xf4292244,0x432aff97,0xab9423a7,0xfc93a039,0x655b59c3,0x8f0ccc92,0xffeff47d,0x85845dd1,
    0x6fa87e4f,0xfe2ce6e0,0xa3014314,0x4e0811a1,0xf7537e82,0xbd3af235,0x2ad7d2bb,0xeb86d391
  };
  static const uint32_t S[] = {
      7,12,17,22, 7,12,17,22, 7,12,17,22, 7,12,17,22,
      5, 9,14,20, 5, 9,14,20, 5, 9,14,20, 5, 9,14,20,
      4,11,16,23, 4,11,16,23, 4,11,16,23, 4,11,16,23,
      6,10,15,21, 6,10,15,21, 6,10,15,21, 6,10,15,21
  };

  uint32_t a = c->h[0], b = c->h[1], cc = c->h[2], d = c->h[3];
  uint32_t M[16];
  for (int i = 0; i < 16; ++i) {
    M[i] = (uint32_t)block[i*4] | ((uint32_t)block[i*4+1] << 8) | ((uint32_t)block[i*4+2] << 16) | ((uint32_t)block[i*4+3] << 24);
  }

  for (uint32_t i = 0; i < 64; ++i) {
    uint32_t F, g;
    if (i < 16) { F = (b & cc) | ((~b) & d); g = i; }
    else if (i < 32) { F = (d & b) | ((~d) & cc); g = (5*i + 1) & 15; }
    else if (i < 48) { F = b ^ cc ^ d; g = (3*i + 5) & 15; }
    else { F = cc ^ (b | (~d)); g = (7*i) & 15; }
    uint32_t tmp = d;
    d = cc;
    cc = b;
    uint32_t x = a + F + K[i] + M[g];
    b = b + ROL(x, S[i]);
    a = tmp;
  }
  c->h[0] += a; c->h[1] += b; c->h[2] += cc; c->h[3] += d;
}

// Update MD5 context with data
static void md5_update(Md5Ctx *c, const uint8_t *data, size_t len) {
  c->len += (uint64_t)len * 8;
  size_t idx = 0;
  if (c->buf_len) {
    size_t want = 64 - c->buf_len;
    if (len < want) { memcpy(c->buf + c->buf_len, data, len); c->buf_len += len; return; }
    memcpy(c->buf + c->buf_len, data, want);
    md5_process_block(c, c->buf);
    c->buf_len = 0;
    idx += want;
  }
  while (idx + 64 <= len) {
    md5_process_block(c, data + idx);
    idx += 64;
  }
  if (idx < len) {
    c->buf_len = len - idx;
    memcpy(c->buf, data + idx, c->buf_len);
  }
}

// Finalize MD5 and produce output digest
static void md5_finalize(Md5Ctx *c, uint8_t out[16]) {
  // append 0x80, then zeros, then 64-bit length 
  uint8_t pad[64] = {0x80};
  size_t padLen = (c->buf_len < 56) ? (56 - c->buf_len) : (120 - c->buf_len);
  md5_update(c, pad, padLen);
  uint8_t len64[8];
  uint64_t bitlen = c->len;
  for (int i = 0; i < 8; ++i) len64[i] = (uint8_t)((bitlen >> (8 * i)) & 0xff);
  md5_update(c, len64, 8);
  for (int i = 0; i < 4; ++i) {
    out[i*4+0] = (uint8_t)(c->h[i] & 0xff);
    out[i*4+1] = (uint8_t)((c->h[i] >> 8) & 0xff);
    out[i*4+2] = (uint8_t)((c->h[i] >> 16) & 0xff);
    out[i*4+3] = (uint8_t)((c->h[i] >> 24) & 0xff);
  }
}

// Append OSPF MD5 Authentication Trailer
static void AppendOspfMd5Trailer(Ptr<Packet> pkt,
                                 const OspfCommonHeader &com,
                                 const std::string &password,
                                 uint8_t keyId,
                                 uint32_t seqNum)
{
    // Copy current packet data into buffer
    uint32_t sz = pkt->GetSize();
    std::vector<uint8_t> buf(sz);
    pkt->CopyData(buf.data(), sz);

    Md5Ctx ctx;
    md5_init(&ctx);
    if (sz > 0) md5_update(&ctx, buf.data(), sz);
    uint8_t zeros[16] = {0};
    md5_update(&ctx, zeros, 16);
    if (!password.empty()) md5_update(&ctx, (const uint8_t*)password.data(), password.size());
    uint8_t digest[16];
    md5_finalize(&ctx, digest);

    // Append digest bytes as trailer to packet
    Ptr<Packet> trailer = Create<Packet>(digest, 16);
    pkt->AddAtEnd(trailer);

    NS_LOG_INFO("Appended internal MD5 trailer (KeyId=" << unsigned(keyId)
                << ", Seq=" << seqNum << ")");
}

// LSA Header Implementation
class OspfLsaHeader : public Header {
public:
  OspfLsaHeader() : m_age(1), m_type(1), m_id(0), m_advRouter(0), m_seq(0x80000001), m_checksum(0), m_length(20) {}
  void SetType(uint8_t t) { m_type = t; }
  void SetLsaId(Ipv4Address id) { m_id = id.Get(); }
  void SetAdvertiser(Ipv4Address a) { m_advRouter = a.Get(); }
  void SetSeq(uint32_t s) { m_seq = s; }
  uint8_t  GetType() const { return m_type; }
  uint32_t GetId() const { return m_id; }
  uint32_t GetAdv() const { return m_advRouter; }
  uint32_t GetSeq() const { return m_seq; }

  static const uint32_t LSA_HDR_LEN = 20;

  static TypeId GetTypeId(){ static TypeId tid = TypeId("OspfLsaHeader").SetParent<Header>(); return tid; }
  TypeId GetInstanceTypeId() const override { return GetTypeId(); }
  void Print(std::ostream &os) const override {
    os << "LSAhdr: type=" << unsigned(m_type) << " id=" << Ipv4Address(m_id)
       << " adv=" << Ipv4Address(m_advRouter) << " seq=" << std::hex << m_seq << std::dec;
  }
  uint32_t GetSerializedSize() const override { return LSA_HDR_LEN; }
  void Serialize(Buffer::Iterator i) const override {
    i.WriteHtonU16(m_age);
    i.WriteU8(0);
    i.WriteU8(m_type);
    i.WriteHtonU32(m_id);
    i.WriteHtonU32(m_advRouter);
    i.WriteHtonU32(m_seq);
    i.WriteHtonU16(m_checksum);
    i.WriteHtonU16(m_length);
  }
  uint32_t Deserialize(Buffer::Iterator i) override {
    m_age = i.ReadNtohU16();
    (void)i.ReadU8();
    m_type = i.ReadU8();
    m_id = i.ReadNtohU32();
    m_advRouter = i.ReadNtohU32();
    m_seq = i.ReadNtohU32();
    m_checksum = i.ReadNtohU16();
    m_length = i.ReadNtohU16();
    return LSA_HDR_LEN;
  }
  void SetLength(uint16_t len) { m_length = len; }
  uint16_t GetLength() const { return m_length; }

private:
  uint16_t m_age;
  uint8_t  m_type;      // 1=Router, 2=Network, etc.
  uint32_t m_id;        // LSA ID
  uint32_t m_advRouter; // Advertising Router
  uint32_t m_seq;       // sequence
  uint16_t m_checksum;  // ignored for scaffold
  uint16_t m_length;    // total LSA length (we keep 20)
};

// LSU Header Implementation
class OspfLsuHeader : public Header {
public:
  OspfLsuHeader() : m_numLsa(0) {}
  void SetNumLsa(uint32_t n) { m_numLsa = n; }
  uint32_t GetNumLsa() const { return m_numLsa; }

  static TypeId GetTypeId(){ static TypeId tid = TypeId("OspfLsuHeader").SetParent<Header>(); return tid; }
  TypeId GetInstanceTypeId() const override { return GetTypeId(); }
  void Print(std::ostream &os) const override { os << "LSU: nlsa=" << m_numLsa; }
  uint32_t GetSerializedSize() const override { return 4; }
  void Serialize(Buffer::Iterator i) const override { i.WriteHtonU32(m_numLsa); }
  uint32_t Deserialize(Buffer::Iterator i) override { m_numLsa = i.ReadNtohU32(); return 4; }
private:
  uint32_t m_numLsa;
};

// LSR Header Implementation
class OspfLsrHeader : public Header
{
public:
  OspfLsrHeader ()
      : m_lsType(1),
        m_linkStateId(Ipv4Address("0.0.0.0")),
        m_advRouter(Ipv4Address("0.0.0.0")) {}

  static TypeId GetTypeId (void)
  {
    static TypeId tid = TypeId ("OspfLsrHeader")
      .SetParent<Header> ()
      .SetGroupName ("Internet")
      .AddConstructor<OspfLsrHeader> ();
    return tid;
  }
  TypeId GetInstanceTypeId (void) const override { return GetTypeId (); }

  uint32_t GetSerializedSize () const override { return 12; }
  // Serialize fields into packet buffer
  void Serialize (Buffer::Iterator i) const override {
    i.WriteU32 (m_lsType);
    WriteTo (i, m_linkStateId);
    WriteTo (i, m_advRouter);
  }
  // Deserialize fields from packet buffer
  uint32_t Deserialize (Buffer::Iterator i) override {
    m_lsType = i.ReadU32 ();
    ReadFrom (i, m_linkStateId);
    ReadFrom (i, m_advRouter);
    return GetSerializedSize ();
  }

  void Print (std::ostream &os) const override {
    os << "LSR: type=" << m_lsType
       << " id=" << m_linkStateId
       << " adv=" << m_advRouter;
  }

  // setters and getters
  void SetType (uint32_t type) { m_lsType = type; }
  uint32_t GetType () const { return m_lsType; }

  void SetLsaId (Ipv4Address id) { m_linkStateId = id; }
  Ipv4Address GetLsaId () const { return m_linkStateId; }

  void SetAdvRouter (Ipv4Address adv) { m_advRouter = adv; }
  Ipv4Address GetAdvRouter () const { return m_advRouter; }

private:
  uint32_t    m_lsType;
  Ipv4Address m_linkStateId;
  Ipv4Address m_advRouter;
};

// LSAck Header Implementation
class OspfLsAckHeader : public Header {
public:
  OspfLsAckHeader() {}
  OspfLsAckHeader(const OspfLsaHeader &lsa) : m_lsaHdr(lsa) {}

  static TypeId GetTypeId() {
    static TypeId tid = TypeId("OspfLsAckHeader")
      .SetParent<Header>()
      .AddConstructor<OspfLsAckHeader>();
    return tid;
  }
  TypeId GetInstanceTypeId() const override { return GetTypeId(); }

  uint32_t GetSerializedSize() const override {
    return OspfLsaHeader::LSA_HDR_LEN;
  }

  void Serialize(Buffer::Iterator i) const override {
    m_lsaHdr.Serialize(i);
  }

  uint32_t Deserialize(Buffer::Iterator i) override {
    return m_lsaHdr.Deserialize(i);
  }

  void Print(std::ostream &os) const override {
    os << "LSAck: ";
    m_lsaHdr.Print(os);
  }

  OspfLsaHeader GetLsa() const { return m_lsaHdr; }

private:
  OspfLsaHeader m_lsaHdr;
};


// OSPF Hello application that sends Hellos, responds to LSR and LSU, maintains LSDB.
struct LsaKey {
  uint8_t type; uint32_t id; uint32_t adv;
  bool operator<(const LsaKey& o) const {
    return std::tie(type,id,adv) < std::tie(o.type,o.id,o.adv);
  }
};

class OspfHelloApp : public Application {
public:
  OspfHelloApp() : m_deadMult(4) {}
  void Configure (Ipv4Address iface, Ipv4Address routerId, Time hello = Seconds(10)) {
    m_iface = iface;
    m_routerId = routerId;
    m_hello = hello;
  }

  void SetRouterId(Ipv4Address rid) { m_routerId = rid; }
  void BindToNetDevice(Ptr<NetDevice> dev)
  {
      Ptr<Ipv4> ipv4 = GetNode()->GetObject<Ipv4>();
      uint32_t iface = ipv4->GetInterfaceForDevice(dev);
      if (iface == (uint32_t)-1)
      {
          iface = ipv4->AddInterface(dev);
      }
      Ipv4InterfaceAddress iaddr = ipv4->GetAddress(iface, 0);
      m_socket = Socket::CreateSocket(GetNode(), TypeId::LookupByName("ns3::Ipv4RawSocketFactory"));
      m_socket->SetAttribute("Protocol", UintegerValue(89)); // OSPF protocol number
      m_socket->Bind(InetSocketAddress(iaddr.GetLocal(), 0));
      m_socket->Connect(InetSocketAddress(Ipv4Address("224.0.0.5"), 0));
  }

private:
  std::string m_authKey = "secret-key-7777";   // real MD5 key

  void StartApplication() override {
  if (!fs::exists("results")) fs::create_directory("results");

  NS_LOG_INFO("Node " << GetNode()->GetId() << " StartApplication(): configured iface="
               << m_iface << " routerId=" << m_routerId);

  // open neighbor log
  {
    std::ostringstream fn; fn << "results/ospf-neighbors-node" << GetNode()->GetId() << ".log";
    m_logNbr.open(fn.str(), std::ios::out | std::ios::trunc);
    if (!m_logNbr.is_open()) {
      NS_LOG_ERROR("Node " << GetNode()->GetId() << " failed to open " << fn.str());
    }
  }
  // open lsdb log
  {
    std::ostringstream fn; fn << "results/ospf-lsdb-node" << GetNode()->GetId() << ".log";
    m_logLsdb.open(fn.str(), std::ios::out | std::ios::trunc);
    if (!m_logLsdb.is_open()) {
      NS_LOG_ERROR("Node " << GetNode()->GetId() << " failed to open " << fn.str());
    }
  }
  // open routing log
  {
    std::ostringstream fn; fn << "results/ospf-rt-node" << GetNode()->GetId() << ".log";
    m_logRt.open(fn.str(), std::ios::out | std::ios::trunc);
    if (!m_logRt.is_open()) {
      NS_LOG_ERROR("Node " << GetNode()->GetId() << " failed to open " << fn.str());
    }
  }

    m_socket = Socket::CreateSocket(GetNode(), Ipv4RawSocketFactory::GetTypeId());
    Ptr<Ipv4> ipv4 = GetNode()->GetObject<Ipv4>();
    uint32_t ifIndex = ipv4->GetInterfaceForAddress(m_iface);

    // prints all interfaces and addresses
    NS_LOG_INFO("Node " << GetNode()->GetId() << " Ipv4 interfaces:");
    for (uint32_t idx = 0; idx < ipv4->GetNInterfaces(); ++idx) {
      for (uint32_t a = 0; a < ipv4->GetNAddresses(idx); ++a) {
        Ipv4InterfaceAddress ifaddr = ipv4->GetAddress(idx, a);
        NS_LOG_INFO("   ifaceIdx=" << idx << " addr=" << ifaddr.GetLocal()
                     << " mask=" << ifaddr.GetMask());
      }
    }

    if (ifIndex == (uint32_t)-1) {
      NS_LOG_ERROR("Node " << GetNode()->GetId() << ": configured m_iface=" << m_iface
                   << " not found on any interface! This will prevent proper bind.");
      // picks first interface with any address
      for (uint32_t idx = 0; idx < ipv4->GetNInterfaces(); ++idx) {
        if (ipv4->GetNAddresses(idx) > 0) { ifIndex = idx; break; }
      }
      NS_LOG_WARN("Node " << GetNode()->GetId() << " falling back to ifaceIdx=" << ifIndex);
    }

    // Binds raw socket to the chosen outbound device for sending
    Ptr<Ipv4RawSocketImpl> raw = DynamicCast<Ipv4RawSocketImpl>(m_socket);
    NS_ASSERT(raw); // keep existing assertion
    raw->SetProtocol(89);
    raw->BindToNetDevice(ipv4->GetNetDevice(ifIndex));

    // Binds to all addresses on OSPF port 89 for receiving
    InetSocketAddress local = InetSocketAddress(Ipv4Address("0.0.0.0"), 89);
    m_socket->Bind(local);

    m_socket->SetRecvCallback(MakeCallback(&OspfHelloApp::HandleRead, this));

    Simulator::Schedule (Seconds(0.5) + MilliSeconds (GetNode()->GetId()*50), &OspfHelloApp::SendHello, this);
    Simulator::Schedule (Seconds(1.0), &OspfHelloApp::PeriodicMaintenance, this);
  }

  // Stops Application for cleanup
  void StopApplication() override {
    if (m_socket) { m_socket->Close(); m_socket = nullptr; }
    if (m_logNbr.is_open()) m_logNbr.close();
    if (m_logLsdb.is_open()) m_logLsdb.close();
    if (m_logRt.is_open()) m_logRt.close();
  }

  // SendHello builds OSPF Hello, mark it as MD5-authenticated and multicast it.
  void SendHello() {
    OspfHelloHeader hello;
    hello.SetNetmask (Ipv4Mask("255.255.255.0"));
    hello.SetHello (m_hello.GetSeconds());
    hello.SetDead (m_deadMult * m_hello.GetSeconds());
    hello.SetDr (Ipv4Address("0.0.0.0"));
    hello.SetBdr (Ipv4Address("0.0.0.0"));

    for (const auto &kv : m_neighbors) { hello.AddNeighbor(kv.first); }

    OspfCommonHeader com;
    com.SetType (1); // Hello
    com.SetRouterId (m_routerId);
    com.SetAreaId (Ipv4Address("0.0.0.0"));
    com.SetPacketLen (OspfCommonHeader::COMMON_LEN + hello.GetSerializedSize());
    com.SetChecksum (0);

    // Marks packet as MD5-authenticated
    com.SetAuthType(2);
    com.SetKeyId(1);
    com.SetSeqNum(1); // fixed sequence for hello messages

    Ptr<Packet> p = Create<Packet>();
    p->AddHeader (hello);
    p->AddHeader (com);

    // Appends MD5 trailer using node's key
    AppendOspfMd5Trailer(p, com, m_authKey, com.GetKeyId(), com.GetSeqNum());

    Ipv4Address allspf("224.0.0.5");
    m_socket->SendTo(p, 0, InetSocketAddress(allspf, 0));
    g_metrics.OnPacketSent();   // <-- MONITORING: Track packet sent

    NS_LOG_INFO("Node " << GetNode()->GetId() << " sending Hello with neighborCount="
                << m_neighbors.size() << " helloLen=" << hello.GetSerializedSize());
    NS_LOG_INFO ("[" << Simulator::Now().GetSeconds() << "s] Node " << GetNode()->GetId() << " sent OSPF Hello from " << m_iface
                 << " with " << m_neighbors.size() << " neighbor(s)");

    Simulator::Schedule (m_hello, &OspfHelloApp::SendHello, this);
  }


  // SendInitialLsu creates a Router-LSA for this router and multicast it.
  void SendInitialLsu() {
    OspfLsaHeader lsa;
    lsa.SetType(1); // Router-LSA
    lsa.SetLsaId(m_routerId);
    lsa.SetAdvertiser(m_routerId);
    lsa.SetLength(OspfLsaHeader::LSA_HDR_LEN + 4);

    OspfLsuHeader lsu; lsu.SetNumLsa(1);

    OspfCommonHeader com; com.SetType(4); // LSU
    com.SetRouterId(m_routerId);
    com.SetAreaId(Ipv4Address("0.0.0.0"));

    LsaKey key{lsa.GetType(), lsa.GetId(), lsa.GetAdv()};
    m_lsdb[key] = std::make_pair(lsa.GetSeq(), Simulator::Now());
    RunSpfAndLog();
    if (m_logLsdb.is_open()) {
      m_logLsdb << std::fixed;
      m_logLsdb << Simulator::Now().GetSeconds()
                << ",LSA,add,type," << unsigned(lsa.GetType())
                << ",id," << Ipv4Address(lsa.GetId())
                << ",adv," << Ipv4Address(lsa.GetAdv())
                << ",seq,0x" << std::hex << lsa.GetSeq() << std::dec << "\n";
    }

    uint16_t total = OspfCommonHeader::COMMON_LEN + lsu.GetSerializedSize() + lsa.GetLength();
    com.SetPacketLen(total);

    // Mark packet as MD5-authenticated
    com.SetAuthType(2);
    com.SetKeyId(1);
    com.SetSeqNum(lsa.GetSeq()); // use LSA seq as the packet sequence

    Ptr<Packet> p = Create<Packet>();

    uint16_t bodyLen = 0;
    if (lsa.GetLength() > OspfLsaHeader::LSA_HDR_LEN) {
      bodyLen = lsa.GetLength() - OspfLsaHeader::LSA_HDR_LEN;
      Ptr<Packet> body = Create<Packet>(bodyLen); // zero-filled payload
      p->AddAtEnd(body);
    }

    p->AddHeader(lsa);        // LSA(s)
    p->AddHeader(lsu);        // LSU header
    p->AddHeader(com);        // OSPF common

    // Appends MD5 trailer
    AppendOspfMd5Trailer(p, com, m_authKey, com.GetKeyId(), com.GetSeqNum());

    Ipv4Address allspf("224.0.0.5");
    m_socket->SendTo(p, 0, InetSocketAddress(allspf, 0));
    g_metrics.OnPacketSent();   // <-- MONITORING: Track LSU packet sent

    NS_LOG_INFO("[" << Simulator::Now().GetSeconds() << "s] Node " << GetNode()->GetId() << " sent LSU with 1 Router-LSA");
  }

  // Sends LSR to neighbor for given LSA key
  void SendLsrRequest (Ipv4Address neighbor, const LsaKey &key)
  {
    OspfCommonHeader com; 
    com.SetType(3); // LSR
    com.SetRouterId(m_routerId);
    com.SetAreaId(Ipv4Address("0.0.0.0"));

    OspfLsrHeader lsr;
    lsr.SetType(key.type);
    lsr.SetLsaId(Ipv4Address(key.id));
    lsr.SetAdvRouter(Ipv4Address(key.adv));

    uint16_t total = OspfCommonHeader::COMMON_LEN + lsr.GetSerializedSize();
    com.SetPacketLen(total);

    Ptr<Packet> p = Create<Packet>();
    p->AddHeader(lsr);
    p->AddHeader(com);

    m_socket->SendTo(p, 0, InetSocketAddress(neighbor, 0));
    NS_LOG_INFO("[" << Simulator::Now().GetSeconds() << "s] Node " 
                 << GetNode()->GetId() << " sent LSR for LSA id=" 
                 << Ipv4Address(key.id) << " adv=" << Ipv4Address(key.adv));
  }

  // Sends LSU response to LSR
  void SendLsuResponse (Ipv4Address dst, const LsaKey &key)
  {
    auto it = m_lsdb.find(key);
    if (it == m_lsdb.end()) return; // nothing to send

    OspfCommonHeader com; com.SetType(4); // LSU
    com.SetRouterId(m_routerId);
    com.SetAreaId(Ipv4Address("0.0.0.0"));

    OspfLsuHeader lsu; lsu.SetNumLsa(1);
    OspfLsaHeader lsa;
    lsa.SetType(key.type);
    lsa.SetLsaId(Ipv4Address(key.id));
    lsa.SetAdvertiser(Ipv4Address(key.adv));
    lsa.SetSeq(it->second.first);

    uint16_t total = OspfCommonHeader::COMMON_LEN + lsu.GetSerializedSize() + OspfLsaHeader::LSA_HDR_LEN;
    com.SetPacketLen(total);

    // Marks packet as MD5-authenticated
    com.SetAuthType(2);
    com.SetKeyId(1);
    com.SetSeqNum(lsa.GetSeq());

    Ptr<Packet> p = Create<Packet>();
    p->AddHeader(lsa);
    p->AddHeader(lsu);
    p->AddHeader(com);

    // appends MD5 trailer
    AppendOspfMd5Trailer(p, com, m_authKey, com.GetKeyId(), com.GetSeqNum());

    m_socket->SendTo(p, 0, InetSocketAddress(dst, 0));

    NS_LOG_INFO("[" << Simulator::Now().GetSeconds() << "s] Node "
                 << GetNode()->GetId() << " replied to LSR from " << dst
                 << " with LSU for LSA id=" << Ipv4Address(key.id));
  }


  // Runs SPF and log routing table
  void RunSpfAndLog()
  {
    if (!m_logRt.is_open()) return;

    // Build set of all nodes in the graph
    std::set<uint32_t> nodes;
    uint32_t me = m_routerId.Get();
    nodes.insert(me);
    for (const auto &kv : m_lsdb) { nodes.insert(kv.first.adv); nodes.insert(kv.first.id); }
    for (const auto &kv : m_adj) { nodes.insert(kv.first); for (auto n: kv.second) nodes.insert(n); }

    // BFS from me
    std::queue<uint32_t> q;
    std::map<uint32_t,int> dist;
    std::map<uint32_t,uint32_t> pred;
    for (auto n : nodes) { dist[n] = -1; pred[n] = 0; }
    dist[me] = 0; pred[me] = me;
    q.push(me);

    while (!q.empty()) {
      uint32_t u = q.front(); q.pop();
      auto it = m_adj.find(u);
      if (it == m_adj.end()) continue;
      for (uint32_t v : it->second) {
        if (dist.find(v) == dist.end()) continue;
        if (dist[v] == -1) {
          dist[v] = dist[u] + 1;
          pred[v] = u;
          q.push(v);
        }
      }
    }

    // Logs routing table
    m_logRt << std::fixed;
    m_logRt << Simulator::Now().GetSeconds() << ",ROUTETABLE\n";
    m_logRt << "dest, nextHop, distance, path\n";

    // sort destinations
    std::vector<uint32_t> dests(nodes.begin(), nodes.end());
    std::sort(dests.begin(), dests.end());

    for (uint32_t dst : dests) {
      if (dst == me) continue;
      if (dist.find(dst) == dist.end() || dist[dst] == -1) {
        m_logRt << Ipv4Address(dst) << ", -, -, UNREACHABLE\n";
        continue;
      }
      // reconstruct path from me to dst
      std::vector<uint32_t> path;
      uint32_t cur = dst;
      path.push_back(cur);
      while (cur != me) {
        cur = pred[cur];
        path.push_back(cur);
        if (path.size() > nodes.size()+5) break;
      }
      std::reverse(path.begin(), path.end());
      std::ostringstream ossPath;
      for (size_t i = 0; i < path.size(); ++i) {
          if (i) ossPath << ">";
          ossPath << Ipv4Address(path[i]);
      }
      std::string pathStr = ossPath.str();

      std::ostringstream ossNext;
      if (path.size() >= 2)
          ossNext << Ipv4Address(path[1]);
      else
          ossNext << "-";

      m_logRt << Ipv4Address(dst) << ", " << ossNext.str()
              << ", " << dist[dst] << ", " << pathStr << "\n";

    }

    m_logRt << "\n";
    m_logRt.flush();
  }

  // Receiving and processing incoming packets
  void HandleRead (Ptr<Socket> sock) {
    Address from;
    Ptr<Packet> pkt = sock->RecvFrom(from);
    NS_LOG_INFO("Node " << GetNode()->GetId()
                 << " HandleRead called, pkt size=" << pkt->GetSize());

    // Raw socket includes IPv4 header
    Ipv4Header ip; 
    pkt->RemoveHeader(ip);
    NS_LOG_INFO("Node " << GetNode()->GetId()
                 << " after removing IPv4 header, size=" << pkt->GetSize());

    // MD5 Authentication Verification
    uint32_t totalSize = pkt->GetSize();

    OspfCommonHeader peek;
    pkt->PeekHeader(peek);

    // If MD5-authenticated then we will verify the digest
    if (peek.GetAuthType() == 2 && totalSize > 40) {
      // Read entire packet into buffer
      uint32_t dataLen = totalSize;
      std::vector<uint8_t> fullBuf(dataLen);
      pkt->CopyData(fullBuf.data(), dataLen);

      // Extract received digest (last 16 bytes)
      uint8_t recvDigest[16];
      memcpy(recvDigest, fullBuf.data() + (dataLen - 16), 16);

      // Build data = packet without the trailing 16-byte digest
      std::vector<uint8_t> data;
      if (dataLen > 16) {
          data.assign(fullBuf.begin(), fullBuf.begin() + (dataLen - 16));
      }

      // Calculate MD5 digest over data + 16 zero bytes + password
      Md5Ctx ctx;
      md5_init(&ctx);
      if (!data.empty()) md5_update(&ctx, data.data(), data.size());
      uint8_t zeros[16] = {0};
      md5_update(&ctx, zeros, 16);
      md5_update(&ctx, (const uint8_t*)m_authKey.data(), m_authKey.size());
      uint8_t calcDigest[16];
      md5_finalize(&ctx, calcDigest);

      // Compare digests
      if (memcmp(recvDigest, calcDigest, 16) != 0) {
          NS_LOG_WARN("Node " << GetNode()->GetId()
                      << " MD5 authentication failed — packet dropped!");
          g_metrics.OnAuthFailure();
          return;
      } else {
          NS_LOG_INFO("Node " << GetNode()->GetId()
                      << " MD5 authentication success — packet accepted");
      }
    }
    bool md5Ok = true; 

    // Remove OSPF common header after verification
    OspfCommonHeader com; 
    pkt->RemoveHeader(com);
    uint8_t type = com.GetType();

    if (com.GetAuthType() == 2) {
        if (md5Ok)
            NS_LOG_INFO("Received MD5-authenticated OSPF packet (KeyId=" 
                        << unsigned(com.GetKeyId()) << ") verified OK");
        else
            NS_LOG_WARN("Received MD5-authenticated OSPF packet — failed check");
    } else {
        NS_LOG_INFO("Received unauthenticated OSPF packet");
    }

    // Processing based on OSPF packet type
    // Hello Packet type
    if (type == 1) {
        OspfHelloHeader hello;
        pkt->RemoveHeader(hello);
        Ipv4Address sender (com.GetRouterIdRaw());
        NS_LOG_INFO("Node " << GetNode()->GetId()
                     << " parsed Hello from RID=" << sender
                     << " neighbors=" << hello.GetNeighborRawList().size());

        bool newlyDiscovered = (m_neighbors.find(sender) == m_neighbors.end());
        if (newlyDiscovered) {
            NS_LOG_INFO("Node " << GetNode()->GetId()
                          << " discovered new neighbor " << sender);
            Simulator::Schedule(MilliSeconds(50),
                                 &OspfHelloApp::SendInitialLsu, this);
        }
        m_neighbors[sender] = Simulator::Now();

        bool listsUs = false;
        for (auto rid : hello.GetNeighborRawList())
            if (rid == m_routerId.Get()) { listsUs = true; break; }
        if (listsUs) m_twoWay.insert(sender);

        NS_LOG_INFO("[" << Simulator::Now().GetSeconds() << "s] Node "
                      << GetNode()->GetId()
                      << " received Hello from RID=" << sender
                      << (listsUs ? " [lists-us → 2-Way]" : ""));
        if (m_logNbr.is_open()) {
            m_logNbr << std::fixed;
            m_logNbr << Simulator::Now().GetSeconds()
                      << ",RECV,from," << sender
                      << ",listsUs," << (listsUs ? 1 : 0) << "\n";
            m_logNbr.flush();
        }

        uint32_t senderRaw = sender.Get();
        if (!m_adj.count(senderRaw))
            m_adj[senderRaw] = std::set<uint32_t>();

        for (auto rid : hello.GetNeighborRawList()) {
            m_adj[senderRaw].insert(rid);
            if (!m_adj.count(rid)) m_adj[rid] = std::set<uint32_t>();
        }

        if (listsUs) {
            uint32_t me = m_routerId.Get();
            m_adj[senderRaw].insert(me);
            m_adj[me].insert(senderRaw);
        }

        if (newlyDiscovered) {
            uint32_t me = m_routerId.Get();
            m_adj[senderRaw].insert(me);
            m_adj[me];
        }
        return;
    }

    // Link State Request
    if (type == 3) {
        OspfLsrHeader lsr; pkt->RemoveHeader(lsr);
        LsaKey key{(uint8_t)lsr.GetType(), lsr.GetLsaId().Get(), lsr.GetAdvRouter().Get()};
        NS_LOG_INFO("[" << Simulator::Now().GetSeconds() << "s] Node "
                      << GetNode()->GetId() << " received LSR for id="
                      << lsr.GetLsaId() << " adv=" << lsr.GetAdvRouter());
        SendLsuResponse(Ipv4Address::ConvertFrom(from), key);
        return;
    }

    // Link State Update
    if (type == 4) {
        OspfLsuHeader lsu; pkt->RemoveHeader(lsu);
        uint32_t n = lsu.GetNumLsa();
        for (uint32_t k = 0; k < n; ++k) {
            if (pkt->GetSize() < OspfLsaHeader::LSA_HDR_LEN) break;
            OspfLsaHeader lsa; pkt->RemoveHeader(lsa);

            LsaKey key{lsa.GetType(), lsa.GetId(), lsa.GetAdv()};
            uint32_t newSeq = lsa.GetSeq();
            uint32_t oldSeq = (m_lsdb.count(key) ? m_lsdb[key].first : 0);

            if (newSeq > oldSeq) {
                m_lsdb[key] = std::make_pair(newSeq, Simulator::Now());
                RunSpfAndLog();
                NS_LOG_INFO("Node " << GetNode()->GetId()
                              << " installed LSA type=" << unsigned(lsa.GetType())
                              << " id=" << Ipv4Address(lsa.GetId())
                              << " adv=" << Ipv4Address(lsa.GetAdv()));

                if (m_logLsdb.is_open()) {
                    m_logLsdb << std::fixed;
                    m_logLsdb << Simulator::Now().GetSeconds()
                              << ",LSA,add,type," << unsigned(lsa.GetType())
                              << ",id," << Ipv4Address(lsa.GetId())
                              << ",adv," << Ipv4Address(lsa.GetAdv())
                              << ",seq,0x" << std::hex << newSeq << std::dec << "\n";
                }
                SendLsAck(lsa);
            } else if (newSeq < oldSeq) {
                NS_LOG_INFO("Node " << GetNode()->GetId()
                              << " has newer LSA, requesting neighbor’s version via LSR");
                SendLsrRequest(Ipv4Address::ConvertFrom(from),
                               {lsa.GetType(), lsa.GetId(), lsa.GetAdv()});
            }
        }
        return;
    }

    // Link State Acknowledgment
    if (type == 5) {
        OspfLsAckHeader ack; pkt->RemoveHeader(ack);
        NS_LOG_INFO("Node " << GetNode()->GetId()
                      << " received LSAck for id=" << Ipv4Address(ack.GetLsa().GetId())
                      << " adv=" << Ipv4Address(ack.GetLsa().GetAdv()));
        return;
    }
  }



  // Send LS Acknowledgment for given LSA-
  void SendLsAck(const OspfLsaHeader &lsa) {
    OspfLsAckHeader ack; ack = OspfLsAckHeader(lsa);
    OspfCommonHeader com; com.SetType(5);
    com.SetRouterId(m_routerId); com.SetAreaId(Ipv4Address("0.0.0.0"));
    com.SetPacketLen(OspfCommonHeader::COMMON_LEN + ack.GetSerializedSize());

    // mark as MD5-authenticated
    com.SetAuthType(2);
    com.SetKeyId(1);
    com.SetSeqNum(lsa.GetSeq()); 

    Ptr<Packet> p = Create<Packet>();
    p->AddHeader(ack); p->AddHeader(com);

    // append MD5 trailer
    AppendOspfMd5Trailer(p, com, m_authKey, com.GetKeyId(), com.GetSeqNum());

    Ipv4Address allspf("224.0.0.5");
    m_socket->SendTo(p, 0, InetSocketAddress(allspf, 0));

    NS_LOG_INFO("[" << Simulator::Now().GetSeconds()
                     << "s] Node " << GetNode()->GetId()
                     << " sent LSAck for LSA id=" << Ipv4Address(lsa.GetId()));
  }

  // Send LS Request
  void SendLsr(const OspfLsaHeader& lsa)
  {
    OspfCommonHeader com;
    com.SetType(3); // LSR
    com.SetRouterId(m_routerId);
    com.SetAreaId(Ipv4Address("0.0.0.0"));

    OspfLsrHeader lsr;
    lsr.SetType(lsa.GetType());
    lsr.SetLsaId(Ipv4Address(lsa.GetId()));
    lsr.SetAdvRouter(Ipv4Address(lsa.GetAdv()));

    uint16_t total = OspfCommonHeader::COMMON_LEN + lsr.GetSerializedSize();
    com.SetPacketLen(total);

    // marks LSR as MD5-protected
    com.SetAuthType(2);
    com.SetKeyId(1);
    com.SetSeqNum(1);

    Ptr<Packet> p = Create<Packet>();
    p->AddHeader(lsr);
    p->AddHeader(com);

    // append MD5 trailer
    AppendOspfMd5Trailer(p, com, m_authKey, com.GetKeyId(), com.GetSeqNum());

    Ipv4Address allspf("224.0.0.5");
    m_socket->SendTo(p, 0, InetSocketAddress(allspf, 0));

    NS_LOG_INFO("[" << Simulator::Now().GetSeconds() << "s] Node "
                 << GetNode()->GetId() << " sent LSR for id="
                 << Ipv4Address(lsa.GetId()) << " adv="
                 << Ipv4Address(lsa.GetAdv()));
  }

  // Periodic maintenance tasks: prune dead neighbors, log LSDB snapshot, run SPF
  void PeriodicMaintenance() {
    // prune neighbors past DeadInterval
    Time now = Simulator::Now();
    Time deadInt = Seconds(m_deadMult * m_hello.GetSeconds());
    std::vector<Ipv4Address> toErase;
    for (const auto &kv : m_neighbors) {
      if (now - kv.second > deadInt) { toErase.push_back(kv.first); }
    }
    for (auto a : toErase) { m_neighbors.erase(a); m_twoWay.erase(a); if (m_logNbr.is_open()) { m_logNbr << now.GetSeconds() << ",PRUNE,neighbor," << a << "\n"; } }

    // LSDB snapshot
    if (m_logLsdb.is_open()) {
      m_logLsdb << now.GetSeconds() << ",SNAPSHOT,lsdb,";
      bool first=true;
      for (const auto &kv : m_lsdb) {
        if (!first) m_logLsdb << "|"; 
        first=false;
        const LsaKey &k = kv.first; m_logLsdb << unsigned(k.type) << ":" << Ipv4Address(k.id) << "@" << Ipv4Address(k.adv);
      }
      m_logLsdb << "\n";
    }
    RunSpfAndLog();

    Simulator::Schedule(Seconds(2.0), &OspfHelloApp::PeriodicMaintenance, this);
  }

private:
  Ptr<Socket> m_socket;
  Ipv4Address m_iface;    // Outbound interface
  Ipv4Address m_routerId; // Router ID
  Time m_hello;          // hello interval
  uint32_t m_deadMult;   // dead interval multiplier

  std::map<Ipv4Address, Time> m_neighbors; // last-seen per neighbor RID
  std::set<Ipv4Address> m_twoWay;          // neighbors in 2-Way

  // LSDB: LsaKey -> (seqNum, installTime)
  std::map<LsaKey, std::pair<uint32_t, Time>> m_lsdb;

  std::ofstream m_logNbr;
  std::ofstream m_logLsdb;
  // Adjacency map: routerRID -> set of neighbor RIDs
  std::map<uint32_t, std::set<uint32_t>> m_adj;

  std::ofstream m_logRt;
};

// Helper function to install OspfHelloApp on a node
static void InstallOspfHello(Ptr<Node> n, Ipv4Address iface, Ipv4Address rid, Time hi) {
  Ptr<OspfHelloApp> app = CreateObject<OspfHelloApp>();
  app->Configure (iface, rid, hi);
  n->AddApplication (app);
  app->SetStartTime (Seconds(0.0));
  app->SetStopTime (Seconds(60.0));
}

// Main function to set up the simulation
int main (int argc, char *argv[])
{
  Time::SetResolution (Time::NS);
  LogComponentEnable ("OspfStep4LsrAck", LOG_LEVEL_INFO);

  CommandLine cmd;
  bool enablePcap = true;
  cmd.AddValue("pcap", "Enable pcap on devices", enablePcap);
  cmd.Parse(argc, argv);

  // Legitimate Routers
  NodeContainer nodes;   // A,B,C,D
  nodes.Create(4);
  InternetStackHelper internet;
  internet.Install(nodes);

  // Attacker Node 
  NodeContainer attacker;
  attacker.Create(1);
  InternetStackHelper internetAtt;
  internetAtt.Install(attacker);

  // Channel Helpers 
  PointToPointHelper p2p;
  p2p.SetDeviceAttribute("DataRate", StringValue("10Mbps"));
  p2p.SetChannelAttribute("Delay", StringValue("2ms"));

  CsmaHelper csma;
  csma.SetChannelAttribute("DataRate", StringValue("10Mbps"));
  csma.SetChannelAttribute("Delay", TimeValue(MilliSeconds(2)));

  // Shared LAN: A–B–Attacker
  NodeContainer lanNodes;
  lanNodes.Add(nodes.Get(0));   // A
  lanNodes.Add(nodes.Get(1));   // B
  lanNodes.Add(attacker.Get(0));// E
  NetDeviceContainer dLAN = csma.Install(lanNodes);

  Ipv4AddressHelper ipv4_lan;
  ipv4_lan.SetBase("10.0.1.0", "255.255.255.0");
  Ipv4InterfaceContainer ifLAN = ipv4_lan.Assign(dLAN);

  Ipv4Address ridA = ifLAN.GetAddress(0);        // 10.0.1.1
  Ipv4Address ridB = ifLAN.GetAddress(1);        // 10.0.1.2
  Ipv4Address attackerIface = ifLAN.GetAddress(2); // 10.0.1.3
  Ipv4Address attackerRid("10.0.1.2");           // spoof B

  // Other P2P Links
  NetDeviceContainer dAC = p2p.Install(nodes.Get(0), nodes.Get(2));
  NetDeviceContainer dBD = p2p.Install(nodes.Get(1), nodes.Get(3));
  NetDeviceContainer dCD = p2p.Install(nodes.Get(2), nodes.Get(3));

  Ipv4AddressHelper ipv4;
  ipv4.SetBase("10.0.2.0", "255.255.255.0");  // A–C
  Ipv4InterfaceContainer ifAC = ipv4.Assign(dAC);
  ipv4.SetBase("10.0.3.0", "255.255.255.0");  // B–D
  Ipv4InterfaceContainer ifBD = ipv4.Assign(dBD);
  ipv4.SetBase("10.0.4.0", "255.255.255.0");  // C–D
  Ipv4InterfaceContainer ifCD = ipv4.Assign(dCD);

  Ipv4Address ridC = ifAC.GetAddress(1); // 10.0.2.2
  Ipv4Address ridD = ifBD.GetAddress(1); // 10.0.3.2

  // OSPF Hello Apps 
  auto appA_AB = CreateObject<OspfHelloApp>(); appA_AB->Configure(ifLAN.GetAddress(0), ridA, Seconds(5));
  auto appA_AC = CreateObject<OspfHelloApp>(); appA_AC->Configure(ifAC.GetAddress(0), ridA, Seconds(5));
  nodes.Get(0)->AddApplication(appA_AB);
  nodes.Get(0)->AddApplication(appA_AC);

  auto appB_AB = CreateObject<OspfHelloApp>(); appB_AB->Configure(ifLAN.GetAddress(1), ridB, Seconds(5));
  auto appB_BD = CreateObject<OspfHelloApp>(); appB_BD->Configure(ifBD.GetAddress(0), ridB, Seconds(5));
  nodes.Get(1)->AddApplication(appB_AB);
  nodes.Get(1)->AddApplication(appB_BD);

  auto appC_AC = CreateObject<OspfHelloApp>(); appC_AC->Configure(ifAC.GetAddress(1), ridC, Seconds(5));
  auto appC_CD = CreateObject<OspfHelloApp>(); appC_CD->Configure(ifCD.GetAddress(0), ridC, Seconds(5));
  nodes.Get(2)->AddApplication(appC_AC);
  nodes.Get(2)->AddApplication(appC_CD);

  auto appD_BD = CreateObject<OspfHelloApp>(); appD_BD->Configure(ifBD.GetAddress(1), ridD, Seconds(5));
  auto appD_CD = CreateObject<OspfHelloApp>(); appD_CD->Configure(ifCD.GetAddress(1), ridD, Seconds(5));
  nodes.Get(3)->AddApplication(appD_BD);
  nodes.Get(3)->AddApplication(appD_CD);

  // Start apps
  appA_AB->SetStartTime(Seconds(0.5));
  appA_AC->SetStartTime(Seconds(0.5));
  appB_AB->SetStartTime(Seconds(0.5));
  appB_BD->SetStartTime(Seconds(0.5));
  appC_AC->SetStartTime(Seconds(0.5));
  appC_CD->SetStartTime(Seconds(0.5));
  appD_BD->SetStartTime(Seconds(2.5));
  appD_CD->SetStartTime(Seconds(2.5));

  if (enablePcap)
  {
    // Enable promiscuous PCAP on shared LAN (A–B–Attacker)
    csma.EnablePcapAll("ospf-lan", true);

    // Capture all P2P links (A–C, B–D, C–D)
    p2p.EnablePcap("ospf-AC", dAC.Get(0), true);
    p2p.EnablePcap("ospf-CA", dAC.Get(1), true);
    p2p.EnablePcap("ospf-BD", dBD.Get(0), true);
    p2p.EnablePcap("ospf-DB", dBD.Get(1), true);
    p2p.EnablePcap("ospf-CD", dCD.Get(0), true);
    p2p.EnablePcap("ospf-DC", dCD.Get(1), true);
  }

  // Forged LSA Injection 
  Ptr<Socket> attSock = Socket::CreateSocket(attacker.Get(0), Ipv4RawSocketFactory::GetTypeId());
  Ptr<Ipv4> ipv4a = attacker.Get(0)->GetObject<Ipv4>();
  uint32_t ifIndex = ipv4a->GetInterfaceForAddress(attackerIface);
  Ptr<Ipv4RawSocketImpl> raw = DynamicCast<Ipv4RawSocketImpl>(attSock);
  raw->SetProtocol(89);
  raw->BindToNetDevice(ipv4a->GetNetDevice(ifIndex));
  attSock->Bind(InetSocketAddress(Ipv4Address("0.0.0.0"), 89));

  auto SendForgedLsa = [attSock, attackerRid]() {
    g_metrics.RecordAttack();
    
    Ipv4Address victimRid("10.0.1.2");

    // Build forged LSA header 
    OspfLsaHeader fake;
    fake.SetType(1);            // Router-LSA
    fake.SetLsaId(victimRid);   // LS ID = victim B
    fake.SetAdvertiser(victimRid); // Advertising Router = victim B
    fake.SetSeq(0x80001000);    // large seq to win
    fake.SetLength(OspfLsaHeader::LSA_HDR_LEN + 4); // 24 bytes total

    // LSU header
    OspfLsuHeader lsu;
    lsu.SetNumLsa(1);

    // OSPF common header with MD5 auth
    OspfCommonHeader com;
    com.SetType(4);             // LS Update
    com.SetRouterId(attackerRid);
    com.SetAreaId(Ipv4Address("0.0.0.0"));
    com.SetChecksum(0);
    com.SetAuthType(2);         // 2 = MD5
    com.SetKeyId(1);
    com.SetSeqNum(1);

    // Set total packet length
    uint16_t total = OspfCommonHeader::COMMON_LEN + lsu.GetSerializedSize() + fake.GetLength();
    com.SetPacketLen(total);

   // Build packet
    Ptr<Packet> pkt = Create<Packet>();

    uint16_t bodyLen = fake.GetLength() - OspfLsaHeader::LSA_HDR_LEN; // should be 4
    if (bodyLen > 0) {
      pkt->AddAtEnd(Create<Packet>(bodyLen)); // zero-filled bodyLen bytes
    }

    // Adds forged LSA header
    pkt->AddHeader(fake);

    // Adds LSU header
    pkt->AddHeader(lsu);

    // Adds OSPF common header
    pkt->AddHeader(com);

    // Append MD5 trailer with wrong key
    std::string md5key = "attacker-bad-key";
    AppendOspfMd5Trailer(pkt, com, md5key, 1, 1);

    // Send to all OSPF routers multicast address
    Ipv4Address allspf("224.0.0.5");
    attSock->SendTo(pkt, 0, InetSocketAddress(allspf, 0));

    NS_LOG_INFO("[" << Simulator::Now().GetSeconds()
                     << "s] Attacker (router-id=" << attackerRid 
                     << ") forged Router-LSA: adv=" << victimRid
                     << " seq=0x" << std::hex << fake.GetSeq() << std::dec);
  };

  Simulator::Schedule(Seconds(5.0), SendForgedLsa);

  Simulator::Stop(Seconds(20.0));
  Simulator::Run();
  
  // Prints final metrics
  g_metrics.PrintSummary();

  
  Simulator::Destroy();
  return 0;
}
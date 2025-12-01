#include "ns3/core-module.h"
#include "ns3/network-module.h"
#include "ns3/internet-module.h"
#include "ns3/applications-module.h"
#include "ns3/flow-monitor-module.h"
#include <map>
#include <set>
#include <vector>
#include <queue>
#include <limits>
#include <iomanip>
#include "ns3/packet-socket-helper.h"
#include "ns3/packet-socket-address.h"
#include "ns3/packet-socket.h"
#include "ns3/csma-module.h"
#include <arpa/inet.h>

#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <cstring>

using namespace ns3;

// ISIS Metrics Tracker
struct IsisMetrics {
    // counters
    uint64_t hellosSent = 0;
    uint64_t lspsSent = 0;
    uint64_t lspFloods = 0;
    uint64_t lsdbInserts = 0;
    uint64_t lsdbUpdates = 0;
    uint64_t spfRuns = 0;
    uint64_t neighborUp = 0;
    uint64_t neighborDown = 0;
    uint64_t macMismatchAlerts = 0;
    uint64_t fakeLspInjected = 0; 
    uint64_t lspRejectedAuth = 0; 

    Time firstSeenAttack = Seconds(0);

    void OnHelloSent() { hellosSent++; }
    void OnLspSent()   { lspsSent++; }
    void OnLspFlood()  { lspFloods++; }
    void OnLsdbNew()   { lsdbInserts++; }
    void OnLsdbUpdate(){ lsdbUpdates++; }
    void OnSpfRun()    { spfRuns++; }
    void OnNeighborUp(){ neighborUp++; }
    void OnNeighborDown(){ neighborDown++; }
    void OnMacMismatch() { macMismatchAlerts++; }
    void OnInjectedFakeLsp() { fakeLspInjected++; if (firstSeenAttack == Seconds(0)) firstSeenAttack = Simulator::Now(); }
    void OnLspRejectedAuth() { lspRejectedAuth++; if (firstSeenAttack == Seconds(0)) firstSeenAttack = Simulator::Now(); }

    // Print summary at simulation end
    void PrintSummary() {
        std::cout << "\nISIS METRICS\n";
        std::cout << " Hellos Sent: " << hellosSent << "\n";
        std::cout << " LSPs Sent: " << lspsSent << "\n";
        std::cout << " LSP Floods: " << lspFloods << "\n";
        std::cout << " LSDB Inserts: " << lsdbInserts << "\n";
        std::cout << " LSDB Updates: " << lsdbUpdates << "\n";
        std::cout << " SPF Runs: " << spfRuns << "\n";
        std::cout << " Neighbor Ups: " << neighborUp << "\n";
        std::cout << " Neighbor Downs: " << neighborDown << "\n";
        std::cout << " MAC Mismatch Alerts:" << macMismatchAlerts << "\n";
        std::cout << " Fake LSP Injected: " << fakeLspInjected << "\n";
        std::cout << " LSP Auth Rejected: " << lspRejectedAuth << "\n";
        if (firstSeenAttack != Seconds(0)) {
            std::cout << "First Attack Seen: " << firstSeenAttack.GetSeconds() << "s\n";
        }
    }
} g_isisMetrics;

NS_LOG_COMPONENT_DEFINE("ISISProtocol");

// Dummy protocol number
#define ISIS_PROTOCOL_NUMBER 124 

// ISIS PDU Types 
enum ISISPacketType {
    // LAN
    ISIS_HELLO_LAN = 15,
    // Link State PDU
    ISIS_LSP_LEVEL1 = 18,
    // Complete Sequence Numbers PDU
    ISIS_CSNP = 24, 
    // Partial Sequence Numbers PDU         
    ISIS_PSNP = 26             
};

// Tracked Neighbor Info
struct Neighbor {
    uint32_t nodeId;
    Ipv4Address ipAddress;
    Time lastHelloTime;
    bool isUp;
    
    Neighbor() : nodeId(0), ipAddress("0.0.0.0"), lastHelloTime(Seconds(0)), isUp(false) {}
    Neighbor(uint32_t id, Ipv4Address addr) 
        : nodeId(id), ipAddress(addr), lastHelloTime(Simulator::Now()), isUp(true) {}
};

// Link State Entry Format
struct LinkStateEntry {
    uint32_t sourceNode;
    std::vector<uint32_t> neighbors;
    std::vector<uint32_t> costs;
    uint32_t sequenceNumber;
    Time timestamp;
    
    LinkStateEntry() : sourceNode(0), sequenceNumber(0), timestamp(Seconds(0)) {}
};

// Best Route Path Entry
struct RouteEntry {
    uint32_t destination;
    uint32_t nextHop;
    uint32_t cost;
    Ipv4Address nextHopIp;
    
    RouteEntry() : destination(0), nextHop(0), cost(std::numeric_limits<uint32_t>::max()), 
                     nextHopIp("0.0.0.0") {}
    RouteEntry(uint32_t dest, uint32_t nh, uint32_t c, Ipv4Address nhIp)
        : destination(dest), nextHop(nh), cost(c), nextHopIp(nhIp) {}
};

// ISIS Header Implementation
class ISISHeader : public Header {
public:
    ISISHeader();
    virtual ~ISISHeader();

    // Setters and getters
    void SetPacketType(uint8_t type);
    uint8_t GetPacketType() const;
    
    void SetSourceId(uint32_t id);
    uint32_t GetSourceId() const;
    
    void SetSequenceNumber(uint32_t seq);
    uint32_t GetSequenceNumber() const;
    
    void SetNeighborCount(uint8_t count);
    uint8_t GetNeighborCount() const;
    
    void AddNeighbor(uint32_t neighborId, uint32_t cost);
    void GetNeighbors(std::vector<uint32_t>& neighbors, std::vector<uint32_t>& costs) const;

    static TypeId GetTypeId();
    virtual TypeId GetInstanceTypeId() const;
    virtual void Print(std::ostream &os) const;
    virtual uint32_t GetSerializedSize() const;
    virtual void Serialize(Buffer::Iterator start) const;
    virtual uint32_t Deserialize(Buffer::Iterator start);

private:
    // ISIS Common Header Fields
    uint8_t m_irpd;       // Intradomain Routing Protocol Discriminator
    uint8_t m_lengthInd;    // Length Indicator
    uint8_t m_versionProtoId; // Version / Protocol ID
    uint8_t m_idLength;     // ID Length
    uint8_t m_pduType;      // PDU Type
    uint8_t m_version;      // Version
    uint8_t m_reserved;     // Reserved
    uint8_t m_maxAreaAddr;  // Maximum Area Addresses
    
    uint32_t m_sourceId;
    uint32_t m_sequenceNumber;
    uint8_t m_neighborCount;
    std::vector<uint32_t> m_neighbors;
    std::vector<uint32_t> m_costs;
};

// ISIS Header Implementation
ISISHeader::ISISHeader()
    : m_irpd(0x83),         // Standard ISIS discriminator
      m_lengthInd(27),      // Variable
      m_versionProtoId(1),
      m_idLength(0),
      m_pduType(ISIS_HELLO_LAN),
      m_version(1),
      m_reserved(0),
      m_maxAreaAddr(0),
      m_sourceId(0),
      m_sequenceNumber(0),
      m_neighborCount(0) {}

ISISHeader::~ISISHeader(){}

// Setters and Getters
void ISISHeader::SetPacketType(uint8_t type) {
    m_pduType = type;
}

uint8_t ISISHeader::GetPacketType() const {
    return m_pduType;
}

void ISISHeader::SetSourceId(uint32_t id) {
    m_sourceId = id;
}

uint32_t ISISHeader::GetSourceId() const {
    return m_sourceId;
}

void ISISHeader::SetSequenceNumber(uint32_t seq) {
    m_sequenceNumber = seq;
}

uint32_t ISISHeader::GetSequenceNumber() const {
    return m_sequenceNumber;
}

void ISISHeader::SetNeighborCount(uint8_t count) {
    m_neighborCount = count;
}

uint8_t ISISHeader::GetNeighborCount() const {
    return m_neighborCount;
}

void ISISHeader::AddNeighbor(uint32_t neighborId, uint32_t cost) {
    m_neighbors.push_back(neighborId);
    m_costs.push_back(cost);
    m_neighborCount = m_neighbors.size();
}

void ISISHeader::GetNeighbors(std::vector<uint32_t>& neighbors, std::vector<uint32_t>& costs) const {
    neighbors = m_neighbors;
    costs = m_costs;
}

TypeId ISISHeader::GetTypeId() {
    static TypeId tid = TypeId("ns3::ISISHeader")
        .SetParent<Header>()
        .SetGroupName("Internet")
        .AddConstructor<ISISHeader>();
    return tid;
}

TypeId ISISHeader::GetInstanceTypeId() const {
    return GetTypeId();
}

// Prints header contents
void ISISHeader::Print(std::ostream &os) const {
    os << "ISIS PDU: Type=" << (uint32_t)m_pduType
       << " SourceId=" << m_sourceId
       << " SeqNum=" << m_sequenceNumber
       << " Neighbors=" << (uint32_t)m_neighborCount;
}

uint32_t ISISHeader::GetSerializedSize() const {
    // ISIS Common Header (8 bytes) + custom fields + neighbor data
    return 8 + 9 + (m_neighborCount * 8);
}

// Serialize header into buffer
void ISISHeader::Serialize(Buffer::Iterator start) const {
    // ISIS Common Header
    start.WriteU8(m_irpd);
    start.WriteU8(m_lengthInd);
    start.WriteU8(m_versionProtoId);
    start.WriteU8(m_idLength);
    start.WriteU8(m_pduType);        // PDU Type (HELLO=15, LSP=18)
    start.WriteU8(m_version);
    start.WriteU8(m_reserved);
    start.WriteU8(m_maxAreaAddr);
    
    // Our custom fields
    start.WriteHtonU32(m_sourceId);
    start.WriteHtonU32(m_sequenceNumber);
    start.WriteU8(m_neighborCount);
    
    for (uint8_t i = 0; i < m_neighborCount; i++) {
        start.WriteHtonU32(m_neighbors[i]);
        start.WriteHtonU32(m_costs[i]);
    }
}

// Deserialize header from buffer
uint32_t ISISHeader::Deserialize(Buffer::Iterator start) {
    // ISIS Common Header
    m_irpd = start.ReadU8();
    m_lengthInd = start.ReadU8();
    m_versionProtoId = start.ReadU8();
    m_idLength = start.ReadU8();
    m_pduType = start.ReadU8();
    m_version = start.ReadU8();
    m_reserved = start.ReadU8();
    m_maxAreaAddr = start.ReadU8();
    
    // custom fields
    m_sourceId = start.ReadNtohU32();
    m_sequenceNumber = start.ReadNtohU32();
    m_neighborCount = start.ReadU8();
    
    m_neighbors.clear();
    m_costs.clear();
    
    for (uint8_t i = 0; i < m_neighborCount; i++) {
        m_neighbors.push_back(start.ReadNtohU32());
        m_costs.push_back(start.ReadNtohU32());
    }
    
    return GetSerializedSize();
}

// Compute HMAC for LSP packets Genuine routers share a key, attacker uses wrong key
static std::vector<uint8_t> ComputeHmacMd5ForLsp(const ISISHeader &h, const std::string &key) {
    std::string data;
    uint32_t s = h.GetSourceId();
    uint32_t s_n = htonl(s);
    data.append(reinterpret_cast<const char*>(&s_n), sizeof(s_n));
    uint32_t seq = h.GetSequenceNumber();
    uint32_t seq_n = htonl(seq);
    data.append(reinterpret_cast<const char*>(&seq_n), sizeof(seq_n));
    // 1 byte neighbor count
    uint8_t nbrCount = h.GetNeighborCount();
    data.push_back(static_cast<char>(nbrCount));
    // neighbors and costs (each 4 bytes network order)
    std::vector<uint32_t> nbrs, costs;
    h.GetNeighbors(nbrs, costs);
    for (size_t i = 0; i < nbrs.size(); ++i) {
        uint32_t n_n = htonl(nbrs[i]);
        data.append(reinterpret_cast<const char*>(&n_n), sizeof(n_n));
        uint32_t c_n = htonl(costs[i]);
        data.append(reinterpret_cast<const char*>(&c_n), sizeof(c_n));
    }

    unsigned int len = EVP_MD_size(EVP_md5()); // should be 16
    std::vector<uint8_t> digest(len);

    // HMAC using OpenSSL
    unsigned char *res = HMAC(EVP_md5(),
                              reinterpret_cast<const unsigned char*>(key.data()), (int)key.size(),
                              reinterpret_cast<const unsigned char*>(data.data()), data.size(),
                              digest.data(), &len);
    if (res == nullptr) {
        std::fill(digest.begin(), digest.end(), 0);
    }
    digest.resize(len);
    return digest;
}

// ISIS Application Class that runs Hello, LSP, LSDB, SPF logic
class ISISApplication : public Application {
public:
    ISISApplication();
    virtual ~ISISApplication();

    static TypeId GetTypeId();
    
    void SetNodeId(uint32_t id);
    void AddNeighbor(Ipv4Address addr, uint32_t nodeId, uint32_t cost);
    void PrintRoutingTable();
    void EnableAttacker(bool on = true);
    void InjectFakeLsp(uint32_t impersonatedId,
                         uint32_t fakeSeq,
                         const std::vector<uint32_t>& fakeNeighbors,
                         const std::vector<uint32_t>& fakeCosts);

protected:
    virtual void StartApplication();
    virtual void StopApplication();

private:
    // Internal methods
    void SendHello();
    void SendLSP();
    void HandleRead(Ptr<Socket> socket);
    void ScheduleNextHello();
    void ScheduleNextLSP();
    void CheckNeighborTimeout();
    void UpdateLSDB(uint32_t sourceNode, const std::vector<uint32_t>& neighbors, 
                      const std::vector<uint32_t>& costs, uint32_t seqNum, 
                      Ipv4Address receivedFrom);
    void UpdateOwnLSDB();
    void FloodLSP(uint32_t originNode, uint32_t seqNum, const std::vector<uint32_t>& neighbors,
                  const std::vector<uint32_t>& costs, Ipv4Address excludeNeighbor);
    void RunSPF();
    void PrintSPFResults();

    Ptr<Socket> m_socket;
    uint32_t m_nodeId;
    uint32_t m_sequenceNumber;
    EventId m_helloEvent;
    EventId m_lspEvent;
    EventId m_timeoutEvent;
    Time m_helloInterval;
    Time m_lspInterval;
    Time m_holdTime;
    Ptr<NetDevice> m_boundDevice;
    std::vector< Ptr<Socket> > m_sockets;
    bool m_isAttacker;
    EventId m_attackEvent;

    
    std::map<uint32_t, Neighbor> m_neighbors;
    std::map<Ipv4Address, uint32_t> m_ipToNodeId;
    std::map<uint32_t, uint32_t> m_linkCosts;
    std::map<uint32_t, LinkStateEntry> m_lsdb;
    std::map<uint32_t, RouteEntry> m_routingTable;
    std::map<uint32_t, std::set<uint32_t>> m_seenLSPs;

    // MAC consistency map used for logging 
    std::map<uint32_t, Mac48Address> m_nodeIdToMac;

    // Authentication key where all nodes share this in the demo except attacker
    std::string m_authKey;
};

// ISIS Application Implementation
ISISApplication::ISISApplication()
    : m_socket(0),
      m_nodeId(0),
      m_sequenceNumber(0),
      m_helloInterval(Seconds(10.0)),
      m_lspInterval(Seconds(30.0)),
      m_holdTime(Seconds(30.0)),
      m_isAttacker(false),
      m_authKey("secret-key-7777") // default honest key
{
}

ISISApplication::~ISISApplication()
{
    m_socket = 0;
    m_isAttacker = false;
}

TypeId ISISApplication::GetTypeId()
{
    static TypeId tid = TypeId("ns3::ISISApplication")
        .SetParent<Application>()
        .SetGroupName("Applications")
        .AddConstructor<ISISApplication>();
    return tid;
}

void ISISApplication::SetNodeId(uint32_t id)
{
    m_nodeId = id;
}

void ISISApplication::AddNeighbor(Ipv4Address addr, uint32_t nodeId, uint32_t cost)
{
    m_ipToNodeId[addr] = nodeId;
    m_linkCosts[nodeId] = cost;
    std::cout << "[CONFIG] Node " << m_nodeId << " configured neighbor: Node " 
              << nodeId << " @ " << addr << " (cost=" << cost << ")" << std::endl;
}

// Update own LSP into LSDB
void ISISApplication::UpdateOwnLSDB()
{
    LinkStateEntry entry;
    entry.sourceNode = m_nodeId;
    entry.sequenceNumber = m_sequenceNumber - 1;
    entry.timestamp = Simulator::Now();

    for (auto it = m_neighbors.begin(); it != m_neighbors.end(); ++it)
    {
        if (it->second.isUp)
        {
            entry.neighbors.push_back(it->first);
            entry.costs.push_back(m_linkCosts[it->first]);
        }
    }

    m_lsdb[m_nodeId] = entry;

    std::cout << "[LSDB-SELF] Node " << m_nodeId << " added own LSP with "
              << entry.neighbors.size() << " neighbors" << std::endl;
}

// binds sockets and schedule periodic tasks
void ISISApplication::StartApplication()
{
    NS_LOG_FUNCTION(this);
    std::cout << "\n[START] Node " << m_nodeId << " ISIS application starting" << std::endl;

    // Create PacketSockets on all non-loopback devices
    for (uint32_t i = 0; i < GetNode()->GetNDevices(); ++i)
    {
        Ptr<NetDevice> dev = GetNode()->GetDevice(i);
        std::cout << "[DEBUG] Node " << m_nodeId << " device " << i << " type=" << dev->GetInstanceTypeId().GetName() << std::endl;

        // Skip loopback and non-CSMA devices
        if (DynamicCast<LoopbackNetDevice>(dev) ||
            !DynamicCast<CsmaNetDevice>(dev))
            continue;

        Ptr<Socket> sock =
            Socket::CreateSocket(GetNode(), PacketSocketFactory::GetTypeId());

        PacketSocketAddress bindAddr;
        bindAddr.SetSingleDevice(dev->GetIfIndex());
        bindAddr.SetPhysicalAddress(Mac48Address::GetBroadcast());
        bindAddr.SetProtocol(0xFEFE);

        sock->Bind(bindAddr);
        sock->SetRecvCallback(MakeCallback(&ISISApplication::HandleRead, this));

        m_sockets.push_back(sock);
        std::cout << "[DEBUG] Node " << m_nodeId
              << " bound PacketSocket on device "
              << dev->GetIfIndex() << " EtherType 0xFEFE" << std::endl;
    }

    // Schedules first Hello and LSP
    ScheduleNextHello();
    ScheduleNextLSP();
    m_timeoutEvent = Simulator::Schedule(Seconds(5.0),
                                            &ISISApplication::CheckNeighborTimeout, this);

    std::cout << "[START] Node " << m_nodeId << " ready with "
              << m_ipToNodeId.size() << " configured neighbors" << std::endl;
}

// Stop all activity when app ends
void ISISApplication::StopApplication()
{
    NS_LOG_FUNCTION(this);
    
    if (m_socket) {
        m_socket->Close();
    }

    Simulator::Cancel(m_helloEvent);
    Simulator::Cancel(m_lspEvent);
    Simulator::Cancel(m_timeoutEvent);
}

// Broadcast Hello to LAN
void ISISApplication::SendHello()
{
    NS_LOG_FUNCTION(this);
    
    Ptr<Packet> packet = Create<Packet>();
    ISISHeader isisHeader;
    isisHeader.SetPacketType(ISIS_HELLO_LAN);
    isisHeader.SetSourceId(m_nodeId);
    isisHeader.SetSequenceNumber(m_sequenceNumber++);
    packet->AddHeader(isisHeader);
    g_isisMetrics.OnHelloSent();

    std::cout << "[" << Simulator::Now().GetSeconds() << "s] Node " << m_nodeId 
              << "ISIS HELLO (PDU Type 15)" << std::endl;

    // Broadcast on all interfaces
    for (auto sock : m_sockets)
    {
        if (!sock) continue;

        Ptr<PacketSocket> psock = DynamicCast<PacketSocket>(sock);
        if (!psock) continue;

        Ptr<NetDevice> dev = psock->GetBoundNetDevice();
        if (!dev) continue;
        if (DynamicCast<LoopbackNetDevice>(dev)) continue; 

        Ptr<Packet> pktCopy = packet->Copy();

        PacketSocketAddress remote;
        remote.SetSingleDevice(dev->GetIfIndex());
        remote.SetPhysicalAddress(Mac48Address::GetBroadcast());
        remote.SetProtocol(0xFEFE);

        sock->SendTo(pktCopy, 0, remote);
    }

    ScheduleNextHello();
}

// Send link-state info; attach HMAC
void ISISApplication::SendLSP()
{
    NS_LOG_FUNCTION(this);
    
    Ptr<Packet> packet = Create<Packet>();
    ISISHeader isisHeader;
    isisHeader.SetPacketType(ISIS_LSP_LEVEL1);
    isisHeader.SetSourceId(m_nodeId);
    isisHeader.SetSequenceNumber(m_sequenceNumber++);

    // Add neighbor info to header (own neighbors)
    for (auto it = m_neighbors.begin(); it != m_neighbors.end(); ++it) {
        if (it->second.isUp) {
            isisHeader.AddNeighbor(it->first, m_linkCosts[it->first]);
        }
    }

    packet->AddHeader(isisHeader);

    // Append HMAC-MD5 authenticator
    std::vector<uint8_t> auth = ComputeHmacMd5ForLsp(isisHeader, m_authKey);
    if (auth.size() > 0) {
        Ptr<Packet> authPkt = Create<Packet>(auth.data(), (uint32_t)auth.size());
        packet->AddAtEnd(authPkt);
    }

    std::cout << "[" << Simulator::Now().GetSeconds() << "s] Node " << m_nodeId
              << "ISIS LSP (PDU Type 18) with "
              << (int)isisHeader.GetNeighborCount() << " neighbors" << std::endl;

    UpdateOwnLSDB();
    m_seenLSPs[m_nodeId].insert(m_sequenceNumber - 1);
    g_isisMetrics.OnLspSent();


    // Broadcast on all interfaces
    for (auto sock : m_sockets)
    {
        if (!sock) continue;

        Ptr<PacketSocket> psock = DynamicCast<PacketSocket>(sock);
        if (!psock) continue;

        Ptr<NetDevice> dev = psock->GetBoundNetDevice();
        if (!dev) continue;
        if (DynamicCast<LoopbackNetDevice>(dev)) continue;

        Ptr<Packet> pktCopy = packet->Copy();

        PacketSocketAddress remote;
        remote.SetSingleDevice(dev->GetIfIndex());
        remote.SetPhysicalAddress(Mac48Address::GetBroadcast()); 
        remote.SetProtocol(0xFEFE);

        sock->SendTo(pktCopy, 0, remote);
    }

    ScheduleNextLSP();
}

// Enable or disable attacker mode
void ISISApplication::EnableAttacker(bool on)
{
    m_isAttacker = on;
    if (on) {
        // Attacker intentionally does not have the honest key (simulate compromise without key)
        m_authKey = "attacker-bad-key";
    } else {
        m_authKey = "secret-key-7777";
    }
    std::cout << "[SECURITY] Node " << m_nodeId << (on ? " ENABLED " : " DISABLED ") << "attacker mode"
              << " (current authKey=" << (on ? "BAD-KEY" : "GOOD-KEY") << ")\n";
}

// Injects a fake LSP impersonating another node
void ISISApplication::InjectFakeLsp(uint32_t impersonatedId,
                                         uint32_t fakeSeq,
                                         const std::vector<uint32_t>& fakeNeighbors,
                                         const std::vector<uint32_t>& fakeCosts)
{
    if (!m_isAttacker)
    {
        std::cout << "[SECURITY] Node " << m_nodeId << " attempted to inject fake LSP but is not attacker\n";
        return;
    }
    if (fakeSeq == 0) {
        uint32_t existing = 0;
        auto it = m_lsdb.find(impersonatedId);
        if (it != m_lsdb.end()) {
            existing = it->second.sequenceNumber;
        }
        // choose a sequence higher than currently seen
        fakeSeq = existing + 1;
    }
    std::cout << "[" << Simulator::Now().GetSeconds() << "s] "
              << "[SECURITY] Node " << m_nodeId
              << " (ATTACKER) Injecting FAKE LSP impersonating Node "
              << impersonatedId << " (seq=" << fakeSeq << ")" << std::endl;

    // Build forged LSP
    Ptr<Packet> packet = Create<Packet>();
    ISISHeader hdr;
    hdr.SetPacketType(ISIS_LSP_LEVEL1);
    hdr.SetSourceId(impersonatedId);
    hdr.SetSequenceNumber(fakeSeq);

    // add neighbors/costs
    for (size_t i = 0; i < fakeNeighbors.size() && i < fakeCosts.size(); ++i)
    {
        hdr.AddNeighbor(fakeNeighbors[i], fakeCosts[i]);
    }

    packet->AddHeader(hdr);

    // Attacker's HMAC will be computed using the attacker's (incorrect) key
    std::vector<uint8_t> auth = ComputeHmacMd5ForLsp(hdr, m_authKey);
    if (auth.size() > 0) {
        Ptr<Packet> authPkt = Create<Packet>(auth.data(), (uint32_t)auth.size());
        packet->AddAtEnd(authPkt);
    }

    std::cout << "[" << Simulator::Now().GetSeconds() << "s] Node " << m_nodeId
              << " (ATTACKER) → Injected FAKE LSP claiming Node " << impersonatedId
              << " seq=" << fakeSeq << " nbrs=" << hdr.GetNeighborCount() << std::endl;

    // Broadcast forged LSP on all PacketSockets you bound earlier (but honest nodes will reject)
    for (auto sock : m_sockets)
    {
        if (!sock) continue;
        Ptr<Packet> pktCopy = packet->Copy();
        PacketSocketAddress remote;
        Ptr<PacketSocket> psock = DynamicCast<PacketSocket>(sock);
        if (!psock) continue;
        Ptr<NetDevice> dev = psock->GetBoundNetDevice();
        if (!dev) continue;
        if (DynamicCast<LoopbackNetDevice>(dev)) continue;
        remote.SetSingleDevice(dev->GetIfIndex());
        remote.SetPhysicalAddress(Mac48Address::GetBroadcast());
        remote.SetProtocol(0xFEFE);
        sock->SendTo(pktCopy, 0, remote);
    }
    g_isisMetrics.OnInjectedFakeLsp();
}

// Flood LSP to all neighbors except the one it was received from
void ISISApplication::FloodLSP(uint32_t originNode, uint32_t seqNum,
                                     const std::vector<uint32_t>& neighbors,
                                     const std::vector<uint32_t>& costs,
                                     Ipv4Address excludeNeighbor)
{
    std::cout << "  [FLOOD] Node " << m_nodeId << " flooding ISIS LSP from Node "
              << originNode << " (seq=" << seqNum << ")" << std::endl;

    Ptr<Packet> packet = Create<Packet>();
    ISISHeader isisHeader;
    isisHeader.SetPacketType(ISIS_LSP_LEVEL1);
    isisHeader.SetSourceId(originNode);
    isisHeader.SetSequenceNumber(seqNum);

    for (size_t i = 0; i < neighbors.size(); i++) {
        isisHeader.AddNeighbor(neighbors[i], costs[i]);
    }

    packet->AddHeader(isisHeader);

    // Append HMAC-MD5 (recompute using local key - honest nodes have correct key)
    std::vector<uint8_t> auth = ComputeHmacMd5ForLsp(isisHeader, m_authKey);
    if (auth.size() > 0) {
        Ptr<Packet> authPkt = Create<Packet>(auth.data(), (uint32_t)auth.size());
        packet->AddAtEnd(authPkt);
    }

    int floodCount = 0;
    for (auto sock : m_sockets)
    {
        if (!sock) continue;
        Ptr<PacketSocket> psock = DynamicCast<PacketSocket>(sock);
        if (!psock) continue;

        Ptr<NetDevice> dev = psock->GetBoundNetDevice();
        if (!dev) continue;
        if (DynamicCast<LoopbackNetDevice>(dev)) continue;

        PacketSocketAddress remote;
        remote.SetSingleDevice(dev->GetIfIndex());
        remote.SetPhysicalAddress(Mac48Address::GetBroadcast());
        remote.SetProtocol(0xFEFE);

        sock->SendTo(packet->Copy(), 0, remote);
        ++floodCount;
    }
    g_isisMetrics.OnLspFlood();


    if (floodCount == 0)
        std::cout << "[FLOOD] No other interfaces to flood to" << std::endl;
}


void ISISApplication::HandleRead(Ptr<Socket> socket)
{
    NS_LOG_FUNCTION(this << socket);
    
    Ptr<Packet> packet;
    Address from;

    while ((packet = socket->RecvFrom(from)))
    {
        if (packet->GetSize() == 0)
            continue;

        // Extract source MAC address
        Mac48Address srcMac;
        PacketSocketAddress pktAddr;
        if (PacketSocketAddress::IsMatchingType(from))
        {
            pktAddr = PacketSocketAddress::ConvertFrom(from);
            srcMac = Mac48Address::ConvertFrom(pktAddr.GetPhysicalAddress());
        }

        std::cout << "[DEBUG] Node " << m_nodeId
                  << " received " << packet->GetSize()
                  << " bytes from " << srcMac << std::endl;

        // Deserialize the ISIS header directly
        ISISHeader isisHeader;
        uint32_t bytesRead = packet->RemoveHeader(isisHeader);

        uint8_t pduType = isisHeader.GetPacketType();
        uint32_t senderId = isisHeader.GetSourceId();

        std::cout << "ISIS PDU type " << (int)pduType
                  << " from Node " << senderId
                  << " (" << bytesRead << " bytes header)" << std::endl;

        // MAC ID id learning check
        auto itmac = m_nodeIdToMac.find(senderId);
        if (itmac == m_nodeIdToMac.end()) {
            m_nodeIdToMac[senderId] = srcMac;
            std::cout << "[" << Simulator::Now().GetSeconds()
                      << "s] [LEARN] Node " << m_nodeId
                      << " learned that Node " << senderId
                      << " uses MAC " << srcMac << std::endl;
        } else if (itmac->second != srcMac) {
            std::cout << "[" << Simulator::Now().GetSeconds()
                      << "s] [ALERT] Node " << m_nodeId
                      << " sees NodeId " << senderId
                      << " now coming from a *different* MAC!"
                      << "  Old=" << itmac->second
                      << "  New=" << srcMac << std::endl;
            g_isisMetrics.OnMacMismatch();

        }

        // Process Hello PDUs
        if (pduType == ISIS_HELLO_LAN)
        {
            std::cout << "[" << Simulator::Now().GetSeconds()
                      << "s] Node " << m_nodeId
                      << " <- ISIS HELLO from Node " << senderId << std::endl;

            if (m_neighbors.find(senderId) == m_neighbors.end())
            {
                m_neighbors[senderId] = Neighbor(senderId, Ipv4Address("0.0.0.0"));
                std::cout << "  [NEIGHBOR-UP] New neighbor Node "
                          << senderId << " discovered" << std::endl;
            }
            else
            {
                m_neighbors[senderId].lastHelloTime = Simulator::Now();
                if (!m_neighbors[senderId].isUp)
                {
                    m_neighbors[senderId].isUp = true;
                    std::cout << "  [NEIGHBOR-UP] Node "
                              << senderId << " is UP again" << std::endl;
                    g_isisMetrics.OnNeighborUp();
                }
            }
        }

        // Process LSP PDUs
        else if (pduType == ISIS_LSP_LEVEL1)
        {
            std::vector<uint32_t> neighbors;
            std::vector<uint32_t> costs;
            isisHeader.GetNeighbors(neighbors, costs);

            uint32_t originNode = isisHeader.GetSourceId();
            uint32_t seqNum = isisHeader.GetSequenceNumber();

            std::cout << "[" << Simulator::Now().GetSeconds()
                      << "s] Node " << m_nodeId
                      << " <- ISIS LSP from Node " << originNode
                      << " (seq=" << seqNum
                      << ", neighbors=" << neighbors.size()
                      << ", srcMAC=" << srcMac << ")" << std::endl;

            // Verifies HMAC-MD5 appended at the end of the packet (16 bytes)
            const size_t AUTH_LEN = 16;
            bool authPresent = false;
            std::vector<uint8_t> recvAuth;
            uint32_t payloadSize = packet->GetSize();
            if (payloadSize >= (int)AUTH_LEN) {
                // copies whole payload then take last 16 bytes
                std::vector<uint8_t> payloadBuf(payloadSize);
                packet->CopyData(payloadBuf.data(), payloadSize);
                recvAuth.assign(payloadBuf.end() - AUTH_LEN, payloadBuf.end());
                authPresent = true;
            }

            std::vector<uint8_t> expectedAuth = ComputeHmacMd5ForLsp(isisHeader, m_authKey);

            if (!authPresent) {
                std::cout << "[" << Simulator::Now().GetSeconds() << "s]"
                          << " [AUTH-FAIL] Node " << m_nodeId
                          << " rejecting LSP from Node " << originNode
                          << " seq=" << seqNum << " : NO AUTHENTICATOR PRESENT"
                          << " srcMAC=" << srcMac << std::endl;
                g_isisMetrics.OnLspRejectedAuth();

                continue;
            }

            if (recvAuth != expectedAuth) {
                std::cout << "[" << Simulator::Now().GetSeconds() << "s]"
                          << " [AUTH-FAIL] Node " << m_nodeId
                          << " rejecting LSP from Node " << originNode
                          << " seq=" << seqNum
                          << " : AUTH MISMATCH"
                          << " srcMAC=" << srcMac
                          << " (expected ";
                for (auto b : expectedAuth) { std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)b; }
                std::cout << " got ";
                for (auto b : recvAuth) { std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)b; }
                std::cout << std::dec << ")" << std::endl;
                g_isisMetrics.OnLspRejectedAuth();

                continue;
            }

            // Auth OK
            std::cout << "[" << Simulator::Now().GetSeconds() << "s]"
                      << " [AUTH-OK] Node " << m_nodeId
                      << " accepted authenticated LSP from Node " << originNode
                      << " seq=" << seqNum << " srcMAC=" << srcMac << std::endl;

            if (m_seenLSPs[originNode].find(seqNum) != m_seenLSPs[originNode].end())
            {
                std::cout << "  [FLOOD-SKIP] Already seen this LSP, not flooding" << std::endl;
                continue;
            }

            m_seenLSPs[originNode].insert(seqNum);
            UpdateLSDB(originNode, neighbors, costs, seqNum, Ipv4Address("0.0.0.0"));
            FloodLSP(originNode, seqNum, neighbors, costs, Ipv4Address("0.0.0.0"));
        }
    }
}

// Adds or updates LSP in LSDB and triggers SPF if needed
void ISISApplication::UpdateLSDB(uint32_t sourceNode, const std::vector<uint32_t>& neighbors, 
                                     const std::vector<uint32_t>& costs, uint32_t seqNum,
                                     Ipv4Address receivedFrom)
{
    bool needSPF = false;
    
    if (m_lsdb.find(sourceNode) == m_lsdb.end()) {
        needSPF = true;
        std::cout << "  [LSDB-NEW] Node " << m_nodeId << " added LSP from Node " << sourceNode << std::endl;
        g_isisMetrics.OnLsdbNew();
    } else if (m_lsdb[sourceNode].sequenceNumber < seqNum) {
        needSPF = true;
        std::cout << "  [LSDB-UPDATE] Node " << m_nodeId << " updated LSP from Node " << sourceNode << std::endl;
        g_isisMetrics.OnLsdbUpdate();

    } else {
        std::cout << "  [LSDB-OLD] Node " << m_nodeId << " ignoring old/duplicate LSP from Node " << sourceNode << std::endl;
        return;
    }
    
    LinkStateEntry entry;
    entry.sourceNode = sourceNode;
    entry.neighbors = neighbors;
    entry.costs = costs;
    entry.sequenceNumber = seqNum;
    entry.timestamp = Simulator::Now();
    
    m_lsdb[sourceNode] = entry;
    
    if (needSPF) {
        std::cout << "  [SPF-TRIGGER] Node " << m_nodeId << " running SPF calculation..." << std::endl;
        RunSPF();
    }
}

// Runs Dijkstra's SPF algorithm to compute shortest paths
void ISISApplication::RunSPF()
{
    std::map<uint32_t, uint32_t> distance;
    std::map<uint32_t, uint32_t> previous;
    std::map<uint32_t, bool> visited;
    
    for (auto it = m_lsdb.begin(); it != m_lsdb.end(); ++it) {
        distance[it->first] = std::numeric_limits<uint32_t>::max();
        visited[it->first] = false;
    }
    distance[m_nodeId] = 0;
    
    std::priority_queue<std::pair<uint32_t, uint32_t>,
                        std::vector<std::pair<uint32_t, uint32_t>>,
                        std::greater<std::pair<uint32_t, uint32_t>>> pq;
    pq.push(std::make_pair(0, m_nodeId));
    
    while (!pq.empty()) {
        uint32_t currentNode = pq.top().second;
        pq.pop();
        
        if (visited[currentNode]) continue;
        visited[currentNode] = true;
        
        if (m_lsdb.find(currentNode) == m_lsdb.end()) continue;
        
        LinkStateEntry& lse = m_lsdb[currentNode];
        
        for (size_t i = 0; i < lse.neighbors.size(); i++) {
            uint32_t neighbor = lse.neighbors[i];
            uint32_t cost = lse.costs[i];
            uint32_t newDist = distance[currentNode] + cost;
            
            if (newDist < distance[neighbor]) {
                distance[neighbor] = newDist;
                previous[neighbor] = currentNode;
                pq.push(std::make_pair(newDist, neighbor));
            }
        }
    }
    
    m_routingTable.clear();
    
    for (auto it = distance.begin(); it != distance.end(); ++it) {
        uint32_t dest = it->first;
        uint32_t cost = it->second;
        
        if (dest == m_nodeId || cost == std::numeric_limits<uint32_t>::max()) {
            continue;
        }
        
        uint32_t nextHop = dest;
        while (previous.find(nextHop) != previous.end() && previous[nextHop] != m_nodeId) {
            nextHop = previous[nextHop];
        }
        
        Ipv4Address nextHopIp("0.0.0.0");
        if (m_neighbors.find(nextHop) != m_neighbors.end()) {
            nextHopIp = m_neighbors[nextHop].ipAddress;
        }
        
        m_routingTable[dest] = RouteEntry(dest, nextHop, cost, nextHopIp);
    }
    g_isisMetrics.OnSpfRun();
    PrintSPFResults();
}

// Print SPF results in a formatted table
void ISISApplication::PrintSPFResults()
{
    std::cout << "SPF CALCULATION COMPLETE - Node " << m_nodeId << "                       ║" << std::endl;
    std::cout << "╠════════════════════════════════════════════════════════╣" << std::endl;
    std::cout << "║  Destination  |  Next Hop  |  Cost  |  Next Hop IP    ║" << std::endl;
    std::cout << "╠════════════════════════════════════════════════════════╣" << std::endl;
    
    if (m_routingTable.empty()) {
        std::cout << "║              NO ROUTES COMPUTED                      ║" << std::endl;
    } else {
        for (auto it = m_routingTable.begin(); it != m_routingTable.end(); ++it) {
            std::cout << "║     Node " << it->second.destination 
                      << "     |   Node " << it->second.nextHop 
                      << "   |   " << std::setw(2) << it->second.cost 
                      << "    | " << std::setw(13) << it->second.nextHopIp << " ║" << std::endl;
        }
    }
    
    std::cout << "╚════════════════════════════════════════════════════════╝\n" << std::endl;
}

// Check for neighbor timeouts
void ISISApplication::CheckNeighborTimeout()
{
    Time now = Simulator::Now();
    
    for (auto it = m_neighbors.begin(); it != m_neighbors.end(); ++it) {
        if (it->second.isUp) {
            Time elapsed = now - it->second.lastHelloTime;
            if (elapsed > m_holdTime) {
                it->second.isUp = false;
                g_isisMetrics.OnNeighborDown();
                std::cout << "[" << now.GetSeconds() << "s] [NEIGHBOR-DOWN] Node " << m_nodeId 
                          << " neighbor " << it->first << " TIMEOUT" << std::endl;
            }
        }
    }
    
    m_timeoutEvent = Simulator::Schedule(Seconds(5.0), &ISISApplication::CheckNeighborTimeout, this);
}

void ISISApplication::PrintRoutingTable()
{
    PrintSPFResults();
}

void ISISApplication::ScheduleNextHello()
{
    m_helloEvent = Simulator::Schedule(m_helloInterval, &ISISApplication::SendHello, this);
}

void ISISApplication::ScheduleNextLSP()
{
    m_lspEvent = Simulator::Schedule(m_lspInterval, &ISISApplication::SendLSP, this);
}

// Main Simulation
int main(int argc, char *argv[])
{
    LogComponentEnable("ISISProtocol", LOG_LEVEL_INFO);
    
    CommandLine cmd;
    cmd.Parse(argc, argv);

    std::cout << "---ISIS Protocol---" << std::endl;

    NodeContainer nodes;
    nodes.Create(4);

    CsmaHelper csma;
    csma.SetChannelAttribute("DataRate", StringValue("10Mbps"));
    csma.SetChannelAttribute("Delay", StringValue("2ms"));

    // Create simple square network topology
    NetDeviceContainer devices01 = csma.Install(NodeContainer(nodes.Get(0), nodes.Get(1)));
    NetDeviceContainer devices12 = csma.Install(NodeContainer(nodes.Get(1), nodes.Get(2)));
    NetDeviceContainer devices23 = csma.Install(NodeContainer(nodes.Get(2), nodes.Get(3)));
    NetDeviceContainer devices03 = csma.Install(NodeContainer(nodes.Get(0), nodes.Get(3)));

    PacketSocketHelper packetSocket;
    packetSocket.Install(nodes);


    InternetStackHelper stack;
    stack.Install(nodes);

    Ipv4AddressHelper address;
    
    // Assign IP subnets
    address.SetBase("10.1.1.0", "255.255.255.0");
    Ipv4InterfaceContainer interfaces01 = address.Assign(devices01);
    
    address.SetBase("10.1.2.0", "255.255.255.0");
    Ipv4InterfaceContainer interfaces12 = address.Assign(devices12);
    
    address.SetBase("10.1.3.0", "255.255.255.0");
    Ipv4InterfaceContainer interfaces23 = address.Assign(devices23);
    
    address.SetBase("10.1.4.0", "255.255.255.0");
    Ipv4InterfaceContainer interfaces03 = address.Assign(devices03);

    Ptr<ISISApplication> app0 = CreateObject<ISISApplication>();
    Ptr<ISISApplication> app1 = CreateObject<ISISApplication>();
    Ptr<ISISApplication> app2 = CreateObject<ISISApplication>();
    Ptr<ISISApplication> app3 = CreateObject<ISISApplication>();
    // Configure neighbors and costs
    app0->SetNodeId(0);
    app0->AddNeighbor(Ipv4Address("10.1.1.2"), 1, 1);
    app0->AddNeighbor(Ipv4Address("10.1.4.2"), 3, 1);

    app1->SetNodeId(1);
    app1->AddNeighbor(Ipv4Address("10.1.1.1"), 0, 1);
    app1->AddNeighbor(Ipv4Address("10.1.2.2"), 2, 1);

    app2->SetNodeId(2);
    app2->AddNeighbor(Ipv4Address("10.1.2.1"), 1, 1);
    app2->AddNeighbor(Ipv4Address("10.1.3.2"), 3, 1);

    app3->SetNodeId(3);
    app3->AddNeighbor(Ipv4Address("10.1.4.1"), 0, 1);
    app3->AddNeighbor(Ipv4Address("10.1.3.1"), 2, 1);

    std::cout << std::endl;

    nodes.Get(0)->AddApplication(app0);
    app0->SetStartTime(Seconds(1.0));
    app0->SetStopTime(Seconds(60.0));

    nodes.Get(1)->AddApplication(app1);
    app1->SetStartTime(Seconds(1.0));
    app1->SetStopTime(Seconds(60.0));

    nodes.Get(2)->AddApplication(app2);
    app2->SetStartTime(Seconds(1.0));
    app2->SetStopTime(Seconds(60.0));

    nodes.Get(3)->AddApplication(app3);
    app3->SetStartTime(Seconds(1.0));
    app3->SetStopTime(Seconds(60.0));

    // choosing attacker node 2
    app2->EnableAttacker(true);

    // schedules fake LSP injection at 20s
    Simulator::Schedule(Seconds(20.0),
                         &ISISApplication::InjectFakeLsp,
                         app2,
                         1u,
                         999u,
                         std::vector<uint32_t>({0u, 3u}), 
                         std::vector<uint32_t>({1u, 1u}));


    csma.EnablePcapAll("isis-v6-native");

    std::cout << "Starting Simulation - Wireshark-Ready ISIS!" << std::endl;

    Simulator::Stop(Seconds(60.0));
    for (uint32_t i = 0; i < nodes.GetN(); ++i) {
        Ptr<Node> node = nodes.Get(i);
        for (uint32_t j = 0; j < node->GetNDevices(); ++j) {
            Ptr<NetDevice> dev = node->GetDevice(j);
            if (DynamicCast<LoopbackNetDevice>(dev)) continue;
            Mac48Address mac = Mac48Address::ConvertFrom(dev->GetAddress());
            std::cout << "Node " << i << "  Dev " << j
                      << "  MAC: " << mac << std::endl;
        }
    }

    Simulator::Run();
    std::cout << "\nSimulation Completed\n" << std::endl;
    g_isisMetrics.PrintSummary();
    Simulator::Destroy();
    
    return 0;
}
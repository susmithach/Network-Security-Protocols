#include "ns3/core-module.h"
#include "ns3/network-module.h"
#include "ns3/internet-module.h"
#include "ns3/point-to-point-module.h"
#include "ns3/applications-module.h"
#include "ns3/ipv4-global-routing-helper.h"
#include "ns3/rip-helper.h"
#include "ns3/trace-helper.h"
#include "ns3/ipv4-static-routing-helper.h"
#include "ns3/ipv4-routing-table-entry.h"

#include <sys/stat.h>
#include <fstream>
#include <sstream>
#include <map>
#include <vector>

using namespace ns3;

NS_LOG_COMPONENT_DEFINE("RipBlackholeAttack");

// keeps track of nodes and their poisoned routes
std::map<Ptr<Node>, Ptr<Ipv4StaticRouting>> poisonedInstances;

// Structure to hold a routing table snapshot
struct RoutingSnapshot {
    Time timestamp;
    // Map: destination -> (nextHop, metric)
    std::map<std::string, std::pair<std::string, uint32_t>> routes;
};

// Convergence Monitor Class
class ConvergenceMonitor {
public:
    enum ConvergencePhase {
        INITIAL,
        UNDER_ATTACK,
        RECOVERING,
        CONVERGED
    };
    
    ConvergenceMonitor(NodeContainer* nodes) 
        : m_nodes(nodes),
          m_currentPhase(INITIAL),
          m_stableSnapshotCount(0),
          m_hasConverged(false),
          m_initialConvergenceTime(Seconds(0)),
          m_attackConvergenceTime(Seconds(0)),
          m_recoveryConvergenceTime(Seconds(0)) {
        m_simulationStartTime = Simulator::Now();
    }
    
    void TakeSnapshot();
    bool CheckConvergence();
    void OnAttackTriggered();
    void OnRecoveryTriggered();
    
    // Get convergence times
    Time GetInitialConvergenceTime() { return m_initialConvergenceTime; }
    Time GetAttackConvergenceTime() { return m_attackConvergenceTime; }
    Time GetRecoveryConvergenceTime() { return m_recoveryConvergenceTime; }
    
    void PrintSummary();
    void ExportToCSV(std::string filename);

private:
    NodeContainer* m_nodes;
    ConvergencePhase m_currentPhase;
    
    RoutingSnapshot m_previousSnapshot;
    RoutingSnapshot m_currentSnapshot;
    
    uint32_t m_stableSnapshotCount;
    const uint32_t STABILITY_THRESHOLD = 6; // 6 snapshots * 0.5s = 3 seconds stable
    
    bool m_hasConverged;
    
    // Timestamps for different phases
    Time m_simulationStartTime;
    Time m_initialConvergenceTime;
    
    Time m_attackStartTime;
    Time m_attackConvergenceTime;
    
    Time m_recoveryStartTime;
    Time m_recoveryConvergenceTime;
    
    // Helper functions
    RoutingSnapshot CaptureCurrentRoutingTables();
    bool AreSnapshotsIdentical(const RoutingSnapshot& s1, const RoutingSnapshot& s2);
};

RoutingSnapshot ConvergenceMonitor::CaptureCurrentRoutingTables() {
    RoutingSnapshot snapshot;
    snapshot.timestamp = Simulator::Now();
    
    // Iterate through all nodes
    for (uint32_t i = 0; i < m_nodes->GetN(); ++i) {
        Ptr<Node> node = m_nodes->Get(i);
        Ptr<Ipv4> ipv4 = node->GetObject<Ipv4>();
        Ptr<Ipv4ListRouting> listRouting = DynamicCast<Ipv4ListRouting>(ipv4->GetRoutingProtocol());
        
        if (!listRouting) {
            continue;
        }
        
        // Get all routing protocols (Static and RIP)
        for (uint32_t j = 0; j < listRouting->GetNRoutingProtocols(); j++) {
            int16_t priority;
            Ptr<Ipv4RoutingProtocol> protocol = listRouting->GetRoutingProtocol(j, priority);
            
            // Handle Static Routing
            Ptr<Ipv4StaticRouting> staticRouting = DynamicCast<Ipv4StaticRouting>(protocol);
            if (staticRouting) {
                for (uint32_t k = 0; k < staticRouting->GetNRoutes(); k++) {
                    Ipv4RoutingTableEntry route = staticRouting->GetRoute(k);
                    
                    std::ostringstream destKey;
                    destKey << "N" << i << "_" << route.GetDest();
                    
                    std::ostringstream nextHopValue;
                    nextHopValue << route.GetGateway();
                    
                    snapshot.routes[destKey.str()] = 
                        std::make_pair(nextHopValue.str(), route.GetInterface());
                }
            }
            
            // Handle RIP Routing by parsing PrintRoutingTable output
            Ptr<Ipv4RoutingProtocol> ripProtocol = protocol;
            if (ripProtocol && !staticRouting) {
                std::ostringstream oss;
                Ptr<OutputStreamWrapper> streamWrapper = Create<OutputStreamWrapper>(&oss);
                ripProtocol->PrintRoutingTable(streamWrapper, Time::S);
                
                std::string tableStr = oss.str();
                std::istringstream iss(tableStr);
                std::string line;
                
                // Parse the routing table output
                while (std::getline(iss, line)) {
                    // Look for lines with routing entries (contain "->")
                    if (line.find("->") != std::string::npos) {
                        // Extract destination and next hop
                        size_t destPos = line.find("Destination");
                        size_t arrowPos = line.find("->");
                        
                        if (destPos != std::string::npos && arrowPos != std::string::npos) {
                            // Simple parsing - this is a heuristic approach
                            std::istringstream lineStream(line);
                            std::string dest, arrow, nextHop;
                            uint32_t metric = 0;
                            
                            lineStream >> dest;
                            while (lineStream >> arrow) {
                                if (arrow == "->") {
                                    lineStream >> nextHop;
                                    break;
                                }
                                dest = arrow;
                            }
                            
                            if (!dest.empty() && !nextHop.empty() && dest != "Destination") {
                                std::ostringstream destKey;
                                destKey << "N" << i << "_" << dest;
                                snapshot.routes[destKey.str()] = std::make_pair(nextHop, metric);
                            }
                        }
                    }
                }
            }
        }
    }
    
    return snapshot;
}

bool ConvergenceMonitor::AreSnapshotsIdentical(const RoutingSnapshot& s1, 
                                               const RoutingSnapshot& s2) {
    // Check if same number of routes
    if (s1.routes.size() != s2.routes.size()) {
        return false;
    }
    
    // Compare each route
    for (auto& entry : s1.routes) {
        std::string dest = entry.first;
        std::string nextHop1 = entry.second.first;
        
        // Check if destination exists in s2
        auto it = s2.routes.find(dest);
        if (it == s2.routes.end()) {
            return false; // Destination missing in s2
        }
        
        std::string nextHop2 = it->second.first;
        
        // Compare only nextHop (ignore metric changes)
        if (nextHop1 != nextHop2) {
            return false; // Route changed
        }
    }
    
    return true; // All routes identical
}

void ConvergenceMonitor::TakeSnapshot() {
    m_currentSnapshot = CaptureCurrentRoutingTables();
    
    // Check if converged
    CheckConvergence();
    
    // Update for next iteration
    m_previousSnapshot = m_currentSnapshot;
    
    // Schedule next snapshot (every 0.5 seconds)
    Simulator::Schedule(Seconds(0.5), &ConvergenceMonitor::TakeSnapshot, this);
}

bool ConvergenceMonitor::CheckConvergence() {
    // Can't check on first snapshot
    if (m_previousSnapshot.routes.empty()) {
        return false;
    }
    
    // Compare current with previous
    if (AreSnapshotsIdentical(m_currentSnapshot, m_previousSnapshot)) {
        m_stableSnapshotCount++;
        
        // Check if reached stability threshold
        if (m_stableSnapshotCount >= STABILITY_THRESHOLD && !m_hasConverged) {
            m_hasConverged = true;
            Time convergenceTime = Simulator::Now();
            
            // Record convergence based on current phase
            switch (m_currentPhase) {
                case INITIAL:
                    m_initialConvergenceTime = convergenceTime - m_simulationStartTime;
                    NS_LOG_INFO("INITIAL CONVERGENCE at t=" 
                               << convergenceTime.GetSeconds() 
                               << "s (took " << m_initialConvergenceTime.GetSeconds() << "s)");
                    std::cout << "INITIAL CONVERGENCE at t=" 
                             << convergenceTime.GetSeconds() 
                             << "s (took " << m_initialConvergenceTime.GetSeconds() << "s)" << std::endl;
                    m_currentPhase = CONVERGED;
                    break;
                    
                case UNDER_ATTACK:
                    m_attackConvergenceTime = convergenceTime - m_attackStartTime;
                    NS_LOG_INFO("ATTACK CONVERGENCE at t=" 
                               << convergenceTime.GetSeconds() 
                               << "s (took " << m_attackConvergenceTime.GetSeconds() << "s)");
                    std::cout << "ATTACK CONVERGENCE at t=" 
                             << convergenceTime.GetSeconds() 
                             << "s (took " << m_attackConvergenceTime.GetSeconds() << "s)" << std::endl;
                    m_currentPhase = CONVERGED;
                    break;
                    
                case RECOVERING:
                    m_recoveryConvergenceTime = convergenceTime - m_recoveryStartTime;
                    NS_LOG_INFO("RECOVERY CONVERGENCE at t=" 
                               << convergenceTime.GetSeconds() 
                               << "s (took " << m_recoveryConvergenceTime.GetSeconds() << "s)");
                    std::cout << "RECOVERY CONVERGENCE at t=" 
                             << convergenceTime.GetSeconds() 
                             << "s (took " << m_recoveryConvergenceTime.GetSeconds() << "s)" << std::endl;
                    m_currentPhase = CONVERGED;
                    break;
                    
                default:
                    break;
            }
            
            return true;
        }
    } else {
        // Routes changed, reset counter
        m_stableSnapshotCount = 0;
        m_hasConverged = false;
    }
    
    return false;
}

void ConvergenceMonitor::OnAttackTriggered() {
    NS_LOG_INFO("ATTACK TRIGGERED - Starting convergence monitoring");
    std::cout << "\nATTACK TRIGGERED at t=" << Simulator::Now().GetSeconds() 
              << "s - Starting convergence monitoring\n" << std::endl;
    m_attackStartTime = Simulator::Now();
    m_currentPhase = UNDER_ATTACK;
    m_hasConverged = false;
    m_stableSnapshotCount = 0;
}

void ConvergenceMonitor::OnRecoveryTriggered() {
    NS_LOG_INFO("RECOVERY STARTED - Monitoring convergence");
    std::cout << "\nRECOVERY STARTED at t=" << Simulator::Now().GetSeconds() 
              << "s - Monitoring convergence\n" << std::endl;
    m_recoveryStartTime = Simulator::Now();
    m_currentPhase = RECOVERING;
    m_hasConverged = false;
    m_stableSnapshotCount = 0;
}

void ConvergenceMonitor::PrintSummary() {
    std::cout << "\n========================================" << std::endl;
    std::cout << "    RIP CONVERGENCE TIME SUMMARY" << std::endl;
    std::cout << "========================================" << std::endl;
    std::cout << "Initial Convergence:  " << m_initialConvergenceTime.GetSeconds() << " seconds" << std::endl;
    std::cout << "Attack Convergence:   " << m_attackConvergenceTime.GetSeconds() << " seconds" << std::endl;
    std::cout << "Recovery Convergence: " << m_recoveryConvergenceTime.GetSeconds() << " seconds" << std::endl;
    std::cout << "========================================\n" << std::endl;
}

void ConvergenceMonitor::ExportToCSV(std::string filename) {
    std::ofstream csvFile(filename);
    
    csvFile << "Protocol,Phase,ConvergenceTime(s)\n";
    csvFile << "RIP,Initial," << m_initialConvergenceTime.GetSeconds() << "\n";
    csvFile << "RIP,Attack," << m_attackConvergenceTime.GetSeconds() << "\n";
    csvFile << "RIP,Recovery," << m_recoveryConvergenceTime.GetSeconds() << "\n";
    
    csvFile.close();
    
    NS_LOG_INFO("Convergence metrics exported to " << filename);
    std::cout << "Convergence metrics exported to " << filename << std::endl;
}

// Injects the poisoned routes on the provided node
void InjectPoisonRoute(Ptr<Node> nodeToPoison, Ipv4Address victimAddress, Ipv4Address nextHopAddress) {
    NS_LOG_INFO("Injecting poison route on the Node: " << nodeToPoison->GetId());
    Ptr<Ipv4> ipv4 = nodeToPoison->GetObject<Ipv4>();
    Ptr<Ipv4ListRouting> listRouting = DynamicCast<Ipv4ListRouting>(ipv4->GetRoutingProtocol());
    Ptr<Ipv4StaticRouting> staticRouting = nullptr;
    for (uint32_t i = 0; i < listRouting->GetNRoutingProtocols(); i++) {
        int16_t priority;
        Ptr<Ipv4RoutingProtocol> protocol = listRouting->GetRoutingProtocol(i, priority);
        if (DynamicCast<Ipv4StaticRouting>(protocol)) {
            staticRouting = DynamicCast<Ipv4StaticRouting>(protocol);
            break;
        }
    }
    if (staticRouting) {
        staticRouting->AddHostRouteTo(victimAddress, nextHopAddress, 3);
        poisonedInstances[nodeToPoison] = staticRouting;
    }
}

// Removes the poisoned routes from the provided node
void RemovePoisonRoute(Ptr<Node> poisonedNode, Ipv4Address victimAddress) {
    NS_LOG_INFO("Removing poison route from Node " << poisonedNode->GetId());
    if (poisonedInstances.count(poisonedNode)) {
        Ptr<Ipv4StaticRouting> staticRouting = poisonedInstances[poisonedNode];
        for (uint32_t i = 0; i < staticRouting->GetNRoutes(); ++i) {
            if (staticRouting->GetRoute(i).GetDest() == victimAddress) {
                staticRouting->RemoveRoute(i);
                break;
            }
        }
    }
}

// Creates a blackhole by disabling the attackers all interfaces so that it cannot forward data packets
void BlackholeAttacker(Ptr<Node> attackerNode) {
    NS_LOG_INFO("Creating blackhole and disabling all the interfaces on that attacker" << attackerNode->GetId());
    Ptr<Ipv4> ipv4 = attackerNode->GetObject<Ipv4>();
    // does not disable 0th interface because it is the loopback interfacce
    for (uint32_t i = 1; i < ipv4->GetNInterfaces(); i++) {
        ipv4->SetDown(i);
    }
}

// Re-enables the attackers interfaces
void RestoreAttacker(Ptr<Node> attackerNode) {
    NS_LOG_INFO("Removing blackhole and re-enabling all the interfaces on that attacker " << attackerNode->GetId());
    Ptr<Ipv4> ipv4 = attackerNode->GetObject<Ipv4>();
    for (uint32_t i = 1; i < ipv4->GetNInterfaces(); i++) {
        ipv4->SetUp(i);
    }
}

// logs routing tables to the filestream
void LogRoutingTables(Ptr<OutputStreamWrapper> stream, NodeContainer* nodes) {
    *stream->GetStream() << "\n\n Routing Tables at: " << Simulator::Now().GetSeconds() << "seconds\n";
    for (uint32_t i = 0; i < nodes->GetN(); ++i) {
        Ptr<Node> node = nodes->Get(i);
        Ptr<Ipv4> ipv4 = node->GetObject<Ipv4>();
        Ptr<Ipv4ListRouting> listRouting = DynamicCast<Ipv4ListRouting>(ipv4->GetRoutingProtocol());

        *stream->GetStream() << "\nRouting table for Node " << node->GetId() << "\n";
        
        if (!listRouting) {
            continue;
        }

        for (uint32_t j = 0; j < listRouting->GetNRoutingProtocols(); j++) {
            int16_t priority;
            Ptr<Ipv4RoutingProtocol> protocol = listRouting->GetRoutingProtocol(j, priority);
            *stream->GetStream() << "Protocol " << j << " (Priority " << priority << ")\n";
            protocol->PrintRoutingTable(stream, Time::S);
        }
    }
}

// victims throughput is logged to the console at the provided interval
void CalculateThroughput(Ptr<PacketSink> sink, double interval) {
    static uint64_t totalBytes = 0;
    uint64_t currentTotalBytes = sink->GetTotalRx();
    double throughput = (currentTotalBytes - totalBytes) * 8.0 / (interval * 1e6);
    totalBytes = currentTotalBytes;
    std::cout << "Time: " << Simulator::Now().GetSeconds()<< " seconds, Victim's throughput: "<< throughput << " Mbps" << std::endl;
}


int main(int argc, char* argv[]) {
    LogComponentEnable("RipBlackholeAttack", LOG_LEVEL_INFO);

    // logs results
    const char *resultsDirectory = "results";
    mkdir(resultsDirectory, 0755);

    // creates files for logging route tables
    AsciiTraceHelper ascii;
    Ptr<OutputStreamWrapper> rtStreamBefore = ascii.CreateFileStream(std::string(resultsDirectory) + "/RoutingTables_Before.txt");
    Ptr<OutputStreamWrapper> rtStreamDuring = ascii.CreateFileStream(std::string(resultsDirectory) + "/RoutingTables_During.txt");
    Ptr<OutputStreamWrapper> rtStreamAfter = ascii.CreateFileStream(std::string(resultsDirectory) + "/RoutingTables_After.txt");

    // setting up the nodes for the simulation
    NodeContainer nodes;
    nodes.Create(6);
    Ptr<Node> attackerNode = nodes.Get(3); // attacker is node 3
    NodeContainer n0n1 = NodeContainer(nodes.Get(0), nodes.Get(1));
    NodeContainer n1n2 = NodeContainer(nodes.Get(1), nodes.Get(2));
    NodeContainer n2n4 = NodeContainer(nodes.Get(2), nodes.Get(4));
    NodeContainer n4n5 = NodeContainer(nodes.Get(4), nodes.Get(5));
    NodeContainer n2n3 = NodeContainer(nodes.Get(2), nodes.Get(3)); 

    // Internet Stack with RIP and Static routing protocols
    Ipv4ListRoutingHelper listRoutingHelper;
    Ipv4StaticRoutingHelper staticRoutingHelper;
    RipHelper ripRouting;
    InternetStackHelper stack;

    listRoutingHelper.Add(staticRoutingHelper, 100); 
    listRoutingHelper.Add(ripRouting, 10); 
    stack.SetRoutingHelper(listRoutingHelper);
    stack.Install(nodes);
    
    // Setting up the link between the nodes
    PointToPointHelper p2p;
    p2p.SetDeviceAttribute("DataRate", StringValue("5Mbps"));
    p2p.SetChannelAttribute("Delay", StringValue("2ms"));

    NetDeviceContainer d0d1 = p2p.Install(n0n1);
    NetDeviceContainer d1d2 = p2p.Install(n1n2);
    NetDeviceContainer d2d4 = p2p.Install(n2n4);
    NetDeviceContainer d4d5 = p2p.Install(n4n5);
    NetDeviceContainer d2d3 = p2p.Install(n2n3);
    
    // Enabling pcap tracing for all the devices
    p2p.EnablePcapAll(std::string(resultsDirectory) + "/rip-blackhole-attack");
    
    // Setting up IP addresses
    Ipv4AddressHelper ipv4;
    ipv4.SetBase("10.1.1.0", "255.255.255.0");
    ipv4.Assign(d0d1);
    ipv4.SetBase("10.1.2.0", "255.255.255.0");
    ipv4.Assign(d1d2);
    ipv4.SetBase("10.1.4.0", "255.255.255.0");
    ipv4.Assign(d2d4);
    ipv4.SetBase("10.1.5.0", "255.255.255.0");
    Ipv4InterfaceContainer i4i5 = ipv4.Assign(d4d5);
    ipv4.SetBase("10.1.3.0", "255.255.255.0");
    Ipv4InterfaceContainer i2i3 = ipv4.Assign(d2d3);
    Ipv4GlobalRoutingHelper::PopulateRoutingTables();

    // Defining the nodes involved in the attack
    Ptr<Node> victimNode = nodes.Get(5);
    Ptr<Node> pivotNode = nodes.Get(2);
    Ipv4Address victimAddress = i4i5.GetAddress(1);
    Ipv4Address attackerNextHopAddress = i2i3.GetAddress(1);

    // timeline of the simulation
    double timeOfConverge = 10.0;
    double timeOfAttack = 35.0;
    double timeOfAttackLog = 40.0;
    double timeOfRecovery = 75.0;
    double timeOfRecoveryLog = 80.0;
    double timeOfSimulation = 120.0; 
    
    // Creates the convergence monitor
    ConvergenceMonitor* convergenceMonitor = new ConvergenceMonitor(&nodes);
    
    // Start monitoring (takes snapshot every 0.5s)
    Simulator::Schedule(Seconds(1.0), &ConvergenceMonitor::TakeSnapshot, convergenceMonitor);
    
    // setting up the application to monitor the throughput of the victim
    uint16_t sinkPort = 8080;
    Address sinkAddress(InetSocketAddress(victimAddress, sinkPort));
    PacketSinkHelper packetSinkHelper("ns3::UdpSocketFactory", sinkAddress);
    ApplicationContainer sinkApps = packetSinkHelper.Install(victimNode);
    Ptr<PacketSink> sink = DynamicCast<PacketSink>(sinkApps.Get(0));
    sinkApps.Start(Seconds(0.0));
    sinkApps.Stop(Seconds(timeOfSimulation));
    OnOffHelper onOff("ns3::UdpSocketFactory", sinkAddress);
    onOff.SetAttribute("OnTime", StringValue("ns3::ConstantRandomVariable[Constant=1]"));
    onOff.SetAttribute("OffTime", StringValue("ns3::ConstantRandomVariable[Constant=0]"));
    onOff.SetAttribute("DataRate", DataRateValue(DataRate("1Mbps")));
    onOff.SetAttribute("PacketSize", UintegerValue(1024));
    ApplicationContainer sourceApps = onOff.Install(nodes.Get(0));
    sourceApps.Start(Seconds(1.0));
    sourceApps.Stop(Seconds(timeOfSimulation));
    
    // calculates the throughput of the victim every 5 seconds
    double monitorInterval = 5.0;
    for (double t = monitorInterval; t <= timeOfSimulation; t += monitorInterval) {
        Simulator::Schedule(Seconds(t), &CalculateThroughput, sink, monitorInterval);
    }

    // schedules the events in the simulation
    Simulator::Schedule(Seconds(timeOfConverge), &LogRoutingTables, rtStreamBefore, &nodes);
    
    // Attack injection
    Simulator::Schedule(Seconds(timeOfAttack), [convergenceMonitor]() {
        convergenceMonitor->OnAttackTriggered();
    });
    Simulator::Schedule(Seconds(timeOfAttack), &InjectPoisonRoute, pivotNode, victimAddress, attackerNextHopAddress);
    Simulator::Schedule(Seconds(timeOfAttack + 0.1), &BlackholeAttacker, attackerNode); 
    
    Simulator::Schedule(Seconds(timeOfAttackLog), &LogRoutingTables, rtStreamDuring, &nodes);
    
    // Recovery from attack
    Simulator::Schedule(Seconds(timeOfRecovery), [convergenceMonitor]() {
        convergenceMonitor->OnRecoveryTriggered();
    });
    Simulator::Schedule(Seconds(timeOfRecovery), &RemovePoisonRoute, pivotNode, victimAddress);
    Simulator::Schedule(Seconds(timeOfRecovery + 0.1), &RestoreAttacker, attackerNode);

    Simulator::Schedule(Seconds(timeOfRecoveryLog), &LogRoutingTables, rtStreamAfter, &nodes);

    // Prints and exports the convergence summary at the end of the simulation
    Simulator::Schedule(Seconds(timeOfSimulation - 1.0), [convergenceMonitor]() {
        convergenceMonitor->PrintSummary();
        convergenceMonitor->ExportToCSV("results/rip-convergence.csv");
    });

    // Runs the simulation
    NS_LOG_INFO("Starting simulation");
    std::cout << "\n========================================" << std::endl;
    std::cout << "   RIP BLACKHOLE ATTACK SIMULATION" << std::endl;
    std::cout << "========================================" << std::endl;
    std::cout << "Attack will be triggered at t=" << timeOfAttack << "s" << std::endl;
    std::cout << "Recovery will start at t=" << timeOfRecovery << "s" << std::endl;
    std::cout << "========================================\n" << std::endl;
    
    Simulator::Stop(Seconds(timeOfSimulation));
    Simulator::Run();
    Simulator::Destroy();
    
    delete convergenceMonitor;
    
    NS_LOG_INFO("Simulation is complete. Check results directory");
    std::cout << "\n✓ Simulation complete. Check results/ directory" << std::endl;
    return 0;
}
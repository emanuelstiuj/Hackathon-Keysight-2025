#include <array>
#include <vector>
#include <iostream>
#include <string>
#include <mutex>
#include <sycl/sycl.hpp>
#include <pcap/pcap.h>
#include <tbb/blocked_range.h>
#include <tbb/global_control.h>
#include <tbb/flow_graph.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>
#include <ctime>
#include <sys/socket.h>
#include <netpacket/packet.h>
#include <net/if.h>
#include <unistd.h>
#include <cstring>
#include "dpc_common.hpp"

const size_t burst_size = 32;
#define PACKET_SIZE 64

static std::mutex cout_mutex;

static std::mutex socket_mutex;

// Structure to hold packet data for burst processing
struct PacketData {
    struct pcap_pkthdr header;
    std::array<u_char, PACKET_SIZE> data; // Fixed-size buffer for packet data
};

// Structure to hold packet statistics
struct PacketStats {
    size_t ipv4 = 0;
    size_t ipv6 = 0;
    size_t arp = 0;
    size_t icmp = 0;
    size_t tcp = 0;
    size_t udp = 0;

    void print() const {
        std::lock_guard<std::mutex> lock(cout_mutex);
        std::cout << "Packet Counts:\n"
                  << "IPv4: " << ipv4 << "\n"
                  << "IPv6: " << ipv6 << "\n"
                  << "ARP: " << arp << "\n"
                  << "ICMP: " << icmp << "\n"
                  << "TCP: " << tcp << "\n"
                  << "UDP: " << udp << "\n"
                  << "------------------------\n";
    }

    void add(const PacketStats& other) {
        ipv4 += other.ipv4;
        ipv6 += other.ipv6;
        arp += other.arp;
        icmp += other.icmp;
        tcp += other.tcp;
        udp += other.udp;
    }
};

// Print packet info to handle IPv4, IPv6, ARP, ICMP, TCP, UDP
void print_packet_info(const struct pcap_pkthdr *pkthdr, const u_char *packet, bool modified = false) {
    time_t seconds = pkthdr->ts.tv_sec;
    struct tm *timeinfo = localtime(&seconds);
    char time_str[32];
    strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", timeinfo);

    std::cout << (modified ? "Modified packet" : "Packet") << " captured at: " << time_str << "." << pkthdr->ts.tv_usec 
              << "\nLength: " << pkthdr->caplen << " bytes\n";

    if (pkthdr->caplen < sizeof(struct ether_header)) {
        std::cout << "Packet too short for Ethernet header\n";
        return;
    }

    // Parse Ethernet header
    struct ether_header *eth_header = (struct ether_header *)packet;
    uint16_t ether_type = ntohs(eth_header->ether_type);

    if (ether_type == ETHERTYPE_IP) {
        if (pkthdr->caplen < sizeof(struct ether_header) + sizeof(struct ip)) {
            std::cout << "Packet too short for IP header\n";
            return;
        }
        struct ip *ip_header = (struct ip *)(packet + sizeof(struct ether_header));
        char src_ip[INET_ADDRSTRLEN], dst_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(ip_header->ip_src), src_ip, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &(ip_header->ip_dst), dst_ip, INET_ADDRSTRLEN);

        std::cout << "Source IP: " << src_ip << ", Dest IP: " << dst_ip << "\n";

        size_t ip_header_len = ip_header->ip_hl * 4;
        if (pkthdr->caplen < sizeof(struct ether_header) + ip_header_len) {
            std::cout << "Packet too short for full IP header\n";
            return;
        }
        switch (ip_header->ip_p) {
            case IPPROTO_TCP: {
                if (pkthdr->caplen < sizeof(struct ether_header) + ip_header_len + sizeof(struct tcphdr)) {
                    std::cout << "Packet too short for TCP header\n";
                    return;
                }
                struct tcphdr *tcp_header = (struct tcphdr *)(packet + sizeof(struct ether_header) + ip_header_len);
                std::cout << "Protocol: TCP\n"
                          << "Source Port: " << ntohs(tcp_header->th_sport) 
                          << ", Dest Port: " << ntohs(tcp_header->th_dport) << "\n";
                break;
            }
            case IPPROTO_UDP: {
                if (pkthdr->caplen < sizeof(struct ether_header) + ip_header_len + sizeof(struct udphdr)) {
                    std::cout << "Packet too short for UDP header\n";
                    return;
                }
                struct udphdr *udp_header = (struct udphdr *)(packet + sizeof(struct ether_header) + ip_header_len);
                std::cout << "Protocol: UDP\n"
                          << "Source Port: " << ntohs(udp_header->uh_sport) 
                          << ", Dest Port: " << ntohs(udp_header->uh_dport) << "\n";
                break;
            }
            case IPPROTO_ICMP: {
                if (pkthdr->caplen < sizeof(struct ether_header) + ip_header_len + sizeof(struct icmphdr)) {
                    std::cout << "Packet too short for ICMP header\n";
                    return;
                }
                struct icmphdr *icmp_header = (struct icmphdr *)(packet + sizeof(struct ether_header) + ip_header_len);
                std::cout << "Protocol: ICMP\n"
                          << "Type: " << static_cast<int>(icmp_header->type) 
                          << ", Code: " << static_cast<int>(icmp_header->code) << "\n";
                break;
            }
            default:
                std::cout << "Protocol: Unknown (" << static_cast<int>(ip_header->ip_p) << ")\n";
                break;
        }
    } else if (ether_type == ETHERTYPE_IPV6) {
        if (pkthdr->caplen < sizeof(struct ether_header) + sizeof(struct ip6_hdr)) {
            std::cout << "Packet too short for IPv6 header\n";
            return;
        }
        struct ip6_hdr *ip6_header = (struct ip6_hdr *)(packet + sizeof(struct ether_header));
        char src_ip[INET6_ADDRSTRLEN], dst_ip[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, &(ip6_header->ip6_src), src_ip, INET6_ADDRSTRLEN);
        inet_ntop(AF_INET6, &(ip6_header->ip6_dst), dst_ip, INET6_ADDRSTRLEN);

        std::cout << "Source IP: " << src_ip << ", Dest IP: " << dst_ip << "\n";
        std::cout << "Protocol: IPv6\n";
    } else if (ether_type == ETHERTYPE_ARP) {
        std::cout << "Protocol: ARP\n";
    } else {
        std::cout << "Protocol: Unknown EtherType (" << ether_type << ")\n";
    }
    std::cout << "------------------------\n";
}

int main() {
    sycl::queue q;
    std::cout << "Using device: " << q.get_device().get_info<sycl::info::device::name>() << "\n";

    static PacketStats global_stats;

    int sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sockfd < 0) {
        std::cerr << "Failed to create raw socket (are you running as root?)\n";
        return 1;
    }

    std::string interface = "eth0";
    struct sockaddr_ll socket_address;
    std::memset(&socket_address, 0, sizeof(socket_address));
    socket_address.sll_family = AF_PACKET;
    socket_address.sll_protocol = htons(ETH_P_ALL);
    socket_address.sll_ifindex = if_nametoindex(interface.c_str());
    if (socket_address.sll_ifindex == 0) {
        std::cerr << "Failed to get interface index for " << interface << "\n";
        close(sockfd);
        return 1;
    }

    if (bind(sockfd, (struct sockaddr*)&socket_address, sizeof(socket_address)) < 0) {
        std::cerr << "Failed to bind raw socket to " << interface << "\n";
        close(sockfd);
        return 1;
    }

    // Set up TBB thread control
    int nth = 10;
    auto mp = tbb::global_control::max_allowed_parallelism;
    tbb::global_control gc(mp, nth);
    tbb::flow::graph g;

    // Open PCAP file
    char errbuf[PCAP_ERRBUF_SIZE];
    std::string pcap_file = "/challenge/proiecte/keysight-challenge-2025/src/capture2.pcap";
    pcap_t* pcap_handle = pcap_open_offline(pcap_file.c_str(), errbuf);
    if (!pcap_handle) {
        std::cerr << "pcap_open_offline() failed: " << errbuf << "\n";
        return 1;
    }

    // Input node: Read packets in bursts
    tbb::flow::input_node<std::vector<PacketData>> in_node{g,
        [&](tbb::flow_control& fc) -> std::vector<PacketData> {
            std::vector<PacketData> burst;
            burst.reserve(burst_size); // Avoid reallocations

            const u_char* packet_data;
            struct pcap_pkthdr* header;

            // Read up to burst_size packets
            for (size_t i = 0; i < burst_size; ++i) {
                int result = pcap_next_ex(pcap_handle, &header, &packet_data);
                if (result == 1) {
                    PacketData pkt;
                    pkt.header = *header;
                    size_t copy_len = std::min<size_t>(header->caplen, PACKET_SIZE);
                    std::copy(packet_data, packet_data + copy_len, pkt.data.begin());
                    burst.push_back(pkt);
                } else if (result == -2) {
                    std::lock_guard<std::mutex> lock(cout_mutex);
                    std::cout << "No more packets (EOF)\n";
                    //fc.stop();
                    break;
                } else {
                    std::cout << "Error or timeout reading packet\n";
                    break;
                }
            }

            if (burst.empty()) {
                fc.stop();
                return {};
            }

            std::lock_guard<std::mutex> lock(cout_mutex);
            std::cout << "Read burst of " << burst.size() << " packets\n";
            return burst;
        }
    };

    // Packet inspection node: Analyze and filter IPv4/IPv6 packets in parallel
    tbb::flow::function_node<std::vector<PacketData>, std::vector<PacketData>> inspect_packet_node {
        g, tbb::flow::unlimited, [&](std::vector<PacketData> burst) -> std::vector<PacketData> {

            // Print packet info sequentially for debugging
            for (const auto& pkt : burst) {
                //print_packet_info(&pkt.header, pkt.data.data());
            }

            // Parallel packet analysis with SYCL
            PacketStats stats;
            std::vector<char> is_ip_packet(burst.size(), 0); // 1 for IPv4/IPv6, 0 otherwise
            {
                sycl::queue gpuQ(sycl::gpu_selector_v, dpc_common::exception_handler);
                //std::cout << "Selected GPU Device: " 
                //          << gpuQ.get_device().get_info<sycl::info::device::name>() << "\n";

                // SYCL buffers
                sycl::buffer<PacketData> burst_buf(burst.data(), burst.size());
                sycl::buffer<char> ip_buf(is_ip_packet.data(), is_ip_packet.size());
                sycl::buffer<size_t> ipv4_buf(&stats.ipv4, 1);
                sycl::buffer<size_t> ipv6_buf(&stats.ipv6, 1);
                sycl::buffer<size_t> arp_buf(&stats.arp, 1);
                sycl::buffer<size_t> icmp_buf(&stats.icmp, 1);
                sycl::buffer<size_t> tcp_buf(&stats.tcp, 1);
                sycl::buffer<size_t> udp_buf(&stats.udp, 1);

                gpuQ.submit([&](sycl::handler& h) {
                    auto burst_acc = burst_buf.get_access<sycl::access::mode::read>(h);
                    auto ip_acc = ip_buf.get_access<sycl::access::mode::write>(h);
                    auto ipv4_acc = ipv4_buf.get_access<sycl::access::mode::atomic>(h);
                    auto ipv6_acc = ipv6_buf.get_access<sycl::access::mode::atomic>(h);
                    auto arp_acc = arp_buf.get_access<sycl::access::mode::atomic>(h);
                    auto icmp_acc = icmp_buf.get_access<sycl::access::mode::atomic>(h);
                    auto tcp_acc = tcp_buf.get_access<sycl::access::mode::atomic>(h);
                    auto udp_acc = udp_buf.get_access<sycl::access::mode::atomic>(h);

                    h.parallel_for(sycl::range<1>(burst.size()), [=](sycl::id<1> idx) {
                        const auto& pkt = burst_acc[idx];
                        auto packet = pkt.data;

                        // Check packet length
                        if (pkt.header.caplen < sizeof(struct ether_header)) {
                            return;
                        }

                        // Parse Ethernet header
                        struct ether_header *eth_header = (struct ether_header *)packet.data();
                        uint16_t ether_type = ntohs(eth_header->ether_type);

                        if (ether_type == ETHERTYPE_IP) {
                            if (pkt.header.caplen < sizeof(struct ether_header) + sizeof(struct ip)) {
                                return;
                            }
                            sycl::atomic_fetch_add(ipv4_acc[0], size_t(1));
                            struct ip *ip_header = (struct ip *)(packet.data() + sizeof(struct ether_header));
                            size_t ip_header_len = ip_header->ip_hl * 4;
                            if (pkt.header.caplen < sizeof(struct ether_header) + ip_header_len) {
                                return;
                            }
                            switch (ip_header->ip_p) {
                                case IPPROTO_ICMP: sycl::atomic_fetch_add(icmp_acc[0], size_t(1)); break;
                                case IPPROTO_TCP: sycl::atomic_fetch_add(tcp_acc[0], size_t(1)); break;
                                case IPPROTO_UDP: sycl::atomic_fetch_add(udp_acc[0], size_t(1)); break;
                            }
                            ip_acc[idx] = 1; // Mark as IPv4
                        } else if (ether_type == ETHERTYPE_IPV6) {
                            if (pkt.header.caplen < sizeof(struct ether_header) + sizeof(struct ip6_hdr)) {
                                return;
                            }
                            sycl::atomic_fetch_add(ipv6_acc[0], size_t(1));
                            ip_acc[idx] = 1; // Mark as IPv6
                        } else if (ether_type == ETHERTYPE_ARP) {
                            sycl::atomic_fetch_add(arp_acc[0], size_t(1));
                        }
                    });
                }).wait_and_throw();
            }

            // Update global stats
            global_stats.add(stats);

            // Collect IPv4/IPv6 packets sequentially
            std::vector<PacketData> ip_packets;
            ip_packets.reserve(burst.size());

            
            if (burst.size() < 32) {
                std::lock_guard<std::mutex> lock(cout_mutex);
                std::cout << "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!";
            }


            for (size_t i = 0; i < burst.size(); ++i) {
                if (is_ip_packet[i]) {
                    ip_packets.push_back(burst[i]);
                }
            }

            // Print stats
            // global_stats.print();

            return ip_packets; // Send only IPv4/IPv6 packets
        }
    };

    // Routing node: Modify IPv4 packets
    tbb::flow::function_node<std::vector<PacketData>, std::vector<PacketData>> routing_node {
        g, tbb::flow::unlimited, [&](std::vector<PacketData> ip_packets) -> std::vector<PacketData> {
            std::vector<PacketData> modified_packets;
            modified_packets.reserve(ip_packets.size());

            // Process only IPv4 packets
            for (auto& pkt : ip_packets) {
                if (pkt.header.caplen < sizeof(struct ether_header)) {
                    continue; // Skip invalid packets
                }
                struct ether_header *eth_header = (struct ether_header *)pkt.data.data();
                uint16_t ether_type = ntohs(eth_header->ether_type);

                if (ether_type == ETHERTYPE_IP) {
                    if (pkt.header.caplen < sizeof(struct ether_header) + sizeof(struct ip)) {
                        continue; // Skip invalid packets
                    }
                    struct ip *ip_header = (struct ip *)(pkt.data.data() + sizeof(struct ether_header));
                    // Modify destination IP: add 1 to each byte
                    uint32_t dst_ip = ntohl(ip_header->ip_dst.s_addr);
                    uint8_t *ip_bytes = (uint8_t*)&dst_ip;
                    for (int i = 0; i < 4; ++i) {
                        ip_bytes[i] = (ip_bytes[i] + 1) % 256; // Handle overflow
                    }
                    ip_header->ip_dst.s_addr = htonl(dst_ip);

                    modified_packets.push_back(pkt); // Store modified packet
                }
                // IPv6 packets are ignored
            }

            if (!modified_packets.empty()) {
                //std::cout << "Routing burst of " << modified_packets.size() << " modified IPv4 packets to sending node\n";
            } else {
                std::cout << "No IPv4 packets to route in this burst\n";
            }

            return modified_packets; // Send to sending_node
        }
    };

    // Sending node: Print packet contents
    tbb::flow::function_node<std::vector<PacketData>> sending_node {
        g, tbb::flow::unlimited, [&](std::vector<PacketData> modified_packets) {
            if (!modified_packets.empty()) {
                std::lock_guard<std::mutex> lock(socket_mutex); // Synchronize socket writes
                for (const auto& pkt : modified_packets) {
                    // Send raw packet data
                    ssize_t bytes_sent = sendto(sockfd, pkt.data.data(), pkt.header.caplen, 0,
                                                (struct sockaddr*)&socket_address, sizeof(socket_address));
                    if (bytes_sent < 0) {
                        std::lock_guard<std::mutex> cout_lock(cout_mutex);
                        std::cerr << "Failed to send packet data\n";
                    }
                }
            }
        }
    };

    // Construct graph
    tbb::flow::make_edge(in_node, inspect_packet_node);
    tbb::flow::make_edge(inspect_packet_node, routing_node);
    tbb::flow::make_edge(routing_node, sending_node);

    // Run the graph
    in_node.activate();
    g.wait_for_all();

    {
        std::lock_guard<std::mutex> lock(cout_mutex);
        std::cout << "Done processing\n";
    }

    global_stats.print();
    
    pcap_close(pcap_handle);
    return 0;
}
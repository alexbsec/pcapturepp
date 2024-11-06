#include "NetProber.hpp"
#include <linux/if_packet.h> // Provides sockaddr_ll structure
#include <net/ethernet.h>    // Defines Ethernet headers
#include <sys/ioctl.h>       // For ioctl calls
#include <net/if.h>          // For ifreq and network interface info
#include <arpa/inet.h>       // For inet_pton and related network functions
#include <cstring>           // For memset and strncpy
#include <sys/socket.h>      // For socket functions
#include <unistd.h>          // For close function
#include <iostream>          // For console output
#include <ifaddrs.h>         // For getifaddrs function
#include <netdb.h>           // For getnameinfo
#include <mutex>
#include <thread>
#include <unordered_set>

namespace pcapturepp {
namespace netprober {
    
    bool GetLocalMacAddress(const string& iface, UINT8 *mac) {
        int fd = socket(AF_INET, SOCK_DGRAM, 0);
        if (fd == -1) {
            perror("socket");
            return false;
        }

        struct ifreq ifr;
        strncpy(ifr.ifr_name, iface.c_str(), IFNAMSIZ - 1);
        if (ioctl(fd, SIOCGIFHWADDR, &ifr) == -1) {
            perror("ioctl");
            close(fd);
            return false;
        }

        memcpy(mac, ifr.ifr_hwaddr.sa_data, MAC_ADDRESS_SIZE);
        close(fd);
        return true;
    }

    string GetSourceIP() {
        struct ifaddrs *ifaddr, *ifa;
        char ip[INET_ADDRSTRLEN];

        if (getifaddrs(&ifaddr) == -1) {
            perror("getifaddrs");
            return "";
        }

        for (ifa = ifaddr; ifa != nullptr; ifa = ifa->ifa_next) {
            if (ifa->ifa_addr == nullptr) continue;

            // Check if it is an IPv4 address
            if (ifa->ifa_addr->sa_family == AF_INET) {
                // Get the IP address
                void* addr_ptr = &((struct sockaddr_in*)ifa->ifa_addr)->sin_addr;
                inet_ntop(AF_INET, addr_ptr, ip, INET_ADDRSTRLEN);

                // Skip loopback address (127.0.0.1)
                if (string(ip) == "127.0.0.1") {
                    continue;
                }

                std::string interface_name(ifa->ifa_name);
                
                if (interface_name == "wlan0") {
                    freeifaddrs(ifaddr);
                    return string(ip);
                }
            }
        }

        freeifaddrs(ifaddr);
        return "";
    }   

    void SendArpRequest(int sock, const std::string& iface, const std::string& source_ip, const std::string& target_ip) {
        struct ether_arp req;
        struct sockaddr_ll sa;
        UINT8 local_mac[6];
        struct ifreq ifr;

        // Step 1: Get the interface index and MAC address
        strncpy(ifr.ifr_name, iface.c_str(), IFNAMSIZ - 1);
        if (ioctl(sock, SIOCGIFHWADDR, &ifr) < 0) {
            perror("ioctl");
            return;
        }
        memcpy(local_mac, ifr.ifr_hwaddr.sa_data, 6);

        if (ioctl(sock, SIOCGIFINDEX, &ifr) < 0) {
            perror("ioctl");
            return;
        }
        int ifindex = ifr.ifr_ifindex;

        // Step 2: Construct ARP request packet
        memset(&req, 0, sizeof(req));
        req.arp_hrd = htons(ARPHRD_ETHER);   // Ethernet
        req.arp_pro = htons(ETHERTYPE_IP);   // IPv4
        req.arp_hln = ETHER_ADDR_LEN;        // MAC address length
        req.arp_pln = 4;                     // IPv4 address length
        req.arp_op = htons(ARPOP_REQUEST);   // ARP request

        // Set source MAC and IP
        memcpy(req.arp_sha, local_mac, 6);
        inet_pton(AF_INET, source_ip.c_str(), req.arp_spa);

        // Set target MAC to unknown and IP to the requested address
        memset(req.arp_tha, 0x00, 6);
        inet_pton(AF_INET, target_ip.c_str(), req.arp_tpa);

        // Step 3: Construct Ethernet frame
        UINT8 frame[42];
        struct ether_header *eth_header = (struct ether_header*) frame;

        memset(eth_header->ether_dhost, 0xff, 6);        // Destination MAC (broadcast)
        memcpy(eth_header->ether_shost, local_mac, 6);   // Source MAC
        eth_header->ether_type = htons(ETHERTYPE_ARP);   // ARP packet

        // Copy ARP request to the frame
        memcpy(frame + sizeof(struct ether_header), &req, sizeof(req));

        // Step 4: Send packet using socket
        memset(&sa, 0, sizeof(sa));
        sa.sll_ifindex = ifindex;  // Interface index
        sa.sll_halen = ETH_ALEN;
        memcpy(sa.sll_addr, local_mac, 6);

        if (sendto(sock, frame, sizeof(frame), 0, (struct sockaddr*)&sa, sizeof(sa)) < 0) {
            perror("sendto");
        } else {
            std::cout << "[SEND] ARP request sent to " << target_ip << std::endl;
        }
    }

    string GetSubnet() {
        struct ifaddrs *ifaddr, *ifa;
        char ip[INET_ADDRSTRLEN];
        char netmask[INET_ADDRSTRLEN];
        string subnet;

        // Get the list of network interfaces
        if (getifaddrs(&ifaddr) == -1) {
            perror("getifaddrs");
            return "";
        }

        for (ifa = ifaddr; ifa != nullptr; ifa = ifa->ifa_next) {
            if (ifa->ifa_addr == nullptr) {
                continue;
            }

            // Only process IPv4 addresses and skip loopback interfaces
            if (ifa->ifa_addr->sa_family == AF_INET && !(ifa->ifa_flags & IFF_LOOPBACK)) {
                void *addr = &((struct sockaddr_in *)ifa->ifa_addr)->sin_addr;
                inet_ntop(AF_INET, addr, ip, INET_ADDRSTRLEN);

                // Get subnet mask
                void *netmask_addr = &((struct sockaddr_in *)ifa->ifa_netmask)->sin_addr;
                inet_ntop(AF_INET, netmask_addr, netmask, INET_ADDRSTRLEN);

                // Calculate subnet address
                struct in_addr ip_addr, netmask_addr_struct, subnet_addr;
                inet_pton(AF_INET, ip, &ip_addr);
                inet_pton(AF_INET, netmask, &netmask_addr_struct);

                subnet_addr.s_addr = ip_addr.s_addr & netmask_addr_struct.s_addr;

                char subnet_str[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &subnet_addr, subnet_str, INET_ADDRSTRLEN);

                freeifaddrs(ifaddr);  // Clean up allocated memory

                subnet = string(subnet_str);
                return subnet;  // Return as soon as you find the correct subnet
            }
        }

        freeifaddrs(ifaddr);  // Clean up allocated memory
        return "";
    }

    string GetHostname(const string& ip) {
        struct sockaddr_in sa;
        char hostname[NI_MAXHOST];

        sa.sin_family = AF_INET;
        inet_pton(AF_INET, ip.c_str(), &sa.sin_addr);

        int res = getnameinfo((struct sockaddr*)&sa, sizeof(sa), hostname, NI_MAXHOST, nullptr, 0, NI_NAMEREQD);
        if (res == 0) return string(hostname);
        return "unknown";
    }

    std::mutex console_mutex;


    vector<DeviceInfo> GetAllConnectedDevices(const string& iface) {
        cout << "Start probing..." << endl;
        vector<DeviceInfo> devices;
        char errbuff[PCAP_ERRBUF_SIZE];
        pcap_if_t *all_devs;
        pcap_if_t *device;

        // Find all devices
        if (pcap_findalldevs(&all_devs, errbuff) != 0) {
            throw std::runtime_error("Error finding devices: " + string(errbuff));
        }

        device = all_devs;
        if (!device) {
            return devices;
        }

        pcap_t *handle = pcap_open_live(device->name, BUFSIZ, 1, 1000, errbuff);
        if (!handle) {
            throw std::runtime_error("Could not open device " + string(device->name) + ": " + string(errbuff));
        }

        string subnet = GetSubnet(), source_ip = GetSourceIP();
        vector<string> subnet_split = pcapturepp::SplitByDelimiter(subnet);

        const int num_threads = 4;  // Number of threads to divide the IP space for ARP requests
        const int ip_range_per_thread = 254 / num_threads;

        // A lambda function for each thread to send ARP requests
        auto send_arp_requests = [&](int start_ip, int end_ip) {
            int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
            if (sock < 0) {
                perror("socket");
                return;
            }
            for (int i = start_ip; i <= end_ip; ++i) {
                string target_ip = subnet_split[0] + "." + subnet_split[1] + "." + subnet_split[2] + "." + std::to_string(i);
                try {
                    SendArpRequest(sock, iface, source_ip, target_ip);
                    std::lock_guard<std::mutex> lock(console_mutex);
                    cout << "[SEND] Sending ARP packet to " << target_ip << endl;
                    std::this_thread::sleep_for(std::chrono::milliseconds(1500)); 
                } catch (const std::exception& e) {
                    // Handle error
                    cout << "Error while sending ARP packet: " << e.what() << endl;
                }
            }
            close(sock);
        };

        // Launch threads for ARP requests
        vector<std::thread> threads;
        for (int i = 0; i < num_threads; ++i) {
            int start_ip = (i * ip_range_per_thread) + 1;
            int end_ip = (i == num_threads - 1) ? 254 : start_ip + ip_range_per_thread - 1;
            threads.emplace_back(send_arp_requests, start_ip, end_ip);
        }

        // Join threads
        for (auto& t : threads) {
            if (t.joinable()) {
                t.join();
            }
        }

        // Capture ARP responses
        struct pcap_pkthdr *header;
        const u_char *packet_data;

        // Maximum number of packets to capture
        const int max_packets = 100;  // Adjust this value for better results
        int packet_count = 0;

        // Track IPs for which you have received replies
        std::unordered_set<string> received_ips;

        while (packet_count < max_packets && received_ips.size() < 254) {
            int res = pcap_next_ex(handle, &header, &packet_data);
            if (res == 0) continue; // Timeout without a packet
            if (res == -1 || res == -2) {
                break;  // Error or end of packets
            }

            packet_count++;

            const struct ether_header *eth_header = (struct ether_header*) packet_data;
            if (ntohs(eth_header->ether_type) != ETHERTYPE_ARP) continue;

            const struct ether_arp *arp_response = (struct ether_arp*) (packet_data + sizeof(struct ether_header));
            if (ntohs(arp_response->arp_op) != ARPOP_REPLY) continue;

            char ip_ch[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, arp_response->arp_spa, ip_ch, INET_ADDRSTRLEN);
            string ip_str(ip_ch);

            // Check if we have already received a response from this IP
            if (received_ips.find(ip_str) == received_ips.end()) {
                DeviceInfo device_info;
                device_info.ip = ip_str;
                device_info.hostname = GetHostname(ip_str);
                device_info.is_own = false;
                if (ip_str == "192.168.15.6") device_info.is_own = true;
                for (UINT i = 0; i < MAC_ADDRESS_SIZE; i++) {
                    device_info.mac[i] = arp_response->arp_sha[i];
                }

                devices.push_back(device_info);
                received_ips.insert(ip_str);
            }

        }

        pcap_close(handle);
        pcap_freealldevs(all_devs);

        return devices;
    }
}
}
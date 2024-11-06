#ifndef PCAPTURECPP_ARPSPOOFING_HPP
#define PCAPTURECPP_ARPSPOOFING_HPP

#include "Includes.hpp"
#include "Structures.hpp"
#include "Async.hpp"
#include "Utils.hpp"
#include <pcap.h>            // pcap functions
#include <netinet/if_ether.h> // Ethernet header
#include <netinet/ip.h>       // IP header
#include <netinet/tcp.h>      // TCP header
#include <netinet/udp.h>      // UDP header
#include <arpa/inet.h>        // IP address conversion functions
#include <net/if.h>           // Network interfaces
#include <sys/ioctl.h>        // ioctl calls for interface manipulation
#include <sys/socket.h>       // Socket definitions
#include <unistd.h>  
#include <thread>
#include <netdb.h>
#include <ifaddrs.h>

namespace pcapturepp {
namespace modules {
    using pcapturepp::structures::requests::CliRequest;
    using pcapturepp::structures::responses::ModuleResponse;
    template <typename T>
    using Asynq = pcapturepp::AsyncQueue<T>;
    using namespace pcapturepp::structures;

    constexpr int FETCH_ARP_TABLE_ERROR = 0x0000;
    constexpr int FETCH_ARP_TABLE_SUCCESS = 0x0001;
    constexpr int FETCH_ARP_TABLE_UNKNOWN = 0x0002;

    struct ArpHeader {
        UINT16 hardware;
        UINT16 protocol;
        UINT8 hardware_address_len;
        UINT8 protocol_address_len;
        UINT16 operation;
        array<UINT8, MAC_ADDRESS_SIZE> source_hardware_address;
        array<UINT8, IPV4_SIZE> source_protocol_address;
        array<UINT8, MAC_ADDRESS_SIZE> target_hardware_address;
        array<UINT8, IPV4_SIZE> target_protocol_address;
    };

    struct SpooferParameters {
        std::string net_interface;
        array<UINT8, IPV4_SIZE> target_ip;
        array<UINT8, IPV4_SIZE> source_ip;
        array<UINT8, IPV4_SIZE> spoofing_ip;
        array<UINT8, MAC_ADDRESS_SIZE> target_mac;
        array<UINT8, MAC_ADDRESS_SIZE> source_mac;
        array<UINT8, MAC_ADDRESS_SIZE> spoofing_mac;
        array<UINT8, 64> ethernet_frame;

        SpooferParameters() = default;
        SpooferParameters(const std::string& nifc,
                         const array<UINT8, IPV4_SIZE>& tgt_ip,
                         const array<UINT8, IPV4_SIZE>& src_ip,
                         const array<UINT8, IPV4_SIZE>& spf_ip,
                         const array<UINT8, MAC_ADDRESS_SIZE>& tgt_mac,
                         const array<UINT8, MAC_ADDRESS_SIZE>& src_mac,
                         const array<UINT8, MAC_ADDRESS_SIZE>& spf_mac,
                         const array<UINT8, 64>& eth_fra)
            : net_interface(nifc),
              target_ip(tgt_ip),
              source_ip(src_ip),
              spoofing_ip(spf_ip),
              target_mac(tgt_mac),
              source_mac(src_mac),
              spoofing_mac(spf_mac),
              ethernet_frame(eth_fra) {}
    };

    class ArpSpoofer {
    public:
        explicit ArpSpoofer()
            : _opt(-1) {}

        int FetchARPTable(const std::string& tgt_ip, array<UINT8, MAC_ADDRESS_SIZE>& tgt_mac);
        int GetInterfaceInfo(const std::string& iface, array<UINT8, IPV4_SIZE>& local_ip, array<UINT8, MAC_ADDRESS_SIZE>& local_mac);
        void Spoof();
        void HandleCliRequest(const CliRequest& request); // New method to handle CliRequest and respond with ModuleResponse
        std::optional<ModuleResponse> ResponseStreamer();

    private:
        SpooferParameters _spoof_params;
        int _opt;
        bool _configured = false;
        bool _run = false;

        Asynq<ModuleResponse> _response_queue;
        std::mutex _response_queue_mtx;

        void BuildArpPacket(array<UINT8, 64>& packet, const SpooferParameters& params);
        void SendSpoofedPacket(pcap_t* handle, const array<UINT8, 64>& packet);
        void CapturePackets(pcap_t* handle);

    };

} // namespace arp
} // namespace pcapturecpp

#endif // PCAPTURECPP_ARPSPOOFING_HPP

#ifndef PCAPTUREPP_STRUCTURES_HPP
#define PCAPTUREPP_STRUCTURES_HPP

#include "Includes.hpp"

namespace pcapturepp {
namespace structures {

    struct EnumClassHash {
        template <typename T>
        std::size_t operator()(T t) const {
            return static_cast<std::size_t>(t);
        }
    };

    enum class CliPrintTypes {
        ERROR,
        INPUT,
        GENERAL,
        NONE,
    };

    enum class Actions {
        START,
        STOP,
        NONE,
    };

    enum class ResponseType {
        STATUS_UPDATE,
        PACKET_PROCESSED,
        ERROR,
        MOCK,
    };

    enum class SendTo {
        ARP,
        DNS,
        HTTPS,
        CLI
    };

    struct DeviceInfo {
        string ip;
        string hostname;
        array<UINT8, MAC_ADDRESS_SIZE> mac;
        bool is_own;
        bool online;

        DeviceInfo() : ip("0.0.0.0"), hostname("unknown"), is_own(false), online(false) {}
    };

    struct ThreadInput {
        string message;

        ThreadInput() : message("") {}
        ThreadInput(string msg) : message(msg) {}
    };

    struct CliPrintMessage {
        CliPrintTypes print_type;
        string message;

        CliPrintMessage() : print_type(CliPrintTypes::NONE), message("") {}
        CliPrintMessage(CliPrintTypes pt, string message) : print_type(pt), message(message) {}

        void Reset() {
            print_type = CliPrintTypes::INPUT;
            message = "";
        }
    };

    namespace network {
        struct NetworkProbeInfo {
            string source_ip;
            umap<UINT, string> devices_names;
            umap<UINT, std::pair<string, string>> devices;
        };

        struct HttpRequest {
            string method;                      // HTTP method (e.g., GET, POST)
            string url;                         // Full URL of the request
            std::unordered_map<string, string> headers; // HTTP headers as key-value pairs
            string body;                        // The request body (for POST, PUT, etc.)

            HttpRequest()
                : method(""), url("") {}
            
            HttpRequest(const string& method, const string& url)
                : method(method), url(url) {}

            // Utility to add a header
            void addHeader(const string& key, const string& value) {
                headers[key] = value;
            }

            // Utility to format the request as a string for easy viewing or logging
            string ToString() const {
                std::stringstream ss;
                ss << method << " " << url << " HTTP/1.1\n";
                for (const auto& header : headers) {
                    ss << header.first << ": " << header.second << "\n";
                }
                ss << "\n" << body;
                return ss.str();
            }
        };

        struct Packet {
            string source_ip;
            string destination_ip;
            std::vector<uint8_t> payload;  // Raw packet data

            Packet() : source_ip(""), destination_ip("") {}
            Packet(const std::string& src_ip, const std::string& dest_ip, const std::vector<uint8_t>& data)
                : source_ip(src_ip), destination_ip(dest_ip), payload(data) {}

            // Utility function to get packet data as a string for display
            string ToString() const {
                std::stringstream ss;
                ss << "Source IP: " << source_ip << ", Destination IP: " << destination_ip << ", Payload size: " << payload.size() << " bytes";
                return ss.str();
            }
        };

    }

    namespace requests {
        namespace cli {
            struct IConfig {
                string name;
                virtual ~IConfig() = default;

                IConfig() : name("") {}
                IConfig(string name) : name(name) {}
            };

            struct ArpConfig : public IConfig {
                string target_ip;
                string source_ip;
                string gateway_ip;
                string iface;
                array<UINT8, MAC_ADDRESS_SIZE> gateway_mac;
                array<UINT8, MAC_ADDRESS_SIZE> target_mac;
                array<UINT8, MAC_ADDRESS_SIZE> source_mac;
                bool fullduplex = false;

                ArpConfig() : IConfig("arp") {}
            };

            struct ArpNetProbe : public IConfig {
                string iface;

                ArpNetProbe() : IConfig("net") {}
            };

            struct DnsConfig : public IConfig {
                string address;
                uset<string> spoofed_domains;
                UINT ttl = 3600;

                DnsConfig() : IConfig("dns") {}
            };

            struct HttpsConfig : public IConfig {
                string cert_filename;
                string key_filename;
                string cacert_path;
                string cakey_path;
                string output_path;
                UINT cert_ttl = 3600;
                UINT validity_in_days = 365;

                HttpsConfig() : IConfig("https") {}
            };

            struct BundledConfig {
                ArpConfig *arp_config;
                ArpNetProbe *arp_probe;
                DnsConfig *dns_config;
                HttpsConfig *tls_config;

                BundledConfig(ArpConfig *arp = nullptr, ArpNetProbe *probe = nullptr, DnsConfig *dns = nullptr, HttpsConfig *tls = nullptr)
                    : arp_config(arp), arp_probe(probe), dns_config(dns), tls_config(tls) {}
            };
        }

        struct CliRequest {
            SendTo recipient;
            string message;
            Actions action;
            cli::BundledConfig configs;
            std::chrono::time_point<std::chrono::steady_clock> timestamp;

            CliRequest()
                : configs(cli::BundledConfig()), recipient(SendTo::ARP), message(""), action(Actions::NONE), timestamp(std::chrono::steady_clock::now()) {}

            // Constructor that accepts parameters for BundledConfig as well
            CliRequest(cli::BundledConfig bc, SendTo rec, string msg, Actions act)
                : configs(bc), recipient(rec), message(msg), action(act), timestamp(std::chrono::steady_clock::now()) {}
        };
    }

    namespace responses {
        struct ArpResponse {
            string target_ip;
            string source_ip;
            network::Packet packet;
            network::NetworkProbeInfo *netprobe;

            ArpResponse() : target_ip(""), source_ip(""), packet(network::Packet()), netprobe(nullptr) {}
            ArpResponse(const std::string& target_ip, const std::string& source_ip, const network::Packet& packet)
                :  target_ip(target_ip), source_ip(source_ip), packet(packet), netprobe(nullptr) {}
        };

        struct DnsResponse {
            bool landed;

            DnsResponse(bool landed) : landed(landed) {}
        };

        struct TlsResponse {
            string cert_path;
            network::HttpRequest decrypted_request;

            TlsResponse(ResponseType type, const std::string& message, bool success, const std::string& cert_path, const network::HttpRequest& request)
                : cert_path(cert_path), decrypted_request(request) {}
        };

        struct BundledResponse {
            ArpResponse *arp_response;
            DnsResponse *dns_response;
            TlsResponse *tls_response;

            BundledResponse()
                : arp_response(nullptr), dns_response(nullptr), tls_response(nullptr) {}

            BundledResponse(ArpResponse *arp, DnsResponse *dns, TlsResponse *tls)
                : arp_response(arp), dns_response(dns), tls_response(tls) {}
        };

        struct ModuleResponse : public BundledResponse {
            ResponseType type;
            humap<ResponseType, std::pair<SendTo, SendTo>, EnumClassHash> recipients;
            std::string message;
            bool success;
            std::chrono::time_point<std::chrono::steady_clock> timestamp;

            // Constructor that initializes both BundledResponse and ModuleToControllerResponse members
            ModuleResponse()
                : BundledResponse(),
                type(ResponseType::MOCK),
                message(""),
                success(true),
                timestamp(std::chrono::steady_clock::now()) {}

            ModuleResponse(ResponseType type, humap<ResponseType, std::pair<SendTo, SendTo>, EnumClassHash> rec, const std::string& message, bool success,
                                    ArpResponse* arp, DnsResponse* dns, TlsResponse* tls)
                : BundledResponse(arp, dns, tls),  // Initialize base class
                type(type),
                message(message),
                success(success),
                timestamp(std::chrono::steady_clock::now()) {
                    recipients = rec;
                }
        };

    }

}
}

#endif // PCAPTURE_STRUCTURES_HPP
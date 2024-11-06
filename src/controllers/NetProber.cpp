#include "NetProber.hpp"
#include "ArpPing.hpp"

using namespace arping;

namespace pcapturepp {
namespace netprober {

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


    bool GetLocalMacAddress(const std::string& iface, array<UINT8, MAC_ADDRESS_SIZE>& mac) {
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

        // Copy MAC address to std::array
        std::memcpy(mac.data(), ifr.ifr_hwaddr.sa_data, MAC_ADDRESS_SIZE);
        close(fd);
        return true;
    }

    std::mutex console_mutex;

    vector<DeviceInfo> GetAllConnectedDevices(const string& iface, int quiet) {
        vector<DeviceInfo> devices;

        string subnet = GetSubnet(), source_ip = GetSourceIP();
        vector<string> subnet_split = pcapturepp::SplitByDelimiter(subnet);
        uset<string> found_devices;

        DeviceInfo my_dev;
        my_dev.hostname = GetHostname(source_ip);
        my_dev.online = true;
        if (!GetLocalMacAddress(iface, my_dev.mac)) {
            my_dev.mac.fill(0);
        }
        my_dev.ip = source_ip;
        my_dev.is_own = true;
        devices.push_back(my_dev);
        found_devices.insert(source_ip);

        const int num_threads = 6;  // Number of threads to divide the IP space for ARP requests
        const int ip_range_per_thread = 254 / num_threads;

        // A lambda function for each thread to send ARP requests
        auto send_arp_requests = [&](int start_ip, int end_ip) {
            for (int i = start_ip; i <= end_ip; ++i) {
                string target_ip = subnet_split[0] + "." + subnet_split[1] + "." + subnet_split[2] + "." + std::to_string(i);
                DeviceInfo dev;
                try {
                    std::lock_guard<std::mutex> lock(console_mutex);
                    dev = Arping(iface, source_ip, target_ip, quiet);
                    if (dev.online && found_devices.find(target_ip) == found_devices.end()) {
                        found_devices.insert(target_ip);
                        dev.hostname = GetHostname(target_ip);
                        devices.push_back(dev);
                    }
                    //std::this_thread::sleep_for(std::chrono::milliseconds(10));
                } catch (const std::exception& e) {
                    cout << "Error while sending ARP packet: " << e.what() << endl;
                }
            }
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

        return devices;
    }
}
}
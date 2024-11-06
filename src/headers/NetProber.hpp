#ifndef PCAPTUREPP_NETPROBER_HPP
#define PCAPTUREPP_NETPROBER_HPP

#define INCLUDE_NETWORK
#include "Includes.hpp"
#include "Utils.hpp"
#include "Structures.hpp"
#include <chrono>
#include <linux/if_packet.h>

using pcapturepp::structures::DeviceInfo;

namespace pcapturepp {
namespace netprober {

    bool GetLocalMacAddress(const string& iface, UINT8 *mac);

    void SendArpRequest(pcap_t *handle, const string& iface, const string& source_ip, const string& target_ip);

    string GetSubnet();

    string GetHostname(const string& ip);

    vector<DeviceInfo> GetAllConnectedDevices(const string& iface);

}
}

#endif // PCAPTUREPP_NETPROBER_HPP
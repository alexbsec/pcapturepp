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

    string GetSourceIP();

    string GetSubnet();

    string GetHostname(const string& ip);

    bool GetLocalMacAddress(const std::string& iface, array<UINT8, MAC_ADDRESS_SIZE>& mac);

    vector<DeviceInfo> GetAllConnectedDevices(const string& iface, int quiet = 1);

}
}

#endif // PCAPTUREPP_NETPROBER_HPP
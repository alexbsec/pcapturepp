// Colors
#define C_NONE "\033[m"
#define C_RED "\033[0;31m"
#define C_GREEN "\033[0;32m"
#define C_YELLOW "\033[0;33m"
#define VERSION "v.0.0.1"
#define CMD_ERROR "\033[0;31mError:\033[m command does not exist"
#define INVALID_TYPE_ERROR "\033[0;31mError:\033[m invalid value provided"
#define MISSING_ARGS_ERROR "\033[0;31mError:\033[m missing configuration parameters"
#define CMD_EXIT "See ya!"
#define MAX_CMD_HIST 10

#define MAC_ADDRESS_SIZE 6
#define IPV4_SIZE        4
#define ARP_TYPE         0x0806
#define ARP_REQUEST      1
#define ARP_REPLY        2
#define REV_REQUEST      3
#define REV_REPLY        4

#include <iostream>
#include <stdio.h>
#include <termios.h>
#include <unistd.h> 
#include <string>
#include <filesystem>

#include <vector>
#include <sstream>
#include <fstream>
#include <memory>
#include <stdexcept>
#include <algorithm>
#include <array>
#include <cstring>
#include <cstdio>
#include <unordered_map>
#include <unordered_set>
#include <deque>
#include <tuple>
#include <functional>
#include <iomanip>
#include <chrono> 
#include <ctime>
#include <optional>

typedef unsigned char UCHAR;
typedef unsigned int UINT;
typedef uint8_t UINT8;
typedef uint16_t UINT16;
typedef unsigned short USHORT;
typedef std::string string;

using std::cout;
using std::endl;
using std::cin;
using std::filesystem::path;
using std::array;

template <typename... Args>
using uset = std::unordered_set<Args...>;

template <typename... Args>
using tuple = std::tuple<Args...>;

template <typename... Args>
using vector = std::vector<Args...>;

template <typename... Args>
using deque = std::deque<Args...>;

template <typename... Args>
using uptr = std::unique_ptr<Args...>;

template <typename Key, typename Value>
using umap = std::unordered_map<Key, Value>;

template <typename Key, typename Value, typename Hash>
using humap = std::unordered_map<Key, Value, Hash>;


// Standard Libraries
#ifdef INCLUDE_UTILS
#include <string>
#endif

#ifdef INCLUDE_NETWORK
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
#endif

// Networking and Packet Handling
#ifdef INCLUDE_PCAP_SSL
#include <iostream>
#include <thread>
#include <chrono> 
#include <stdio.h>
#include <string>
#include <vector>
#include <sstream>
#include <fstream>
#include <memory>
#include <stdexcept>
#include <algorithm>
#include <array>
#include <cstring>
#include <sys/ioctl.h>
#include <pcap.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <linux/if_arp.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>             // for close()
#endif

// Google test
#ifndef UNIT_TEST
#include <gtest/gtest.h>
#endif
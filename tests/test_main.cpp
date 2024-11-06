// // #include <gtest/gtest.h>
// // #include <arpa/inet.h>
// // #include <linux/if_packet.h>
// // #include <net/if.h>
// // #include <sys/socket.h>
// // #include <unistd.h>
// // #include "IPUtils.hpp"
// // #include "ArpPing.hpp"

// // using namespace arping;

// // class SendPackTest : public ::testing::Test {
// // protected:
// //     struct arping::RunState ctl;

// //     void SetUp() override {
// //         memset(&ctl, 0, sizeof(ctl));
        
// //         // Initialize control structure similar to `event_loop`
// //         ctl.device.name = strdup("wlan0");  // Set your interface here
// //         ctl.count = 1;                      // Single ARP request
// //         ctl.interval = 1;
// //         ctl.quiet = 1;                      // Suppress output during test

// //         // Raw socket setup
// //         ctl.socketfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
// //         ASSERT_NE(ctl.socketfd, -1) << "Socket creation failed; root permissions may be required.";

// //         ctl.device.ifindex = if_nametoindex(ctl.device.name);
// //         ASSERT_NE(ctl.device.ifindex, 0) << "Interface not found: " << ctl.device.name;

// //         // Set source (gsrc) and destination (gdst) IP addresses
// //         inet_pton(AF_INET, "192.168.15.6", &ctl.gsrc);  // Replace with valid IP
// //         inet_pton(AF_INET, "192.168.15.1", &ctl.gdst);  // Replace with valid target IP

// //         // Set up `me` and `he` sockaddr_ll structs
// //         struct sockaddr_ll *me = (struct sockaddr_ll *)&ctl.me;
// //         me->sll_family = AF_PACKET;
// //         me->sll_ifindex = ctl.device.ifindex;
// //         me->sll_protocol = htons(ETH_P_ARP);

// //         // Bind socket to interface
// //         ASSERT_EQ(bind(ctl.socketfd, (struct sockaddr *)me, sizeof(ctl.me)), 0)
// //             << "Failed to bind socket to interface.";

// //         // Obtain hardware address (MAC) of the interface
// //         socklen_t len = sizeof(ctl.me);
// //         ASSERT_EQ(getsockname(ctl.socketfd, (struct sockaddr *)&ctl.me, &len), 0)
// //             << "Failed to get hardware address from socket.";
        
// //         // Setup for unicast by default
// //         struct sockaddr_ll *he = (struct sockaddr_ll *)&ctl.he;
// //         *he = *me;
// //         ctl.advert = 0; // ARP request mode
// //         ctl.unicasting = 1;  // Explicitly set unicasting to avoid broadcast counts
// //     }

// //     void TearDown() override {
// //         if (ctl.socketfd >= 0) {
// //             close(ctl.socketfd);
// //         }
// //         free(ctl.device.name);
// //     }
// // };

// // TEST_F(SendPackTest, SendArpRequestSuccessfully) {
// //     int result = send_pack(&ctl);

// //     // Validate that `send_pack` worked as expected
// //     EXPECT_GT(result, 0) << "send_pack failed to send ARP packet.";
// //     EXPECT_EQ(ctl.sent, 1) << "Expected exactly 1 ARP packet to be sent.";
// //     EXPECT_EQ(ctl.brd_sent, 0) << "Expected 0 broadcast packets for unicast ARP.";
// // }


// // #include <gtest/gtest.h>
// // #include <arpa/inet.h>
// // #include <linux/if_packet.h>
// // #include <net/if.h>
// // #include <sys/socket.h>
// // #include <unistd.h>
// // #include "IPUtils.hpp"
// // #include "ArpPing.hpp"

// // using namespace arping;

// // class SendPackBroadcastTest : public ::testing::Test {
// // protected:
// //     struct arping::RunState ctl = {
// //         .device = { .name = DEFAULT_DEVICE },
// //         .count = -1,
// //         .interval = 1,
// // #ifdef HAVE_LIBCAP
// //         .cap_raw = CAP_CLEAR,
// // #endif
// //         0
// //     };

// //     void SetUp() override {
// //         memset(&ctl, 0, sizeof(ctl));

// //         // Initialize ctl for broadcast
// //         ctl.device.name = strdup("wlan0");  // Replace with your interface name
// //         ctl.count = 1;                      // Send a single ARP packet
// //         ctl.interval = 1;
// //         ctl.quiet = 1;
// //         ctl.broadcast_only = 1;             // Enable broadcasting

// //         // Initialize raw socket
// //         ctl.socketfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
// //         ASSERT_NE(ctl.socketfd, -1) << "Socket creation failed; root permissions may be required.";

// //         // Set up the device
// //         ctl.device.ifindex = if_nametoindex(ctl.device.name);
// //         ASSERT_NE(ctl.device.ifindex, 0) << "Interface not found: " << ctl.device.name;

// //         // Set the source IP (gsrc) and destination IP (gdst)
// //         inet_pton(AF_INET, "192.168.15.6", &ctl.gsrc);  // Replace with a valid source IP
// //         inet_pton(AF_INET, "192.168.15.255", &ctl.gdst); // Broadcast IP for the subnet

// //         // Prepare the sockaddr structures
// //         struct sockaddr_ll *me = (struct sockaddr_ll *)&ctl.me;
// //         me->sll_family = AF_PACKET;
// //         me->sll_ifindex = ctl.device.ifindex;
// //         me->sll_protocol = htons(ETH_P_ARP);

// //         // Bind the socket to the specified interface
// //         ASSERT_EQ(bind(ctl.socketfd, (struct sockaddr *)me, sizeof(ctl.me)), 0)
// //             << "Failed to bind socket to interface.";

// //         // Get the interface hardware address (MAC)
// //         socklen_t len = sizeof(ctl.me);
// //         ASSERT_EQ(getsockname(ctl.socketfd, (struct sockaddr *)&ctl.me, &len), 0)
// //             << "Failed to get socket name for hardware address.";

// //         // Set hardware address length and target address
// //         struct sockaddr_ll *he = (struct sockaddr_ll *)&ctl.he;
// //         *he = *me;
// //         ctl.advert = 0;  // ARP request mode
// //     }

// //     void TearDown() override {
// //         if (ctl.socketfd >= 0) {
// //             close(ctl.socketfd);
// //         }
// //         free(ctl.device.name);
// //     }
// // };

// // TEST_F(SendPackBroadcastTest, SendBroadcastArpRequestSuccessfully) {
// //     // Call send_pack and expect it to succeed
// //     int result = send_pack(&ctl);
// //     EXPECT_GT(result, 0) << "send_pack failed to send ARP broadcast packet.";

// //     // Validate that send_pack incremented the broadcast count correctly
// //     EXPECT_EQ(ctl.sent, 1) << "Expected 1 ARP packet sent count.";
// //     EXPECT_EQ(ctl.brd_sent, 1) << "Expected 1 broadcast ARP packet sent count.";
// // }

// #include <gtest/gtest.h>
// #include <arpa/inet.h>
// #include <linux/if_packet.h>
// #include <net/if.h>
// #include <sys/socket.h>
// #include <unistd.h>
// #include "IPUtils.hpp"
// #include "ArpPing.hpp"
// #include <netinet/if_ether.h> 

// using namespace arping;

// class ArpRequestLoopTest : public ::testing::Test {
// protected:
//     struct arping::RunState ctl = {
//         .device = { .name = DEFAULT_DEVICE },
//         .count = 5,  // Send 5 ARP packets in total
//         .interval = 1,
// #ifdef HAVE_LIBCAP
//         .cap_raw = CAP_CLEAR,
// #endif
//         0
//     };

//     void SetUp() override {
//         memset(&ctl, 0, sizeof(ctl));

//         // Set interface and other necessary fields
//         ctl.device.name = strdup("wlan0");  // Use your specific interface here
//         ctl.quiet = 1;

//         // Initialize raw socket
//         ctl.socketfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
//         ASSERT_NE(ctl.socketfd, -1) << "Socket creation failed; root permissions may be required.";

//         // Set up the device
//         ctl.device.ifindex = if_nametoindex(ctl.device.name);
//         ASSERT_NE(ctl.device.ifindex, 0) << "Interface not found: " << ctl.device.name;

//         // Set the source IP (gsrc) and destination IP (gdst) range
//         inet_pton(AF_INET, "192.168.15.6", &ctl.gsrc);  // Replace with valid source IP
//         inet_pton(AF_INET, "192.168.15.255", &ctl.gdst); // Broadcast IP

//         // Prepare sockaddr structures
//         struct sockaddr_ll *me = (struct sockaddr_ll *)&ctl.me;
//         me->sll_family = AF_PACKET;
//         me->sll_ifindex = ctl.device.ifindex;
//         me->sll_protocol = htons(ETH_P_ARP);

//         // Bind the socket
//         ASSERT_EQ(bind(ctl.socketfd, (struct sockaddr *)me, sizeof(ctl.me)), 0)
//             << "Failed to bind socket to interface.";

//         // Set hardware address and broadcast mode
//         struct sockaddr_ll *he = (struct sockaddr_ll *)&ctl.he;
//         *he = *me;
//         ctl.advert = 0;  // ARP request mode
//         ctl.broadcast_only = 1;  // Enable broadcasting
//     }

//     void TearDown() override {
//         if (ctl.socketfd >= 0) {
//             close(ctl.socketfd);
//         }
//         free(ctl.device.name);
//     }
// };

// #include <iostream>
// #include <iomanip>
// #include <arpa/inet.h>


// TEST_F(ArpRequestLoopTest, ContinuousSendAndReceive) {
//     unsigned char packet[4096];
//     struct sockaddr_storage from = {0};
//     socklen_t addr_len = sizeof(from);

//     // Sending and receiving loop
//     for (int i = 0; i < ctl.count; ++i) {
//         int sent = send_pack(&ctl);
//         EXPECT_GT(sent, 0) << "Failed to send ARP packet.";

//         // Set timeout for response
//         struct timeval tv;
//         tv.tv_sec = 1;
//         tv.tv_usec = 0;
//         setsockopt(ctl.socketfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

//         ssize_t received = recvfrom(ctl.socketfd, packet, sizeof(packet), 0,
//                                     (struct sockaddr *)&from, &addr_len);
//         if (received > 0) {
//             int recv_result = recv_pack(&ctl, packet, received, (struct sockaddr_ll *)&from);
//             EXPECT_NE(recv_result, -1) << "Failed to process received ARP response.";

//             struct ether_arp *arp_resp = reinterpret_cast<struct ether_arp*>(packet);

//             // Convert the sender's IP address
//             char sender_ip[INET_ADDRSTRLEN];
//             inet_ntop(AF_INET, arp_resp->arp_spa, sender_ip, sizeof(sender_ip));

//             // Print the sender's MAC address and IP address
//             std::cout << "Received ARP response from IP: " << sender_ip
//                       << " MAC: ";
//             for (int j = 0; j < ETH_ALEN; ++j) {
//                 if (j != 0) std::cout << ":";
//                 std::cout << std::hex << std::setw(2) << std::setfill('0')
//                           << static_cast<int>(arp_resp->arp_sha[j]);
//             }
//             std::cout << std::dec << std::endl;
//             std::cout.flush();  // Ensure immediate output to console
//         } else {
//             std::cout << "No response received for ARP packet " << i + 1 << std::endl;
//             std::cout.flush();  // Ensure immediate output to console
//         }
//     }
//     EXPECT_EQ(ctl.received, ctl.count);
//     // Validate that the number of packets sent matches expectations
//     EXPECT_EQ(ctl.sent, ctl.count) << "Number of ARP packets sent does not match expected count.";
// }

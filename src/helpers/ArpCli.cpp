#include "Cli.hpp"

namespace pcapturepp {

    /******* ArpCli definitions *******/
    /* PUBLIC METHODS */

    ArpCli::ArpCli() : _tgt_ip("0.0.0.0"), _src_ip("0.0.0.0"), _gateway_ip("0.0.0.0"), _fullduplex(false), _running(false), _net_probed(false), _probing(false) {
        _command_list["config"] = {"src", "tgt", "fullduplex", "tgt_mac", "router" , "router_mac", "iface", "src_mac"};
        _command_list["net"] = {"probe"};
        _command_list["status"] = uset<string>();
        _command_list["back"] = uset<string>();
        _command_list["start"] = uset<string>();
        _command_list["stop"] = uset<string>();
        _command_list["status"] = uset<string>();
        _command_list["devices"] = uset<string>();
        _iface = "eth0";
    }

    string ArpCli::ProcessCommand(const vector<string>& args, string& module) {
        string res = "";

        if (!ValidateArgs(args, 2)) {
            res = CMD_ERROR;
            return res;
        }

        if (args[0] == "help") {
            res = ShowHelp(args);
            return res;
        }

        // Split the dotted commands
        vector<string> parsed_args = SplitByDelimiter(args[0]);

        auto it = _command_list.find(parsed_args[0]);
        if (it == _command_list.end()) {
            res = CMD_ERROR;
            return res;
        }

        UINT pargs_len = parsed_args.size();
        // Concatenate with the remaining args
        if (pargs_len >= 2) {
            // If multiple elements, append the remaining args to parsed_args.
            // Move the elements from args.begin() + 1 to args.end() to avoid copying.
            parsed_args.insert(
                parsed_args.end(),
                std::make_move_iterator(args.begin() + 1),
                std::make_move_iterator(args.end())
            );
            if (parsed_args[0] == "config") {
                res = Configure(parsed_args);
            } else if (parsed_args[0] == "net") {
                res = ProbeNet(parsed_args);
            }
            
            return res;
        }

        if (parsed_args[0] == "start") {
            res = StartArpSpoofing(args);
        }

        if (parsed_args[0] == "stop") {
            res = StopArpSpoofing();
        }

        if (parsed_args[0] == "status") {
            res = ShowStatus(args);
        }

        if (parsed_args[0] == "back") {
            module = "";
        }
        
        if (parsed_args[0] == "devices") {
            res = PrintDeviceList();
        }

        return res;
    }

    string ArpCli::Configure(const vector<string>& args) {
        string message = "";
        auto it = _command_list[args[0]].find(args[1]);
        if (!ValidateArgs(args, 3) || it == _command_list[args[0]].end()) {
            message = CMD_ERROR;
            return message;
        }

        if (args[1] == "src") {
            _src_ip = args[2];
        }

        if (args[1] == "tgt") {
            _tgt_ip = args[2];
        }

        if (args[1] == "router") {
            _gateway_ip = args[2];
        }

        if (args[1] == "iface") {
            _iface = args[2];
        }

        if (args[1] == "tgt_mac") {
            PopulateMACAddress(_tgt_mac, args[2]);
        }

        if (args[1] == "src_mac") {
            PopulateMACAddress(_src_mac, args[2]);
        }

        if (args[1] == "router_mac") {
            PopulateMACAddress(_gateway_mac, args[2]);
        }

        if (args[1] == "fullduplex") {
            try {
                _fullduplex = StringToBool(args[2]);
            } catch (const std::invalid_argument& e) {
                message = CMD_ERROR;
                return message;
            }
        }

        return message;
    }

    string ArpCli::ShowStatus(const vector<string>& args) {
        string message = "";
        if (!ValidateArgs(args, 1)) {
            message = CMD_ERROR;
            return message;
        }

        string duplex, run, probe;
        _fullduplex == true ? duplex = string(C_GREEN) + "set" + string(C_NONE) : duplex = string(C_YELLOW) + "unset" + string(C_NONE);
        if (_probing) {
            probe = string(C_YELLOW) + "probing" + string(C_NONE);
        } else {
            probe = "not probing";
        }

        if (_net_probed) {
            probe = string(C_GREEN) + "probed" + string(C_NONE);
        }

        UINT num_devs = _devices_found.size();

        // _probe_net == true ? probe = string(C_GREEN) + "yes" + string(C_NONE) : probe = string(C_YELLOW) + "no" + string(C_NONE);
        cout << "ARP General Status:\n"
             << "Source IP:          " << _src_ip << "\n"
             << "Source MAC:         " << PrintMACArray(_src_mac) << "\n"
             << "Target IP:          " << _tgt_ip << "\n"
             << "Target MAC:         " << PrintMACArray(_tgt_mac) << "\n"
             << "Gateway IP:         " << _gateway_ip << "\n"
             << "Gateway MAC:        " << PrintMACArray(_gateway_mac) << "\n"
             << "Interface:          " << _iface << "\n"
             << "Full Duplex:        " << duplex << "\n"
             << "Probe status:       " << probe << "\n";
        if (_net_probed) cout << "Devices online:     " << num_devs << "\n";
        cout << endl;
        return message;
    }

    string ArpCli::ShowHelp(const vector<string>& args) const {
        string message = "";
        if (!ValidateArgs(args, 2)) {
            message = CMD_ERROR;
            return message;
        }

        if (args.size() == 1) {
            PrintGeneralHelp("arp");
            return message;
        }

        string fcmd = args[1];
        auto it = _command_list.find(fcmd);
        if (it == _command_list.end()) {
            message = CMD_ERROR;
            return message;
        }

        if (fcmd == "config") {
            cout << "ARP Configuration Help:\n"
                 << "   config.src          <source ip>   - Configure source IP address\n"
                 << "   config.tgt          <target ip>   - Configure target IP address to spoof\n"
                 << "   config.router       <router ip>   - Configure router IP address to spoof\n"
                 << "   config.fullduplex   <bool>        - Enable fullduplex mode (Default is false)\n"
                 << "   config.iface        <interface>   - Configure internet interface to listen on\n"
                 << "   config.tgt_mac      <target mac>  - Configure target MAC address\n"
                 << "   config.router_mac   <router_mac>  - Configure router MAC address\n"
                 << "   config.src_mac      <source_mac>  - Configure attacker MAC address\n"
                 << endl;
        }

        if (fcmd == "net") {
            cout << "ARP Internet Probing Help:\n"
                 << "   net.probe                       - Start internet probing (interface must be set)\n"
                 << endl;
        }

        if (fcmd == "start") {
            cout << "ARP Start Help:\n"
                 << "   start                        - Set the ARP spoofing module online\n"
                 << endl;
        }

        if (fcmd == "stop") {
            cout << "ARP Stop Help:\n"
                 << "   stop                         - Set the ARP spoofing module offline\n"
                 << endl;
        }

        if (fcmd == "back") {
            cout << "ARP Back Help:\n"
                 << "   back                         - Back to main program\n"
                 << endl;
        }

        if (fcmd == "status") {
            cout << "ARP Status Help:\n"
                 << "   status                       - Show the general status of ARP module\n"
                 << endl;
        }

        return message;
    }

    bool ArpCli::CheckStatus() const {
        return _running;
    }

    uptr<cli::IConfig> ArpCli::GetConfig() const {
        uptr<cli::ArpConfig> config = std::make_unique<cli::ArpConfig>();
        config->fullduplex = _fullduplex;
        config->gateway_ip = _gateway_ip;
        config->gateway_mac = _gateway_mac;
        config->iface = _iface;
        config->source_ip = _src_ip;
        config->target_ip = _tgt_ip;
        config->target_mac = _tgt_mac;
        config->source_mac = _src_mac;
        return config;
    }

    string ArpCli::PrintDeviceList() const {
        std::stringstream output;
        if (_devices_found.empty()) return "";
        for (const auto& dev : _devices_found) {
            output << endl << C_NONE << "------------------------- DEVICE FOUND -----------------------------\n"
                   << "ID:                          " << "[" << dev.first << "]\n"
                   << "Hostname:                    " << dev.second.hostname << "\n"
                   << "IP:                          " << dev.second.ip << "\n"
                   << "MAC:                         " << PrintMACArray(dev.second.mac) << "\n"
                   << endl;
        }
        output << "------------------------- END DEVICE LIST --------------------------\n";

        return output.str();
    }

    /* PRIVATE METHODS */
    string ArpCli::StartArpSpoofing(const vector<string>& args) {
        // Start arp spoofing
        string message = "";
        message = string(C_GREEN) + "Starting ARP Spoofing" + string(C_NONE);
        _running = true;
        return message;
    }

    string ArpCli::StopArpSpoofing() {
        // Stop arp spoofing
        string message = "";
        message = string(C_GREEN) + "Stopping ARP Spoofing" + string(C_NONE);
        _running = false;
        return message;
    }


    string ArpCli::ProbeNet(const vector<string>& args, bool callback) {
        std::stringstream message;

        // Launch a new thread for the network probing
        if (!callback) {

            auto it = _command_list[args[0]].find(args[1]);
            if (!ValidateArgs(args, 2) || it == _command_list[args[0]].end()) {
                message << CMD_ERROR;
                return message.str();
            }
            message << endl << C_GREEN << "Starting to probe, please wait..." << C_NONE;
            _probing = true;
            std::thread([this]() {
                vector<DeviceInfo> devices;
                try {
                    devices = GetAllConnectedDevices(_iface);
                    UINT idx = 1;
                    for (const DeviceInfo& dev : devices) {
                        string d_id = "D";
                        d_id += std::to_string(idx);
                        _devices_found[d_id] = dev;
                        idx++;
                        if (dev.is_own) {
                            _src_ip = dev.ip;
                            _src_mac = dev.mac;
                        }
                    }
                } catch (const std::runtime_error& e) {
                    return;
                }

                _probing = false;
                _net_probed = true;
                ProbeNet(vector<string>(), true);
            }).detach();
        } else {
            message << endl << C_GREEN "Probe finished successfully!" << C_NONE;
        }

        // Return immediately since the thread is detached
        return message.str();
    }

    void ArpCli::PopulateMACAddress(array<UINT8, MAC_ADDRESS_SIZE>& who, const string& mac_str) {
        std::fill(who.begin(), who.end(), 0);
        std::istringstream mac_stream(mac_str);
        string byte_str;
        std::size_t index = 0;
        
        // Split by :
        while (std::getline(mac_stream, byte_str, ':') && index < MAC_ADDRESS_SIZE) {
            who[index++] = static_cast<UINT8>(stoi(byte_str, nullptr, 16));
        }
    }
}
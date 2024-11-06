#include "Cli.hpp"

namespace pcapturepp {

    /******* DnsCli definitions *******/
    /* PUBLIC METHODS */

    DnsCli::DnsCli() : _address("0.0.0.0"), _spoofed_domains(uset<string>()), _ttl(1024), _running(false) {
        _command_list["config"] = {"address", "domains", "ttl"};
        _command_list["back"] = uset<string>();
        _command_list["start"] = uset<string>();
        _command_list["stop"] = uset<string>();
        _command_list["status"] = uset<string>();
    }

    string DnsCli::ProcessCommand(const vector<string>& args, string& module) {
        string message = "";
        if (!ValidateArgs(args, 2)) {
            message = CMD_ERROR;
            return message;
        }

        if (args[0] == "help") {
            message = ShowHelp(args);
            return message;
        }

        // Split the dotted commands
        vector<string> parsed_args = SplitByDelimiter(args[0]);

        auto it = _command_list.find(parsed_args[0]);
        if (it == _command_list.end()) {
            message = CMD_ERROR;
            return message;
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
            message = Configure(parsed_args);
            return message;
        }

        if (parsed_args[0] == "start") {
            message = StartDnsSpoofing(args);
        }

        if (parsed_args[0] == "stop") {
            message = StopDnsSpoofing();
        }

        if (parsed_args[0] == "status") {
            message = ShowStatus(args);
        }

        if (parsed_args[0] == "back") {
            module = "";
        }

        return message;
    }

    string DnsCli::Configure(const vector<string>& args) {
        string message = "";
        auto it = _command_list[args[0]].find(args[1]);
        if (!ValidateArgs(args, 3) || it == _command_list[args[0]].end()) {
            message = CMD_ERROR;
            return message;
        }

        if (args[1] == "address") {
            _address = args[2];
        }

        if (args[1] == "domains") {
            vector<string> domains = SplitByDelimiter(args[2], ',');
            for (const string& d : domains) {
                _spoofed_domains.insert(d);
            }
        }

        if (args[1] == "ttl") {
            try {
                _ttl = std::stoi(args[2]);
            } catch (const std::invalid_argument& e) {
                message = INVALID_TYPE_ERROR;
            } 
        }

        return message;
    }

    string DnsCli::ShowStatus(const vector<string>& args) {
        string message = "";
        if (!ValidateArgs(args, 1)) {
            message = CMD_ERROR;
            return message;
        }

        string run;
        _running == true ? run = string(C_GREEN) + "true" + string(C_NONE) : run = string(C_RED) + "false" + string(C_NONE); 

        string formatted_domains = FormatSetIntoList(_spoofed_domains);

        cout << "ARP General Status:\n"
             << "Redirect Address:          " << _address << "\n"
             << "Spoofed domains:           " << formatted_domains << "\n"
             << "TTL                        " << _ttl << "\n"
             << "Running:                   " << run << "\n"
             << endl;

        return message;
    }

    string DnsCli::ShowHelp(const vector<string>& args) const {
        string message = "";
        if (!ValidateArgs(args, 2)) {
            message = CMD_ERROR;
            return message;
        }

        if (args.size() == 1) {
            PrintGeneralHelp("dns");
            return message;
        }

        string fcmd = args[1];
        auto it = _command_list.find(fcmd);
        if (it == _command_list.end()) {
            message = CMD_ERROR;
            return message;
        }

        if (fcmd == "config") {
            cout << "DNS Spoofing Configuration:\n"
                << "    config.address  <ip>                     - Set the IP address for redirection\n"
                << "    config.domains  <domain1,domain2,...>    - Specify domains to redirect\n"
                << "    config.ttl      <uint>                   - Set TTL for responses (default: 1024)\n"
                << endl;
        }

        if (fcmd == "start") {
            cout << "DNS Start Help:\n"
                 << "   start                        - Set the DNS spoofing module online\n"
                 << endl;
        }

        if (fcmd == "stop") {
            cout << "DNS Stop Help:\n"
                 << "   stop                         - Set the DNS spoofing module offline\n"
                 << endl;
        }

        if (fcmd == "back") {
            cout << "DNS Back Help:\n"
                 << "   back                         - Back to main program\n"
                 << endl;
        }

        if (fcmd == "status") {
            cout << "DNS Status Help:\n"
                 << "   status                       - Show the general status of DNS module\n"
                 << endl;
        }

        return message;
    }

    bool DnsCli::CheckStatus() const  {
        return _running;
    }

    /* PRIVATE METHODS */

    string DnsCli::StartDnsSpoofing(const vector<string>& args) {
        string message = "";
        message = string(C_GREEN) + "Starting DNS Spoofing" + string(C_NONE);
        _running = true;
        return message;
    }

    string DnsCli::StopDnsSpoofing() {
        string message = "";
        message = string(C_GREEN) + "Stopping DNS Spoofing" + string(C_NONE);
        return message;
    }
 
}
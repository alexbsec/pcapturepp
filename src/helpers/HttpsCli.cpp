#include "Cli.hpp"

namespace pcapturepp {

    /******* HttpsCli definitions *******/
    /* PUBLIC METHODS */

    HttpsCli::HttpsCli() : _output_path(""), _cert_ttl(1024), _running(false), _cert_generated(false) {
        _command_list["config"] = {"cacert_path", "cakey_path", "ttl", "output"};
        _command_list["status"] = uset<string>();       // Show status of HTTPS module
        _command_list["back"] = uset<string>();         // Return to main interface
        _command_list["start"] = uset<string>();        // Start HTTPS interception
        _command_list["stop"] = uset<string>();         // Stop HTTPS interception
        _command_list["generate"] = {"cacert"};           // Generate a new certificate
        // _command_list["show"] = {"config"};             // Show current configuration settings
        // _command_list["reset"] = {"config"};            // Reset configuration to defaults

        path certs_path = utils::GetExecutablePath() / "cert";
        path output_path = utils::GetExecutablePath() / "out";
        _ca_cert_path = certs_path.string();
        _ca_key_path = certs_path.string();
        _output_path = output_path.string();
    }

    string HttpsCli::ProcessCommand(const vector<string>& args, string& module) {
        string message = "";

        if (!ValidateArgs(args, 2)) {
            message = CMD_ERROR;
            return message;
        }

        if (args[0] == "help") {
            message = ShowHelp(args);
            return message;
        }

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
            if (parsed_args[0] == "config") {
                message = Configure(parsed_args);
            } else if (parsed_args[0] == "generate") {
                message = GenerateCertificate(parsed_args);
            } else {
                message = CMD_ERROR;
            }
            
            return message;
        }

        if (parsed_args[0] == "start") {
            message = StartIntercept(args);
        }

        if (parsed_args[0] == "stop") {
            message = StopIntercept(args);
        }

        if (parsed_args[0] == "status") {
            message = ShowStatus(args);
        }

        if (parsed_args[0] == "back") {
            module = "";
        }

        return message;
    }

    string HttpsCli::Configure(const vector<string>& args) {
        string message = "";
        auto it = _command_list[args[0]].find(args[1]);
        if (!ValidateArgs(args, 3) || it == _command_list[args[0]].end()) {
            message = CMD_ERROR;
            return message;
        }

        if (args[1] == "cacert_path") {
            _ca_cert_path = args[2];
        }

        if (args[1] == "cakey_path") {
            _ca_key_path = args[2];
        }

        if (args[1] == "output") {
            _output_path = args[2];
        }

        if (args[1] == "ttl") {
            try {
                _cert_ttl = stoi(args[2]);
            } catch (const std::invalid_argument& e) {
                message = INVALID_TYPE_ERROR;
            }
        }

        return message;
    }

    string HttpsCli::ShowStatus(const vector<string>& args) {
        string message = "";
        if (!ValidateArgs(args, 1)) {
            message = CMD_ERROR;
            return message;
        }

        string run, gen;
        _running == true ? run = string(C_GREEN) + "true" + string(C_NONE) : run = string(C_RED) + "false" + string(C_NONE); 
        _cert_generated == true ? gen = string(C_GREEN) + "yes" + string(C_NONE) : gen = string(C_RED) + "no" + string(C_NONE);
        cout << "HTTPS General Status:\n"
             << "CA Certificate Path:           " << _ca_cert_path << "\n"
             << "CA Key Path:                   " << _ca_key_path << "\n"
             << "Captured Requests out:         " << _output_path << "\n"
             << "Is CA Cert generated:          " << gen << "\n"
             << "Certificate TTL:               " << _cert_ttl << "\n"
             << "Certificate validity:          " << _validity_in_days << " days\n"
             << "Running:                       " << run << "\n"
             << endl;
        return message;
    }

    string HttpsCli::ShowHelp(const vector<string>& args) const {
        string message = "";
        if (!ValidateArgs(args, 2)) {
            message = CMD_ERROR;
            return message;
        }

        if (args.size() == 1) {
            PrintGeneralHelp("tls");
            return message;
        }

        string fcmd = args[1];
        auto it = _command_list.find(fcmd);
        if (it == _command_list.end()) {
            message = CMD_ERROR;
            return message;
        }

        if (fcmd == "config") {
            cout << "HTTPS Configuration Help:\n"
                 << "   config.cacert_path  <path/to/ca_cert>         - Set the path to which CA certificate will be saved to\n"
                 << "   config.cakey_path   <path/to/ca_key>          - Set the path to which CA key will be saved to\n"
                 << "   config.ttl          <uint>                    - Set TTL for responses (default: 1024)\n"
                 << "   config.output       <path/to/output>          - Set the output path to which the decrypted requests are saved\n"
                 << endl;
        }

        if (fcmd == "start") {
            cout << "HTTPS Sniffing Start Help:\n"
                 << "   start                        - Set the HTTPs sniffing module online\n"
                 << endl;
        }

        if (fcmd == "stop") {
            cout << "HTTPS Sniffinf Stop Help:\n"
                 << "   stop                         - Set the HTTPS sniffing module offline\n"
                 << endl;
        }

        if (fcmd == "back") {
            cout << "HTTPS Back Help:\n"
                 << "   back                         - Back to main program\n"
                 << endl;
        }

        if (fcmd == "status") {
            cout << "HTTPS Status Help:\n"
                 << "   status                       - Show the general status of HTTPS module\n"
                 << endl;
        }

        if (fcmd == "generate") {
            cout << "HTTPS Generate CA Certificate Help:\n"
                 << "   generate.cacert  <validity>  - Generate CA certificate and key with validity in days (Default is 365 days)\n"
                 << "                                  OBS: cacert_path and cakey_path must be configured before running this command\n"
                 << endl;
        }

        return message;
    }

    bool HttpsCli::CheckStatus() const {
        return _running;
    }

    /* PRIVATE METHODS */

    string HttpsCli::GenerateCertificate(const vector<string>& args) {
        string message = "";
        auto it = _command_list[args[0]].find(args[1]);
        if (!ValidateArgs(args, 3) || it == _command_list[args[0]].end() || args[1] != "cacert") {
            message = CMD_ERROR;
            return message;
        }

        try {
            _validity_in_days = stoi(args[2]);
            if (_ca_cert_path.empty() || _ca_key_path.empty()) {
                message = MISSING_ARGS_ERROR;
                return message;
            }      

            message = utils::cacert::GenerateCACertificate(_ca_cert_path, _ca_key_path, _validity_in_days);
        } catch (const std::invalid_argument& e) {
            message = INVALID_TYPE_ERROR;
            return message;
        }

        _cert_generated = true;
        return message;
    }

    string HttpsCli::StartIntercept(const vector<string>& args) {
        string message = "";
        if (_cert_generated) {
            message = string(C_GREEN) +"Starting HTTPS interception" + string(C_NONE);
            _running = true;
            return message;
        } 

        message = string(C_RED) + "Error: " + string(C_NONE) + "Could not start HTTPS interception";
        return message;
    }

    string HttpsCli::StopIntercept(const vector<string>& args) {
        string message = "";
        if (_running) {
            message = string(C_GREEN) + "Stopping HTTP interception" + string(C_NONE);
            _running = false;
            return message;
        }

        return message;
    }
 
}
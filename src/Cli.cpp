#include "Cli.hpp"

namespace pcapturepp {
    /******* ArpCli Definitions *******/
    /* PUBLIC METHODS */
    void PrintGeneralHelp(string module) {
        if (module == "arp") {
            cout << "ARP Spoofing Module:\n"
                    << "  (arp) start      - Start ARP spoofing\n"
                    << "  (arp) stop       - Stop ARP spoofing\n"
                    << "  (arp) config     - Configure ARP settings\n"
                    << "  (arp) status     - Show status of ARP module\n"
                    << endl;
        } else if (module == "dns") {
            cout << "DNS Spoofing Module:\n"
                    << "  (dns) start      - Start DNS spoofing\n"
                    << "  (dns) stop       - Stop DNS spoofing\n"
                    << "  (dns) config     - Configure DNS settings\n"
                    << "  (dns) status     - Show status of DNS module\n"
                    << endl;
        } else if (module == "tls") {
            cout << "TLS Interception Module:\n"
                    << "  (tls) start      - Start TLS interception\n"
                    << "  (tls) stop       - Stop TLS interception\n"
                    << "  (tls) config     - Configure TLS settings\n"
                    << "  (tls) status     - Show status of TLS module\n"
                    << "  (tls) generate   - Generate new certificate\n"
                    << endl;
        } else {
            throw std::invalid_argument("Invalid module name: " + module);
        }
    }
    
    bool StringToBool(const string& str) {
        string lower = str;
        std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);

        if (lower == "true" || lower == "1") return true;
        if (lower == "false" || lower == "0") return false;

        throw std::invalid_argument("Invalid string for boolean conversion: " + str);
    }


    bool ValidateArgs(const vector<string>& args, UINT max_size) {
        UINT args_len = args.size();
        if (args_len > max_size) return false;
        return true;
    }

    string FormatSetIntoList(const uset<string>& set) {
        string result = "[";

        for (auto it = set.begin(); it != set.end(); ++it) {
            result += *it;
            if (std::next(it) != set.end()) {
                result += ", ";
            }
        }

        result += "]";
        return result;
    }

    /******* Cli definitions *******/
    /* PUBLIC METHODS */

    Cli::Cli() : _module_prefix(""), _history_index(-1), _running(false) {
        _modules[Modules::ARP] = std::make_unique<ArpCli>();
        _modules[Modules::DNS] = std::make_unique<DnsCli>();
        _modules[Modules::HTTPS] = std::make_unique<HttpsCli>();

        _module_status[Modules::ARP] = false;
        _module_status[Modules::DNS] = false;
        _module_status[Modules::HTTPS] = false;

        // Populate command list
        _command_list["arp"]  = {Modules::ARP};
        _command_list["dns"]  = {Modules::DNS};
        _command_list["tls"]  = {Modules::HTTPS};
        _command_list["run"]  = vector<Modules>();

        _controller = std::make_unique<controllers::MainController>();

        auto now = std::chrono::system_clock::now();
        _time = std::chrono::system_clock::to_time_t(now);
        localtime_r(&_time, &_time_buffer);
        _pm = new structures::CliPrintMessage();

    }

    void Cli::Start() {
        Hail();
        ProcessInput();
    }

    void Cli::ProcessInput() {
        char ch;
        _pm->print_type = structures::CliPrintTypes::INPUT;
        _pm->message = _input;
        PrintCli(_time_buffer, nullptr);
        while (true) {
            bool cmd_found = false;
            string message = "";
            UpdateTimeBuffer();
            ch = GetChar();  // Capture individual keystrokes
            if (ch == '\n') {  // Enter key
                cout << "\n";
                if (_input.empty()) {
                    PrintCli(_time_buffer, nullptr);
                    continue;
                }
                
                AddToHistory(_input); // Save input to history

                if (_input == "exit") {
                    _pm->message = CMD_EXIT;
                    _pm->print_type = structures::CliPrintTypes::GENERAL;
                    PrintCli(_time_buffer, nullptr);
                    exit(EXIT_SUCCESS);
                }

                vector<string> args = ParseCommand(_input);

                if (!_module_prefix.empty()) {
                    Modules module = StringToModule(_module_prefix);
                    message = _modules[module]->ProcessCommand(args, _module_prefix); 
                    UpdateTimeBuffer();
                    if (!message.empty()) {
                        _pm->message = message;
                        _pm->print_type = structures::CliPrintTypes::ERROR;
                        PrintCli(_time_buffer, nullptr);
                    }
                    _input.clear();
                    _pm->message = _input;
                    _pm->print_type = structures::CliPrintTypes::INPUT;
                    PrintCli(_time_buffer, nullptr);
                    continue;
                }

                if (args[0] == "help") {
                    ShowHelp(args);
                    cmd_found = true;
                } 
                
                if (args[0] == "status") {
                    ShowStatus();
                    cmd_found = true;
                } 

                auto it = _command_list.find(args[0]);
                if (it != _command_list.end()) {
                    if (args[0] != "run") {
                        _module_prefix = _input;
                        cmd_found = true;
                    } else if (args.size() == 2 && args[0] == "run") {
                        try {
                            Modules mod = StringToModule(args[1]);
                            Run(mod);
                            cmd_found = true;
                        } catch (const std::invalid_argument& e) {
                            cmd_found = false;
                        }
                    } else {
                        cmd_found = false;
                    }
                }

                if (!cmd_found) {
                    _pm->message = CMD_ERROR;
                    _pm->print_type = structures::CliPrintTypes::ERROR;
                    PrintCli(_time_buffer, nullptr);
                }
                
                _input.clear();  // Clear input for the next command
                // Print new prompt for the next command
                _pm->message = _input;
                _pm->print_type = structures::CliPrintTypes::INPUT;
                UpdateTimeBuffer();
                PrintCli(_time_buffer, nullptr);
            }
            else if (ch == 127 || ch == 8) {  // Backspace
                if (!_input.empty()) {
                    _input.pop_back();
                    _pm->message = _input;
                    std::cout << "\33[2K\r";  // Clear entire line
                    PrintCli(_time_buffer, nullptr);
                }
            }
            else if (ch == '\033') {  // Arrow key escape sequence
                GetChar();            // Skip the '[' character
                ch = GetChar();       // Get actual arrow key
                _pm->print_type = structures::CliPrintTypes::INPUT;
                if (ch == 'A') {  // Up arrow
                    _input = GetHistoryUp();
                    _pm->message = _input;
                }
                else if (ch == 'B') {  // Down arrow
                    _input = GetHistoryDown();
                    _pm->message = _input;
                }
                // Reprint prompt and current input after history navigation
                std::cout << "\33[2K\r";
                PrintCli(_time_buffer, nullptr);
            }
            else if (isprint(ch)) {  // Printable character
                _input += ch;
                _pm->message = _input;
                
                std::cout << "\33[2K\r"; 
                PrintCli(_time_buffer, nullptr);
            }

            std::cout.flush();
            _pm->print_type = structures::CliPrintTypes::INPUT;
        }
    }

    /* PRIVATE METHODS */
    
    // Command processing
    vector<string> Cli::ParseCommand(const string& input) {
        std::istringstream stream(input);
        string word;
        vector<string> args;

        while (stream >> word) {
            args.push_back(word);
        }

        return args;
    }

    // Command Handlers
    void Cli::Run(Modules module) {
        _controller->Start();
        _running = true;

        // Synchronization to ensure that _controller is fully initialized
        std::this_thread::sleep_for(std::chrono::milliseconds(100)); // small delay to ensure controller is ready (you may replace this with a more robust solution)

        switch (module) {
            case Modules::ARP: {
                // Use a joinable thread or at least ensure the controller has completed initialization
                std::thread([this, module] {
                    cli::ArpConfig* arpc = dynamic_cast<cli::ArpConfig*>(_modules[module]->GetConfig().get());
                    if (!arpc) {
                        std::cerr << "Failed to obtain valid ARP config." << std::endl;
                        return; // Early exit if dynamic_cast fails
                    }

                    BundledConfig configs(arpc, nullptr, nullptr, nullptr);
                    CliRequest request(configs, structures::SendTo::ARP, "", structures::Actions::START);
                    _controller->ProcessCliRequests(request);
                }).detach(); // Consider replacing with a joinable thread and storing it in a member variable
                break;
            }
        }

        // Thread to keep checking for responses
        std::thread([this]() {
            while (_running) {
                std::optional<ModuleResponse> response = _controller->RespondCliBack();
                if (response) {
                    UpdateTimeBuffer();
                    structures::ThreadInput *ti = new structures::ThreadInput(response->message);
                    PrintCli(_time_buffer, ti);
                }
                std::this_thread::sleep_for(std::chrono::milliseconds(500));
            }
        }).detach(); // Consider replacing with a joinable thread and storing it in a member variable
    }


    void Cli::Stop() {
        _running = false;
    }

    void Cli::StartArp(const vector<string>& args) {}

    void Cli::StopArp() {}

    void Cli::StartDns(const vector<string>& args) {}

    void Cli::StopDns() {}

    void Cli::StartHttps(const vector<string>& args) {}

    void Cli::StopHttps() {}

    void Cli::SetConfig(const vector<string>& args) {}

    void Cli::ShowStatus() {
        vector<Modules> modules_to_update;
        for (const auto& pair : _module_status) {
            modules_to_update.push_back(pair.first);
        }

        for (Modules module : modules_to_update) {
            // Temp if because this module is not built (prevent segmentation fault)
            bool bstatus = _modules[module]->CheckStatus();
            _module_status[module] = bstatus;
        }

        for (const auto pair : _module_status) {
            string status;
            string module_str = ModuleToString(pair.first);
            status = pair.second == true ? string(C_GREEN) + "running" + string(C_NONE) : string(C_RED) + "offline" + string(C_NONE);
            cout << "Current " << module_str << " status:\n"
                 << module_str << "     " << status << endl;
        }

        cout << endl;
    }

    void Cli::ShowHelp(const vector<string>& args) {
        UINT arg_size = args.size();
        if (arg_size > 2) {
            PrintCli(_time_buffer, CMD_ERROR);
            return;
        }

        if (arg_size == 1) {
            cout << "Available commands:\n"
                    << "  start          - Start capture\n"
                    << "  stop           - Stop capture\n"
                    << "  help  [module] - Show help for a specific module\n"
                    << "  status         - Show statuses of all modules\n"
                    << "\nModules:\n"
                    << "  arp            - ARP spoofing module\n"
                    << "  dns            - DNS spoofing module\n"
                    << "  tls            - TLS interception module\n"
                    << "\nExample usage:\n"
                    << "  help arp       - Show help for the ARP module\n"
                    << "  start tls      - Start the TLS interception\n"
                    << "  stop dns       - Stop the DNS spoofing\n"
                    << endl;
            return;
        }

        string module = args[1];
        try {
            PrintGeneralHelp(module);
        } catch (const std::invalid_argument& e) {
            // Unknown module
            PrintCli(_time_buffer, CMD_ERROR);
        }
    }

    // Utils

    void Cli::Hail() const {
        cout << "                        _                              "       << endl;
        cout << "                       | |                   _     _   "       << endl;
        cout << "  _ __   ___ __ _ _ __ | |_ _   _ _ __ ___ _| |_ _| |_ "       << endl;
        cout << " | '_ \\ / __/ _` | '_ \\| __| | | | '__/ _ \\_   _|_   _|"    << endl;
        cout << " | |_) | (_| (_| | |_) | |_| |_| | | |  __/ |_|   |_|  "       << endl;
        cout << " | .__/ \\___\\__,_| .__/ \\__|\\__,_|_|  \\___|            "  << endl;
        cout << " | |             | |                                   "       << endl;
        cout << " |_|             |_|                                   "       << endl;
        cout << endl;
        printf("%s\n", VERSION);
        cout << endl;
        cout << endl;
    }

    void Cli::PrintCli(std::tm buffer, string message, bool is_input, structures::ThreadInput *ti) {
    // If it's a message from the controller, print it above the prompt
        if (ti) {
            // Move cursor up, clear line, print message, and move cursor back down to prompt
            cout << endl;
            cout << "\33[1A" << "\33[2K\r";      // Move up one line and clear it
            cout << ti->message << endl;        // Print the controller message
            cout << "\33[1B\r";                  // Move cursor back down to the prompt
            cout.flush();
        } 

        if (!is_input) return;

        
        if (_module_prefix.empty()) {
            std::cout << C_YELLOW << "[" << std::put_time(&buffer, "%Y-%m-%d %H:%M:%S") << "]" << C_NONE << " >> " << message;
        } else {
            std::cout << C_YELLOW << "[" << std::put_time(&buffer, "%Y-%m-%d %H:%M:%S") << "]" << C_NONE << " (" << _module_prefix << ") >> " << message;
        }
        cout.flush();
    }

    void Cli::PrintCli(std::tm buffer, structures::ThreadInput *ti) {
    // If it's a message from the controller, print it above the prompt
        // string tmp_pm_msg = _pm->message;
        if (ti) {
            // Move cursor up, clear line, print message, and move cursor back down to prompt
            cout << endl;
            cout << "\33[1A" << "\33[2K\r";      // Move up one line and clear it
            cout << ti->message << endl;        // Print the controller message
            cout << "\33[1B\r";                  // Move cursor back down to the prompt
            // _pm->message = "";
        } 

        if (!_pm) {
            cout.flush();
            return;
        }

        std::stringstream ss_base, ss_mod, ss_gen;
        ss_base << "\33[2K\r" << C_YELLOW << "[" << std::put_time(&buffer, "%Y-%m-%d %H:%M:%S") << "]" << C_NONE << " >> ";
        ss_mod << "\33[2K\r" << C_YELLOW << "[" << std::put_time(&buffer, "%Y-%m-%d %H:%M:%S") << "]" << C_NONE << " (" << _module_prefix << ") >> ";
        switch (_pm->print_type) {
            case structures::CliPrintTypes::ERROR:
                ss_base << C_RED << _pm->message << C_NONE << endl;
                ss_mod << C_RED << _pm->message << C_NONE << endl;
                break;
            case structures::CliPrintTypes::GENERAL:
                ss_gen << "\33[2K\r" << _pm->message;
                break;
            case structures::CliPrintTypes::INPUT:
                ss_base << _pm->message;
                ss_mod << _pm->message;
                break;
            case structures::CliPrintTypes::NONE:
                break;
        }

        if (!ss_gen.str().empty()) {
            cout << ss_gen.str();
            cout.flush();
            return;
        }

        if (_module_prefix.empty()) {
            cout << ss_base.str();
        } else {
            cout << ss_mod.str();
        }

        // _pm->message = tmp_pm_msg;
    
        cout.flush();
    }


    // void Cli::PrintCli(std::tm buffer, string message, bool is_input) {
    //     if (!message.empty() && is_input) {
    //         if (_module_prefix.empty()) {
    //             cout << "\33[2K\r" << C_YELLOW << "[" << std::put_time(&buffer, "%Y-%m-%d %H:%M:%S") << "]" << C_NONE << " >> " << message;
    //         } else {
    //             cout << "\33[2K\r" << C_YELLOW << "[" << std::put_time(&buffer, "%Y-%m-%d %H:%M:%S") << "]" << C_NONE << " (" << _module_prefix << ") >> " << message;
    //         }
    //         std::cout.flush();
    //         return;
    //     }

    //     if (!message.empty()) {
    //         if (_module_prefix.empty()) {
    //             cout << "\33[2K\r" << C_YELLOW << "[" << std::put_time(&buffer, "%Y-%m-%d %H:%M:%S") << "]" << C_NONE << " >> " << message << endl;
    //         } else {
    //             cout << "\33[2K\r" << C_YELLOW << "[" << std::put_time(&buffer, "%Y-%m-%d %H:%M:%S") << "]" << C_NONE << " (" << _module_prefix << ") >> " << message << endl;
    //         }
    //         std::cout.flush();
    //         return;          
    //     }

    //     if (_module_prefix.empty()) {
    //         cout << "\33[2K\r" << C_YELLOW << "[" << std::put_time(&buffer, "%Y-%m-%d %H:%M:%S") << "]" << C_NONE << " >> ";
    //         cout.flush();
    //         return;
    //     }

    //     cout << "\33[2K\r" << C_YELLOW << "[" << std::put_time(&buffer, "%Y-%m-%d %H:%M:%S") << "]" << C_NONE << " (" << _module_prefix << ") >> ";
    //     std::cout.flush();
    // }

    void Cli::UpdateTimeBuffer() {
        auto now = std::chrono::system_clock::now();
        _time = std::chrono::system_clock::to_time_t(now);
        localtime_r(&_time, &_time_buffer);
    }

    string Cli::ModuleToString(const Modules& module) {
        string ret;
        switch (module) {
            case Modules::ARP:
                ret = "arp";
                break;
            case Modules::DNS:
                ret = "dns";
                break;
            case Modules::HTTPS:
                ret = "tls";
                break;
            default:
                ret = "";
                break;
        }

        return ret;
    }

    Modules Cli::StringToModule(const string& module_str) {
        if (module_str == "arp") {
            return Modules::ARP;
        } else if (module_str == "dns") {
            return Modules::DNS;
        } else if (module_str == "tls") {
            return Modules::HTTPS;
        } else {
            // Return a default value or handle the error
            throw std::invalid_argument("Unknown module string: " + module_str);
        }
    }

    void Cli::AddToHistory(const string& input) {
        if (input.empty()) return;

        if (!_command_history.empty() && _command_history.back() == input) {
            _history_index = -1;
            return;
        }

        if (_command_history.size() == MAX_CMD_HIST) {
            _command_history.pop_front();
        }

        _command_history.push_back(input);
        _history_index = -1;
    }

    string Cli::GetHistoryUp() {
        UINT hist_size = _command_history.size();
        if (_history_index + 1 < hist_size) {
            _history_index++;
            // cout << _command_history[hist_size - 1 - _history_index] << endl;
            return _command_history[hist_size - 1 - _history_index];
        }

        _history_index = -1;
        return "";
    }

    string Cli::GetHistoryDown() {
        if (_history_index > 0) {
            _history_index--;
            UINT hist_size = _command_history.size();
            return _command_history[hist_size - 1 - _history_index];
        }

        if (_history_index == 0) {
            _history_index = -1;
        }

        return "";
    }

    char Cli::GetChar() {
        struct termios oldt, newt;
        char ch;
        tcgetattr(STDIN_FILENO, &oldt);
        newt = oldt;
        newt.c_lflag &= ~(ICANON | ECHO);
        tcsetattr(STDIN_FILENO, TCSANOW, &newt);
        ch = getchar();
        tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
        return ch;
    }


}
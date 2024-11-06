#ifndef PCAPTUREPP_CLI_HPP
#define PCAPTUREPP_CLI_HPP

#include "Includes.hpp"
#include "Utils.hpp"
#include "Structures.hpp"
#include "Controllers.hpp"
#include "Async.hpp"
#include "NetProber.hpp"
#include <thread>

template <typename T>
using Asynq = pcapturepp::AsyncQueue<T>;

using pcapturepp::utils::PrintMACArray;
using namespace pcapturepp::structures::requests;
using namespace pcapturepp::structures::responses;
using namespace pcapturepp::structures::network;
using namespace pcapturepp::netprober;

namespace pcapturepp {
    enum class Modules {
        ARP,
        DNS,
        HTTPS,
    };

    void PrintGeneralHelp(string module);

    bool StringToBool(const string& str);
    
    bool ValidateArgs(const vector<string>& args, UINT max_size);

    string FormatSetIntoList(const uset<string>& set); 

    class ICli {
        public:
            virtual ~ICli() noexcept = default;

            // Process command specific to the module
            virtual string ProcessCommand(const vector<string>& args, string& module) = 0;
            
            // Configure specific settings for the module
            virtual string Configure(const vector<string>& args) = 0;

            // Display status of the module
            virtual string ShowStatus(const vector<string>& args) = 0;

            // Display help of the module
            virtual string ShowHelp(const vector<string>& args) const = 0;

            virtual bool CheckStatus() const = 0;

            virtual std::unique_ptr<cli::IConfig> GetConfig() const = 0;
    };

    class ArpCli : public ICli {
        public:
            ArpCli();

            string ProcessCommand(const vector<string>& args, string& module) override;

            string Configure(const vector<string>& args) override;

            string ShowStatus(const vector<string>& args) override;

            string ShowHelp(const vector<string>& args) const override;

            bool CheckStatus() const override;

            std::unique_ptr<cli::IConfig> GetConfig() const override;

            string PrintDeviceList() const;

        private:
            string _tgt_ip;
            string _src_ip;
            string _gateway_ip;
            string _iface;
            array<UINT8, MAC_ADDRESS_SIZE> _gateway_mac;
            array<UINT8, MAC_ADDRESS_SIZE> _tgt_mac;
            array<UINT8, MAC_ADDRESS_SIZE> _src_mac;
            bool _fullduplex;
            bool _running;
            umap<string, uset<string>> _command_list;
            umap<string, DeviceInfo> _devices_found;

            string StartArpSpoofing(const vector<string>& args);
            string StopArpSpoofing();
            string ProbeNet(const vector<string>& args);
            void PopulateMACAddress(array<UINT8, MAC_ADDRESS_SIZE>& who, const string& mac_str);
    };

    class DnsCli : public ICli {
        public:
            DnsCli();

            string ProcessCommand(const vector<string>& args, string& module) override;

            string Configure(const vector<string>& args) override;

            string ShowStatus(const vector<string>& args) override;

            string ShowHelp(const vector<string>& args) const override;

            bool CheckStatus() const override;

            std::unique_ptr<cli::IConfig> GetConfig() const override {
                return nullptr;
            }

        private:
            string _address;
            uset<string> _spoofed_domains;
            UINT _ttl;
            bool _running;
            umap<string, uset<string>> _command_list;


            string StartDnsSpoofing(const vector<string>& args);
            string StopDnsSpoofing();
    };

    class HttpsCli : public ICli {
        public:
            HttpsCli();

            string ProcessCommand(const vector<string>& args, string& module) override;

            string Configure(const vector<string>& args) override;

            string ShowStatus(const vector<string>& args) override;

            string ShowHelp(const vector<string>& args) const override;

            bool CheckStatus() const override;

            std::unique_ptr<cli::IConfig> GetConfig() const override {
                return nullptr;
            }

        private:
            string _ca_cert_path;
            string _ca_key_path;
            string _output_path;
            UINT _cert_ttl;
            UINT _validity_in_days;
            bool _running;
            bool _cert_generated;
            umap<string, uset<string>> _command_list;

            string GenerateCertificate(const vector<string>& args);
            string StartIntercept(const vector<string>& args);
            string StopIntercept(const vector<string>& args);

    };


    class Cli {
        public:
            Cli();
            void Start();
            void ProcessInput();

        private:
            // Command processing
            vector<string> ParseCommand(const string& input);

            // Command handlers
            void Run(Modules module);
            void Stop();
            void StartArp(const vector<string>& args);
            void StopArp();
            void StartDns(const vector<string>& args);
            void StopDns();
            void StartHttps(const vector<string>& args);
            void StopHttps();
            void SetConfig(const vector<string>& args);
            void ShowStatus();
            void ShowHelp(const vector<string>& args);

            // Utils
            void Hail() const;
            void PrintCli(std::tm buffer, string message = "", bool is_input = false, structures::ThreadInput *ti = nullptr);
            void PrintCli(std::tm buffer, structures::ThreadInput *ti = nullptr);
            void UpdateTimeBuffer();
            string ModuleToString(const Modules& module);
            Modules StringToModule(const string& module_str);
            void AddToHistory(const string& input);
            string GetHistoryUp();
            string GetHistoryDown();
            char GetChar();

            // Data members
            umap<string, void (Cli::*)(const vector<string>&)> _cmd_handlers;
            humap<Modules, uptr<ICli>, structures::EnumClassHash> _modules;
            umap<string, string> _config;
            humap<Modules, bool, structures::EnumClassHash> _module_status;
            deque<string> _command_history;
            int _history_index;
            umap<string, vector<Modules>> _command_list;
            std::tm _time_buffer;
            time_t _time;
            string _module_prefix;
            uptr<controllers::MainController> _controller;
            Asynq<CliRequest> _cli_queue;
            std::atomic<bool> _running;  
            string _input;
            structures::CliPrintMessage *_pm;

    };
}

#endif // PCAPTUREPP_CLI_HPP

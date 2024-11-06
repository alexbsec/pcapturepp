#ifndef PCAPTUREPP_CONTROLLERS_HPP
#define PCAPTUREPP_CONTROLLERS_HPP

#include "Includes.hpp"
#include "Structures.hpp"
#include "Async.hpp"
#include "TestModule.hpp"
#include "ArpSpoofing.hpp"

using pcapturepp::structures::requests::cli::BundledConfig;
using pcapturepp::structures::responses::ModuleResponse;
using pcapturepp::structures::requests::CliRequest;


template <typename T>
using Asynq = pcapturepp::AsyncQueue<T>;

namespace pcapturepp {
namespace controllers {
    class IController {
        public:
            virtual ~IController() noexcept = default;

            virtual string Start() = 0;

            virtual string Stop() = 0;
    };

    class MainController {
        public:
            MainController();
            void Start();
            void Stop();
            void ProcessCliRequests(const CliRequest& request);
            void ForwardToModule();
            void FetchResponseStream();
            void ProccessModuleResponse();
            std::optional<ModuleResponse> RespondCliBack();

        private:
            Asynq<CliRequest> _cli_queue;
            Asynq<ModuleResponse> _mres_queue;
            Asynq<CliRequest> _creq_queue;
            Asynq<ModuleResponse> _cres_queue;

            uptr<modules::ArpSpoofer> _module;
            std::atomic<bool> _stop_request;
            std::vector<std::thread> _threads;
    };
}
}

#endif // PCAPTUREPP_CONTROLLERS_HPP
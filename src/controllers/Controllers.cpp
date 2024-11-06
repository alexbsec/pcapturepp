#include "Controllers.hpp"
#include <thread>
#include <functional>

namespace pcapturepp {
namespace controllers {
    MainController::MainController() 
        : _cli_queue(), _mres_queue(), _creq_queue(), _cres_queue() {}

    void MainController::Start() {
        _module = std::make_unique<modules::ArpSpoofer>();
        std::thread(&MainController::ForwardToModule, this).detach();
        std::thread(&MainController::FetchResponseStream, this).detach();
        std::thread(&MainController::ProccessModuleResponse, this).detach();
        std::thread(&MainController::RespondCliBack, this).detach();
    }

    void MainController::ProcessCliRequests(const CliRequest& request) {
        // Addes to the async queue
        _cli_queue.Push(request);
    }

    void MainController::ForwardToModule() {
        while (true) {
            if (_cli_queue.Empty()) {
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
                continue;
            }

            CliRequest req = _cli_queue.Pop();
            _module->HandleCliRequest(req);
        }
    }

    void MainController::FetchResponseStream() {
        while (true) {
            std::optional<ModuleResponse> res = _module->ResponseStreamer();
            if (res) {
                _mres_queue.Push(*res);
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
    }
 
    void MainController::ProccessModuleResponse() {
        while (true) {
            if (_mres_queue.Empty()) continue;
            ModuleResponse mres = _mres_queue.Pop();
            _cres_queue.Push(mres);
        }
    }

    std::optional<ModuleResponse> MainController::RespondCliBack() {
        // Check if there is a response in the queue
        if (!_cres_queue.Empty()) {
            // Pop and return the response
            ModuleResponse response = _cres_queue.Pop();
            return response;
        }
        // No response available, return std::nullopt
        return std::nullopt;
    }

}
}
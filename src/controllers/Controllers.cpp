#include "Controllers.hpp"
#include <thread>
#include <functional>

namespace pcapturepp {
namespace controllers {
    MainController::MainController() 
        : _cli_queue(), _mres_queue(), _creq_queue(), _cres_queue(), _stop_request(true) {}

    void MainController::Start() {
        Stop();
        _stop_request = false;
        _module = std::make_unique<modules::ArpSpoofer>();
        _threads.emplace_back(&MainController::ForwardToModule, this);
        _threads.emplace_back(&MainController::FetchResponseStream, this);
        _threads.emplace_back(&MainController::ProccessModuleResponse, this);
        _threads.emplace_back(&MainController::RespondCliBack, this);
    }

    void MainController::Stop() {
        _stop_request = true;

        for (auto& thread : _threads) {
            if (thread.joinable()) {
                thread.join();
            }
        }

        _threads.clear(); 
        _cli_queue.Clear();
        _mres_queue.Clear();
        _cres_queue.Clear();
    }

    void MainController::ProcessCliRequests(const CliRequest& request) {
        // Addes to the async queue
        if (!_stop_request) _cli_queue.Push(request);
    }

    void MainController::ForwardToModule() {
        while (!_stop_request) {
            if (_cli_queue.Empty()) {
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
                continue;
            }

            CliRequest req = _cli_queue.Pop();
            _module->HandleCliRequest(req);
        }
    }

    void MainController::FetchResponseStream() {
        while (!_stop_request) {
            std::optional<ModuleResponse> res = _module->ResponseStreamer();
            if (res) {
                _mres_queue.Push(*res);
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
    }
 
    void MainController::ProccessModuleResponse() {
        while (!_stop_request) {
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
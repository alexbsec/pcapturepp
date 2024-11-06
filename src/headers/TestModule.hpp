#ifndef PCAPTUREPP_TEST_MODULE_HPP
#define PCAPTUREPP_TEST_MODULE_HPP

#include "Includes.hpp"
#include "Structures.hpp"

namespace pcapturepp {
namespace modules {
    using pcapturepp::structures::requests::CliRequest;
    using pcapturepp::structures::responses::ModuleResponse;

    class TestModule {
        public:
            TestModule() = default;

            ModuleResponse ProccessRequest(const CliRequest& request) {
                ModuleResponse res;
                res.message = "Tell CLI that i can respond!";
                return res;
            }

    };
}
}

#endif
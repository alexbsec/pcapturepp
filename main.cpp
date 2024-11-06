#define INCLUDE_ALL
#define INCLUDE_MAIN
#include "Cli.hpp"
#include "ArpPing.hpp"

using namespace pcapturepp;

int main(int argc, char* argv[]) {
    Cli cli;

    cli.Start();
    return 0;
}
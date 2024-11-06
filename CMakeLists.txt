cmake_minimum_required(VERSION 3.10)
project(pcapturepp)

# Add Google Test
add_subdirectory(googletest)
include_directories(googletest/include)

# Add src/includes to the include path
include_directories(${CMAKE_SOURCE_DIR}/src/includes)
include_directories(${CMAKE_SOURCE_DIR}/src/headers)

# Find the ncurses and OpenSSL libraries
find_package(Curses REQUIRED)
find_package(OpenSSL REQUIRED)
include_directories(${CURSES_INCLUDE_DIR})
include_directories(${OPENSSL_INCLUDE_DIR})

# Enable testing
enable_testing()

# Add source files and main executable for pcapturepp
add_executable(pcapturepp 
    main.cpp 
    src/utils/IPUtils.cpp 
    src/Cli.cpp 
    src/helpers/ArpCli.cpp 
    src/controllers/NetProber.cpp 
    src/helpers/DnsCli.cpp 
    src/helpers/HttpsCli.cpp 
    src/controllers/Controllers.cpp 
    src/utils/Utils.cpp 
    src/modules/ArpModule.cpp 
    src/controllers/CertManager.cpp 
    src/modules/HttpsModule.cpp 
    src/modules/DnsModule.cpp 
    src/Logger.cpp
)

# Link libraries to the main executable
target_link_libraries(pcapturepp ${CURSES_LIBRARIES} ${OPENSSL_LIBRARIES} gtest gtest_main pcap)

# Add test executable and include IPUtils.cpp
add_executable(runTests 
    tests/test_main.cpp 
    src/utils/IPUtils.cpp  # Ensure IPUtils.cpp is included here
    src/Cli.cpp 
    src/helpers/ArpCli.cpp 
    src/controllers/NetProber.cpp 
    src/helpers/DnsCli.cpp 
    src/helpers/HttpsCli.cpp 
    src/controllers/Controllers.cpp 
    src/utils/Utils.cpp 
    src/modules/ArpModule.cpp 
    src/controllers/CertManager.cpp 
    src/modules/HttpsModule.cpp 
    src/modules/DnsModule.cpp 
    src/Logger.cpp
)

# Link libraries to the test executable
target_link_libraries(runTests gtest gtest_main ${CURSES_LIBRARIES} ${OPENSSL_LIBRARIES} pcap)

# Register tests
add_test(NAME runTests COMMAND runTests)

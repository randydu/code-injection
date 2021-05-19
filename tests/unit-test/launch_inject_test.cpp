#include <catch2/catch.hpp>
#include <code_injection/code_injection.hpp>
#include <code_injection/injectors.hpp>

#include "shell_codes.h"
#include "test_util.h"

#include <chrono>
#include <thread>

namespace {
constexpr auto tag = "[launch-inject][inject]";
}

using namespace CI;

void dummy_injector(const PROCESS_INFORMATION &pi, const shell_code_t &sc, inject_option_t opt) {}

#ifdef _WIN64

TEST_CASE("launch-inject-test", tag) {
    SECTION("UNICODE") {
        SECTION("target is 64 bit") {
            target_info_w target{CI::ut::get_test_data_file(L"bin/Notepad2_64.exe")};
            printf("injecting %ls...\n", target.exe_path.c_str());

            SECTION("Shell Code") {
                const auto &shellcode = CI::ut::sc_beep(false);
                CHECK_NOTHROW(launch_inject(target, shellcode, inject_context, CI::inject_option_t::INJECT_RESUME));
            }
            if(0) SECTION("Dll") {
                return;
                injected_dll_w dll{};
                CHECK_NOTHROW(launch_inject(target, dll, dummy_injector));
            }
        }
        if(1) SECTION("target is 32 bit") {
            target_info_w target{CI::ut::get_test_data_file(L"bin/Notepad2_32.exe")};
            printf("injecting %ls...\n", target.exe_path.c_str());

            if(1) SECTION("Shell Code") {
                printf("sleep...\n"); // sleep for a while so we can hear different beeps.
                std::this_thread::sleep_for(std::chrono::seconds(1));
                //const auto &shellcode = CI::ut::sc_beep(true);
                const auto &shellcode = CI::shellcode::sc_dummy();
                CHECK_NOTHROW(launch_inject(target, shellcode, inject_context, CI::inject_option_t::INJECT_RESUME));
            }
            if(0) SECTION("Dll") {
                injected_dll_w dll{};
                CHECK_NOTHROW(launch_inject(target, dll, dummy_injector));
            }
        }
    }
    SECTION("ANSI") {
        SECTION("target is 64 bit") {
            target_info_a target{CI::ut::get_test_data_file("bin/Notepad2_64.exe")};
            printf("injecting %s...\n", target.exe_path.c_str());

            SECTION("Shell Code") {
                printf("sleep...\n"); // sleep for a while so we can hear different beeps.
                std::this_thread::sleep_for(std::chrono::seconds(2));

                const auto &shellcode = CI::ut::sc_beep(false);
                CHECK_NOTHROW(launch_inject(target, shellcode, inject_context, CI::inject_option_t::INJECT_RESUME));
            }
            if(0) SECTION("Dll") {
                injected_dll_a dll{};
                CHECK_NOTHROW(launch_inject(target, dll, dummy_injector));
            }
        }
        if(1) SECTION("target is 32 bit") {
            target_info_a target{CI::ut::get_test_data_file("bin/Notepad2_32.exe")};
            printf("injecting %s...\n", target.exe_path.c_str());

            if(1) SECTION("Shell Code") {
                printf("sleep...\n"); // sleep for a while so we can hear different beeps.
                std::this_thread::sleep_for(std::chrono::seconds(3));

                //const auto &shellcode = CI::ut::sc_beep(true);
                const auto &shellcode = CI::shellcode::sc_dummy();
                CHECK_NOTHROW(launch_inject(target, shellcode, inject_context, CI::inject_option_t::INJECT_RESUME));
            }
            if(0) SECTION("Dll") {
                injected_dll_a dll{};
                CHECK_NOTHROW(launch_inject(target, dll, dummy_injector));
            }
        }
    }
}

#else


TEST_CASE("launch-inject-test", tag) {
    printf("32bit launching test\n");
    SECTION("UNICODE") {
        if(0) SECTION("target is 64 bit") {
            target_info_w target{CI::ut::get_test_data_file(L"bin/Notepad2_64.exe")};
            printf("injecting %ls...\n", target.exe_path.c_str());

            SECTION("Shell Code") {
                //const auto &shellcode = CI::ut::sc_beep(true);
                //CHECK_NOTHROW(launch_inject(target, shellcode, inject_context, CI::inject_option_t::INJECT_RESUME));
            }
            SECTION("Dll") {
                //injected_dll_w dll{};
                //CHECK_NOTHROW(launch_inject(target, dll, dummy_injector));
            }
        }
        SECTION("target is 32 bit") {
            target_info_w target{CI::ut::get_test_data_file(L"bin/Notepad2_32.exe")};
            printf("injecting %ls...\n", target.exe_path.c_str());

            SECTION("Shell Code") {
                const auto &shellcode = CI::ut::sc_beep(false);
                CHECK_NOTHROW(launch_inject(target, shellcode, inject_context, CI::inject_option_t::INJECT_RESUME));
            }
            if(0) SECTION("Dll") {
                injected_dll_w dll{};
                CHECK_NOTHROW(launch_inject(target, dll, dummy_injector));
            }
        }
    }
    SECTION("ANSI") {
        if(0) SECTION("target is 64 bit") {
            target_info_a target{CI::ut::get_test_data_file("bin/Notepad2_64.exe")};
            printf("injecting %s...\n", target.exe_path.c_str());

            SECTION("Shell Code") {
                printf("sleep...\n"); // sleep for a while so we can hear different beeps.
                std::this_thread::sleep_for(std::chrono::seconds(1));

                const auto &shellcode = CI::ut::sc_beep(true);
                CHECK_NOTHROW(launch_inject(target, shellcode, inject_context, CI::inject_option_t::INJECT_RESUME));
            }
            SECTION("Dll") {
                injected_dll_a dll{};
                CHECK_NOTHROW(launch_inject(target, dll, dummy_injector));
            }
        }
        SECTION("target is 32 bit") {
            target_info_a target{CI::ut::get_test_data_file("bin/Notepad2_32.exe")};
            printf("injecting %s...\n", target.exe_path.c_str());

            SECTION("Shell Code") {
                printf("sleep...\n"); // sleep for a while so we can hear different beeps.
                std::this_thread::sleep_for(std::chrono::seconds(1));

                const auto &shellcode = CI::ut::sc_beep(false);
                CHECK_NOTHROW(launch_inject(target, shellcode, inject_context, CI::inject_option_t::INJECT_RESUME));
            }
            if(0) SECTION("Dll") {
                injected_dll_a dll{};
                CHECK_NOTHROW(launch_inject(target, dll, dummy_injector));
            }
        }
    }
}


#endif
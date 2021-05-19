#include <catch2/catch.hpp>
#include <code_injection/code_injection.hpp>
#include <code_injection/injectors.hpp>

#include "test_util.h"
#include "shell_codes.h"

#include <thread>
#include <chrono>

namespace {
constexpr auto tag = "[launch-inject]";
}

using namespace CI;

void dummy_injector(const PROCESS_INFORMATION &pi, const shell_code_t &sc, inject_option_t opt) {}

TEST_CASE("launch-inject-test", tag) {
    SECTION("UNICODE") {
        target_info_w target{CI::ut::get_test_data_file(L"bin/Notepad3.exe")};

        SECTION("Shell Code") {
            const auto& shellcode = CI::ut::sc_beep_64();
            CHECK_NOTHROW(launch_inject(target, shellcode, inject_context, CI::inject_option_t::INJECT_RESUME));
        }
        SECTION("Dll") {
            return;
            injected_dll_w dll{};
            CHECK_NOTHROW(launch_inject(target, dll, dummy_injector));
        }
    }
    SECTION("ANSI") {
        target_info_a target{CI::ut::get_test_data_file("bin/Notepad3.exe")};

        SECTION("Shell Code") {
            printf("sleep...\n");// sleep for a while so we can hear different beeps.
            std::this_thread::sleep_for(std::chrono::seconds(1));

            const auto& shellcode = CI::ut::sc_beep_64();
            CHECK_NOTHROW(launch_inject(target, shellcode, inject_context, CI::inject_option_t::INJECT_EXITPROCESS));
        }
        SECTION("Dll") {
            return;
            injected_dll_a dll{};
            CHECK_NOTHROW(launch_inject(target, dll, dummy_injector));
        }
    }
}
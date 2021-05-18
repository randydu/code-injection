#include <catch2/catch.hpp>
#include <code_injection/code_injection.hpp>

#include "test_util.h"

namespace {
constexpr auto tag = "[launch-inject]";
}

using namespace CI;

void dummy_injector(const PROCESS_INFORMATION &pi, const shell_code_t &sc) {}

TEST_CASE("launch-inject-test", tag) {
    SECTION("ANSI") {
        target_info_a target{CI::get_test_data_file("bin/Notepad3.exe")};

        SECTION("Shell Code") {
            shell_code_t shellcode{};
            injected_dll_a dll{};
            CHECK_NOTHROW(launch_inject(target, shellcode, dummy_injector));
        }
        SECTION("Dll") {
            injected_dll_a dll{};
            CHECK_NOTHROW(launch_inject(target, dll, dummy_injector));
        }
    }
    SECTION("UNICODE") {
        target_info_w target{CI::get_test_data_file(L"bin/Notepad3.exe")};

        SECTION("Shell Code") {
            shell_code_t shellcode{};
            injected_dll_w dll{};
            CHECK_NOTHROW(launch_inject(target, shellcode, dummy_injector));
        }
        SECTION("Dll") {
            injected_dll_w dll{};
            CHECK_NOTHROW(launch_inject(target, dll, dummy_injector));
        }
    }
}
#include <catch2/catch.hpp>
#include <code_injection/code_injection.hpp>
#include <code_injection/injectors.hpp>

#include "shell_codes.h"
#include "test_util.h"

#include <chrono>
#include <thread>

namespace {
constexpr auto tag = "[launch-inject][inject]";

#ifdef _WIN64
constexpr bool test_unicode = true;
constexpr bool test_ansi = false;
constexpr bool test_target_32 = true;
constexpr bool test_target_64 = true;

constexpr bool test_shellcode = false;
constexpr bool test_dll = true;
#else
constexpr bool test_unicode = false;
constexpr bool test_ansi = true;
constexpr bool test_target_32 = true;
constexpr bool test_target_64 = false; //32=>64 not supported yet

constexpr bool test_shellcode = false;
constexpr bool test_dll = true;

#endif

} // namespace

using namespace CI;

void dummy_injector(const PROCESS_INFORMATION &pi, const shell_code_t &sc, inject_option_t opt) {}

#ifdef _WIN64

TEST_CASE("launch-inject-test", tag) {
    CI::inject_option_t opt;
    opt.wait_target = true;
    opt.wait_before_injection = true;

    if (test_unicode)
        SECTION("UNICODE") {
            if (test_target_64)
                SECTION("target is 64 bit") {
                    target_info_w target{true, CI::ut::get_test_data_file(L"bin/Notepad2_64.exe")};
                    printf("injecting %ls...\n", target.exe_path.c_str());

                    if (test_shellcode)
                        SECTION("Shell Code") {
                            const auto &shellcode = CI::ut::sc_beep(false, shell_code_t::arch_t::X64);
                            CHECK_NOTHROW(launch_inject(target, shellcode, inject_context, opt));
                        }
                    if (test_dll)
                        SECTION("Dll") {
                            injected_dll_w dll{
                                true,
                                CI::ut::get_test_data_file(L"bin\\mydll64.dll"),
                                "hello",
                            };
                            printf("injecting dll (%ls : %s)...\n", dll.dll_path.c_str(), dll.proc_name.c_str());
                            CHECK_NOTHROW(launch_inject(target, dll, inject_context, opt));
                        }
                }
            if (test_target_32)
                SECTION("target is 32 bit") {
                    target_info_w target{false, CI::ut::get_test_data_file(L"bin/Notepad2_32.exe")};
                    printf("injecting %ls...\n", target.exe_path.c_str());

                    if (test_shellcode)
                        SECTION("Shell Code") {
                            printf("sleep...\n"); // sleep for a while so we can hear different beeps.
                            std::this_thread::sleep_for(std::chrono::seconds(1));
                            //const auto &shellcode = CI::ut::sc_beep(true, shell_code_t::arch_t::X86);
                            const auto &shellcode = CI::shellcode::sc_dummy();
                            CHECK_NOTHROW(launch_inject(target, shellcode, inject_context, opt));
                        }
                    if (test_dll)
                        SECTION("Dll") {
                            injected_dll_w dll{
                                false,
                                CI::ut::get_test_data_file(L"bin\\mydll32.dll"),
                                "hello",
                            };
                            printf("injecting dll (%ls : %s)...\n", dll.dll_path.c_str(), dll.proc_name.c_str());
                            CHECK_NOTHROW(launch_inject(target, dll, inject_context, opt));
                        }
                }
        }
    if (test_ansi)
        SECTION("ANSI") {
            if (test_target_64)
                SECTION("target is 64 bit") {
                    target_info_a target{true, CI::ut::get_test_data_file("bin/Notepad2_64.exe")};
                    printf("injecting %s...\n", target.exe_path.c_str());

                    if (test_shellcode)
                        SECTION("Shell Code") {
                            printf("sleep...\n"); // sleep for a while so we can hear different beeps.
                            std::this_thread::sleep_for(std::chrono::seconds(2));

                            const auto &shellcode = CI::ut::sc_beep(false, shell_code_t::arch_t::X64);
                            CHECK_NOTHROW(launch_inject(target, shellcode, inject_context, opt));
                        }
                    if (test_dll)
                        SECTION("Dll") {
                            injected_dll_a dll{
                                true,
                                CI::ut::get_test_data_file("bin\\mydll64.dll"),
                                "hello",
                            };
                            printf("injecting dll (%s : %s)...\n", dll.dll_path.c_str(), dll.proc_name.c_str());

                            CHECK_NOTHROW(launch_inject(target, dll, inject_context, opt));
                        }
                }
            if (test_target_32)
                SECTION("target is 32 bit") {
                    target_info_a target{false, CI::ut::get_test_data_file("bin/Notepad2_32.exe")};
                    printf("injecting %s...\n", target.exe_path.c_str());

                    if (test_shellcode)
                        SECTION("Shell Code") {
                            printf("sleep...\n"); // sleep for a while so we can hear different beeps.
                            std::this_thread::sleep_for(std::chrono::seconds(3));

                            //const auto &shellcode = CI::ut::sc_beep(true, shell_code_t::arch_t::X86);
                            const auto &shellcode = CI::shellcode::sc_dummy();
                            CHECK_NOTHROW(launch_inject(target, shellcode, inject_context, opt));
                        }
                    if (test_dll)
                        SECTION("Dll") {
                            injected_dll_a dll{
                                false,
                                CI::ut::get_test_data_file("bin\\mydll32.dll"),
                                "hello",
                            };
                            printf("injecting dll (%s : %s)...\n", dll.dll_path.c_str(), dll.proc_name.c_str());
                            CHECK_NOTHROW(launch_inject(target, dll, inject_context, opt));
                        }
                }
        }
}

#else

TEST_CASE("launch-inject-test", tag) {
    printf("32bit launching test\n");
    CI::inject_option_t opt;

    if (test_unicode)
        SECTION("UNICODE") {
            if (test_target_64)
                SECTION("target is 64 bit") {
                    target_info_w target{true, CI::ut::get_test_data_file(L"bin/Notepad2_64.exe")};
                    printf("injecting %ls...\n", target.exe_path.c_str());

                    if (test_shellcode)
                        SECTION("Shell Code") {
                            const auto &shellcode = CI::ut::sc_beep(true, shell_code_t::arch_t::X64);
                            CHECK_NOTHROW(launch_inject(target, shellcode, inject_context, opt));
                        }
                    if (test_dll)
                        SECTION("Dll") {
                            injected_dll_w dll{
                                true,
                                L"user32.dll",
                                "MessageBeep",
                                0};
                            CHECK_NOTHROW(launch_inject(target, dll, inject_context, opt));
                        }
                }
            if (test_target_32)
                SECTION("target is 32 bit") {
                    target_info_w target{false, CI::ut::get_test_data_file(L"bin/Notepad2_32.exe")};
                    printf("injecting %ls...\n", target.exe_path.c_str());

                    if (test_shellcode)
                        SECTION("Shell Code") {
                            const auto &shellcode = CI::ut::sc_beep(false, shell_code_t::arch_t::X86);
                            CHECK_NOTHROW(launch_inject(target, shellcode, inject_context, opt));
                        }
                    if (test_dll)
                        SECTION("Dll") {
                            injected_dll_w dll{
                                false,
                                L"user32.dll",
                                "MessageBeep",
                                0};
                            CHECK_NOTHROW(launch_inject(target, dll, inject_context, opt));
                        }
                }
        }
    if (test_ansi)
        SECTION("ANSI") {
            if (test_target_64)
                SECTION("target is 64 bit") {
                    target_info_a target{true, CI::ut::get_test_data_file("bin/Notepad2_64.exe")};
                    printf("injecting %s...\n", target.exe_path.c_str());

                    if (test_shellcode)
                        SECTION("Shell Code") {
                            printf("sleep...\n"); // sleep for a while so we can hear different beeps.
                            std::this_thread::sleep_for(std::chrono::seconds(1));

                            const auto &shellcode = CI::ut::sc_beep(true, shell_code_t::arch_t::X64);
                            CHECK_NOTHROW(launch_inject(target, shellcode, inject_context, opt));
                        }
                    if (test_dll)
                        SECTION("Dll") {
                            injected_dll_a dll{
                                true,
                                "user32.dll",
                                "MessageBeep",
                                0};
                            CHECK_NOTHROW(launch_inject(target, dll, inject_context, opt));
                        }
                }
            if (test_target_32)
                SECTION("target is 32 bit") {
                    target_info_a target{false, CI::ut::get_test_data_file("bin/Notepad2_32.exe")};
                    printf("injecting %s...\n", target.exe_path.c_str());

                    if (test_shellcode)
                        SECTION("Shell Code") {
                            printf("sleep...\n"); // sleep for a while so we can hear different beeps.
                            std::this_thread::sleep_for(std::chrono::seconds(1));

                            const auto &shellcode = CI::ut::sc_beep(false, shell_code_t::arch_t::X86);
                            CHECK_NOTHROW(launch_inject(target, shellcode, inject_context, opt));
                        }
                    if (test_dll)
                        SECTION("Dll") {
                            injected_dll_a dll{
                                false,
                                "user32.dll",
                                "MessageBeep",
                                0};
                            CHECK_NOTHROW(launch_inject(target, dll, inject_context, opt));
                        }
                }
        }
}

#endif
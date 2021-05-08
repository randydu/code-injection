#include <catch2/catch.hpp>
#include <code_injection/code_injection.hpp>

namespace {
    constexpr auto tag = "[launch-inject]";
}

using namespace CI;

target_info_t target {};
injected_dll_t dll{};
shell_code_t shellcode{};

void dummy_injector(const PROCESS_INFORMATION& pi, const shell_code_t& sc){}

TEST_CASE("launch-inject-test", tag){
    CHECK_NOTHROW(launch_inject(target, shellcode, dummy_injector));
}
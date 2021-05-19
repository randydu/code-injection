#include <catch2/catch.hpp>

#include <code_injection/shell_code.hpp>

#include "shell_codes.h"

namespace {
constexpr auto tag = "[shellcode]";
}

TEST_CASE("sc-helloworld", tag) {
    SECTION("32 bit") {
        const auto &sc = CI::ut::sc_hello_world_32();
        CHECK(sc.code.empty());
        CHECK(sc.entry == 0);
    }
    SECTION("64 bit") {
        const auto &sc = CI::ut::sc_hello_world_64();
        CHECK(sc.code.size() == 60);
        CHECK(sc.entry == 0);
    }
}

TEST_CASE("sc-join", tag) {
    using namespace CI;
    using namespace CI::shellcode;

    shell_code_t sa, sb;
    SECTION("cannot join") {
        CHECK_THROWS(sa + sb);
    }
    SECTION("joinable") {
        sa.joinable = true;
        sb.joinable = true;
        const auto &sc = sa + sb;
        CHECK(sc.entry == sa.entry);
    }
}
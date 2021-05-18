#include <catch2/catch.hpp>

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
        CHECK(sc.code.size() == 76);
        CHECK(sc.entry == 0);
    }
}
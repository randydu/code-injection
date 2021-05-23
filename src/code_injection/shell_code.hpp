#ifndef CI_SHELL_CODE_HPP
#define CI_SHELL_CODE_HPP

// simple shell-code generation framework

#include <cstdint>
#include <vector>

#include <windows.h>

#include "error.hpp"

namespace CI::shellcode {

struct shell_code_t {
    enum class arch_t : uint8_t {
        UNKNOWN = 0,   //not specified, entry point is "entry"
        X86 = 1,       //shell-code is for 32bit intel i386 only
        X64 = 2,       //shell-code is for 64bit AMD64 only
        UNIVERSAL = 3, //shell-code can work for both 32bit and 64 bit machine
    };

    arch_t arch{arch_t::UNKNOWN};
    std::vector<uint8_t> code; //shell code content

    int16_t entry{0};     //entry point offset in the code (index of the code vector)
    bool joinable{false}; // whether the shell code can be joined together with other codes
};

#pragma pack(push, 1)

//shell-code has small parameter block (size < 2^31)
struct sc_prolog_t {
    uint8_t _0[5]{0xe8, 0, 0, 0, 0}; //call *ip
    uint8_t _1{0x5b};                //pop *bx; now *bx+6 => param block
    uint8_t _2{0xe9};                //jmp *ip+param_size
    int32_t param_size{0};           //size of parameter block, filled by caller
    //--- param-block starts here
};

//shell-code has small parameter block (size < 128)
struct sc_prolog_small_t {
    uint8_t _0[5]{0xe8, 0, 0, 0, 0}; //call *ip
    uint8_t _1{0x5b};                //pop *bx; now *bx+6 => param block
    uint8_t _2{0xeb};                //jmp *ip+param_size
    int8_t param_size{0};            //size of parameter block, filled by caller
    //--- param-block starts here
};

//shell code logic begin
struct sc_begin_code_64_t {
    uint8_t _0[4]{0x48, 0x83, 0xc3, 0x06}; //add rbx, 6; now rbx => param-block
};
struct sc_begin_code_small_64_t {
    uint8_t _0[4]{0x48, 0x83, 0xc3, 0x03}; //add rbx, 3; now rbx => param-block
};
struct sc_begin_code_32_t {
    uint8_t _0[3]{0x83, 0xc3, 0x06}; //add ebx, 6; now ebx => param-block
};
struct sc_begin_code_small_32_t {
    uint8_t _0[3]{0x83, 0xc3, 0x03}; //add ebx, 3; now ebx => param-block
};

struct sc_jmp_t {
    uint8_t _0{0xe9};
    int32_t offset{0};
};

struct sc_jmp_near_t {
    uint8_t _0{0xeb};
    int8_t offset{0};
};

struct sc_save_xbx_t {
    uint8_t _0{0x53}; //push *bx
};
struct sc_restore_xbx_t {
    uint8_t _0{0x5b}; //pop *bx
};
struct sc_add_rbx_64_t {
    uint8_t _0[3]{0x48, 0x83, 0xc3}; //add rbx, xx
    uint8_t offset{0};
};
struct sc_add_ebx_32_t {
    uint8_t _0[2]{0x83, 0xc3}; //add ebx, xx
    uint8_t offset{0};
};

struct sc_int3_t {
    uint8_t cc{0xcc};
};

shell_code_t sc_exit_process(UINT exit_code, bool self_resolve_api, shell_code_t::arch_t arch);

shell_code_t sc_resume(const CONTEXT &cxt);
shell_code_t sc_resume(const WOW64_CONTEXT &cxt);

shell_code_t sc_dummy();

#pragma pack(pop)

template <typename T>
void sc_append(std::vector<uint8_t> &vec, const T &t) {
    const uint8_t *p0 = (const uint8_t *)&t;
    const uint8_t *p1 = (const uint8_t *)(&t + 1);
    for (auto p = p0; p < p1; ++p)
        vec.push_back(*p);
};

void sc_append(std::vector<uint8_t> &vec, const void *ptr, int len);
void sc_append(std::vector<uint8_t> &vec, const char *ptr, bool includes_ending_zero);

template <typename T, typename U>
shell_code_t sc_compose(const T &param, const U &code, shell_code_t::arch_t arch) {
    if (arch == shell_code_t::arch_t::UNKNOWN)
        CI::ci_error::raise(ci_error_code::INVALID_ARG, "%s: shell-code architecture not specified", __FUNCTION__);

    std::vector<uint8_t> vec;

    bool small_param = sizeof(param) < 128;

    if (small_param) {
        sc_prolog_small_t prolog;
        prolog.param_size = sizeof(param);
        sc_append(vec, prolog);
    } else {
        sc_prolog_t prolog;
        prolog.param_size = sizeof(param);
        sc_append(vec, prolog);
    }

    sc_append(vec, param);

    switch (arch) {
    case shell_code_t::arch_t::X86:
        if (small_param)
            sc_append(vec, sc_begin_code_small_32_t{});
        else
            sc_append(vec, sc_begin_code_32_t{});
        break;
    case shell_code_t::arch_t::X64:
        if (small_param)
            sc_append(vec, sc_begin_code_small_64_t{});
        else
            sc_append(vec, sc_begin_code_64_t{});
        break;
    default:
        CI::ci_error::raise(ci_error_code::INVALID_ARG, "%s: shell-code architecture [%d] not supported", __FUNCTION__, (int)arch);
    }
    sc_append(vec, code);
    return {arch, vec, 0, true};
}

shell_code_t sc_compose(const void *param, int param_size, const void *code, int code_size, shell_code_t::arch_t arch);

shell_code_t join(const shell_code_t &sca, const shell_code_t &scb);
} // namespace CI::shellcode

inline CI::shellcode::shell_code_t operator+(const CI::shellcode::shell_code_t &sca, const CI::shellcode::shell_code_t &scb) {
    return CI::shellcode::join(sca, scb);
}

#endif
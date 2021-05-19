#include <code_injection/code_injection.hpp>
#include <code_injection/shell_code.hpp>

namespace CI::shellcode {

shell_code_t join(const shell_code_t &sca, const shell_code_t &scb) {
    if (!sca.joinable || !scb.joinable)
        CI::ci_error::raise(CI::ci_error_code::INVALID_ARG, "operator+: shell-code is not joinable");

    std::vector<uint8_t> x(sca.code);
    if (scb.entry != 0) {
        if (scb.entry < 128 && scb.entry >= -128) {
            //near jmp
            sc_jmp_near_t jmp;
            jmp.offset = scb.entry;
            sc_append(x, jmp);
        } else {
            sc_jmp_t jmp;
            jmp.offset = scb.entry;
            sc_append(x, jmp);
        }
    }
    x.reserve(x.size() + scb.code.size());
    for (auto b : scb.code)
        x.push_back(b);

    return {std::move(x), sca.entry, true};
}

namespace {

#pragma pack(push, 1)
struct sc_exitprocess_param_64_t {
    using exitprocess_t = void(WINAPI *)(UINT uExitCode);
    exitprocess_t exitprocess;
};

struct sc_exitprocess_t {
    uint8_t set_exitcode[2]{0x33, 0xc9}; //xor ecx, ecx
    uint8_t call[2]{0xff, 0x13};         //call [rbx]
};

//Continue to where the app should go normally
struct sc_continue_param_64_t {
    uint64_t rsp;
    uint64_t rbp;

    uint64_t rax;
    uint64_t rbx;
    uint64_t rcx;
    uint64_t rdx;
    uint64_t rsi;
    uint64_t rdi;

    uint64_t r8;
    uint64_t r9;
    uint64_t r10;
    uint64_t r11;
    uint64_t r12;
    uint64_t r13;
    uint64_t r14;
    uint64_t r15;

    uint64_t flags;
    uint64_t rip;
};

struct sc_continue_64_t {
    uint8_t _0[4]{0x48, 0x8d, 0x73, 0x08};          //lea rsi, [rbx+8]
    uint8_t _1[3]{0x48, 0x8b, 0x23};                //mov rsp, [rbx]
    uint8_t _2[7]{0x48, 0x81, 0xec, 0x88, 0, 0, 0}; //sub rsp, sizeof(sc_continue_param_64_t)-8 = 8*17
    uint8_t _3[3]{0x48, 0x8b, 0xfc};                //mov rdi, rsp
    uint8_t _4[5]{0xb9, 0x11, 0, 0, 0};             //mov rcx, 17
    uint8_t _5[1]{0xfc};                            //cld
    uint8_t _6[3]{0xf3, 0x48, 0xa5};                //rep movsq

    uint8_t _7{0x5d};  //pop rbp
    uint8_t _8{0x58};  //pop rax;
    uint8_t _9{0x5b};  //pop rbx;
    uint8_t _10{0x59}; //pop rcx;
    uint8_t _11{0x5a}; //pop rdx;
    uint8_t _12{0x5e}; //pop rsi;
    uint8_t _13{0x5f}; //pop rdi;

    uint8_t _14[2]{0x41, 0x58}; //pop r8;
    uint8_t _15[2]{0x41, 0x59}; //pop r9;
    uint8_t _16[2]{0x41, 0x5a}; //pop r10;
    uint8_t _17[2]{0x41, 0x5b}; //pop r11;
    uint8_t _18[2]{0x41, 0x5c}; //pop r12;
    uint8_t _19[2]{0x41, 0x5d}; //pop r13;
    uint8_t _20[2]{0x41, 0x5e}; //pop r14;
    uint8_t _21[2]{0x41, 0x5f}; //pop r15;

    uint8_t _22{0x9d}; //popfq
    uint8_t _23{0xc3}; //ret
};

#pragma pack(pop)
} // namespace

shell_code_t sc_exit_process(UINT exit_code) {
    sc_exitprocess_param_64_t param;
    param.exitprocess = (sc_exitprocess_param_64_t::exitprocess_t)get_api("kernel32.dll", "ExitProcess");

    return sc_compose(param, sc_exitprocess_t{});
}

shell_code_t sc_resume(const CONTEXT &cxt) {
    sc_continue_param_64_t continue_param;

    continue_param.rsp = cxt.Rsp;
    continue_param.rbp = cxt.Rbp;
    continue_param.rax = cxt.Rax;
    continue_param.rbx = cxt.Rbx;
    continue_param.rcx = cxt.Rcx;
    continue_param.rdx = cxt.Rdx;
    continue_param.rsi = cxt.Rsi;
    continue_param.rdi = cxt.Rdi;
    continue_param.r8 = cxt.R8;
    continue_param.r9 = cxt.R9;
    continue_param.r10 = cxt.R10;
    continue_param.r11 = cxt.R11;
    continue_param.r12 = cxt.R12;
    continue_param.r13 = cxt.R13;
    continue_param.r14 = cxt.R14;
    continue_param.r15 = cxt.R15;
    continue_param.flags = cxt.EFlags;
    continue_param.rip = cxt.Rip;

    return sc_compose(continue_param, sc_continue_64_t{});
}

} // namespace CI::shellcode
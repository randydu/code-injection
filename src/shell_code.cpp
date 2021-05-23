#include <code_injection/code_injection.hpp>
#include <code_injection/shell_code.hpp>

namespace CI::shellcode {

shell_code_t join(const shell_code_t &sca, const shell_code_t &scb) {
    if (!sca.joinable || !scb.joinable)
        CI::ci_error::raise(CI::ci_error_code::INVALID_ARG, "operator+: shell-code is not joinable");

    if (sca.arch == shell_code_t::arch_t::UNKNOWN || sca.arch == shell_code_t::arch_t::UNKNOWN)
        CI::ci_error::raise(CI::ci_error_code::INVALID_ARG, "operator+: shell-code architecture not specified");

    //resolve final arch
    shell_code_t::arch_t arch = sca.arch;
    if (arch == shell_code_t::arch_t::UNIVERSAL)
        arch = scb.arch;

    if (arch != scb.arch && scb.arch != shell_code_t::arch_t::UNIVERSAL)
        CI::ci_error::raise(CI::ci_error_code::INVALID_ARG, "operator+: shell-codes have incompatible architecture");

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

    return {arch, std::move(x), sca.entry, true};
}

namespace {

#pragma pack(push, 1)

using exitprocess_t = void(WINAPI *)(UINT uExitCode);
struct sc_exitprocess_param_32_t {
    uint32_t exitprocess;
};
struct sc_exitprocess_param_64_t {
    uint64_t exitprocess;
};

struct sc_exitprocess_t {
    uint8_t set_exitcode[2]{0x33, 0xc9}; //xor ecx, ecx
    uint8_t call[2]{0xff, 0x13};         //call [rbx] | call [ebx]
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

struct sc_continue_param_32_t {
    uint32_t esp;
    uint32_t ebp;

    uint32_t eax;
    uint32_t ebx;
    uint32_t ecx;
    uint32_t edx;
    uint32_t esi;
    uint32_t edi;

    uint32_t flags;
    uint32_t eip;
};

struct sc_continue_32_t {
    uint8_t _0[3]{0x8d, 0x73, 0x04};   //lea esi, [ebx+4]
    uint8_t _1[2]{0x8b, 0x23};         //mov esp, [ebx]
    uint8_t _2[3]{0x83, 0xec, 0x24};   //sub esp, sizeof(sc_continue_param_32_t)-4 = 4*9
    uint8_t _3[2]{0x8b, 0xfc};         //mov edi, esp
    uint8_t _4[5]{0xb9, 0x9, 0, 0, 0}; //mov ecx, 9
    uint8_t _5[1]{0xfc};               //cld
    uint8_t _6[2]{0xf3, 0xa5};         //rep movsd

    uint8_t _7{0x5d};  //pop ebp
    uint8_t _8{0x58};  //pop eax;
    uint8_t _9{0x5b};  //pop ebx;
    uint8_t _10{0x59}; //pop ecx;
    uint8_t _11{0x5a}; //pop edx;
    uint8_t _12{0x5e}; //pop esi;
    uint8_t _13{0x5f}; //pop edi;

    uint8_t _22{0x9d}; //popfd
    uint8_t _23{0xc3}; //ret
};

#pragma pack(pop)
} // namespace

shell_code_t sc_exit_process(UINT exit_code, bool self_resolve_api, shell_code_t::arch_t arch) {
    if (self_resolve_api)
        CI::ci_error::raise(ci_error_code::FEATURE_NOT_IMPLEMENTED, "sc_exit_process: self-resolve-api not implemented");

    if (arch == shell_code_t::arch_t::UNKNOWN)
        CI::ci_error::raise(ci_error_code::INVALID_ARG, "%s: arch not specified", __FUNCTION__);

    switch (arch) {
    case shell_code_t::arch_t::X64:
        if (!self_resolve_api) {
#ifndef _WIN64
            CI::ci_error::raise(ci_error_code::INVALID_ARG, "%s: x64 api cannot be resolved by 32-bit code", __FUNCTION__);
#endif
            sc_exitprocess_param_64_t param;
            param.exitprocess = (uint64_t)get_api("kernel32.dll", "ExitProcess");

            return sc_compose(param, sc_exitprocess_t{}, arch);
        }
        break;

    case shell_code_t::arch_t::X86:
        if (!self_resolve_api) {
#ifdef _WIN64
            CI::ci_error::raise(ci_error_code::INVALID_ARG, "%s: x86 api cannot be resolved by 64-bit code", __FUNCTION__);
#else
            sc_exitprocess_param_32_t param;
            param.exitprocess = (uint32_t)get_api("kernel32.dll", "ExitProcess");

            return sc_compose(param, sc_exitprocess_t{}, arch);
#endif
        }
        break;
    }

    CI::ci_error::raise(ci_error_code::INVALID_ARG, "%s: arch (%d) not supported", __FUNCTION__, (int)arch);
}

#ifdef _WIN64
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

    return sc_compose(continue_param, sc_continue_64_t{}, shell_code_t::arch_t::X64);
}

#else
shell_code_t sc_resume(const CONTEXT &cxt) {
    sc_continue_param_32_t continue_param;

    continue_param.esp = cxt.Esp;
    continue_param.ebp = cxt.Ebp;
    continue_param.eax = cxt.Eax;
    continue_param.ebx = cxt.Ebx;
    continue_param.ecx = cxt.Ecx;
    continue_param.edx = cxt.Edx;
    continue_param.esi = cxt.Esi;
    continue_param.edi = cxt.Edi;
    continue_param.flags = cxt.EFlags;
    continue_param.eip = cxt.Eip;

    return sc_compose(continue_param, sc_continue_32_t{}, shell_code_t::arch_t::X86);
}
#endif

shell_code_t sc_resume(const WOW64_CONTEXT &cxt) {
    sc_continue_param_32_t continue_param;

    continue_param.esp = cxt.Esp;
    continue_param.ebp = cxt.Ebp;
    continue_param.eax = cxt.Eax;
    continue_param.ebx = cxt.Ebx;
    continue_param.ecx = cxt.Ecx;
    continue_param.edx = cxt.Edx;
    continue_param.esi = cxt.Esi;
    continue_param.edi = cxt.Edi;
    continue_param.flags = cxt.EFlags;
    continue_param.eip = cxt.Eip;

    return sc_compose(continue_param, sc_continue_32_t{}, shell_code_t::arch_t::X86);
}

shell_code_t sc_dummy() {
    shell_code_t sc;
    sc.arch = shell_code_t::arch_t::UNIVERSAL;
    sc.joinable = true;
    return sc;
}

void sc_append(std::vector<uint8_t> &vec, const void *ptr, int len) {
    const uint8_t *p0 = (const uint8_t *)ptr;
    const uint8_t *p1 = (const uint8_t *)ptr + len;
    for (auto p = p0; p < p1; ++p)
        vec.push_back(*p);
}

void sc_append(std::vector<uint8_t> &vec, const char *ptr, bool includes_ending_zero) {
    const uint8_t *p0 = (const uint8_t *)ptr;
    const uint8_t *p1 = (const uint8_t *)ptr + strlen(ptr);
    for (auto p = p0; p < p1; ++p)
        vec.push_back(*p);

    if (includes_ending_zero)
        vec.push_back(0);
}

shell_code_t sc_compose(const void *param, int param_size, const void *code, int code_size, shell_code_t::arch_t arch) {
    std::vector<uint8_t> vec;

    if (param_size < 128) {
        sc_prolog_small_t prolog;
        prolog.param_size = param_size;
        sc_append(vec, prolog);
    } else {
        sc_prolog_t prolog;
        prolog.param_size = param_size;
        sc_append(vec, prolog);
    }

    sc_append(vec, param, param_size);

    switch (arch) {
    case shell_code_t::arch_t::X64:
        sc_append(vec, sc_begin_code_64_t{});
        break;
    case shell_code_t::arch_t::X86:
        sc_append(vec, sc_begin_code_32_t{});
        break;
    }

    sc_append(vec, code, code_size);
    return {arch, vec, 0, true};
}

} // namespace CI::shellcode

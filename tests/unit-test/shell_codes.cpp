#include "shell_codes.h"

#include <cassert>

namespace CI::ut {

namespace {
#pragma pack(push, 1)

struct sc_prolog_64_t {
    uint8_t call_rip[5]{0xE8, 0, 0, 0, 0}; //call rip
    uint8_t pop_rbx{0x5b};                 //pop rbx; now ebx+6 => param block
    uint8_t jmp{0xE9};                     //jmp rip+param_size
    uint32_t param_size{0};                //size of parameter block, filled by caller
    //--- param-block starts here
    //uint8_t param_block[0];
};

//shell code logic begin
struct sc_begin_64_t {
    uint8_t set_rbx_to_paramblock[4]{0x48, 0x83, 0xc3, 0x06}; //add rbx, 6; now rbx => param-block
};

using messagebox_t = int(WINAPI *)(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType);
using exitprocess_t = void(WINAPI *)(UINT uExitCode);

struct sc_helloworld_param_64_t {
    messagebox_t messagebox;
    char text[14]{'H', 'e', 'l', 'l', 'o', ',', ' ', 'W', 'o', 'r', 'l', 'd', '!', 0};
    char caption[8]{'F', 'r', 'o', 'm', ' ', 'C', 'I', 0};
};

struct sc_helloworld_msgbox_64_t {
    uint8_t set_hwnd_to_0[2]{0x33, 0xc9};          //xor ecx, ecx
    uint8_t set_lptext[4]{0x48, 0x8d, 0x53, 0x08}; //lea rdx, [rbx+8]
    uint8_t set_lpcap[4]{0x4c, 0x8d, 0x43, 0x16};  //lea r8, [rbx + 22]
    uint8_t mb_ok[3]{0x45, 0x33, 0xc9};            //xor r9d, r9d
    uint8_t call[2]{0xff, 0x13};                   //call [rbx]
};

using beep_t = BOOL(WINAPI *)(UINT uType);
struct sc_beep_param_64_t {
    beep_t beep;
};
struct sc_call_beep_64_t {
    uint8_t set_type_to_0[2]{0x33, 0xc9}; //xor ecx, ecx
    uint8_t call[2]{0xff, 0x13};          //call [rbx]
};

struct sc_exitprocess_param_64_t {
    exitprocess_t exitprocess;
};

struct sc_exitprocess_t {
    uint8_t set_exitcode[2]{0x33, 0xc9}; //xor ecx, ecx
    uint8_t call[2]{0xff, 0x13};         //call [rbx]
};

struct sc_save_rbx_t {
    uint8_t push_rbx{0x53};
};
struct sc_restore_rbx_t {
    uint8_t pop_rbx{0x5b};
};
struct sc_add_rbx_t {
    uint8_t add_rbx[3]{0x48, 0x83, 0xc3};
    uint8_t offset{0};
};

struct sc_int3_t {
    uint8_t cc{0xcc};
};

struct sc_helloworld_64_t {
    sc_prolog_64_t prolog;

    sc_helloworld_param_64_t msgbox_param;
    sc_exitprocess_param_64_t exit_param;

    sc_begin_64_t begin; // (rbx) = &msgbox_param
    //sc_int3_t dbg;

    sc_helloworld_msgbox_64_t call_msgbox;

    sc_add_rbx_t add_rbx;
    sc_exitprocess_t call_exitprocess;
};

struct sc_beep_64_t {
    sc_prolog_64_t prolog;

    sc_beep_param_64_t beep_param;
    sc_exitprocess_param_64_t exit_param;

    sc_begin_64_t begin; // (rbx) = &beep_param

    sc_call_beep_64_t call_beep;

    sc_add_rbx_t add_rbx;
    sc_exitprocess_t call_exitprocess;
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

struct sc_beep_continue_64_t {
    sc_prolog_64_t prolog;

    sc_beep_param_64_t beep_param;
    sc_continue_param_64_t continue_param;

    sc_begin_64_t begin; // (rbx) = &beep_param

    sc_call_beep_64_t call_beep;

    sc_add_rbx_t add_rbx;
    sc_continue_64_t go_back;
};
#pragma pack(pop)

void *get_api(const char *dll, const char *api) {
    HMODULE h{NULL};
    if (h = GetModuleHandleA(dll); h == NULL) {
        h = LoadLibraryA(dll);
    }

    assert(h != NULL);
    return GetProcAddress(h, api);
}

} // namespace

//show hello world message box in target process
shell_code_t sc_hello_world_32() {
    return {};
}
shell_code_t sc_hello_world_64() {
    sc_helloworld_64_t sc;

    sc.prolog.param_size = sizeof(sc.msgbox_param) + sizeof(sc.exit_param);

    sc.msgbox_param.messagebox = (messagebox_t)get_api("user32.dll", "MessageBoxA");
    sc.exit_param.exitprocess = (exitprocess_t)get_api("kernel32.dll", "ExitProcess");

    sc.add_rbx.offset = sizeof(sc.msgbox_param); //(rbx) = &exit_param

    shell_code_t result;
    const uint8_t *p0 = (const uint8_t *)&sc;
    const uint8_t *p1 = (const uint8_t *)(&sc + 1);

    result.code.assign(p0, p1);
    result.entry = 0;
    return result;
}

shell_code_t sc_beep_64() {
    sc_beep_64_t sc;

    sc.prolog.param_size = sizeof(sc.beep_param) + sizeof(sc.exit_param);

    sc.beep_param.beep = (beep_t)get_api("user32.dll", "MessageBeep");
    sc.exit_param.exitprocess = (exitprocess_t)get_api("kernel32.dll", "ExitProcess");

    sc.add_rbx.offset = sizeof(sc.beep_param); //(rbx) = &exit_param

    shell_code_t result;
    const uint8_t *p0 = (const uint8_t *)&sc;
    const uint8_t *p1 = (const uint8_t *)(&sc + 1);

    result.code.assign(p0, p1);
    result.entry = 0;
    return result;
}

shell_code_t sc_beep_continue_64(const CONTEXT &cxt) {
    sc_beep_continue_64_t sc;

    sc.prolog.param_size = sizeof(sc.beep_param) + sizeof(sc.continue_param);

    sc.beep_param.beep = (beep_t)get_api("user32.dll", "MessageBeep");
    sc.continue_param.rsp = cxt.Rsp;
    sc.continue_param.rbp = cxt.Rbp;
    sc.continue_param.rax = cxt.Rax;
    sc.continue_param.rbx = cxt.Rbx;
    sc.continue_param.rcx = cxt.Rcx;
    sc.continue_param.rdx = cxt.Rdx;
    sc.continue_param.rsi = cxt.Rsi;
    sc.continue_param.rdi = cxt.Rdi;
    sc.continue_param.r8 = cxt.R8;
    sc.continue_param.r9 = cxt.R9;
    sc.continue_param.r10 = cxt.R10;
    sc.continue_param.r11 = cxt.R11;
    sc.continue_param.r12 = cxt.R12;
    sc.continue_param.r13 = cxt.R13;
    sc.continue_param.r14 = cxt.R14;
    sc.continue_param.r15 = cxt.R15;

    sc.add_rbx.offset = sizeof(sc.beep_param); //(rbx) = &continue_param

    shell_code_t result;
    const uint8_t *p0 = (const uint8_t *)&sc;
    const uint8_t *p1 = (const uint8_t *)(&sc + 1);

    result.code.assign(p0, p1);
    result.entry = 0;
    return result;
}

} // namespace CI::ut
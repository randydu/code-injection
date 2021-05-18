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

using beep_t = BOOL (WINAPI*)( UINT uType);
struct sc_beep_param_64_t {
    beep_t beep;
};
struct sc_call_beep_64_t {
    uint8_t set_type_to_0[2]{0x33, 0xc9};          //xor ecx, ecx
    uint8_t call[2]{0xff, 0x13};                   //call [rbx]
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

shell_code_t sc_beep_64(){
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

} // namespace CI::ut
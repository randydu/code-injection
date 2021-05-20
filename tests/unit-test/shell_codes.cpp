#include "shell_codes.h"

#include <cassert>
#include <code_injection/shell_code.hpp>

namespace CI::ut {

namespace {
#pragma pack(push, 1)

using messagebox_t = int(WINAPI *)(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType);

struct sc_helloworld_param_t {
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
struct sc_beep_param_t {
    beep_t beep;
};
struct sc_call_beep_t {
    uint8_t set_type_to_0[2]{0x33, 0xc9}; //xor ecx, ecx
    uint8_t call[2]{0xff, 0x13};          //call [rbx | ebx]
};



#pragma pack(pop)

} // namespace

//show hello world message box in target process
shell_code_t sc_hello_world_32(bool self_resolve_api) {
    CI::ci_error::raise(ci_error_code::FEATURE_NOT_IMPLEMENTED, "%s: not implemented", __FUNCTION__);
}
shell_code_t sc_hello_world_64(bool self_resolve_api) {
    if(self_resolve_api)
        CI::ci_error::raise(ci_error_code::FEATURE_NOT_IMPLEMENTED, "%s: self-resolve-api not implemented", __FUNCTION__);

    sc_helloworld_param_t param;
    param.messagebox = (messagebox_t)get_api("user32.dll", "MessageBoxA");

    return CI::shellcode::sc_compose(param, sc_helloworld_msgbox_64_t{}, shell_code_t::arch_t::X64);
}

shell_code_t sc_beep(bool self_resolve_api, shell_code_t::arch_t arch) {
    if(self_resolve_api)
        CI::ci_error::raise(ci_error_code::FEATURE_NOT_IMPLEMENTED, "%s: self-resolve-api not implemented", __FUNCTION__);
    sc_beep_param_t param;
    param.beep = (beep_t)get_api("user32.dll", "MessageBeep");

    return CI::shellcode::sc_compose(param, sc_call_beep_t{}, arch);
}

} // namespace CI::ut
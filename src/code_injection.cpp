#include "code_injection/code_injection.hpp"

#include <cassert>
#include <cstdarg>

#include "on_exit.h"

namespace CI {

namespace {

template <bool ansi = true>
struct type_trait_t {
    using char_t = char;
    using string_t = std::string;
    using startupinfo_t = STARTUPINFOA;
    using target_info_t = target_info_a;

    using create_process_t = BOOL(WINAPI *)(
        LPCSTR lpApplicationName,
        LPSTR lpCommandLine,
        LPSECURITY_ATTRIBUTES lpProcessAttributes,
        LPSECURITY_ATTRIBUTES lpThreadAttributes,
        BOOL bInheritHandles,
        DWORD dwCreationFlags,
        LPVOID lpEnvironment,
        LPCSTR lpCurrentDirectory,
        LPSTARTUPINFOA lpStartupInfo,
        LPPROCESS_INFORMATION lpProcessInformation);
    static constexpr create_process_t create_process = CreateProcessA;

    //literals
    static constexpr char_t quote = '"';
    static constexpr char_t space = ' ';
};

template <>
struct type_trait_t<false> {
    using char_t = wchar_t;
    using string_t = std::wstring;
    using startupinfo_t = STARTUPINFOW;
    using target_info_t = target_info_w;

    using create_process_t = BOOL(WINAPI *)(
        LPCWSTR lpApplicationName,
        LPWSTR lpCommandLine,
        LPSECURITY_ATTRIBUTES lpProcessAttributes,
        LPSECURITY_ATTRIBUTES lpThreadAttributes,
        BOOL bInheritHandles,
        DWORD dwCreationFlags,
        LPVOID lpEnvironment,
        LPCWSTR lpCurrentDirectory,
        LPSTARTUPINFOW lpStartupInfo,
        LPPROCESS_INFORMATION lpProcessInformation);
    static constexpr create_process_t create_process = CreateProcessW;
    //literals
    static constexpr char_t quote = L'"';
    static constexpr char_t space = L' ';
};

template <bool ansi, typename target_info_t = type_trait_t<ansi>::target_info_t>
void launch_target(const target_info_t &target, PROCESS_INFORMATION &pi) {
    using startupinfo_t = typename type_trait_t<ansi>::startupinfo_t;
    using char_t = typename type_trait_t<ansi>::char_t;
    using string_t = typename type_trait_t<ansi>::string_t;
    constexpr auto create_process = type_trait_t<ansi>::create_process;
    constexpr auto quote = type_trait_t<ansi>::quote;
    constexpr auto space = type_trait_t<ansi>::space;

    startupinfo_t si{0};
    si.cb = sizeof(si);

    memset(&pi, 0, sizeof(pi));

    assert(!target.exe_path.empty()); //exe must be specified!

    string_t cmdline;
    if (!target.params.empty()) {
        cmdline = quote;
        cmdline += target.exe_path;
        cmdline += quote;
        cmdline += space;
        cmdline += target.params;
    }

    if (!create_process(target.exe_path.c_str(), cmdline.empty() ? NULL : (char_t *)cmdline.c_str(),
                        NULL, NULL, FALSE, CREATE_SUSPENDED, NULL,
                        target.cur_dir.empty() ? NULL : target.cur_dir.c_str(), &si, &pi)) {
        ci_error::raise(ci_error_code::TARGET_LAUNCH_FAILURE, "CreateProcess fails, error-code: [%d]", GetLastError());
    }
}

template <bool ansi, typename target_info_t = type_trait_t<ansi>::target_info_t>
void launch_inject(const target_info_t &target, const shell_code_t &sc, func_injector_t injector, inject_option_t opt) {
    PROCESS_INFORMATION pi;
    launch_target<ansi>(target, pi);
    ON_EXIT({
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    });

    injector(pi, sc, opt);

    if (ResumeThread(pi.hThread) == -1) {
        ci_error::raise(ci_error_code::TARGET_LAUNCH_FAILURE, "ResumeThread fails, error-code: [%d]", GetLastError());
    }
    if (target.wait_until_initialized && (WaitForInputIdle(pi.hProcess, target.wait_timeout) == WAIT_FAILED)) {
        ci_error::raise(ci_error_code::TARGET_LAUNCH_FAILURE, "WaitForInputIdle fails, error-code: [%d]", GetLastError());
    }
}

// shell-code of dll loading
struct dll_param_64_t {
    uint64_t load_library;     //LoadLibrary
    uint64_t get_proc_address; //GetProcAddress

    int64_t dllname_offset; //offset of dll-name (relative to &dll_param_t)
    int64_t apiname_offset; //offset of api-name (relative to &dll_param_t)
    int64_t param_offset;   //offset of optional api-parameter (<0: no parameter)
};
struct dll_param_32_t {
    uint32_t load_library;     //LoadLibrary
    uint32_t get_proc_address; //GetProcAddress

    int32_t dllname_offset; //offset of dll-name (relative to &dll_param_t)
    int32_t apiname_offset; //offset of api-name (relative to &dll_param_t)
    int32_t param_offset;   //offset of optional api-parameter (<0: no parameter)
};

struct dll_code_64_t {
    uint8_t _0[3]{0x48, 0x8b, 0xcb};       //mov rcx, rbx
    uint8_t _1[4]{0x48, 0x03, 0x4b, 0x10}; //add rcx, [rbx + 16]   ; dllname
    uint8_t _2[2]{0xff, 0x13};             //call [rbx]            ; load_library(dllname)
    uint8_t _3[3]{0x48, 0x85, 0xc0};       //test rax, rax
    uint8_t _4[2]{0x74, 0x20};             //jz quit
    //
    uint8_t _5[3]{0x48, 0x8b, 0xc8};       //mov rcx, rax          ; hModule
    uint8_t _6[3]{0x48, 0x8b, 0xd3};       //mov rdx, rbx
    uint8_t _7[4]{0x48, 0x03, 0x53, 0x18}; //add rdx, [rbx + 3*8]   ;api-name
    uint8_t _8[3]{0xff, 0x53, 0x08};       //call [rbx + 8];       ; get_proc_address
    uint8_t _9[3]{0x48, 0x85, 0xc0};       //test rax, rax
    uint8_t _10[2]{0x74, 0x0e};            //jz quit
    //
    uint8_t _11[4]{0x48, 0x8b, 0x4b, 0x20}; //mov rcx, [rbx + 4*8]
    uint8_t _12[3]{0x48, 0x85, 0xc9};       //test rcx, rcx         ;offset == 0 if no param
    uint8_t _13[2]{0x74, 0x03};             //jz no_param
    uint8_t _14[3]{0x48, 0x03, 0xcb};       //add rcx, rbx          ;void * param
    //
    //no_param:
    uint8_t _15[2]{0xff, 0xd0}; //call rax
    //
    //quit:
};

void get_param_bytes(std::any param, std::vector<uint8_t> &vec) {
    if (!param.has_value())
        return;

    const auto &tid = param.type();
    try {
        if (tid == typeid(bool)) {
            auto x = std::any_cast<bool>(param);
            CI::shellcode::sc_append(vec, x);
        }
        if (tid == typeid(int)) {
            auto x = std::any_cast<int>(param);
            CI::shellcode::sc_append(vec, x);
        }
        if (tid == typeid(float)) {
            auto x = std::any_cast<float>(param);
            CI::shellcode::sc_append(vec, x);
        }
        if (tid == typeid(double)) {
            auto x = std::any_cast<double>(param);
            CI::shellcode::sc_append(vec, x);
        }
        if (tid == typeid(std::string)) {
            auto x = std::any_cast<std::string>(param);
            CI::shellcode::sc_append(vec, x.c_str(), true);
        }
    } catch (const std::bad_any_cast &e) {
    }
}

shell_code_t prepare_shell_code(const injected_dll_a &dll) {
    dll_param_64_t param;

    auto knl = GetModuleHandleA("kernel32.dll");
    param.load_library = (uint64_t)GetProcAddress(knl, "LoadLibraryA");
    param.get_proc_address = (uint64_t)GetProcAddress(knl, "GetProcAddress");

    const int param_size = sizeof(param);
    param.dllname_offset = param_size;
    param.apiname_offset = param_size + (dll.dll_path.size() + 1);                                            //dll-path includes ending zero
    param.param_offset = !dll.proc_param.has_value() ? 0 : param.apiname_offset + (dll.proc_name.size() + 1); //proc-name includes ending zero

    std::vector<uint8_t> vec_param;
    get_param_bytes(dll.proc_param, vec_param);
    int len = param_size + (dll.dll_path.size() + 1) + (dll.proc_name.size() + 1) + vec_param.size();
    void *p = malloc(len);
    ON_EXIT(free(p));

    memset(p, 0, len);

    char *ptr = (char *)p;
    
    strcpy(ptr, dll.dll_path.c_str());
    ptr += (dll.dll_path.size() + 1);

    strcpy(ptr, dll.proc_name.c_str());
    ptr += (dll.proc_name.size() + 1);
    
    if (dll.proc_param.has_value())
        memcpy(ptr, vec_param.data(), vec_param.size());

    std::vector<uint8_t> v;
    CI::shellcode::sc_append(v, param);
    CI::shellcode::sc_append(v, p, len);

    dll_code_64_t dc;
    return CI::shellcode::sc_compose(v.data(), v.size(), &dc, sizeof(dc));
}

shell_code_t prepare_shell_code(const injected_dll_w &dll) {
    return {};
}

} // namespace

void ci_error::raise(ci_error_code err, const char *fmt, ...) {
    std::va_list args;
    va_start(args, fmt);

    char buf[2048];
    vsprintf_s(buf, fmt, args);
    va_end(args);

    throw ci_error(err, buf);
}

//launch target and inject
void launch_inject(const target_info_a &target, const injected_dll_a &dll, func_injector_t injector, inject_option_t opt) {
    const auto &sc = prepare_shell_code(dll);
    launch_inject(target, sc, injector, opt);
}
void launch_inject(const target_info_w &target, const injected_dll_w &dll, func_injector_t injector, inject_option_t opt) {
    const auto &sc = prepare_shell_code(dll);
    launch_inject(target, sc, injector, opt);
}
void launch_inject(const target_info_a &target, const shell_code_t &sc, func_injector_t injector, inject_option_t opt) {
    launch_inject<true>(target, sc, injector, opt);
}
void launch_inject(const target_info_w &target, const shell_code_t &sc, func_injector_t injector, inject_option_t opt) {
    launch_inject<false>(target, sc, injector, opt);
}

//inject into running target
void inject(const target_info_a &target, const injected_dll_a &dll, func_injector_t injector, inject_option_t opt) {
    const auto &sc = prepare_shell_code(dll);
    inject(target, sc, injector, opt);
}
void inject(const target_info_w &target, const injected_dll_w &dll, func_injector_t injector, inject_option_t opt) {
    const auto &sc = prepare_shell_code(dll);
    inject(target, sc, injector, opt);
}
void inject(const target_info_a &target, const shell_code_t &sc, func_injector_t injector, inject_option_t opt) {
}
void inject(const target_info_w &target, const shell_code_t &sc, func_injector_t injector, inject_option_t opt) {}

void *get_api(const char *dll, const char *api) {
    HMODULE h{NULL};
    if (h = GetModuleHandleA(dll); h == NULL) {
        h = LoadLibraryA(dll);
    }

    assert(h != NULL);
    return GetProcAddress(h, api);
}
} // namespace CI
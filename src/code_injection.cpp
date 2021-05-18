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
void launch_inject(const target_info_t &target, const shell_code_t &sc, func_injector_t injector) {
    PROCESS_INFORMATION pi;
    launch_target<ansi>(target, pi);
    ON_EXIT({
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    });

    injector(pi, sc);

    if (ResumeThread(pi.hThread) == -1) {
        ci_error::raise(ci_error_code::TARGET_LAUNCH_FAILURE, "ResumeThread fails, error-code: [%d]", GetLastError());
    }
    if (target.wait_until_initialized && (WaitForInputIdle(pi.hProcess, target.wait_timeout) == WAIT_FAILED)) {
        ci_error::raise(ci_error_code::TARGET_LAUNCH_FAILURE, "WaitForInputIdle fails, error-code: [%d]", GetLastError());
    }
}

template <typename injected_dll_t>
void prepare_shell_code(const injected_dll_t &dll, shell_code_t &sc) {
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
void launch_inject(const target_info_a &target, const injected_dll_a &dll, func_injector_t injector) {
    shell_code_t sc;
    prepare_shell_code(dll, sc);
    launch_inject(target, sc, injector);
}
void launch_inject(const target_info_w &target, const injected_dll_w &dll, func_injector_t injector) {
    shell_code_t sc;
    prepare_shell_code(dll, sc);
    launch_inject(target, sc, injector);
}
void launch_inject(const target_info_a &target, const shell_code_t &sc, func_injector_t injector) {
    launch_inject<true>(target, sc, injector);
}
void launch_inject(const target_info_w &target, const shell_code_t &sc, func_injector_t injector) {
    launch_inject<false>(target, sc, injector);
}

//inject into running target
void inject(const target_info_a &target, const injected_dll_a &dll, func_injector_t injector) {
    shell_code_t sc;
    prepare_shell_code(dll, sc);
    inject(target, sc, injector);
}
void inject(const target_info_w &target, const injected_dll_w &dll, func_injector_t injector) {
    shell_code_t sc;
    prepare_shell_code(dll, sc);
    inject(target, sc, injector);
}
void inject(const target_info_a &target, const shell_code_t &sc, func_injector_t injector) {
}
void inject(const target_info_w &target, const shell_code_t &sc, func_injector_t injector) {}

} // namespace CI
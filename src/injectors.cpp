#include "code_injection/injectors.hpp"

namespace CI {

namespace {

template <typename T>
struct inject_helper {
    typedef T context_t;
    static void get_thread_context(HANDLE hThread, context_t &cxt) {
        if (!GetThreadContext(hThread, &cxt))
            ci_error::raise(ci_error_code::TARGET_INJECT_FAILURE, "GetThreadContext fails, err-code: [%d]", GetLastError());
    }
    static void set_thread_context(HANDLE hThread, const context_t &cxt) {
        if (!SetThreadContext(hThread, &cxt))
            ci_error::raise(ci_error_code::TARGET_INJECT_FAILURE, "SetThreadContext fails, err-code: [%d]", GetLastError());
    }
    static void set_ip(context_t &cxt, void *p) {
#ifdef _WIN64
        cxt.Rip = (uint64_t)p;
#else
        cxt.Eip = (uint32_t)p;
#endif
    }
};

template <>
struct inject_helper<WOW64_CONTEXT> {
    typedef WOW64_CONTEXT context_t;
    static void get_thread_context(HANDLE hThread, context_t &cxt) {
        if (!Wow64GetThreadContext(hThread, &cxt))
            ci_error::raise(ci_error_code::TARGET_INJECT_FAILURE, "Wow64GetThreadContext fails, err-code: [%d]", GetLastError());
    };
    static void set_thread_context(HANDLE hThread, const context_t &cxt) {
        if (!Wow64SetThreadContext(hThread, &cxt))
            ci_error::raise(ci_error_code::TARGET_INJECT_FAILURE, "Wow64SetThreadContext fails, err-code: [%d]", GetLastError());
    }
    static void set_ip(context_t &cxt, void *p) {
        cxt.Eip = (uint64_t)p;
    }
};

template <typename T>
void impl_inject_context(const PROCESS_INFORMATION &pi, const shell_code_t &sc, inject_option_t opt, bool shellcode_resolve_api) {
    T cxt{0};
    cxt.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER;

    inject_helper<T>::get_thread_context(pi.hThread, cxt);

    const shell_code_t *psc = &sc;

    shell_code_t composed_sc;

    switch (opt) {
    case inject_option_t::INJECT_EXITPROCESS:
        composed_sc = sc + CI::shellcode::sc_exit_process(0, shellcode_resolve_api, sc.arch);
        psc = &composed_sc;
        break;
    case inject_option_t::INJECT_RESUME:
        composed_sc = sc + CI::shellcode::sc_resume(cxt);
        psc = &composed_sc;
        break;
    case inject_option_t::INJECT_NONE:
        //do nothing
        break;
    };

    auto len = psc->code.size();
    auto p = VirtualAllocEx(pi.hProcess, NULL, len, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (p == NULL)
        ci_error::raise(ci_error_code::TARGET_INJECT_FAILURE, "VirtualAllocEx fails, err-code: [%d]", GetLastError());

    printf("injector: remote sc address = %I64X\n", (uint64_t)p);

    if (!WriteProcessMemory(pi.hProcess, p, psc->code.data(), len, NULL))
        ci_error::raise(ci_error_code::TARGET_INJECT_FAILURE, "WriteProcessMemory fails, err-code: [%d]", GetLastError());

    inject_helper<T>::set_ip(cxt, (char *)p + psc->entry);

    cxt.ContextFlags = CONTEXT_CONTROL;
    inject_helper<T>::set_thread_context(pi.hThread, cxt);
}

} // namespace

void inject_context(const PROCESS_INFORMATION &pi, const shell_code_t &sc, inject_option_t opt) {
    BOOL is_WOW64;
    if (!IsWow64Process(pi.hProcess, &is_WOW64))
        ci_error::raise(ci_error_code::TARGET_INJECT_FAILURE, "IsWow64Process fails, err-code: [%d]", GetLastError());

    printf("WOW64: %d\n", is_WOW64);

#ifdef _WIN64
    if (is_WOW64) {
        impl_inject_context<WOW64_CONTEXT>(pi, sc, opt, true); //64 => 32
    } else {
        impl_inject_context<CONTEXT>(pi, sc, opt, false); //64 => 64
    }
#else
    if (is_WOW64) {
        impl_inject_context<CONTEXT>(pi, sc, opt, false); //32 => 32
    } else {
        //32=>64 code injection not supported.
        ci_error::raise(ci_error_code::TARGET_INJECT_FAILURE, "%s: 32 => 64 injection not supported", __FUNCTION__);
    }
#endif
}
} // namespace CI
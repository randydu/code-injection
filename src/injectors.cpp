#include "code_injection/injectors.hpp"

namespace CI {

void inject_context(const PROCESS_INFORMATION &pi, const shell_code_t &sc, inject_option_t opt) {
    CONTEXT cxt{0};
    cxt.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER;

    if (!GetThreadContext(pi.hThread, &cxt))
        ci_error::raise(ci_error_code::TARGET_INJECT_FAILURE, "GetThreadContext fails, err-code: [%d]", GetLastError());

    const shell_code_t * psc = &sc;

    shell_code_t composed_sc;

    switch (opt) {
    case inject_option_t::INJECT_EXITPROCESS:
        composed_sc = sc + CI::shellcode::sc_exit_process(0);
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

    cxt.Rip = (uint64_t)p + psc->entry;
    cxt.ContextFlags = CONTEXT_CONTROL;
    if (!SetThreadContext(pi.hThread, &cxt))
        ci_error::raise(ci_error_code::TARGET_INJECT_FAILURE, "SetThreadContext fails, err-code: [%d]", GetLastError());
}
} // namespace CI
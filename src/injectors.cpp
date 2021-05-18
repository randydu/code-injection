#include "code_injection/injectors.hpp"

namespace CI {
void inject_context(const PROCESS_INFORMATION &pi, const shell_code_t &sc) {
   // MessageBoxA(NULL, "Hi", "xxx", MB_OK);
    
    CONTEXT cxt{0};
    cxt.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER;

    if (!GetThreadContext(pi.hThread, &cxt))
        ci_error::raise(ci_error_code::TARGET_INJECT_FAILURE, "GetThreadContext fails, err-code: [%d]", GetLastError());

    auto len = sc.code.size();
    auto p = VirtualAllocEx(pi.hProcess, NULL, len, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (p == NULL)
        ci_error::raise(ci_error_code::TARGET_INJECT_FAILURE, "VirtualAllocEx fails, err-code: [%d]", GetLastError());

    printf("injector: remote sc address = %I64X\n", (uint64_t)p);

    if (!WriteProcessMemory(pi.hProcess, p, sc.code.data(), len, NULL))
        ci_error::raise(ci_error_code::TARGET_INJECT_FAILURE, "WriteProcessMemory fails, err-code: [%d]", GetLastError());

    cxt.Rip = (uint64_t)p;
    cxt.ContextFlags = CONTEXT_CONTROL;
    if (!SetThreadContext(pi.hThread, &cxt))
        ci_error::raise(ci_error_code::TARGET_INJECT_FAILURE, "SetThreadContext fails, err-code: [%d]", GetLastError());
}
} // namespace CI
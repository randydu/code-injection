#include "code_injection/code_injection.hpp"

namespace CI {

namespace {
void launch_target(const target_info_t &target, PROCESS_INFORMATION &pi) {}

void prepare_shell_code(const injected_dll_t &dll, shell_code_t &sc) {}
} // namespace

//launch target and inject
void launch_inject(const target_info_t &target, const injected_dll_t &dll, func_injector_t injector) {
    shell_code_t sc;
    prepare_shell_code(dll, sc);

    launch_inject(target, sc, injector);
}

void launch_inject(const target_info_t &target, const shell_code_t &shellcode, func_injector_t injector) {
    PROCESS_INFORMATION pi;
    launch_target(target, pi);

    injector(pi, shellcode);
}

//inject into running target
void inject(const target_info_t &target, const injected_dll_t &dll, func_injector_t injector) {
    shell_code_t sc;
    prepare_shell_code(dll, sc);

    inject(target, sc, injector);
}

void inject(const target_info_t &target, const shell_code_t &shellcode, func_injector_t injector) {}
} // namespace CI
#ifndef CODE_INJECTION_H_
#define CODE_INJECTION_H_

#include <any>
#include <functional>
#include <string>

#include <windows.h>

namespace CI {

struct shell_code_t {
    std::vector<uint8_t> code; //shell code content
    int entry;                 //entry point offset in the code (index of the code vector)
};

//details of injected dll
struct injected_dll_t {
    std::string dll_path;  //full path to the injected dll
    std::string proc_name; //name of procedure to call after dll loading
    std::any proc_param;   //optional proc parameter. If has not value, the proc has no input parameter.
};

//details of injecting target
struct target_info_t {
    std::string exe_path; //full path to target exe
};

using func_injector_t = std::function<void(const PROCESS_INFORMATION &, const shell_code_t&)>;

//launch target and inject
void launch_inject(const target_info_t &target, const injected_dll_t &dll, func_injector_t injector);
void launch_inject(const target_info_t &target, const shell_code_t &shellcode, func_injector_t injector);

//inject into running target
void inject(const target_info_t &target, const injected_dll_t &dll, func_injector_t injector);
void inject(const target_info_t &target, const shell_code_t &shellcode, func_injector_t injector);

} // namespace CI

#endif
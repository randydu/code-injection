#ifndef CODE_INJECTION_H_
#define CODE_INJECTION_H_

#include <any>
#include <functional>
#include <string>

#include <windows.h>

#include "shell_code.hpp"

using shell_code_t = CI::shellcode::shell_code_t;

namespace CI {
//details of injected dll
template <typename T>
struct injected_dll_t {
    typedef typename T::value_type char_t;

    bool is_64bit{false};  //64 bit or 32 bit?
    T dll_path;            //full path to the injected dll
    std::string proc_name; //name of procedure to call after dll loading
    std::any proc_param;   //optional proc parameter. If has not value, the proc has no input parameter.
};

//details of injecting target
template <typename T>
struct target_info_t {
    bool is_64bit{false}; //64 bit or 32 bit?

    T exe_path; //full path to target exe
    T params;   //command line parameters
    T cur_dir;  //current directory

    bool wait_until_initialized{false}; //wait until target process has finished its initialization
                                        //and is waiting gor user input with no input pending.
    DWORD wait_timeout{INFINITE};       //time-out intervals in milliseconds.
                                        //INFINITE: wait until the process is idle.
};

enum inject_option_t {
    INJECT_NONE,        //do nothing after injected shellcode is executed, its behavior depends on the shellcode.
    INJECT_EXITPROCESS, //exit target process after injected shellcode is executed.
    INJECT_RESUME,      //resume target process running after injected shellcode is executed
};

using func_injector_t = std::function<void(const PROCESS_INFORMATION &, const shell_code_t &, inject_option_t)>;

using target_info_a = target_info_t<std::string>;
using target_info_w = target_info_t<std::wstring>;

using injected_dll_a = injected_dll_t<std::string>;
using injected_dll_w = injected_dll_t<std::wstring>;

//launch target and inject
void launch_inject(const target_info_a &target, const injected_dll_a &dll, func_injector_t injector, inject_option_t opt = INJECT_NONE);
void launch_inject(const target_info_w &target, const injected_dll_w &dll, func_injector_t injector, inject_option_t opt = INJECT_NONE);
void launch_inject(const target_info_a &target, const shell_code_t &sc, func_injector_t injector, inject_option_t opt = INJECT_NONE);
void launch_inject(const target_info_w &target, const shell_code_t &sc, func_injector_t injector, inject_option_t opt = INJECT_NONE);

//inject into running target
void inject(const target_info_a &target, const injected_dll_a &dll, func_injector_t injector, inject_option_t opt = INJECT_NONE);
void inject(const target_info_w &target, const injected_dll_w &dll, func_injector_t injector, inject_option_t opt = INJECT_NONE);
void inject(const target_info_a &target, const shell_code_t &sc, func_injector_t injector, inject_option_t opt = INJECT_NONE);
void inject(const target_info_w &target, const shell_code_t &sc, func_injector_t injector, inject_option_t opt = INJECT_NONE);

//util
void *get_api(const char *dll, const char *api);
} // namespace CI

#endif
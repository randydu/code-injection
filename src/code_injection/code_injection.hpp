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
};

struct inject_option_t {
    // wait behavior
    bool wait_target{false};           //wait until target process has finished its initialization
                                       //and is waiting for user input with no input pending.
    bool wait_before_injection{false}; //true: wait before injecting, false: wait after injecting
    DWORD wait_timeout{INFINITE};      //time-out intervals in milliseconds.  INFINITE: wait until the process is idle.

    // exit behavior
    enum exit_opt_t {
        EXIT_NONE,        //do nothing after injected shellcode is executed, its behavior depends on the shellcode.
        EXIT_EXITPROCESS, //exit target process after injected shellcode is executed.
        EXIT_RESUME,      //resume target process running after injected shellcode is executed
    };
    exit_opt_t exit_opt{exit_opt_t::EXIT_RESUME};
};

using func_injector_t = std::function<void(const PROCESS_INFORMATION &, const shell_code_t &, const inject_option_t &, bool WOW64)>;

using target_info_a = target_info_t<std::string>;
using target_info_w = target_info_t<std::wstring>;

using injected_dll_a = injected_dll_t<std::string>;
using injected_dll_w = injected_dll_t<std::wstring>;

//launch target and inject
void launch_inject(const target_info_a &target, const injected_dll_a &dll, func_injector_t injector, const inject_option_t &opt);
void launch_inject(const target_info_w &target, const injected_dll_w &dll, func_injector_t injector, const inject_option_t &opt);
void launch_inject(const target_info_a &target, const shell_code_t &sc, func_injector_t injector, const inject_option_t &opt);
void launch_inject(const target_info_w &target, const shell_code_t &sc, func_injector_t injector, const inject_option_t &opt);

//inject into running target
void inject(const target_info_a &target, const injected_dll_a &dll, func_injector_t injector, const inject_option_t &opt);
void inject(const target_info_w &target, const injected_dll_w &dll, func_injector_t injector, const inject_option_t &opt);
void inject(const target_info_a &target, const shell_code_t &sc, func_injector_t injector, const inject_option_t &opt);
void inject(const target_info_w &target, const shell_code_t &sc, func_injector_t injector, const inject_option_t &opt);

//util
void *get_api(const char *dll, const char *api);
} // namespace CI

#endif
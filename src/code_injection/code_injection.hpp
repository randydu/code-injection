#ifndef CODE_INJECTION_H_
#define CODE_INJECTION_H_

#include <any>
#include <exception>
#include <functional>
#include <string>

#include <windows.h>

namespace CI {
enum ci_error_code {
    UNKNOWN = -1,                 //unknown error
    INVALID_ARG = -2,             //invalid argument
    FEATURE_NOT_IMPLEMENTED = -3, //some feature is not implemented yet.
    TARGET_LAUNCH_FAILURE = -4,   //cannot launch target
};

class ci_error : public std::exception {
  private:
    ci_error_code _err;

  public:
    ci_error(ci_error_code err, const char *msg) : std::exception(msg), _err(err) {}
    ci_error_code error() const { return _err; }
    [[noreturn]] static void raise(ci_error_code err, const char *fmt, ...);
};

struct shell_code_t {
    std::vector<uint8_t> code; //shell code content
    int entry;                 //entry point offset in the code (index of the code vector)
};

//details of injected dll
template <typename T>
struct injected_dll_t {
    T dll_path;          //full path to the injected dll
    T proc_name;         //name of procedure to call after dll loading
    std::any proc_param; //optional proc parameter. If has not value, the proc has no input parameter.
};

//details of injecting target
template <typename T>
struct target_info_t {
    T exe_path; //full path to target exe
    T params;   //command line parameters
    T cur_dir;  //current directory
};

using func_injector_t = std::function<void(const PROCESS_INFORMATION &, const shell_code_t &)>;

using target_info_a = target_info_t<std::string>;
using target_info_w = target_info_t<std::wstring>;

using injected_dll_a = injected_dll_t<std::string>;
using injected_dll_w = injected_dll_t<std::wstring>;

//launch target and inject
void launch_inject(const target_info_a &target, const injected_dll_a &dll, func_injector_t injector);
void launch_inject(const target_info_w &target, const injected_dll_w &dll, func_injector_t injector);
void launch_inject(const target_info_a &target, const shell_code_t &sc, func_injector_t injector);
void launch_inject(const target_info_w &target, const shell_code_t &sc, func_injector_t injector);

//inject into running target
void inject(const target_info_a &target, const injected_dll_a &dll, func_injector_t injector);
void inject(const target_info_w &target, const injected_dll_w &dll, func_injector_t injector);
void inject(const target_info_a &target, const shell_code_t &sc, func_injector_t injector);
void inject(const target_info_w &target, const shell_code_t &sc, func_injector_t injector);

} // namespace CI

#endif
#ifndef CI_ERROR_HPP
#define CI_ERROR_HPP

#include <exception>

namespace CI {
enum ci_error_code {
    UNKNOWN = -1,                 //unknown error
    INVALID_ARG = -2,             //invalid argument
    FEATURE_NOT_IMPLEMENTED = -3, //some feature is not implemented yet.
    TARGET_LAUNCH_FAILURE = -4,   //cannot launch target
    TARGET_INJECT_FAILURE = -5,   //cannot inject to target
};

class ci_error : public std::exception {
  private:
    ci_error_code _err;

  public:
    ci_error(ci_error_code err, const char *msg) : std::exception(msg), _err(err) {}
    ci_error_code error() const { return _err; }
    [[noreturn]] static void raise(ci_error_code err, const char *fmt, ...);
};
} // namespace CI

#endif
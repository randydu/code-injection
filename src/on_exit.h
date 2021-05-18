#ifndef ON_EXIT_H_
#define ON_EXIT_H_

#include <utility>

namespace {
template <typename T>
class exit_exec {
  private:
    T f_;

  public:
    exit_exec(T &&f) : f_(std::forward<T>(f)) {}
    ~exit_exec() { f_(); }
};

template <typename T, typename U = exit_exec<T>>
inline U make_on_exit(T &&f) {
    return U(std::forward<T>(f));
}
} // namespace

#define COMBINE1(X, Y) X##Y // helper macro
#define COMBINE(X, Y) COMBINE1(X, Y)

#define ON_EXIT(code) auto COMBINE(exit_exec, __LINE__) = make_on_exit([&]() { code; })

#endif
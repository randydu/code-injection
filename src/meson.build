srcs = [ 'code_injection.cpp', 'injectors.cpp' ]

lib_code_injection = static_library('code_injection', srcs, dependencies: [])

code_injection_dep = declare_dependency(include_directories: '.', link_with: lib_code_injection)
Build With Meson
=================

This project is built with meson and vc2019 on Win10/x64 platform. However, any Windows version that can run meson-build and c++17 compiler will do.

My favorite IDE is VSCode, however it is not necessary for the project build, the project build is based on meson and can be done in command line.

Toolkit: 
------

* C++ Compiler: [VC2019 community](https://visualstudio.microsoft.com/vs/community/);
* Build System: [meson-build](https://mesonbuild.com/index.html);
* IDE: [Visual Studio Code](https://code.visualstudio.com/);
* OS: Windows 10;



To build targets with the minimum dll-dependency, it is recommended to build project with runtime static-link.


Before starting build in a terminal console, we need to setup correct build environment for either 32-bit or 64-bit build, the following two batch files are copied from VC2019 installation, I just copy them to a folder in the PATH environment so they can be invoked anywhere without specifying the long path.

vc32.bat

```bat
%comspec% /k "C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\VC\Auxiliary\Build\vcvars32.bat"
```

vc64.bat

```bat
%comspec% /k "C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\VC\Auxiliary\Build\vcvars64.bat"
```

The following build steps are executed in command console, %PRJ_ROOT% is the root directory of this project (with .git subfolder).

x86 build
---------

Setup 32-bit build environment:
```
cd %PRJ_ROOT%
vc32.bat
```
 
Initialize build sub-folders with meson:

```
# 32-bit Release
meson setup output\release\32 --buildtype=release -Ddebug=false -Db_vscrt=mt

# 32-bit Release (minsize)
meson setup output\release\32s_minsize --buildtype=custom -Ddebug=false -Doptimization=s -Db_vscrt=mt

# 32-bit Debug
meson setup output\debug\32 --buildtype=debug -Ddebug=true -Db_vscrt=mtd
```

x64 build
---------

Setup 64-bit build environment:
```
cd %PRJ_ROOT%
vc64.bat
```

Initialize build sub-folders with meson:

```
# 64-bit Release
meson setup output\release\64 --buildtype=release -Ddebug=false -Db_vscrt=mt

# 64-bit Release (minsize)
meson setup output\release\64_minsize --buildtype=custom -Ddebug=false -Doptimization=s -Db_vscrt=mt 

# 64-bit Debug
meson setup output\debug\64 --buildtype=debug -Db_vscrt=mtd
```

Start building:

Just goes to any output directory and invoke "ninja":

For example:

```
cd output\debug\64
ninja

cd output\release\64
ninja
```

Done!


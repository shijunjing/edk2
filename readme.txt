Windows:
c:\steven\edk2-fork>set CLANG_BIN=C:\steven\LLVM\llvm-project\_build_debug\RelWithDebInfo\bin\
c:\steven\edk2-fork>build -p EmulatorPkg\EmulatorPkg.dsc -a IA32 -t CLANGPDB -DWIN_HOST_BUILD=TRUE
c:\steven\edk2-fork>cd Build\EmulatorIA32\DEBUG_CLANGPDB\IA32
c:\steven\edk2-fork\Build\EmulatorIA32\DEBUG_CLANGPDB\IA32>WinHost.exe

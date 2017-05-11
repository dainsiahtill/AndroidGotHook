#include <stdio.h>
#include <elf.h>

void PatchRemoteGot(pid_t pid, const char* libPath, long origFuncAddr, long hookFuncAddr);
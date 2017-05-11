#include <stdio.h>
#include <stdbool.h>
#include <sys/types.h>

bool CheckSelinuxEnabled();
void DisableSelinux();
pid_t GetPid(const char* processName);
long GetModuleBase(pid_t pid, const char* libPath);
long GetRemoteFuncAddr(pid_t remotePid, const char* libPath, long localFuncAddr);
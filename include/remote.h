#include <stdio.h>
#include <sys/types.h>

#define LIBC_PATH "/system/lib/libc.so"
#define LINKER_PATH "/system/bin/linker"

//base
long RemotePrintf(pid_t pid, const char* content);
long RemotePerror(pid_t pid);
long RemoteKill(pid_t pid);

//maps
long RemoteMmap(pid_t pid, size_t length);
long RemoteMunmap(pid_t pid, long addr, size_t length);

//dl
long RemoteDlopen(pid_t pid, const char* libPath);
long RemoteDlsym(pid_t pid, long soHandle, const char* symbol);
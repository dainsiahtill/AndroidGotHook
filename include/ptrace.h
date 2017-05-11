#include <stdio.h>
#include <sys/types.h>
#include <stdint.h>

int PtraceAttach(pid_t pid);
int PtraceDetach(pid_t pid);
void PtraceWrite(pid_t pid, uint8_t* addr, uint8_t* data, size_t size);
long CallRemoteFunc(pid_t pid, long funcAddr, long* args, size_t argc);
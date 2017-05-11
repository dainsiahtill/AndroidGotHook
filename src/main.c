#include <stdio.h>
#include <sys/ptrace.h>  
#include <sys/types.h>  
#include <sys/wait.h>  
#include <unistd.h>  
#include <linux/user.h>  
#include <sys/syscall.h>
#include "include/utils.h"
#include "include/remote.h"
#include "include/inject.h"
#include "include/ptrace.h"
#include "include/elf_helper.h"

typedef void (*TestProc)(const char*);

int main(int argc, char **argv) 
{   
	if (argc < 2)
		return -1;

	char* targetProcess = argv[1];
	char* hookLibPath = argv[2];
	char* targetLibPath = argv[3];

	printf("target process: %s\n", targetProcess);
	printf("hookLibPath: %s\n", hookLibPath);
	printf("targetLibPath: %s\n", targetLibPath);

	pid_t targetPid = GetPid(targetProcess);

	printf("target pid: %d\n", targetPid);

	if (targetPid != -1)
	{
		long handle = InjectLib(targetPid, hookLibPath);
		
		if (handle != 0)
		{
			PtraceAttach(targetPid);
			long hookFuncAddr = RemoteDlsym(targetPid, handle, "test");
			PtraceDetach(targetPid);
			long origFuncAddr = GetRemoteFuncAddr(targetPid, LIBC_PATH, (long)printf);

			PatchRemoteGot(targetPid, targetLibPath, origFuncAddr, hookFuncAddr);
		}
	}

    return 0;  
} 

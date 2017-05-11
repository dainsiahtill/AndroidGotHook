#include <sys/mman.h>
#include <stdlib.h>
#include <stdio.h>
#include <signal.h>
#include <dlfcn.h>

#include "include/remote.h"
#include "include/ptrace.h"
#include "include/utils.h"


long RemotePrintf(pid_t pid, const char* content)
{
	size_t contentLen = strlen(content);
	size_t size = contentLen + 1;

	#ifdef DEBUG
	printf("RemotePrintf: %d %s %d\n", pid, content, contentLen);
	#endif

	long mmapRet = RemoteMmap(pid, size);
	PtraceWrite(pid, (uint8_t*)mmapRet, (uint8_t*)content, size);

	long funcAddr = GetRemoteFuncAddr(pid, LIBC_PATH, ((long) (void*)printf));
	long params[1];
	params[0] = mmapRet;

	long result = CallRemoteFunc(pid, funcAddr, params, 1);

	RemoteMunmap(pid, mmapRet, size);

	return result;
}

long RemotePerror(pid_t pid)
{
	#ifdef DEBUG
	printf("RemotePerror: %d \n", pid);
	#endif

	long funcAddr = GetRemoteFuncAddr(pid, LIBC_PATH, ((long) (void*)perror));
	long params[1];
	params[0] = 0;

	return CallRemoteFunc(pid, funcAddr, params, 1);
}

long RemoteKill(pid_t pid)
{
	#ifdef DEBUG
	printf("RemoteKill: %d \n", pid);
	#endif

	long funcAddr = GetRemoteFuncAddr(pid, LIBC_PATH, ((long) (void*)kill));
	long params[2];
	params[0] = pid;
	params[1] = SIGKILL;

	return CallRemoteFunc(pid, funcAddr, params, 2);
}

long RemoteMunmap(pid_t pid, long addr, size_t length)
{
	// #ifdef DEBUG
	// printf("RemoteMunmap: %d %d\n", pid, length);
	// #endif

	long funcAddr = GetRemoteFuncAddr(pid, LIBC_PATH, ((long) (void*)munmap));
	long params[2];
	params[0] = addr;
	params[1] = length;

	int result = (int)CallRemoteFunc(pid, funcAddr, params, 2);
	if (result == -1)
	{
		printf("munmap failed! \n");
		RemotePerror(pid);
	}

	return result;
}

long RemoteMmap(pid_t pid, size_t length)
{
	// #ifdef DEBUG
	// printf("RemoteMmap: %d %d\n", pid, length);
	// #endif

	long funcAddr = GetRemoteFuncAddr(pid, LIBC_PATH, ((long) (void*)mmap));
	long params[6];
	params[0] = 0;
	params[1] = length;
	params[2] = PROT_READ | PROT_WRITE | PROT_EXEC;
	params[3] = MAP_PRIVATE | MAP_ANONYMOUS;
	params[4] = 0;
	params[5] = 0;

	int result = (int)CallRemoteFunc(pid, funcAddr, params, 6);
	if (result == -1)
	{
		printf("mmap failed! \n");
		RemotePerror(pid);
	}

	return result;
}

long RemoteDlsym(pid_t pid, long soHandle, const char* symbol)
{
	#ifdef DEBUG
	printf("RemoteDlsym: %d %08lx %s\n", pid, soHandle, symbol);
	#endif

	long funcAddr = GetRemoteFuncAddr(pid, LINKER_PATH, ((long) (void*)dlsym));
	long mmapRet = RemoteMmap(pid, 512);
	PtraceWrite(pid, (uint8_t*)mmapRet, (uint8_t*)symbol, strlen(symbol) + 1);
	
	long params[2];
	params[0] = soHandle;
	params[1] = mmapRet;

	long result = CallRemoteFunc(pid, funcAddr, params, 2);
	if (result == -1 ||result == 0)
	{
		printf("dlsym failed! \n");
		RemotePerror(pid);
	}

	RemoteMunmap(pid, mmapRet, 512);

	return result;
}

long RemoteDlopen(pid_t pid, const char* libPath)
{
	#ifdef DEBUG
	printf("RemoteDlopen: %d %s\n", pid, libPath);
	#endif

	long funcAddr = GetRemoteFuncAddr(pid, LINKER_PATH, ((long) (void*)dlopen));

	long mmapRet = RemoteMmap(pid, 512);
	PtraceWrite(pid, (uint8_t*)mmapRet, (uint8_t*)libPath, strlen(libPath) + 1);

	long params[2];
	params[0] = mmapRet;
	params[1] = RTLD_NOW | RTLD_LOCAL;

	long result = CallRemoteFunc(pid, funcAddr, params, 2);
	if (result == -1 ||result == 0)
	{
		printf("dlopen failed! \n");
		RemotePerror(pid);
	}

	RemoteMunmap(pid, mmapRet, 512);

	#ifdef DEBUG
	printf("so handle: %08lx\n", result);
	#endif
	return result;
}


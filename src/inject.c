#include "include/remote.h"
#include "include/ptrace.h"
#include "include/utils.h"
#include "include/inject.h"
#include <stdio.h>

long InjectLib(pid_t targetPid, const char* injectLibPath)
{
	#ifdef DEBUG
	printf("InjectLib: %d %s\n", targetPid, injectLibPath);
	#endif

	PtraceAttach(targetPid);

	long soHandle = RemoteDlopen(targetPid, injectLibPath);

	PtraceDetach(targetPid);

	return soHandle;
}
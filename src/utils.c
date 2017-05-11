#include <dirent.h>
#include <stdbool.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include "include/utils.h"

bool CheckSelinuxEnabled()
{
	// #ifdef DEBUG 
	// printf("CheckSelinuxEnabled\n");
	// #endif

	FILE* fp = fopen("/proc/filesystems", "r");
	char* line = (char*) calloc(50, sizeof(char));
	bool result = false;
	while(fgets(line, 50, fp)) 
	{
		//#ifdef DEBUG 
		//printf("line: %s\n", line); 
		//#endif

		if (strstr(line, "selinuxfs")) 
		{
			result = true;
		}
	}
	if (line) 
	{
		free(line);
	}

	fclose(fp);
  	return result;
}

void DisableSelinux() 
{
	// #ifdef DEBUG
	// printf("DisableSelinux\n");
	// #endif

	FILE* fp = fopen("/proc/mounts", "r");
	char* line = (char*) calloc(1024, sizeof(char));
	while(fgets(line, 1024, fp)) 
	{
		if (strstr(line, "selinuxfs")) 
		{
			strtok(line, " ");
			char* selinux_dir = strtok(NULL, " ");
			char* selinux_path = strcat(selinux_dir, "/enforce");
			FILE* fp_selinux = fopen(selinux_path, "w");
			char* buf = "0"; // set selinux to permissive
			fwrite(buf, strlen(buf), 1, fp_selinux);
			fclose(fp_selinux);
			break;
		}
	}

	fclose(fp);
	if (line) 
	{
		free(line);
	}
}

pid_t GetPid(const char* processName)
{
	if (processName == NULL)
		return -1;

	DIR* dir = opendir("/proc");

	if (dir == NULL)
		return -1;

	struct dirent* entry;
	while((entry = readdir(dir)) != NULL)
	{
		size_t pid = atoi(entry->d_name);
		if (pid != 0)
		{
			char fileName[30];
			snprintf(fileName, 30, "/proc/%d/cmdline", pid);
			FILE *fp = fopen(fileName, "r");

			if (fp != NULL)
			{
				char tmp[50];

				fgets(tmp, 50, fp);
				fclose(fp);

				int index = strcmp(processName, tmp);
				if (index == 0)
				{
					return pid;
				}
			}

		}
	}
	
	return -1;
}

long GetModuleBase(pid_t pid, const char* libPath)
{	
	// #ifdef DEBUG
	// printf("GetModuleBase: %d %s\n", pid, libPath);
	// #endif

	if (pid == -1)
		return 0;

	char path[256] = {0};
	char line[1024] = {0};
	char* ch = NULL;
	long baseAddr = 0;

	if (pid == 0)
	{
		snprintf(path, sizeof(path), "/proc/self/maps");
	}
	else
	{
		snprintf(path, sizeof(path), "/proc/%d/maps", pid);
	}
	//free(path);

	FILE *fp = fopen(path, "r");
	if (fp != NULL)
	{
		while (fgets(line, sizeof(line), fp))
		{
			//printf("%s\n", line);
			if (strstr(line, libPath))
			{
				ch = strtok(line, "-");
				baseAddr = strtoul(ch, NULL, 16);
				break;
			}
		}

		fclose(fp);
	}

	// #ifdef DEBUG
	// printf("baseAddr: %08lx \n", baseAddr);
	// #endif
	return baseAddr;
}

long GetRemoteFuncAddr(pid_t remotePid, const char* libPath, long localFuncAddr)
{
	// #ifdef DEBUG
	// printf("GetRemoteFuncAddr: %d %s %08lx\n", remotePid, libPath, localFuncAddr);
	// #endif

	if (remotePid == -1)
		return 0;

	pid_t pid = getpid();

	long localBaseAddr = GetModuleBase(pid, libPath);
	long remoteBaseAddr = GetModuleBase(remotePid, libPath);

	if (localBaseAddr == 0 || remoteBaseAddr == 0)
	{
		return 0;
	}

	return localFuncAddr + (remoteBaseAddr - localBaseAddr);
}

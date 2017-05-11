#include <sys/ptrace.h>
#include <sys/wait.h>
#include <string.h>
#include <unistd.h>
#include <linux/user.h>  
#include "include/ptrace.h"
#include "include/utils.h"

#define CPSR_T_MASK     ( 1u << 5 ) 

int PtraceAttach(pid_t pid)
{
	if (pid == -1)
		return -1;

	if (CheckSelinuxEnabled())
		DisableSelinux();

	// printf("attach pid: %d\n", pid);

	int result = ptrace(PTRACE_ATTACH, pid, NULL, NULL);
	if (result < 0)
	{
		perror(NULL);
		return -1;
	}
	waitpid(pid, NULL, WUNTRACED);

	return 0;
}

int PtraceDetach(pid_t pid)
{
	if (pid == -1)
		return -1;

	if (ptrace(PTRACE_DETACH, pid, NULL, NULL) < 0)
	{
		perror(NULL);
		return -1;
	}

	return 0;
}

void PtraceWrite(pid_t pid, uint8_t* addr, uint8_t* data, size_t size)
{
	// #ifdef DEBUG
	// printf("PtraceWrite: %d %08x %08x %d\n", pid, (unsigned int)addr, (unsigned int)data, size);
	// #endif

	const size_t WORD_SIZE = sizeof(long);

	int mod = size % WORD_SIZE;
	int count = size / WORD_SIZE;

	uint8_t* tmpAddr = addr;
	uint8_t* tmpData = data;
	for (int i = 0; i < count; ++i)
	{
		int result = ptrace(PTRACE_POKEDATA, pid, tmpAddr, (void*)(*((long*)tmpData)));
		if (result == -1)
			perror(NULL);

		tmpAddr += WORD_SIZE;
		tmpData += WORD_SIZE;
	}

	if (mod > 0)
	{
		long value = ptrace(PTRACE_PEEKDATA, pid, tmpAddr, NULL);
		uint8_t* pointer = (uint8_t*) &value;
		for (int i = 0; i < mod; ++i)
		{
			*pointer = *(tmpData);
			pointer++;
			tmpData++;
		}
		ptrace(PTRACE_POKEDATA, pid, tmpAddr, (void*)value);
	}

}

long CallRemoteFunc(pid_t pid, long funcAddr, long* args, size_t argc)
{
	// #ifdef DEBUG
	// printf("CallRemoteFunc: %d %08lx [args] %d\n", pid, funcAddr, argc);
	// #endif

	struct pt_regs regs;
	struct pt_regs backupRegs;

	int result = ptrace(PTRACE_GETREGS, pid, NULL, &regs);
	if (result == -1)
	{
		perror(NULL);
		return -1;
	}

	memcpy(&backupRegs, &regs, sizeof(struct pt_regs));
	
	for (int i = 0; i < (int)argc && i < 4; ++i)
	{
		regs.uregs[i] = args[i];
	}

	if (argc > 4)
	{
		int count = (argc - 4);
		int size = count * sizeof(long);
		regs.ARM_sp -= size;
		long* data = &args[4]; //args + 4
		PtraceWrite(pid, (uint8_t*) regs.ARM_sp, (uint8_t*) data, size);
	}

	//-----------------------------
	regs.ARM_lr = 0;
	regs.ARM_pc = funcAddr;
	if (regs.ARM_pc & 1)
	{
		//THUMB
		regs.ARM_pc &= (~1u);
		regs.ARM_cpsr |= CPSR_T_MASK;
	}
	else
	{
		//ARM
		regs.ARM_cpsr &= ~CPSR_T_MASK;
	}
	//-----------------------------
	result = ptrace(PTRACE_SETREGS, pid, NULL, &regs);
	if (result == -1)
	{
		perror(NULL);
		return -1;
	}

	ptrace(PTRACE_CONT, pid, NULL, NULL);
	waitpid(pid, NULL, WUNTRACED);

	ptrace(PTRACE_GETREGS, pid, NULL, &regs);
	ptrace(PTRACE_SETREGS, pid, NULL, &backupRegs);

	// printf("r0: %08lx\n", regs.ARM_r0);
	return regs.ARM_r0;
}
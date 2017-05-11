#include <elf.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ptrace.h>
#include "include/elf_helper.h"
#include "include/ptrace.h"
#include "include/utils.h"

void PrintElfHeader(Elf32_Ehdr* elfHeader)
{
	printf("-----Elf Header----\n");
	printf("type: %d\n", elfHeader->e_type);
	printf("machine: %d\n", elfHeader->e_machine);
	printf("version: %d\n", elfHeader->e_version);
	printf("entry: %08x\n", elfHeader->e_entry);
	printf("phoff: %d\n", elfHeader->e_phoff);
	printf("shoff: %d\n", elfHeader->e_shoff);
	printf("flags: %d\n", elfHeader->e_flags);
	printf("ehsize: %d\n", elfHeader->e_ehsize);
	printf("phentsize: %d\n", elfHeader->e_phentsize);
	printf("phnum: %d\n", elfHeader->e_phnum);
	printf("shentsize: %d\n", elfHeader->e_shentsize);
	printf("shnum: %d\n", elfHeader->e_shnum);
	printf("shstrndx: %d\n", elfHeader->e_shstrndx);
}
void PrintElfSectionHeader(Elf32_Shdr* shHeader)
{
	printf("-----Section Header----\n");
	printf("name: %d\n", shHeader->sh_name);
	printf("type: %d\n", shHeader->sh_type);
	printf("flags: %d\n", shHeader->sh_flags);
	printf("addr: %08x\n", shHeader->sh_addr);
	printf("offset: %d\n", shHeader->sh_offset);
	printf("size: %d\n", shHeader->sh_size);
	printf("link: %d\n", shHeader->sh_link);
	printf("info: %d\n", shHeader->sh_info);
	printf("addralign: %d\n", shHeader->sh_addralign);
	printf("entsize: %d\n", shHeader->sh_entsize);
}


void GetElfHeader(Elf32_Ehdr* elfHeader, FILE* elfFile)
{
	if (elfHeader == NULL || elfFile == NULL)
		return;

	fseek(elfFile, 0, SEEK_SET);
	fread(elfHeader, sizeof(Elf32_Ehdr), 1, elfFile);
}

size_t GetShstrtabContent(char** shstrtabContent, FILE* elfFile)
{
	if (elfFile == NULL)
		return -1;

	Elf32_Ehdr* elfHeader = (Elf32_Ehdr*) malloc(sizeof(Elf32_Ehdr));
	GetElfHeader(elfHeader, elfFile);

	off_t shstrtabHeaderOffset = elfHeader->e_shoff + elfHeader->e_shstrndx * sizeof(Elf32_Shdr);
	free(elfHeader);

	#ifdef DEBUG
	printf("shstrtabHeaderOffset %d\n", (int)shstrtabHeaderOffset);
	#endif

	Elf32_Shdr* shstrtabHeader = (Elf32_Shdr*) malloc(sizeof(Elf32_Shdr));
	fseek(elfFile, shstrtabHeaderOffset, SEEK_SET);
	fread(shstrtabHeader, sizeof(Elf32_Shdr), 1, elfFile);

	// #ifdef DEBUG
	// PrintElfSectionHeader(shstrtabHeader);
	// #endif

	off_t shstrtabOffset = shstrtabHeader->sh_offset;
	off_t shstrtabSize = shstrtabHeader->sh_size;
	free(shstrtabHeader);

	*shstrtabContent = (char*) malloc(shstrtabSize * sizeof(char));

	fseek(elfFile, shstrtabOffset, SEEK_SET);
	fread(*shstrtabContent, shstrtabSize, 1, elfFile);

	return shstrtabSize;
}

void GetSectionHeaderByName(Elf32_Shdr* sectionHeader, FILE* elfFile, const char* targetSecionName)
{
	if (sectionHeader == NULL || elfFile == NULL || targetSecionName == NULL)
		return;

	Elf32_Ehdr* elfHeader = (Elf32_Ehdr*) malloc(sizeof(Elf32_Ehdr));
	GetElfHeader(elfHeader, elfFile);

	#ifdef DEBUG
	PrintElfHeader(elfHeader);
	#endif

	size_t sectionCount = elfHeader->e_shnum;
	off_t sectionHeaderBaseOffset = elfHeader->e_shoff;
	free(elfHeader);

	char* shstrtabContent = NULL;
	GetShstrtabContent(&shstrtabContent, elfFile);

	for (size_t i = 0; i < sectionCount; ++i)
	{
		fseek(elfFile, sectionHeaderBaseOffset, SEEK_SET);
		fread(sectionHeader, sizeof(Elf32_Shdr), 1, elfFile);

		char* sectionName = shstrtabContent + sectionHeader->sh_name;
		if (strcmp(sectionName, targetSecionName) == 0)
		{
			break;
		}

		sectionHeaderBaseOffset += sizeof(Elf32_Shdr);
	}
	free(shstrtabContent);
}

void PatchRemoteGot(pid_t pid, const char* libPath, long origFuncAddr, long targetFuncAddr)
{
	#ifdef DEBUG
	printf("PatchRemoteGot: %d %s %08lx %08lx \n", pid, libPath, origFuncAddr, targetFuncAddr);
	#endif

	PtraceAttach(pid);

	FILE* elfFile = fopen(libPath, "r");
	Elf32_Shdr* gotSectionHeader = (Elf32_Shdr*) malloc(sizeof(Elf32_Shdr));
	GetSectionHeaderByName(gotSectionHeader, elfFile, ".got");
	
	size_t gotSectionSize = gotSectionHeader->sh_size;
	off_t gotAddrOffset = gotSectionHeader->sh_addr;
	free(gotSectionHeader);

	long moduleBaseAddr = GetModuleBase(pid, libPath);
	long gotSectionAddr = moduleBaseAddr + gotAddrOffset;

	for (size_t i = 0; i < gotSectionSize; i += sizeof(long))
	{
		long addr = gotSectionAddr + i;
		long gotEntry = ptrace(PTRACE_PEEKDATA, pid, (void*)addr, NULL);
		if (gotEntry == origFuncAddr)
		{
			printf("found!!\n");
			PtraceWrite(pid, (uint8_t*)addr, (uint8_t*)&targetFuncAddr, sizeof(long));
		}
	}

	PtraceDetach(pid);
	fclose(elfFile);
}
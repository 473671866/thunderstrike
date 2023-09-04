#pragma once
#include <iostream>
#include <map>
#include <memory>
#include <functional>
#include <windows.h>
#include <TlHelp32.h>
#include <assert.h>
#include <winnt.h>
#include <psapi.h>
#include "ia32.h"
#include "nt.h"

typedef struct _ProcessBlock
{
	uint32_t module_size;
	uint64_t module_base;
	uint64_t system_process;
}ProcessBlock;

class Analysis
{
public:
	Analysis(HANDLE handle);
	~Analysis();
	boolean InitializeContext();
	boolean InitializeMemoryRegion();
	boolean InitializeProcessorStatrBlock();
	boolean InitializeNtoskrnl();
	boolean MmReadPhysicalAddress(void* address, size_t size, void* buffer);
	boolean MmWritePhysicalAddress(void* address, size_t size, void* buffer);
	boolean MmReadVirtualAddress(uint64_t cr3, uint64_t address, size_t size, void* buffer);
	boolean MmWriteVirtualAddress(uint64_t cr3, uint64_t address, size_t size, void* buffer);
	LARGE_INTEGER MmGetPhyiscalAddress(uint64_t cr3, uint64_t address);
	void* MmGetSystemRoutineAddress(const char* name_t);

public:
	HANDLE m_handle;
	MEMORY_BASIC_INFORMATION* memory_basic;
	PROCESSOR_START_BLOCK* processor_state_bolck;
	ProcessBlock* process_block;
};

class PsHelper {
public:
	PsHelper(Analysis* analysis);
	~PsHelper();
	void SetCr3(uint64_t cr3);
	boolean PsEnumProcess(std::function<boolean(uint64_t pid, uint64_t cr3, const char* imagename, void* context)> callback, void* context);
	uint64_t PsEnumModule(uint64_t pid, const wchar_t* module_name, size_t* imagesize);
	boolean PsReadMemory(uint64_t cr3, uint64_t address, size_t size, void* buffer);
	boolean PsReadMemory(uint64_t address, size_t size, void* buffer);
	boolean PsWriteMemory(uint64_t cr3, uint64_t address, size_t size, void* buffer);
	boolean PsWriteMemory(uint64_t address, size_t size, void* buffer);

public:
	static PsHelper* PsBuilder();
	static PsHelper* PsBuilder(uint64_t pid);

private:
	Analysis* m_analysis;
	uint64_t m_cr3;
};

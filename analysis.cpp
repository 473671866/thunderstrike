#include "analysis.h"
#include "exit.h"
#include "singleton.hpp"

Analysis::Analysis(HANDLE handle) :m_handle(handle)
{
	this->processor_state_bolck = nullptr;
	this->process_block = nullptr;
	this->memory_basic = nullptr;
}

Analysis::~Analysis()
{
	delete this->memory_basic;
	delete this->process_block;
	delete this->processor_state_bolck;
	CloseHandle(this->m_handle);
}

boolean Analysis::InitializeContext()
{
	if (!InitializeMemoryRegion()) {
		return false;
	}

	if (!InitializeProcessorStatrBlock()) {
		return false;
	}

	if (!InitializeNtoskrnl()) {
		return false;
	}
	return true;
}

boolean Analysis::InitializeMemoryRegion()
{
	boolean success = false;
	unsigned char* p = NULL;
	char lpFilename[MAX_PATH + 1]{ };
	memory_basic = new MEMORY_BASIC_INFORMATION;
	ZeroMemory(this->memory_basic, sizeof(MEMORY_BASIC_INFORMATION));

	//遍历内存区域
	for (p = NULL; VirtualQueryEx(this->m_handle, p, memory_basic, sizeof(MEMORY_BASIC_INFORMATION)) == sizeof(MEMORY_BASIC_INFORMATION); p += memory_basic->RegionSize)
	{
		if ((memory_basic->BaseAddress != memory_basic->AllocationBase)
			|| (memory_basic->RegionSize < 0x01000000)
			|| (memory_basic->RegionSize > 0x10000000000)
			|| ((memory_basic->State != MEM_COMMIT)
				|| (memory_basic->Protect != PAGE_READWRITE)
				|| (memory_basic->AllocationProtect != PAGE_READWRITE)
				|| (memory_basic->Type != MEM_MAPPED))) {
			continue;
		}

		//映射文件
		if (GetMappedFileNameA(this->m_handle, memory_basic->BaseAddress, lpFilename, MAX_PATH)) {
			if (strstr(lpFilename, ".vmem")) {
				success = true;
				break;
			}
		}
	}
	return success;
}

boolean Analysis::InitializeProcessorStatrBlock()
{
	char* buffer = new char[0x10000];
	RtlZeroMemory(buffer, 0x10000);
	auto exit = make_scope_exit([&] {delete[] buffer; });

	//在0x0-0x100000中搜索PROCESSOR_START_BLOCK结构
	for (uint64_t address = 0; address < 0x100000; address += 0x10000)
	{
		if (!this->MmReadPhysicalAddress(reinterpret_cast<PVOID>(address), PAGE_SIZE * 10, buffer)) {
			continue;
		}

		for (uint64_t offset = 0; offset < PAGE_SIZE * 10; offset += PAGE_SIZE) {
			processor_state_bolck = reinterpret_cast<PROCESSOR_START_BLOCK*>(buffer + offset);
			if (processor_state_bolck->Jmp.OpCode == 0xe9) {
				void* temp = new char[sizeof(PROCESSOR_START_BLOCK)];
				RtlCopyMemory(temp, processor_state_bolck, sizeof(PROCESSOR_START_BLOCK));
				processor_state_bolck = static_cast<PROCESSOR_START_BLOCK*>(temp);
				return true;
			}
		}
	}
	return false;
}

boolean Analysis::InitializeNtoskrnl()
{
	char buffer[PAGE_SIZE]{ };
	uint64_t address = reinterpret_cast<uint64_t>(this->processor_state_bolck->LmTarget);
	uint64_t system_cr3 = this->processor_state_bolck->ProcessorState.SpecialRegisters.Cr3;

	//搜索ntoskrnl的pe头
	for (uint64_t i = (address & (~0x1fffff)) + 0x20000000; i > address - 0x20000000; i -= 0x1000)
	{
		if (!this->MmReadVirtualAddress(AddressPageDircetory(system_cr3), i, PAGE_SIZE, buffer)) {
			continue;
		}

		if ((*(short*)(buffer) != IMAGE_DOS_SIGNATURE)) {
			continue;
		}
		//搜索ntoskrnl的main函数
		for (uint64_t offset = 0; offset < PAGE_SIZE; offset++)
		{
			if (*(uint64_t*)(buffer + offset) == 0x4742444b54494e49 || *(uint64_t*)(buffer + offset) == 0x45444f434c4f4f50) {
				this->process_block = new ProcessBlock;
				process_block->module_base = i;
				process_block->module_size = 0x1043000;

				//system进程
				PVOID process = this->MmGetSystemRoutineAddress("PsInitialSystemProcess");
				boolean success = this->MmReadVirtualAddress(system_cr3, reinterpret_cast<uint64_t>(process), 8, &this->process_block->system_process);

				if (process == nullptr || !success || this->process_block->system_process == 0) {
					return false;
				}

				return true;
			}
		}
	}

	return false;
}

boolean Analysis::MmReadPhysicalAddress(void* address, size_t size, void* buffer)
{
	uint64_t base = reinterpret_cast<uint64_t>(this->memory_basic->BaseAddress);
	uint64_t temp = reinterpret_cast<uint64_t>(address);
	if (temp > 0x100000000) {
		temp -= 0x00040000000;
	}
	PVOID real = reinterpret_cast<PVOID>(base + temp);
	return ReadProcessMemory(this->m_handle, real, buffer, size, nullptr);
}

boolean Analysis::MmWritePhysicalAddress(void* address, size_t size, void* buffer)
{
	uint64_t base = reinterpret_cast<uint64_t>(this->memory_basic->BaseAddress);
	uint64_t temp = reinterpret_cast<uint64_t>(address);
	if (temp > 0x100000000) {
		temp -= 0x00040000000;
	}
	PVOID real = reinterpret_cast<PVOID>(base + temp);
	return WriteProcessMemory(this->m_handle, real, buffer, size, nullptr);
}

boolean Analysis::MmReadVirtualAddress(uint64_t cr3, uint64_t address, size_t size, void* buffer)
{
	if (cr3 == 0 || address == 0 || size == 0 || buffer == 0) {
		return false;
	}

	LARGE_INTEGER physical_address{};

	uint64_t start = address & (~0xfff);		//fffff8066bc13000
	uint64_t end = (address + size) & (~0xfff);	//fffff8066cc56000

	while (end >= start)
	{
		uint64_t temp = ADDRESS_CALC(address, size);
		physical_address = this->MmGetPhyiscalAddress(cr3, address);
		if (physical_address.QuadPart == 0) {
			return false;
		}

		this->MmReadPhysicalAddress(reinterpret_cast<PVOID>(physical_address.QuadPart), temp, buffer);
		start += PAGE_SIZE;
		address += temp;
		size -= temp;
		buffer = reinterpret_cast<PVOID>(reinterpret_cast<uint64_t>(buffer) + temp);
	}
	return true;
}

boolean Analysis::MmWriteVirtualAddress(uint64_t cr3, uint64_t address, size_t size, void* buffer)
{
	if (cr3 == 0 || address == 0 || size == 0 || buffer == 0) {
		return false;
	}

	uint64_t start = address & (~0xfff);		//fffff8066bc13000
	uint64_t end = (address + size) & (~0xfff);	//fffff8066cc56000

	while (end >= start)
	{
		uint64_t temp = ADDRESS_CALC(address, size);
		LARGE_INTEGER physical_address = this->MmGetPhyiscalAddress(cr3, address);
		if (physical_address.QuadPart == 0)return false;

		this->MmWritePhysicalAddress(reinterpret_cast<PVOID>(physical_address.QuadPart), temp, buffer);

		start += PAGE_SIZE;
		address += temp;
		size -= temp;
		buffer = reinterpret_cast<PVOID>(reinterpret_cast<uint64_t>(buffer) + temp);
	}
	return true;
}

LARGE_INTEGER Analysis::MmGetPhyiscalAddress(uint64_t cr3, uint64_t address)
{
	if (cr3 == 0 || address == 0) {
		return { 0 };
	}

	LARGE_INTEGER result{};
	HardwarePml4e pml4e{};
	HardwarePdpte pdpte{};
	HardwarePde pde{};
	HardwarePte pte{};
	int64_t pml4e_index = GetPml4eIndex(address);
	int64_t pdpte_index = GetPdpteIndex(address);
	int64_t pde_index = GetPdeIndex(address);
	int64_t pte_index = GetPteIndex(address);

	//pml4e
	if (!this->MmReadPhysicalAddress(ReadDricetoryTable(cr3, pml4e_index), 8, &pml4e)) {
		return result;
	}
	if (pml4e.all == 0 || pml4e.fields.present == false) {
		return result;
	}

	//pdpte
	if (!this->MmReadPhysicalAddress(ReadDricetoryTable((pml4e.all & 0xFFFF1FFFFFF000), pdpte_index), 8, &pdpte.all)) {
		return result;
	}
	if (pdpte.all == 0 || pdpte.fields.present == false) {
		return result;
	}
	if (pdpte.fields.large_page == true) {
		result.QuadPart = (pdpte.all & 0xFFFFFC0000000) + (address & 0x3FFFFFFF);
		return result;
	}

	//pde
	if (!this->MmReadPhysicalAddress(ReadDricetoryTable((pdpte.all & 0xFFFFFFFFFF000), pde_index), 8, &pde.all)) {
		return result;
	}
	if (pde.all == 0 || pde.fields.valid == false) {
		return result;
	}
	if (pde.fields.large_page == true) {
		result.QuadPart = (pde.all & 0xFFFFFFFE00000) + (address & 0x1FFFFF);
		return result;
	}

	//pte
	if (!this->MmReadPhysicalAddress(ReadDricetoryTable((pde.all & 0xFFFFFFFFFF000), pte_index), 8, &pte.all)) {
		return result;
	}
	if (pte.all == 0) {
		return result;
	}
	result.QuadPart = (pte.all & 0xFFFFFFFFFF000) + (address & 0xFFF);
	return result;
}

void* Analysis::MmGetSystemRoutineAddress(const char* name_t)
{
	uint64_t cr3 = this->processor_state_bolck->ProcessorState.SpecialRegisters.Cr3;
	uint64_t imagebase = this->process_block->module_base;
	uint64_t imagesize = this->process_block->module_size;

	char* imagebuffer = new char[imagesize];
	if (imagebuffer == nullptr)return nullptr;
	RtlZeroMemory(imagebuffer, imagesize);
	auto exit = make_scope_exit([&] {delete[] imagebuffer; });
	this->MmReadVirtualAddress(cr3, imagebase, imagesize, imagebuffer);

	IMAGE_DOS_HEADER* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(imagebuffer);
	if (dos->e_magic != IMAGE_DOS_SIGNATURE)return nullptr;

	IMAGE_NT_HEADERS* nt = reinterpret_cast<IMAGE_NT_HEADERS*>(dos->e_lfanew + imagebuffer);
	if (nt->Signature != IMAGE_NT_SIGNATURE)return nullptr;

	IMAGE_DATA_DIRECTORY* dricetory = &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
	if (dricetory == nullptr)return nullptr;

	PIMAGE_EXPORT_DIRECTORY export_t = (PIMAGE_EXPORT_DIRECTORY)(dricetory->VirtualAddress + imagebuffer);
	if (export_t == nullptr)return nullptr;

	int* name = (int*)(export_t->AddressOfNames + imagebuffer);
	int* address = (int*)(export_t->AddressOfFunctions + imagebuffer);
	short* number = (short*)(export_t->AddressOfNameOrdinals + imagebuffer);

	for (uint32_t i = 0; i < export_t->NumberOfNames; i++)
	{
		char* function_name = (char*)(name[i] + imagebuffer);
		if (_stricmp(function_name, name_t) == 0)
		{
			short index = number[i];
			unsigned int offset = address[index];
			uint64_t function_address = (offset + imagebase);
			return reinterpret_cast<PVOID>(function_address);
		}
	}
	return nullptr;
}

PsHelper::PsHelper(Analysis* analysis) :m_analysis(analysis)
{
}

PsHelper::~PsHelper()
{
	delete this->m_analysis;
}

void PsHelper::SetCr3(uint64_t cr3)
{
	this->m_cr3 = cr3;
}

boolean PsHelper::PsEnumProcess(std::function<boolean(uint64_t pid, uint64_t cr3, const char* imagename, void* context)> callback, void* context)
{
	if (callback == nullptr || context == nullptr) {
		return false;
	}

	boolean success = false;
	uint64_t system_cr3 = AddressPageDircetory(m_analysis->processor_state_bolck->ProcessorState.SpecialRegisters.Cr3);
	uint64_t offset = GET_OFFSET_64(EPROCESS, ActiveProcessLinks);
	PLIST_ENTRY header = reinterpret_cast<PLIST_ENTRY>(m_analysis->process_block->system_process + offset);
	PLIST_ENTRY next = reinterpret_cast<PLIST_ENTRY>(m_analysis->process_block->system_process + offset);

	do
	{
		EPROCESS temp{};
		success = m_analysis->MmReadVirtualAddress(system_cr3, (uint64_t)next - offset, sizeof(EPROCESS), &temp);
		if (!success || temp.UniqueProcessId == 0) {
			return false;
		}

		if (callback((uint64_t)temp.UniqueProcessId, AddressPageDircetory(temp.Pcb.DirectoryTableBase), reinterpret_cast<char*>(temp.ImageFileName), context)) {
			return true;
		}
		next = temp.ActiveProcessLinks.Flink;
	} while (next != header);

	return true;
}

uint64_t PsHelper::PsEnumModule(uint64_t pid, const wchar_t* module_name, size_t* imagesize)
{
	if (pid == 0 || module_name == nullptr) {
		return 0;
	}

	uint64_t system_cr3 = AddressPageDircetory(this->m_analysis->processor_state_bolck->ProcessorState.SpecialRegisters.Cr3);
	uint64_t offset = GET_OFFSET_64(EPROCESS, ActiveProcessLinks);
	PLIST_ENTRY header = reinterpret_cast<PLIST_ENTRY>(this->m_analysis->process_block->system_process + offset);
	PLIST_ENTRY next = reinterpret_cast<PLIST_ENTRY>(this->m_analysis->process_block->system_process + offset);
	EPROCESS* process = new EPROCESS; RtlZeroMemory(process, sizeof(EPROCESS));
	auto exit_process = make_scope_exit([=] {delete process; });

	do
	{
		if (this->m_analysis->MmReadVirtualAddress(system_cr3, (uint64_t)next - offset, sizeof(EPROCESS), process) == false) {
			continue;
		}

		if (process->UniqueProcessId == 0) {
			continue;
		}

		if (pid == (uint64_t)process->UniqueProcessId) {
			break;
		}

		next = process->ActiveProcessLinks.Flink;
		RtlZeroMemory(process, sizeof(EPROCESS));
	} while (next != header);

	EWOW64PROCESS* wow64process = static_cast<EWOW64PROCESS*>(process->WoW64Process);
	uint64_t cr3 = AddressPageDircetory(process->Pcb.DirectoryTableBase);
	uint64_t module_base_address = 0;

	if (wow64process)
	{
		boolean success = false;

		std::unique_ptr<EWOW64PROCESS> wprocess(new EWOW64PROCESS); RtlZeroMemory(wprocess.get(), sizeof(EWOW64PROCESS));
		success = this->m_analysis->MmReadVirtualAddress(cr3, (uint64_t)process->WoW64Process, sizeof(EWOW64PROCESS), wprocess.get());
		if (!success) {
			return 0;
		}

		std::unique_ptr<PEB32> peb(new PEB32); RtlZeroMemory(peb.get(), sizeof(PEB32));
		success = this->m_analysis->MmReadVirtualAddress(cr3, (uint64_t)wprocess->Peb, sizeof(PEB32), peb.get());
		if (!success) {
			return 0;
		}

		std::unique_ptr<PEB_LDR_DATA32> ldr_data(new PEB_LDR_DATA32); RtlZeroMemory(ldr_data.get(), sizeof(PEB_LDR_DATA32));
		success = this->m_analysis->MmReadVirtualAddress(cr3, (uint64_t)peb->Ldr, sizeof(PEB32), ldr_data.get());
		if (!success) {
			return 0;
		}

		PLIST_ENTRY32 module_list = reinterpret_cast<PLIST_ENTRY32>(&ldr_data->InLoadOrderModuleList);
		std::unique_ptr<LDR_DATA_TABLE_ENTRY32> ldr_data_entry(new LDR_DATA_TABLE_ENTRY32); RtlZeroMemory(ldr_data_entry.get(), sizeof(LDR_DATA_TABLE_ENTRY32));
		success = this->m_analysis->MmReadVirtualAddress(cr3, (uint64_t)module_list->Flink, sizeof(PEB32), ldr_data_entry.get());
		if (!success) {
			return 0;
		}

		while (module_list != reinterpret_cast<PLIST_ENTRY32>(ldr_data_entry.get()))
		{
			wchar_t* name = new wchar_t[ldr_data_entry->BaseDllName.Length + 2]; RtlZeroMemory(name, ldr_data_entry->BaseDllName.Length + 2);
			auto exit_name = make_scope_exit([&] {delete[] name; });

			success = this->m_analysis->MmReadVirtualAddress(cr3, (uint64_t)ldr_data_entry->BaseDllName.Buffer, ldr_data_entry->BaseDllName.Length, name);
			if (wcsstr(name, module_name) != nullptr)
			{
				module_base_address = ldr_data_entry->DllBase;
				if (imagesize) {
					*imagesize = ldr_data_entry->SizeOfImage;
				}
				break;
			}

			success = this->m_analysis->MmReadVirtualAddress(cr3, (uint64_t)ldr_data_entry->InLoadOrderLinks.Flink, sizeof(LDR_DATA_TABLE_ENTRY32), ldr_data_entry.get());
			if (!success) {
				return 0;
			}
		}
	}
	else
	{
		PVOID address = process->Peb;
		uint64_t cr3 = AddressPageDircetory(process->Pcb.DirectoryTableBase);
		boolean success = false;

		std::unique_ptr<PEB> peb(new PEB); RtlZeroMemory(peb.get(), sizeof(PEB));
		success = this->m_analysis->MmReadVirtualAddress(cr3, (uint64_t)address, sizeof(PEB), peb.get());
		if (!success) {
			return 0;
		}

		std::unique_ptr<PEB_LDR_DATA> ldr_data(new PEB_LDR_DATA); RtlZeroMemory(ldr_data.get(), sizeof(PEB_LDR_DATA));
		success = this->m_analysis->MmReadVirtualAddress(cr3, (uint64_t)peb->Ldr, sizeof(PEB), ldr_data.get());
		if (!success) {
			return 0;
		}

		PLIST_ENTRY module_list = reinterpret_cast<PLIST_ENTRY>(&ldr_data->InLoadOrderModuleList);
		std::unique_ptr<LDR_DATA_TABLE_ENTRY> ldr_data_entry(new LDR_DATA_TABLE_ENTRY); RtlZeroMemory(ldr_data_entry.get(), sizeof(LDR_DATA_TABLE_ENTRY));
		success = this->m_analysis->MmReadVirtualAddress(cr3, (uint64_t)module_list->Flink, sizeof(LDR_DATA_TABLE_ENTRY), ldr_data_entry.get());
		if (!success) {
			return 0;
		}

		while (module_list != reinterpret_cast<PLIST_ENTRY>(ldr_data_entry.get()))
		{
			wchar_t* name = new wchar_t[ldr_data_entry->BaseDllName.Length + 2]; RtlZeroMemory(name, ldr_data_entry->BaseDllName.Length + 2);
			auto exit_name = make_scope_exit([&] {delete[] name; });

			success = this->m_analysis->MmReadVirtualAddress(cr3, (uint64_t)ldr_data_entry->BaseDllName.Buffer, ldr_data_entry->BaseDllName.Length, name);

			if (success) {
				if (wcsstr(name, module_name) != nullptr) {
					module_base_address = reinterpret_cast<uint64_t>(ldr_data_entry->DllBase);
					if (imagesize) {
						*imagesize = ldr_data_entry->SizeOfImage;
					}
					break;
				}
			}

			success = this->m_analysis->MmReadVirtualAddress(cr3, (uint64_t)ldr_data_entry->InLoadOrderLinks.Flink, sizeof(LDR_DATA_TABLE_ENTRY), ldr_data_entry.get());
			if (!success) {
				return 0;
			}
		}
	}

	return module_base_address;
}

boolean PsHelper::PsReadMemory(uint64_t cr3, uint64_t address, size_t size, void* buffer)
{
	return this->m_analysis->MmReadVirtualAddress(cr3, address, size, buffer);
}

boolean PsHelper::PsReadMemory(uint64_t address, size_t size, void* buffer)
{
	return this->m_analysis->MmReadVirtualAddress(this->m_cr3, address, size, buffer);
}

boolean PsHelper::PsWriteMemory(uint64_t cr3, uint64_t address, size_t size, void* buffer)
{
	return this->m_analysis->MmWriteVirtualAddress(cr3, address, size, buffer);
}

boolean PsHelper::PsWriteMemory(uint64_t address, size_t size, void* buffer)
{
	return this->m_analysis->MmWriteVirtualAddress(this->m_cr3, address, size, buffer);
}

PsHelper* PsHelper::PsBuilder()
{
	HANDLE snapshot_handle = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	assert(snapshot_handle != INVALID_HANDLE_VALUE);

	PROCESSENTRY32 process_entry = { .dwSize = sizeof(PROCESSENTRY32) };
	boolean success = Process32First(snapshot_handle, &process_entry);
	while (success) {
		if (_wcsicmp(process_entry.szExeFile, L"vmware-vmx.exe") == 0) {
			HANDLE handle = OpenProcess(PROCESS_ALL_ACCESS, false, process_entry.th32ProcessID);
			if (handle != nullptr && handle != INVALID_HANDLE_VALUE) {
				Analysis* analysis = new Analysis(handle);
				if (analysis->InitializeContext()) {
					return new PsHelper(analysis);
				}
				else {
					delete analysis;
					analysis = nullptr;
				}
			}
			break;
		}
		success = Process32Next(snapshot_handle, &process_entry);
	}
	return nullptr;
}

PsHelper* PsHelper::PsBuilder(uint64_t pid)
{
	if (pid == 0) {
		return nullptr;
	}

	HANDLE handle = OpenProcess(PROCESS_ALL_ACCESS, false, pid);
	if (handle != nullptr && handle != INVALID_HANDLE_VALUE) {
		Analysis* analysis = new Analysis(handle);
		if (analysis->InitializeContext()) {
			return new PsHelper(analysis);
		}
		else {
			delete analysis;
			analysis = nullptr;
		}
	}
	return nullptr;
}
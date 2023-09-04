#include "analysis.h"

int main()
{
	PsHelper* helper = PsHelper::PsBuilder();
	if (helper == nullptr) {
		std::cout << "获取虚拟机进程失败\n";
		return 0;
	}

	uint64_t result[2]{};
	boolean success = helper->PsEnumProcess([](uint64_t pid, uint64_t cr3, const char* imagename, void* context) {
		if (_stricmp(imagename, "test.exe") == 0) {
			uint64_t* result = reinterpret_cast<uint64_t*>(context);
			result[0] = pid;
			result[1] = cr3;
			return true;
		}
		return false;
		}, result);

	if (!success) {
		return 0;
	}

	uint64_t module_address = helper->PsEnumModule(result[0], L"test.dll", nullptr);

	if (module_address == 0) {
		return 0;
	}

	uint64_t buffer = 0;
	helper->PsReadMemory(module_address + 0x0, result[1], sizeof(buffer), &buffer);
	printf("%lld\n", result);
	system("pause");

	helper->PsWriteMemory(module_address + 0x0, result[1], sizeof(buffer), &buffer);
	system("pause");

	delete helper; helper = nullptr;
	return 0;
}
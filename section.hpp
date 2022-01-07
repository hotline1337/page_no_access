#include <functional>

#pragma optimize("", off)
#pragma section(".vm", execute, read, write)
#pragma comment(linker,"/SECTION:.vm,ERW")
#pragma code_seg(push, ".vm")

uint8_t encryption_key;

std::function<PIMAGE_SECTION_HEADER(const char*)> get_section_by_name = [](const char* name)
{
	auto modulebase = reinterpret_cast<uint64_t>(LI_FN(GetModuleHandleA).get()(nullptr));
	auto nt = reinterpret_cast<PIMAGE_NT_HEADERS>(modulebase + (reinterpret_cast<PIMAGE_DOS_HEADER>(modulebase))->e_lfanew);
	auto section = IMAGE_FIRST_SECTION(nt);
	for (auto i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++section) 
	{
		if (!_stricmp(reinterpret_cast<char*>(section->Name), name))
			return section;
	}

	return []()
    	{ 
        	return nullptr; 
    	}();
}

std::function<void(PIMAGE_SECTION_HEADER)> encrypt_section = [](PIMAGE_SECTION_HEADER section) 
{
	auto modulebase = reinterpret_cast<uint64_t>(LI_FN(GetModuleHandleA).get()(nullptr));
	int valid_page_count = section->Misc.VirtualSize / 0x1000;
	for (auto page_idx = 0; page_idx < valid_page_count; page_idx++)
	{
        	DWORD old;
		uintptr_t address = modulebase + section->VirtualAddress + page_idx * 0x1000;
		
		LI_FN(VirtualProtect)(reinterpret_cast<LPVOID>(address), 0x1000, PAGE_EXECUTE_READWRITE, &old);
		for (auto off = 0; off < 0x1000; off += 0x1) 
		{
			*reinterpret_cast<BYTE*>(address + off) = _rotr8((*reinterpret_cast<BYTE*>(address + off) + 0x10) ^ encryption_key, 69);
		}
		LI_FN(VirtualProtect)(reinterpret_cast<LPVOID>(address), 0x1000, PAGE_NOACCESS, &old);
	}
}

std::function<bool(uint64_t)> find_rip_in_module = [](uint64_t rip) 
{
	PPEB peb = reinterpret_cast<PPEB>(__readgsqword(0x60));
	PPEB_LDR_DATA ldr = peb->Ldr;
	PLDR_DATA_TABLE_ENTRY module = NULL;
	PLIST_ENTRY list = ldr->InMemoryOrderModuleList.Flink;
	while (list != NULL && list != &ldr->InMemoryOrderModuleList) 
	{
		module = CONTAINING_RECORD(list, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
		PIMAGE_NT_HEADERS nt = reinterpret_cast<PIMAGE_NT_HEADERS>(reinterpret_cast<uint64_t>(module->DllBase) + (reinterpret_cast<PIMAGE_DOS_HEADER>(module->DllBase))->e_lfanew);
		if ((rip >= reinterpret_cast<uint64_t>(module->DllBase)) && (rip <= reinterpret_cast<uint64_t>(module->DllBase) + nt->OptionalHeader.SizeOfImage))
		{
			return []() 
            		{ 
                		return true; 
            		}();
		}
		list = list->Flink;
	}

	return false;
}

std::function<long __stdcall(struct _EXCEPTION_POINTERS*)> handler = [](struct _EXCEPTION_POINTERS* ExceptionInfo) 
{
	if (ExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_ACCESS_VIOLATION) 
	{
		DWORD old;
		auto page_start = reinterpret_cast<uint64_t>(ExceptionInfo->ExceptionRecord->ExceptionInformation[1]);
		page_start = page_start - (page_start % 0x1000);
    
		if (!find_rip_in_module(ExceptionInfo->ContextRecord->Rip))
            	return []() 
            	{ 
               	 	return EXCEPTION_CONTINUE_SEARCH; 
            	}();

		LI_FN(VirtualProtect)(reinterpret_cast<LPVOID>(page_start), 0x1000, PAGE_READWRITE, &old);
		for (auto off = 0; off < 0x1000; off += 0x1)
        	{
			*reinterpret_cast<BYTE*>(page_start + off) = (_rotl8(*reinterpret_cast<BYTE*>(page_start + off), 69) ^ encryption_key) - 0x10;
		}
    
		LI_FN(VirtualProtect)(reinterpret_cast<LPVOID>(page_start), 0x1000, PAGE_EXECUTE_READ, &old);
		return []() 
        	{ 
           		 return EXCEPTION_CONTINUE_SEARCH; 
       		}();
	}
	return []() 
    	{ 
        	return EXCEPTION_CONTINUE_SEARCH; 
    	}();
}

/* main function */
std::function<void(const char*)> initialize_protection = [](const char* section_to_encrypt) 
{
	LI_FN(srand)(time(nullptr));
	encryption_key = rand() % 255 + 1;

	LI_FN(AddVectoredExceptionHandler)(0x1, handler);
	encrypt_section(get_section_by_name(section_to_encrypt));
	for (auto i = 0; i < reinterpret_cast<uint64_t>(find_rip_in_module) - reinterpret_cast<uint64_t>(encrypt_section); i += 0x1) 
	{
		*reinterpret_cast<uint8_t*>(reinterpret_cast<uint64_t>(encrypt_section) + i) = 0x0;
	}
}

#pragma code_seg(pop, ".vm")
#pragma optimize("", on)

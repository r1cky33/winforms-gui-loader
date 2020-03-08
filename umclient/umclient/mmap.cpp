#include <iostream>

#include "mmap.h"
#include "client.h"

#include "hooker.h"

bool mmap::attach_to_process(const char* process_name) {
	uint32_t lPid;
	while (!is_process_running(process_name, lPid))
		std::this_thread::sleep_for(std::chrono::seconds(1));

	std::this_thread::sleep_for(std::chrono::seconds(5));

	pid = get_child_pid(process_name);

	if (pid)
		return true;
	else
		return false;
}

bool mmap::load_dll(uint8_t image[]) {
	data_size = sizeof(image);
	raw_data = image;

	if (!raw_data)
		return false;

	return true;
}

bool mmap::inject() {
	if (!pid) {
		std::cout << "[-] ERROR 1" << std::endl;
		return false;
	}

	if (!raw_data) {
		std::cout << "[-] ERROR 2" << std::endl;
		return false;
	}

	byte dll_stub[] = {
		0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, //original bytes of PeekMessage
		0x9C, 0x50, 0x51, 0x52, 0x53, 0x55, 0x56, 0x57, 0x41, 0x50, 0x41, 0x51, 0x41, 0x52, 0x41, 0x53, 0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57,   // push     REGISTERS
		0x48, 0xB8, 0x69, 0x69, 0x69, 0x69, 0x69, 0x69, 0x69, 0x69, 0x48, 0x89, 0x05, 0x51, 0x00, 0x00, 0x00,	//mov    QWORD PTR [rip+0x4c], rax
		0x48, 0x83, 0xEC, 0x28,                                                         // sub      RSP, 0x28
		0x48, 0xB9, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,                     // movabs   RCX, 0x0000000000000000 
		0x48, 0xC7, 0xC2, 0x01, 0x00, 0x00, 0x00,                                       // mov      rdx, 0x1
		0x4D, 0x31, 0xC0,                                                               // xor      r8, r8
		0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,                     // movabs   RAX, 0x0000000000000000
		0xFF, 0xD0,                                                                     // call     RAX  
		0x48, 0x83, 0xC4, 0x28,                                                         // add      RSP, 0x28
		0x41, 0x5F, 0x41, 0x5E, 0x41, 0x5D, 0x41, 0x5C, 0x41, 0x5B, 0x41, 0x5A, 0x41, 0x59, 0x41, 0x58, 0x5F, 0x5E, 0x5D, 0x5B, 0x5A, 0x59, 0x58, 0x9D,   // pop      REGISTERS)
		0xFF, 0x25, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0xCC, 0xCC, 0xCC
	};

	IMAGE_DOS_HEADER* dos_header{ (IMAGE_DOS_HEADER*)raw_data };

	if (dos_header->e_magic != IMAGE_DOS_SIGNATURE) {
		std::cout << "[-] ERROR 3" << std::endl;
		return false;
	}

	IMAGE_NT_HEADERS* nt_header{ (IMAGE_NT_HEADERS*)(&raw_data[dos_header->e_lfanew]) };

	driver::init();
	Sleep(1000);

	if (nt_header->Signature != IMAGE_NT_SIGNATURE) {
		std::cout << "[-] ERROR 4" << std::endl;
		return false;
	}
	uint32_t sizebuff = 0;
	uint32_t size = 0;
	uint64_t base = 0;

	base = driver::get_um_module(pid, "7z.dll", sizebuff);

	for (int i = 0; i < 120; i++) {
		base = driver::get_um_module(pid, "7z.dll", sizebuff);
		Sleep(1000);

		if (base != 0)
			break;
	}

	driver::extend_module(pid, (size_t)nt_header->OptionalHeader.SizeOfImage, "7z.dll");
	base = driver::get_um_module(pid, "7z.dll", size);

	driver::extend_module(pid, (size_t)nt_header->OptionalHeader.SizeOfImage, "7z.dll");
	base = driver::get_um_module(pid, "7z.dll", size);

	if (size > sizebuff) {
		base = base + (uint64_t)size - (uint64_t)nt_header->OptionalHeader.SizeOfImage;
	}

	if (!base) {
		std::cout << "[-] ERROR 5" << base << std::endl;
		return false;
	}

	Sleep(500);

	uint64_t stub_base = driver::virtual_alloc(pid,
		MEM_COMMIT | MEM_RESERVE,
		PAGE_EXECUTE_READWRITE,
		sizeof(dll_stub));

	if (!stub_base) {
		std::cout << "[-] ERROR 6" << std::endl;
		return false;
	}

	PIMAGE_IMPORT_DESCRIPTOR import_descriptor{ (PIMAGE_IMPORT_DESCRIPTOR)get_ptr_from_rva(
												(uint64_t)(nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress),
												nt_header,
												raw_data) };

	if (nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size) {
		std::cout << "[+] done" << std::endl;
		solve_imports(raw_data, nt_header, import_descriptor);
	}

	PIMAGE_BASE_RELOCATION base_relocation{ (PIMAGE_BASE_RELOCATION)get_ptr_from_rva(
																	nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress,
																	nt_header,
																	raw_data) };

	if (nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size) {
		std::cout << "[+] done" << std::endl;
		solve_relocations((uint64_t)raw_data,
			base,
			nt_header,
			base_relocation,
			nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size);
	}

	if (!parse_imports()) {
		std::cout << "[-] [-] ERROR 7" << std::endl;
		return false;
	}

	driver::write<void>(pid, (uintptr_t)raw_data, base, nt_header->FileHeader.SizeOfOptionalHeader + sizeof(nt_header->FileHeader) + sizeof(nt_header->Signature));

	map_pe_sections(base, nt_header);

	uint64_t entry_point{ (uint64_t)base + nt_header->OptionalHeader.AddressOfEntryPoint };

	//operation
	uint64_t pRemoteFunc = GetFunctionAddress("user32.dll", "PeekMessageW", true);

	if (!pRemoteFunc) {
		std::cout << "[-] ERROR 8" << std::endl;
		return false;
	}

	*(uint64_t*)& dll_stub[133] = (uint64_t)(pRemoteFunc + 0x14);
	*(uint64_t*)& dll_stub[69] = (uint64_t)base;
	*(uint64_t*)& dll_stub[89] = (uint64_t)entry_point;

	//steamoverlay is hooking the first 5 bytes of PeekMessageW
	Hook(pid, (uintptr_t)(pRemoteFunc + 0x5), stub_base, dll_stub, sizeof(dll_stub));

	WaitToPatchBack(pid, stub_base + sizeof(dll_stub) + 0x2, pRemoteFunc + 0x5);

	return true;
}

void mmap::solve_imports(uint8_t* base, IMAGE_NT_HEADERS* nt_header, IMAGE_IMPORT_DESCRIPTOR* import_descriptor) {
	char* module;
	while ((module = (char*)get_ptr_from_rva((DWORD64)(import_descriptor->Name), nt_header, (PBYTE)base))) {
		HMODULE local_module{ LoadLibrary(module) };
		/*dll should be compiled statically to avoid loading new libraries*/

		//if (!driver::get_um_module(pid, module))
		//	LoadLibrary(module);

		IMAGE_THUNK_DATA* thunk_data{ (IMAGE_THUNK_DATA*)get_ptr_from_rva((DWORD64)(import_descriptor->FirstThunk), nt_header, (PBYTE)base) };

		while (thunk_data->u1.AddressOfData) {
			IMAGE_IMPORT_BY_NAME* iibn{ (IMAGE_IMPORT_BY_NAME*)get_ptr_from_rva((DWORD64)((thunk_data->u1.AddressOfData)), nt_header, (PBYTE)base) };
			thunk_data->u1.Function = (uint64_t)(get_proc_address(module, (char*)iibn->Name));
			thunk_data++;
		}
		import_descriptor++;
	}

	return;
}

void mmap::solve_relocations(uint64_t base, uint64_t relocation_base, IMAGE_NT_HEADERS* nt_header, IMAGE_BASE_RELOCATION* reloc, size_t size) {
	uint64_t image_base{ nt_header->OptionalHeader.ImageBase };
	uint64_t delta{ relocation_base - image_base };
	unsigned int bytes{ 0 };

	while (bytes < size) {
		uint64_t* reloc_base{ (uint64_t*)get_ptr_from_rva((uint64_t)(reloc->VirtualAddress), nt_header, (PBYTE)base) };
		auto num_of_relocations{ (reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD) };
		auto reloc_data = (uint16_t*)((uint64_t)reloc + sizeof(IMAGE_BASE_RELOCATION));

		for (unsigned int i = 0; i < num_of_relocations; i++) {
			if (((*reloc_data >> 12) & IMAGE_REL_BASED_HIGHLOW))
				* (uint64_t*)((uint64_t)reloc_base + ((uint64_t)(*reloc_data & 0x0FFF))) += delta;
			reloc_data++;
		}

		bytes += reloc->SizeOfBlock;
		reloc = (IMAGE_BASE_RELOCATION*)reloc_data;
	}

	return;
}

bool mmap::parse_imports() {
	auto base = driver::get_process_base_by_id(pid);

	if (!base) {
		return false;
	}

	auto dos_header = driver::read<IMAGE_DOS_HEADER>(pid, base);
	auto nt_headers = driver::read<IMAGE_NT_HEADERS>(pid, base + dos_header.e_lfanew);
	auto descriptor = driver::read<IMAGE_IMPORT_DESCRIPTOR>(pid, base + nt_headers.OptionalHeader.DataDirectory[1].VirtualAddress);

	int descriptor_count{ 0 };
	int thunk_count{ 0 };

	while (descriptor.Name) {
		auto first_thunk = driver::read<IMAGE_THUNK_DATA>(pid, base + descriptor.FirstThunk);
		auto original_first_thunk = driver::read<IMAGE_THUNK_DATA>(pid, base + descriptor.OriginalFirstThunk);
		thunk_count = 0;

		while (original_first_thunk.u1.AddressOfData) {
			char name[256];
			driver::copy_memory(pid, (uint64_t)(base + original_first_thunk.u1.AddressOfData + 0x2), GetCurrentProcessId(), (uint64_t)name, 256);

			std::string str_name(name);
			auto thunk_offset{ thunk_count * sizeof(uintptr_t) };

			if (str_name.length() > 0)
				imports[str_name] = base + descriptor.FirstThunk + thunk_offset;


			++thunk_count;
			first_thunk = driver::read<IMAGE_THUNK_DATA>(pid, base + descriptor.FirstThunk + sizeof(IMAGE_THUNK_DATA) * thunk_count);
			original_first_thunk = driver::read<IMAGE_THUNK_DATA>(pid, base + descriptor.OriginalFirstThunk + sizeof(IMAGE_THUNK_DATA) * thunk_count);
		}

		++descriptor_count;
		descriptor = driver::read<IMAGE_IMPORT_DESCRIPTOR>(pid, base + nt_headers.OptionalHeader.DataDirectory[1].VirtualAddress + sizeof(IMAGE_IMPORT_DESCRIPTOR) * descriptor_count);
	}

	return (imports.size() > 0);
}

uint64_t mmap::get_proc_address(char* module_name, char* func) {
	uint32_t size = 0;	//size of the module ... not used here

	uint64_t remote_module = driver::get_um_module(pid, module_name, size);
	uint64_t local_module{ (uint64_t)GetModuleHandle(module_name) };
	uint64_t delta{ remote_module - local_module };
	return ((uint64_t)GetProcAddress((HMODULE)local_module, func) + delta);
}

uint64_t* mmap::get_ptr_from_rva(uint64_t rva, IMAGE_NT_HEADERS* nt_header, uint8_t* image_base) {
	PIMAGE_SECTION_HEADER section_header{ get_enclosing_section_header(rva, nt_header) };

	if (!section_header)
		return 0;

	int64_t delta{ (int64_t)(section_header->VirtualAddress - section_header->PointerToRawData) };
	return (uint64_t*)(image_base + rva - delta);
}

PIMAGE_SECTION_HEADER mmap::get_enclosing_section_header(uint64_t rva, PIMAGE_NT_HEADERS nt_header) {
	PIMAGE_SECTION_HEADER section{ IMAGE_FIRST_SECTION(nt_header) };

	for (int i = 0; i < nt_header->FileHeader.NumberOfSections; i++, section++) {
		uint64_t size{ section->Misc.VirtualSize };
		if (!size)
			size = section->SizeOfRawData;

		if ((rva >= section->VirtualAddress) &&
			(rva < (section->VirtualAddress + size)))
			return section;
	}

	return 0;
}

void mmap::map_pe_sections(uint64_t base, IMAGE_NT_HEADERS* nt_header) {
	auto header{ IMAGE_FIRST_SECTION(nt_header) };
	size_t virtual_size{ 0 };
	size_t bytes{ 0 };

	while (nt_header->FileHeader.NumberOfSections && (bytes < nt_header->OptionalHeader.SizeOfImage)) {
		driver::write<void>(pid, (uintptr_t)(raw_data + header->PointerToRawData), base + header->VirtualAddress, header->SizeOfRawData);

		virtual_size = header->VirtualAddress;
		virtual_size = (++header)->VirtualAddress - virtual_size;
		bytes += virtual_size;

		/*
			TODO:
			Add page protection
		*/
	}

	return;
}
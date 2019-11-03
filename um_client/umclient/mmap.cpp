#include <iostream>

#include "mmap.h"
#include "client.h"

struct proc_idn {
	uint32_t processID;
	uint32_t parent_processID;
};

uint32_t get_child_pid(const char* process_name) {
	proc_idn first = {};
	proc_idn second = {};

	PROCESSENTRY32 process_entry{};
	process_entry.dwSize = sizeof(PROCESSENTRY32);
	auto snapshot{ CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL) };
	if (snapshot == INVALID_HANDLE_VALUE)
		return false;
	if (Process32First(snapshot, &process_entry)) {
		do {
			if (!strcmp(process_name, process_entry.szExeFile)) {
				if (first.processID) {
					second.processID = process_entry.th32ProcessID;
					second.parent_processID = process_entry.th32ParentProcessID;
				}
				else {
					first.processID = process_entry.th32ProcessID;
					first.parent_processID = process_entry.th32ParentProcessID;
				}
			}
		} while (Process32Next(snapshot, &process_entry));
	}

	CloseHandle(snapshot);

	if (first.parent_processID == second.processID)
		return first.processID;
	else
		return second.processID;
}

bool mmap::attach_to_process(const char* process_name) {
	uint32_t lPid;
	while (!is_process_running(process_name, pid /*lPid*/))
		std::this_thread::sleep_for(std::chrono::seconds(1));

	std::this_thread::sleep_for(std::chrono::seconds(2));

	//pid = get_child_pid(process_name);	for getting child process

	if (pid)
		return true;
	else
		return false;
}

bool mmap::load_dll(const char* file_name) {
	std::ifstream f(file_name, std::ios::binary | std::ios::ate);

	if (!f) {
		return false;
	}

	std::ifstream::pos_type pos{ f.tellg() };
	data_size = pos;

	raw_data = new uint8_t[data_size];

	if (!raw_data)
		return false;

	f.seekg(0, std::ios::beg);
	f.read((char*)raw_data, data_size);

	f.close();
	return true;
}

bool mmap::inject() {
	if (!pid) {
		std::cout << "[-] no pid!" << std::endl;
		return true;
	}

	std::cout << "[+] pid: " << pid << std::endl;
	
	if (!raw_data) {
		std::cout << "[-] no raw_data loaded!" << std::endl;
		return true;
	}

	//stub compiled with nasm: https://www.nasm.us/
	uint8_t dll_stub[] = { "\x51\x52\x55\x56\x53\x57\x41\x50\x41\x51\x41\x52\x41\x53\x41\x54\x41\x55\x41\x56\x41\x57\x48\xB8\xFF\x00\xDE\xAD\xBE\xEF\x00\xFF\x48\xBA\xFF\x00\xDE\xAD\xC0\xDE\x00\xFF\x48\x89\x10\x48\x31\xC0\x48\x31\xD2\x48\x83\xEC\x28\x48\xB9\xDE\xAD\xBE\xEF\xDE\xAD\xBE\xEF\x48\x31\xD2\x48\x83\xC2\x01\x48\xB8\xDE\xAD\xC0\xDE\xDE\xAD\xC0\xDE\xFF\xD0\x48\x83\xC4\x28\x41\x5F\x41\x5E\x41\x5D\x41\x5C\x41\x5B\x41\x5A\x41\x59\x41\x58\x5F\x5B\x5E\x5D\x5A\x59\x48\x31\xC0\xC3" };

	/*
		dll_stub:
		00000000  51                push rcx
		00000001  52                push rdx
		00000002  55                push rbp
		00000003  56                push rsi
		00000004  53                push rbx
		00000005  57                push rdi
		00000006  4150              push r8
		00000008  4151              push r9
		0000000A  4152              push r10
		0000000C  4153              push r11
		0000000E  4154              push r12
		00000010  4155              push r13
		00000012  4156              push r14
		00000014  4157              push r15
		00000016  48B8FF00DEADBEEF  mov rax,0xff00efbeadde00ff
				 -00FF
		00000020  48BAFF00DEADC0DE  mov rdx,0xff00dec0adde00ff
				 -00FF
		0000002A  488910            mov [rax],rdx
		0000002D  4831C0            xor rax,rax
		00000030  4831D2            xor rdx,rdx
		00000033  4883EC28          sub rsp,byte +0x28
		00000037  48B9DEADBEEFDEAD  mov rcx,0xefbeaddeefbeadde
				 -BEEF
		00000041  4831D2            xor rdx,rdx
		00000044  4883C201          add rdx,byte +0x1
		00000048  48B8DEADC0DEDEAD  mov rax,0xdec0addedec0adde
				 -C0DE
		00000052  FFD0              call rax
		00000054  4883C428          add rsp,byte +0x28
		00000058  415F              pop r15
		0000005A  415E              pop r14
		0000005C  415D              pop r13
		0000005E  415C              pop r12
		00000060  415B              pop r11
		00000062  415A              pop r10
		00000064  4159              pop r9
		00000066  4158              pop r8
		00000068  5F                pop rdi
		00000069  5B                pop rbx
		0000006A  5E                pop rsi
		0000006B  5D                pop rbp
		0000006C  5A                pop rdx
		0000006D  59                pop rcx
		0000006E  4831C0            xor rax,rax
		00000071  C3                ret
	*/

	IMAGE_DOS_HEADER* dos_header{ (IMAGE_DOS_HEADER*)raw_data };

	if (dos_header->e_magic != IMAGE_DOS_SIGNATURE) {
		std::cout << "[-] dos_header->e_magic != IMAGE_DOS_SIGNATURE" << std::endl;
		return true;
	}

	IMAGE_NT_HEADERS* nt_header{ (IMAGE_NT_HEADERS*)(&raw_data[dos_header->e_lfanew]) };

	if (nt_header->Signature != IMAGE_NT_SIGNATURE) {
		std::cout << "[-] nt_header->Signature != IMAGE_NT_SIGNATURE" << std::endl;
		return true;
	}

	uint64_t base = driver::virtual_alloc(pid,
		MEM_COMMIT | MEM_RESERVE,
		PAGE_EXECUTE_READWRITE, 
		nt_header->OptionalHeader.SizeOfImage);

	//driver::secure_memory(base, nt_header->OptionalHeader.SizeOfImage, PAGE_READWRITE);

	if (!base) {
		std::cout << "[-] failed to allocate base! " << base << std::endl;
		return true;
	}

	std::cout << "[+] allocated base: 0x" << std::hex << base << std::endl;

	uint64_t stub_base = driver::virtual_alloc(pid,
		MEM_COMMIT | MEM_RESERVE,
		PAGE_EXECUTE_READWRITE,
		sizeof(dll_stub));

	//driver::secure_memory(stub_base, sizeof(dll_stub), PAGE_READWRITE);

	if (!stub_base) {
		std::cout << "[-] failed to allocate stub_base!" << std::endl;
		return true;
	}

	std::cout << "[+] allocated stub_base: 0x" << std::hex << stub_base << std::endl;

	PIMAGE_IMPORT_DESCRIPTOR import_descriptor{ (PIMAGE_IMPORT_DESCRIPTOR)get_ptr_from_rva(
												(uint64_t)(nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress),
												nt_header,
												raw_data) };

	if (nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size) {
		std::cout << "[+] solving imports!" << std::endl;
		solve_imports(raw_data, nt_header, import_descriptor);
	}

	PIMAGE_BASE_RELOCATION base_relocation{ (PIMAGE_BASE_RELOCATION)get_ptr_from_rva(
																	nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress,
																	nt_header,
																	raw_data) };

	if (nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size) {
		std::cout << "[+] solve relocations!" << std::endl;
		solve_relocations((uint64_t)raw_data,
			base,
			nt_header,
			base_relocation,
			nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size);
	}

	std::cout << "[+] parsing imports!" << std::endl;
	if (!parse_imports()) {
		std::cout << "[-] parsing imports failed!" << std::endl;
		return true;
	}
	std::cout << "[+] parsing imports succeeded!" << std::endl;

	uint64_t iat_function_ptr{ imports["PostMessageW"] };
	if (!iat_function_ptr) {
		std::cout << "no TranslateMessage found!" << std::endl;
		return true;
	}

	std::cout << "[+] iat_function_ptr: " << iat_function_ptr << std::endl;

	uint64_t orginal_function_addr = driver::read<uint64_t>(pid, iat_function_ptr);

	*(uint64_t*)(dll_stub + 0x18) = iat_function_ptr;
	*(uint64_t*)(dll_stub + 0x22) = orginal_function_addr;
	/* Save pointer and orginal function address for stub to restre it.
	mov rax, 0xff00efbeadde00ff  ; dll_stub + 0x18 (iat_function_ptr)
	mov rdx, 0xff00dec0adde00ff  ; dll_stub + 0x22 (orginal_function_addr)
	mov qword [rax], rdx
	xor rax, rax
	xor rdx, rdx
	*/

	driver::write<void>(pid, (uintptr_t)raw_data, base, nt_header->FileHeader.SizeOfOptionalHeader + sizeof(nt_header->FileHeader) + sizeof(nt_header->Signature));

	std::cout << "[+] mapping pe sections! " << std::endl;
	map_pe_sections(base, nt_header);

	uint64_t entry_point{ (uint64_t)base + nt_header->OptionalHeader.AddressOfEntryPoint };
	*(uint64_t*)(dll_stub + 0x39) = base;
	*(uint64_t*)(dll_stub + 0x4a) = entry_point;
	/* Save module_base and entry_point to call dllmain correctly
	sub rsp, 0x28
	mov rcx, 0xefbeaddeefbeadde ; dll_stub + 0x39 (base)
	xor rdx, rdx
	add rdx, 1
	mov rax, 0xdec0addedec0adde ; dll_stub + 0x4a (entry_point)
	call rax
	*/

	std::cout << "[+] writing dll_stub! " << std::endl;
	driver::write<void>(pid, (uintptr_t)dll_stub, stub_base, sizeof(dll_stub));
	std::cout << "[+] protecting iat_func_ptr! " << std::endl;
	driver::virtual_protect(pid, iat_function_ptr, PAGE_READWRITE, sizeof(uint64_t));
	std::cout << "[+] overwrite iat_func_ptr! " << std::endl;
	driver::write<void>(pid, (uintptr_t)& stub_base, iat_function_ptr, sizeof(uint64_t));

	std::cout << "[+] injected successfully!" << std::endl;
	std::this_thread::sleep_for(std::chrono::milliseconds(2000)); //system("pause") will also stop the kernel thread lol
	driver::virtual_protect(pid, iat_function_ptr, PAGE_READONLY, sizeof(uint64_t));

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

	std::cout << "base by proc id: " << std::hex << base << std::endl;

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

			std::cout << "	> parsed: " << name << std::endl;

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
	uint64_t remote_module = driver::get_um_module(pid, module_name);
	std::cout << "remote module_addr: " << remote_module << "remote module name: " << module_name << "module_function" << func << std::endl;
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
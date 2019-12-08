#include "utils.h"

bool is_process_running(const char* process_name, uint32_t& pid) {
	PROCESSENTRY32 process_entry{};
	process_entry.dwSize = sizeof(PROCESSENTRY32);
	pid = 0;
	auto snapshot{ CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL) };
	if (snapshot == INVALID_HANDLE_VALUE)
		return false;
	if (Process32First(snapshot, &process_entry)) {
		do {
			if (!strcmp(process_name, process_entry.szExeFile)) {
				pid = process_entry.th32ProcessID;
				CloseHandle(snapshot);
				return true;
			}
		} while (Process32Next(snapshot, &process_entry));
	}
	CloseHandle(snapshot);
	return false;
}

uint64_t GetFunctionAddress(LPCTSTR DllName, LPCSTR FunctionName, BOOL LoadDll)
{
	PIMAGE_DOS_HEADER pIDH;
	PIMAGE_NT_HEADERS pINH;
	PIMAGE_EXPORT_DIRECTORY pIED;

	HMODULE hModule;
	PDWORD Address, Name;
	PWORD Ordinal;

	DWORD i;

	if (LoadDll)
	{
		hModule = LoadLibrary(DllName);
	}

	else
	{
		hModule = GetModuleHandle(DllName);
	}

	if (!hModule)
	{
		return NULL;
	}

	pIDH = (PIMAGE_DOS_HEADER)hModule;

	if (pIDH->e_magic != IMAGE_DOS_SIGNATURE)
	{
		return NULL;
	}

	pINH = (PIMAGE_NT_HEADERS)((LPBYTE)hModule + pIDH->e_lfanew);

	if (pINH->Signature != IMAGE_NT_SIGNATURE)
	{
		return NULL;
	}

	if (pINH->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress == 0)
	{
		return NULL;
	}

	pIED = (PIMAGE_EXPORT_DIRECTORY)((LPBYTE)hModule + pINH->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

	Address = (PDWORD)((LPBYTE)hModule + pIED->AddressOfFunctions);
	Name = (PDWORD)((LPBYTE)hModule + pIED->AddressOfNames);

	Ordinal = (PWORD)((LPBYTE)hModule + pIED->AddressOfNameOrdinals);

	for (i = 0; i < pIED->AddressOfFunctions; i++)
	{
		if (!strcmp(FunctionName, (char*)hModule + Name[i]))
		{
			return (uint64_t)((LPBYTE)hModule + Address[Ordinal[i]]);
		}
	}

	return NULL;
}


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
#

#include "krnlutils.h"
#include "imports.h"
#include "defs.h"

//updated for build 1903
#define offset_activeprocesslinks 0x2F0
#define offset_imagefilename 0x450

uintptr_t krnlutils::find_eprocess(const char* pProcessName)
{
	uintptr_t list_head = *(uintptr_t*)((uintptr_t)PsInitialSystemProcess + offset_activeprocesslinks);
	uintptr_t list_current = list_head;

	do
	{
		uintptr_t list_entry = list_current - offset_activeprocesslinks;

		if (!_stricmp(pProcessName, (char*)(list_entry + offset_imagefilename)))
		{
			return list_entry;
		}

		list_current = *(uintptr_t*)list_current;
	} while (list_current != list_head);

	return NULL;
}

uintptr_t krnlutils::get_procbase(PEPROCESS pProcess) {

	if(pProcess)
		return (uintptr_t)PsGetProcessSectionBaseAddress(pProcess);

	return NULL;
}

uintptr_t krnlutils::get_procbase_by_id(uint32_t process_id) {
	PEPROCESS pProcess;
	PsLookupProcessByProcessId((HANDLE)process_id, &pProcess);

	if (pProcess)
		return (uintptr_t)PsGetProcessSectionBaseAddress(pProcess);

	return NULL;
}

uintptr_t krnlutils::get_krnl_module_base(const char* module_name, size_t& size) {

	ULONG bytes = 0;
	NTSTATUS status = ZwQuerySystemInformation(SystemModuleInformation, 0, bytes, &bytes);

	if (!bytes)
		return 0;


	PRTL_PROCESS_MODULES modules = (PRTL_PROCESS_MODULES)ExAllocatePoolWithTag(NonPagedPool, bytes, 'kcuF'); // 'ENON'

	status = ZwQuerySystemInformation(SystemModuleInformation, modules, bytes, &bytes);

	if (!NT_SUCCESS(status)) {
		ExFreePoolWithTag(modules, 'kcuF');
		return 0;
	}



	PRTL_PROCESS_MODULE_INFORMATION module = modules->Modules;
	uintptr_t module_base = 0;
	HANDLE pid = 0;

	for (ULONG i = 0; i < modules->NumberOfModules; i++)
	{

		if (strcmp((char*)(module[i].FullPathName + module[i].OffsetToFileName), module_name) == 0)
		{
			module_base = uintptr_t(module[i].ImageBase);
			size = module[i].ImageSize;
			break;
		}
	}

	if (modules)
		ExFreePoolWithTag(modules, 'kcuF');

	if (module_base <= 0)
		return 0;

	return module_base;
}

uintptr_t krnlutils::get_krnl_module_export(const char* pModuleName, const char* pRoutineName) {
	size_t size;
	uintptr_t lpModule = get_krnl_module_base(pModuleName, size);

	if (!lpModule)
		return NULL;

	return (uintptr_t)RtlFindExportedRoutineByName((PVOID)lpModule, pRoutineName);
}

uint16_t krnlutils::find_os_version() {
	RTL_OSVERSIONINFOW versionInfo = {};
	NTSTATUS			status		= NULL;

	status = RtlGetVersion(&versionInfo);

	if (!NT_SUCCESS(status))
		return NULL;

	return (uint16_t)versionInfo.dwBuildNumber;
}

uintptr_t krnlutils::get_um_module_base(PEPROCESS pProcess, LPCWSTR module_name) {
	uintptr_t base;

	if (!pProcess) {
		DbgPrintEx(0, 0, "> invalid PEPROCESS given!");
		return 0;
	}

	KeAttachProcess((PKPROCESS)pProcess);

	PPEB peb = PsGetProcessPeb(pProcess);
	if (!peb) {
		DbgPrintEx(0, 0, "> failed to get procPEB!");
		KeDetachProcess();
		return 0;
	}

	if (!peb->Ldr || !peb->Ldr->Initialized) {
		DbgPrintEx(0, 0, "> failed to get PEB->ldr!");
		KeDetachProcess();
		return 0;
	}

	if (!module_name) {
		DbgPrintEx(0, 0, "invalid_module_name \n");
		return 0;
	}

	UNICODE_STRING module_name_unicode;
	RtlInitUnicodeString(&module_name_unicode, module_name);

	for (PLIST_ENTRY list = peb->Ldr->ModuleListLoadOrder.Flink;
		list != &peb->Ldr->ModuleListLoadOrder;
		list = list->Flink) {
		PLDR_DATA_TABLE_ENTRY entry = CONTAINING_RECORD(list, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
		if (RtlCompareUnicodeString(&entry->BaseDllName, &module_name_unicode, TRUE) == 0) {
			base = (uintptr_t)entry->DllBase;
			KeDetachProcess();
			return base;
		}
	}

	KeDetachProcess();
	return 0;
}

uintptr_t krnlutils::get_um_module_size(PEPROCESS pProcess, LPCWSTR module_name) {
	uintptr_t size;

	if (!pProcess) {
		DbgPrintEx(0, 0, "> invalid PEPROCESS given!");
		return 0;
	}

	KeAttachProcess((PKPROCESS)pProcess);

	PPEB peb = PsGetProcessPeb(pProcess);
	if (!peb) {
		DbgPrintEx(0, 0, "> failed to get procPEB!");
		KeDetachProcess();
		return 0;
	}

	if (!peb->Ldr || !peb->Ldr->Initialized) {
		DbgPrintEx(0, 0, "> failed to get PEB->ldr!");
		KeDetachProcess();
		return 0;
	}

	if (!module_name) {
		DbgPrintEx(0, 0, "invalid_module_name \n");
		return 0;
	}

	UNICODE_STRING module_name_unicode;
	RtlInitUnicodeString(&module_name_unicode, module_name);

	for (PLIST_ENTRY list = peb->Ldr->ModuleListLoadOrder.Flink;
		list != &peb->Ldr->ModuleListLoadOrder;
		list = list->Flink) {
		PLDR_DATA_TABLE_ENTRY entry = CONTAINING_RECORD(list, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
		if (RtlCompareUnicodeString(&entry->BaseDllName, &module_name_unicode, TRUE) == 0) {
			size = (uintptr_t)entry->SizeOfImage;
			KeDetachProcess();
			return size;
		}
	}

	KeDetachProcess();
	return 0;
}

#include <ntimage.h>

uintptr_t krnlutils::get_krnl_module_export_manually(uint64_t kernel_module_base, const char* function_name) {
	if (!kernel_module_base)
		return 0;

	IMAGE_DOS_HEADER dos_header = { 0 };
	IMAGE_NT_HEADERS64 nt_headers = { 0 };

	NTSTATUS status;

	uint64_t addr_dos = (uint64_t)& dos_header;
	uint64_t addr_nt = (uint64_t)& nt_headers;

	RtlCopyMemory((uint64_t*)addr_dos, (uint64_t*)kernel_module_base, sizeof(dos_header));
	RtlCopyMemory((uint64_t*)addr_nt, (uint64_t*)(kernel_module_base + dos_header.e_lfanew), sizeof(nt_headers));

#define IMAGE_DIRECTORY_ENTRY_EXPORT          0 

	const auto export_base = nt_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
	const auto export_base_size = nt_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;

	if (!export_base || !export_base_size) {
		DbgPrintEx(0, 0, "export_base, or export_base_size was null!");
		return 0;
	}

	const auto export_data = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(ExAllocatePoolWithTag(NonPagedPool, export_base_size, 'kcuF'));

	if (export_data) {
		SIZE_T NumberOfBytesTransferred = 0;
		MM_COPY_ADDRESS AddrToRead;

		PVOID export_data_addr = (PVOID)export_data;
		PVOID export_addr = (PVOID)(kernel_module_base + (uint64_t)export_base);

		AddrToRead.VirtualAddress = export_addr;

		status = MmCopyMemory(export_data, AddrToRead, export_base_size, MM_COPY_MEMORY_VIRTUAL, &NumberOfBytesTransferred);

		if (!NT_SUCCESS(status))
			return 0;
	}

	const auto delta = reinterpret_cast<uint64_t>(export_data) - export_base;

	const auto name_table = reinterpret_cast<uint32_t*>(export_data->AddressOfNames + delta);
	const auto ordinal_table = reinterpret_cast<uint16_t*>(export_data->AddressOfNameOrdinals + delta);
	const auto function_table = reinterpret_cast<uint32_t*>(export_data->AddressOfFunctions + delta);

	for (auto i = 0u; i < export_data->NumberOfNames; ++i)
	{
		const char* current_func_name = reinterpret_cast<char*>(name_table[i] + delta);

		if (strcmp(current_func_name, function_name) == 0)
		{
			const auto function_ordinal = ordinal_table[i];
			const auto function_address = kernel_module_base + function_table[function_ordinal];

			if (function_address >= kernel_module_base + export_base && function_address <= kernel_module_base + export_base + export_base_size)
			{
				ExFreePoolWithTag(export_data, 'kcuF');
				return function_address;
			}

			ExFreePoolWithTag(export_data, 'kcuF');
			return function_address;
		}
	}

	return 0;
}

//find TID by PID
typedef struct _SYSTEM_THREAD {



	LARGE_INTEGER           KernelTime;
	LARGE_INTEGER           UserTime;
	LARGE_INTEGER           CreateTime;
	ULONG                   WaitTime;
	PVOID                   StartAddress;
	CLIENT_ID               ClientId;
	KPRIORITY               Priority;
	LONG                    BasePriority;
	ULONG                   ContextSwitchCount;
	ULONG                   State;
	KWAIT_REASON            WaitReason;

} SYSTEM_THREAD, * PSYSTEM_THREAD;

typedef struct _SYSTEM_PROCESS_INFORMATION {



	ULONG                   NextEntryOffset;
	ULONG                   NumberOfThreads;
	LARGE_INTEGER           Reserved[3];
	LARGE_INTEGER           CreateTime;
	LARGE_INTEGER           UserTime;
	LARGE_INTEGER           KernelTime;
	UNICODE_STRING          ImageName;
	KPRIORITY               BasePriority;
	HANDLE                  ProcessId;
	HANDLE                  InheritedFromProcessId;
	ULONG                   HandleCount;
	ULONG                   Reserved2[2];
	ULONG                   PrivatePageCount;
	VM_COUNTERS             VirtualMemoryCounters;
	IO_COUNTERS             IoCounters;
	SYSTEM_THREAD           Threads[0];

} SYSTEM_PROCESS_INFORMATION, * PSYSTEM_PROCESS_INFORMATION;

typedef void* LPVOID;

NTSTATUS krnlutils::get_thread_id_by_pid(uint32_t pid, uint32_t& tid) {
	NTSTATUS status;
	LPVOID pBuffer;
	ULONG size;
	PSYSTEM_PROCESS_INFORMATION ProcessInfo;
	ULONG NextEntryOffset;

	size = 0x10000;

	pBuffer = ExAllocatePoolWithTag(NonPagedPool, size, 'kcuF');

	while (true) {
		status = ZwQuerySystemInformation(SystemProcessInformation, pBuffer, size, &size);

		if (NT_SUCCESS(status)) {
			break;
		}
		else if (status == STATUS_INFO_LENGTH_MISMATCH) {
			size += 0x10000;
			pBuffer = ExAllocatePoolWithTag(NonPagedPool, size, 'kcuF');
		}
		else {
			ExFreePoolWithTag(pBuffer, 'kcuF');
			return STATUS_UNSUCCESSFUL;
		}
	}

	NextEntryOffset = 0;
	status = STATUS_NOT_FOUND;
	ProcessInfo = (PSYSTEM_PROCESS_INFORMATION)pBuffer;

	do {
		ProcessInfo = (PSYSTEM_PROCESS_INFORMATION)((ULONG_PTR)ProcessInfo + NextEntryOffset);
		if (ProcessInfo->ProcessId == (HANDLE)pid)
		{
			if (ProcessInfo->NumberOfThreads > 0)
			{
				tid = (DWORD)ProcessInfo->Threads[0].ClientId.UniqueThread;
				status = STATUS_SUCCESS;
				break;
			}
		}
		NextEntryOffset = ProcessInfo->NextEntryOffset;
	} while (NextEntryOffset > 0);

	ExFreePoolWithTag(pBuffer, 'kcuF');
	return status;
}
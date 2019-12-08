#define pooltag 'dEad'

#include "cleaner.h"
#include "../imports.h"
#include "../krnlutils.h"
#include "../utils/utils.h"

struct piddbcache
{
	LIST_ENTRY		List;
	UNICODE_STRING	DriverName;
	ULONG			TimeDateStamp;
	NTSTATUS		LoadStatus;
	char			_0x0028[16]; // data from the shim engine, or uninitialized memory for custom drivers
};


void clean_piddb_cache() {
	PRTL_AVL_TABLE PiDDBCacheTable;

	size_t size;
	uintptr_t ntoskrnlBase = krnlutils::get_krnl_module_base("ntoskrnl.exe", size);

	DbgPrintEx(0, 0, "ntoskrnl.exe: %p\n", ntoskrnlBase);
	DbgPrintEx(0, 0, "ntoskrnl.exe size: %p\n", size);
	PiDDBCacheTable = (PRTL_AVL_TABLE)utils::dereference(utils::find_pattern<uintptr_t>((void*)ntoskrnlBase, size, "\x48\x8D\x0D\x00\x00\x00\x00\x4C\x89\x35\x00\x00\x00\x00", "xxx????xxx????"), 3);

	DbgPrintEx(0, 0, "PiDDBCacheTable: %p\n", PiDDBCacheTable);

	uintptr_t entry_address = uintptr_t(PiDDBCacheTable->BalancedRoot.RightChild) + sizeof(RTL_BALANCED_LINKS);
	DbgPrintEx(0, 0, "entry_address: %p\n", entry_address);

	piddbcache* entry = (piddbcache*)(entry_address);

	/*capcom.sys(drvmap) : 0x57CD1415 iqvw64e.sys(kdmapper) : 0x5284EAC3, also cpuz driver*/
	if (entry->TimeDateStamp == 0x57CD1415 || entry->TimeDateStamp == 0x5284EAC3) {
		entry->TimeDateStamp = 0x54EAC3;
		entry->DriverName = RTL_CONSTANT_STRING(L"monitor.sys");
	}

	ULONG count = 0;
	for (auto link = entry->List.Flink; link != entry->List.Blink; link = link->Flink, count++)
	{
		piddbcache* cache_entry = (piddbcache*)(link);

		if (cache_entry->TimeDateStamp == 0x57CD1415 || cache_entry->TimeDateStamp == 0x5284EAC3) {
			DbgPrintEx(0, 0, "suspicious cache entry found!: %lu name: %wZ \t\t stamp: %x\n",
				count,
				cache_entry->DriverName,
				cache_entry->TimeDateStamp);
			cache_entry->TimeDateStamp = 0x54EAC4 + count;
			cache_entry->DriverName = RTL_CONSTANT_STRING(L"monitor.sys");
		}
		DbgPrintEx(0, 0, "cache_entry count: %lu name: %wZ \t\t stamp: %x\n",
			count,
			cache_entry->DriverName,
			cache_entry->TimeDateStamp);
	}
}

// clear our driver mapper
void clean_unloaded_drivers() {

	ULONG bytes = 0;
	auto status = ZwQuerySystemInformation(SystemModuleInformation, 0, bytes, &bytes);

	if (!bytes)
		return;

	PRTL_PROCESS_MODULES modules = (PRTL_PROCESS_MODULES)ExAllocatePoolWithTag(NonPagedPool, bytes, pooltag);

	status = ZwQuerySystemInformation(SystemModuleInformation, modules, bytes, &bytes);

	if (!NT_SUCCESS(status)) {
		DbgPrint("ZwQuerySystemInformation failed(unloaded drivers)\n");
		ExFreePoolWithTag(modules, pooltag);
		return;
	}

	PRTL_PROCESS_MODULE_INFORMATION module = modules->Modules;
	uintptr_t ntoskrnlBase = 0;
	size_t ntoskrnlSize = 0;

	ntoskrnlBase = krnlutils::get_krnl_module_base("ntoskrnl.exe", ntoskrnlSize);

	ExFreePoolWithTag(modules, pooltag);

	if (ntoskrnlBase <= 0) {
		DbgPrintEx(0, 0, "get_kerneladdr failed(unloaded drivers)\n");
		return;
	}

	// NOTE: 4C 8B ? ? ? ? ? 4C 8B C9 4D 85 ? 74 + 3 + current signature address = MmUnloadedDrivers
	auto mmUnloadedDriversPtr = utils::find_pattern<uintptr_t>((void*)ntoskrnlBase, ntoskrnlSize, "\x4C\x8B\x00\x00\x00\x00\x00\x4C\x8B\xC9\x4D\x85\x00\x74", "xx?????xxxxx?x");

	DbgPrintEx(0, 0, "mmUnloadedDriversPtr: %p\n", mmUnloadedDriversPtr);

	if (!mmUnloadedDriversPtr) {
		DbgPrintEx(0, 0, "mmUnloadedDriversPtr equals 0(unloaded drivers)\n");
		return;
	}

	uintptr_t mmUnloadedDrivers = utils::dereference(mmUnloadedDriversPtr, 3);

	DbgPrintEx(0, 0, "memset unloaded drivers\n");
	memset(*(uintptr_t * *)mmUnloadedDrivers, 0, 0x7D0);
}

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

BOOLEAN bDataCompare(const BYTE* pData, const BYTE* bMask, const char* szMask)
{
	for (; *szMask; ++szMask, ++pData, ++bMask)
		if (*szMask == 'x' && *pData != *bMask)
			return 0;

	return (*szMask) == 0;
}

UINT64 FindPattern(UINT64 dwAddress, UINT64 dwLen, BYTE * bMask, char* szMask)
{
	for (UINT64 i = 0; i < dwLen; i++)
		if (bDataCompare((BYTE*)(dwAddress + i), bMask, szMask))
			return (UINT64)(dwAddress + i);

	return 0;
}

bool clean_unloaded_drivers()
{
	ULONG bytes = 0;
	NTSTATUS status = ZwQuerySystemInformation(SystemModuleInformation, 0, bytes, &bytes);

	if (!bytes)
	{
		DbgPrintEx(0, 0, "CleanUnloadedDrivers: first NtQuerySystemInformation failed, status: 0x%x\n", status);
		return FALSE;
	}

	PRTL_PROCESS_MODULES modules = (PRTL_PROCESS_MODULES)ExAllocatePoolWithTag(NonPagedPool, bytes, 0x454E4F45); // 'ENON'

	status = ZwQuerySystemInformation(SystemModuleInformation, modules, bytes, &bytes);

	if (!NT_SUCCESS(status))
	{
		DbgPrintEx(0, 0, "CleanUnloadedDrivers: second NtQuerySystemInformation failed, status: 0x%x\n", status);
		return FALSE;
	}

	PRTL_PROCESS_MODULE_INFORMATION module = modules->Modules;
	UINT64 ntoskrnlBase = 0, ntoskrnlSize = 0;

	for (ULONG i = 0; i < modules->NumberOfModules; i++)
	{
		DbgPrintEx(0, 0, "CleanUnloadedDrivers: path: %s\n", module[i].FullPathName);

		if (!strcmp((char*)module[i].FullPathName, "\\SystemRoot\\system32\\ntoskrnl.exe"))
		{
			ntoskrnlBase = (UINT64)module[i].ImageBase;
			ntoskrnlSize = (UINT64)module[i].ImageSize;
			break;
		}
	}

	if (modules)
		ExFreePoolWithTag(modules, 0);

	if (ntoskrnlBase <= 0)
	{
		DbgPrintEx(0, 0, "CleanUnloadedDrivers: ntoskrnlBase equals zero\n");
		return FALSE;
	}

	// NOTE: 4C 8B ? ? ? ? ? 4C 8B C9 4D 85 ? 74 + 3] + current signature address = MmUnloadedDrivers
	UINT64 mmUnloadedDriversPtr = FindPattern((UINT64)ntoskrnlBase, (UINT64)ntoskrnlSize, (BYTE*)"\x4C\x8B\x00\x00\x00\x00\x00\x4C\x8B\xC9\x4D\x85\x00\x74", "xx?????xxxxx?x");

	if (!mmUnloadedDriversPtr)
	{
		DbgPrintEx(0, 0, "CleanUnloadedDrivers: mmUnloadedDriversPtr equals zero\n");
		return FALSE;
	}

	UINT64 mmUnloadedDrivers = (UINT64)((PUCHAR)mmUnloadedDriversPtr + *(PULONG)((PUCHAR)mmUnloadedDriversPtr + 3) + 7);
	UINT64 bufferPtr = *(UINT64*)mmUnloadedDrivers;

	// NOTE: 0x7D0 is the size of the MmUnloadedDrivers array for win 7 and above
	PVOID newBuffer = ExAllocatePoolWithTag(NonPagedPoolNx, 0x7D0, 0x54446D4D);

	if (!newBuffer)
		return FALSE;

	memset(newBuffer, 0, 0x7D0);

	// NOTE: replace MmUnloadedDrivers
	*(UINT64*)mmUnloadedDrivers = (UINT64)newBuffer;

	// NOTE: clean the old buffer
	ExFreePoolWithTag((PVOID)bufferPtr, 0x54446D4D); // 'MmDT'

	return TRUE;
}
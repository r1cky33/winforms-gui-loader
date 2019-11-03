#include "imports.h"
#include "stdint.h"
#include "krnlutils.h"

#include "cleaner/cleaner.h"

PVOID*	gHalDispatchTable	= NULL;
PVOID	originalAddress		= NULL;

extern void start_server();

void hkHandler() {
	DbgPrintEx(0, 0, "> hkHandler called\n");

	gHalDispatchTable[1] = originalAddress; //restore gHalDispatchTable

	//todo
	clean_piddb_cache();
	clean_unloaded_drivers();

	start_server();
}

extern "C" NTSTATUS DriverEntry(
	PDRIVER_OBJECT  driver_object,
	PUNICODE_STRING registry_path
)
{
	UNREFERENCED_PARAMETER(driver_object);
	UNREFERENCED_PARAMETER(registry_path);
	
	gHalDispatchTable = reinterpret_cast<PVOID*>(krnlutils::get_krnl_module_export("ntoskrnl.exe", "HalDispatchTable"));

	if (!gHalDispatchTable)
		return STATUS_UNSUCCESSFUL;

	originalAddress = gHalDispatchTable[1];	//save the original value
	gHalDispatchTable[1] = &hkHandler;		//patch gHalDispatchTable

	DbgPrintEx(0, 0, "> HalDispatchTable %llx\n", gHalDispatchTable);

	//PEPROCESS pProcess = (PEPROCESS)krnlutils::find_eprocess("notepad.exe");

	//if (!pProcess)
	//	return STATUS_UNSUCCESSFUL;

	//uintptr_t ntdllBase = krnlutils::get_um_module_base(pProcess, L"ntdll.dll");

	//if (!ntdllBase)
	//	return STATUS_UNSUCCESSFUL;

	//DbgPrintEx(0, 0, "> ntdllBase: 0x%p\n", ntdllBase);

	return STATUS_SUCCESS;
}
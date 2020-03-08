#include "server.h"
#include "../krnlutils.h"
#include "shared_defs.h"
#include "../imports.h"
#include "../utils/utils.h"

#include <intrin.h>

extern PMMVAD(*MiAllocateVad)(UINT_PTR start, UINT_PTR end, LOGICAL deletable);
extern NTSTATUS(*MiInsertVadCharges)(PMMVAD vad, PEPROCESS process);
extern VOID(*MiInsertVad)(PMMVAD vad, PEPROCESS process);

void read_um() {
	RtlCopyMemory(&shBuff.buff_0x0, (uint64_t*)(sharedBuffBase), sizeof(uint64_t));
	RtlCopyMemory(&shBuff.buff_0x8, (uint64_t*)(sharedBuffBase + 0x8), sizeof(uint64_t));
}

void finish_req() {
	RtlCopyMemory((uint64_t*)(sharedBuffBase + 0x10), &finisher, sizeof(uint64_t));
	RtlCopyMemory((uint64_t*)(sharedBuffBase), &zeroer, sizeof(uint64_t));
}

void handle_driver_stop() {
	PsTerminateSystemThread(NULL);
}

void handle_get_proc_base() {
	_k_get_base_module* in = (_k_get_base_module*)shBuff.buff_0x8;
	PEPROCESS pProcess = (PEPROCESS)krnlutils::find_eprocess(in->name);

	if (!pProcess) {
		finish_req();
		return;
	}

	uintptr_t proc_base = krnlutils::get_procbase(pProcess);

	if (!proc_base) {
		finish_req();
		return;
	}
	else
		RtlCopyMemory((uint64_t*)in->dst, &proc_base, sizeof(uint64_t));	//copy address to um buffer

	finish_req();
	ObDereferenceObject(pProcess);
}

void handle_get_proc_base_by_id() {
	_k_get_base_by_id* in = (_k_get_base_by_id*)shBuff.buff_0x8;
	_k_get_base_by_id local = { in->pid, in->addr };

	PEPROCESS pProcess = NULL;

	PsLookupProcessByProcessId(HANDLE(local.pid), &pProcess);

	if (!pProcess) {
		finish_req();
		return;
	}

	uintptr_t proc_base = krnlutils::get_procbase(pProcess);

	if (!proc_base) {
		finish_req();
		return;
	}
	else
		RtlCopyMemory((uint64_t*)local.addr, &proc_base, sizeof(uint64_t));

	finish_req();
	ObDereferenceObject(pProcess);
}

void handle_copy_memory() {
	PEPROCESS process_src = nullptr;
	PEPROCESS process_dst = nullptr;
	NTSTATUS status;
	SIZE_T   return_size = 0;
	_k_rw_request* in = (_k_rw_request*)shBuff.buff_0x8;

	if (!NT_SUCCESS(PsLookupProcessByProcessId(HANDLE(in->dst_pid), &process_dst)))
	{
		finish_req();
		return;
	}

	if (!NT_SUCCESS(PsLookupProcessByProcessId(HANDLE(in->src_pid), &process_src)))
	{
		finish_req();
		return;
	}

	status = MmCopyVirtualMemory(process_src,
		(void*)in->src_addr,
		process_dst,
		(void*)in->dst_addr,
		in->size,
		UserMode, &return_size);

	finish_req();

	ObDereferenceObject(process_src);
	ObDereferenceObject(process_dst);
}

void handle_virtual_protect() {
	_k_virtual_protect* in = (_k_virtual_protect*)shBuff.buff_0x8;
	_k_virtual_protect local = { in->pid, in->protect, in->addr, in->size };

	NTSTATUS status;
	PEPROCESS target;
	PVOID protect_base = (PVOID)local.addr;

	if (!NT_SUCCESS(PsLookupProcessByProcessId(HANDLE(local.pid), &target)))
	{
		finish_req();
		return;
	}

	KAPC_STATE apc;
	ULONG old_protection = NULL;
	KeStackAttachProcess(target, &apc);
	status = ZwProtectVirtualMemory(ZwCurrentProcess(), &protect_base, &local.size, (ULONG)local.protect, &old_protection);
	KeUnstackDetachProcess(&apc);
	in->protect = old_protection;

	finish_req();
	ObDereferenceObject(target);
}

void handle_virtual_alloc() {
	_k_virtual_alloc* in = (_k_virtual_alloc*)shBuff.buff_0x8;
	_k_virtual_alloc local = { in->pid, in->allocation_type, in->protect, in->addr, in->size };
	NTSTATUS status;
	PEPROCESS target;
	PVOID alloc_base = NULL;

	if (!NT_SUCCESS(PsLookupProcessByProcessId(HANDLE(local.pid), &target)))
	{
		finish_req();
		return;
	}

	KAPC_STATE apc;
	KeStackAttachProcess(target, &apc);
	status = ZwAllocateVirtualMemory(ZwCurrentProcess(), &alloc_base, 0, &local.size,
		(ULONG)local.allocation_type, (ULONG)local.protect);

	//secure allocated region
	MmSecureVirtualMemory(alloc_base, local.size, PAGE_READWRITE);
	KeUnstackDetachProcess(&apc);

	if(alloc_base)
		RtlCopyMemory((uint64_t*)in->addr, &alloc_base, sizeof(uint64_t));

	finish_req();

	ObDereferenceObject(target);
}

void handle_get_um_module() {
	NTSTATUS status;
	PEPROCESS pProcess = nullptr;

	_k_get_um_module* in = (_k_get_um_module*)shBuff.buff_0x8;

	status = PsLookupProcessByProcessId(HANDLE(in->pid), &pProcess);

	if (!NT_SUCCESS(status)) {
		DbgPrintEx(0, 0, "> handle_get_um_module - invalid procID!");
		finish_req();
		return;
	}

	WCHAR module_name[256] = {};
	wcscpy(module_name, in->moduleName);

	if (!module_name[1]) {
		finish_req();
		return;
	}

	uintptr_t moduleBase = krnlutils::get_um_module_base(pProcess, module_name);
	uint32_t moduleSize = (uint32_t)krnlutils::get_um_module_size(pProcess, module_name);

	if (!moduleBase) {
		finish_req();
		return;
	}
	else {
		RtlCopyMemory((uint64_t*)in->dst_base, &moduleBase, sizeof(uint64_t));
		RtlCopyMemory((uint64_t*)in->dst_size, &moduleSize, sizeof(uint32_t));
	}

	finish_req();
	ObDereferenceObject(pProcess);
}

void handle_secure_memory() {
	_k_secure_mem* in = (_k_secure_mem*)shBuff.buff_0x8;
	_k_secure_mem local = { in->addr, in->size, in->probemode };

	MmSecureVirtualMemory((PVOID)local.addr, local.size, local.probemode);

	finish_req();
}

void handle_write_to_readonly() {
	PEPROCESS process_src = nullptr;
	PEPROCESS process_dst = nullptr;
	NTSTATUS status;
	SIZE_T   return_size = 0;
	_k_rw_request* in = (_k_rw_request*)shBuff.buff_0x8;

	if (!NT_SUCCESS(PsLookupProcessByProcessId(HANDLE(in->dst_pid), &process_dst)))
	{
		finish_req();
		return;
	}

	if (!NT_SUCCESS(PsLookupProcessByProcessId(HANDLE(in->src_pid), &process_src)))
	{
		finish_req();
		return;
	}


	//_disable();
	__writecr0(__readcr0() & (~(1 << 16)));

	status = MmCopyVirtualMemory(process_src,
		(void*)in->src_addr,
		process_dst,
		(void*)in->dst_addr,
		in->size,
		UserMode, &return_size);

	__writecr0(__readcr0() | (1 << 16));
	//_enable();

	finish_req();

	ObDereferenceObject(process_src);
	ObDereferenceObject(process_dst);
}

PLDR_DATA_TABLE_ENTRY GetModuleByName(PEPROCESS process, PWCHAR moduleName) {
	UNICODE_STRING moduleNameStr = { 0 };
	RtlInitUnicodeString(&moduleNameStr, moduleName);

	PLIST_ENTRY list = &(PsGetProcessPeb(process)->Ldr->ModuleListLoadOrder);
	for (PLIST_ENTRY entry = list->Flink; entry != list; ) {
		PLDR_DATA_TABLE_ENTRY module = CONTAINING_RECORD(entry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
		if (RtlCompareUnicodeString(&module->BaseDllName, &moduleNameStr, TRUE) == 0) {
			return module;
		}

		entry = module->InLoadOrderLinks.Flink;
	}

	return NULL;
}

void handle_extend_module() {
	_k_extend_module* in = (_k_extend_module*)shBuff.buff_0x8;

	uint32_t size = (uint32_t)in->size;

	PEPROCESS process = NULL;

	NTSTATUS status = PsLookupProcessByProcessId((HANDLE)in->pid, &process);
	if (!NT_SUCCESS(status)) {
		finish_req();
		return;
	}

	utils::FindVADs();

	if (!MiAllocateVad || !MiInsertVad || !MiInsertVadCharges) {
		DbgPrintEx(0, 0, "> VADs not Found!");
	}

	WCHAR module_name[256] = {};
	wcscpy(module_name, in->moduleName);

	if (!module_name[1]) {
		finish_req();
		return;
	}

	DbgPrintEx(0, 0, "> %ws module\n", module_name);

	KeAttachProcess(process);

	DbgPrintEx(0, 0, "attached!");

	PLDR_DATA_TABLE_ENTRY module = GetModuleByName(process, module_name);
	if (!module) {
		status = STATUS_NOT_FOUND;
		goto cleanup;
	}

	UINT_PTR start = (UINT_PTR)module->DllBase + module->SizeOfImage;
	UINT_PTR end = start + size - 1;

	MEMORY_BASIC_INFORMATION info = { 0 };
	status = ZwQueryVirtualMemory(NtCurrentProcess(), (PVOID)start, MemoryBasicInformation, &info, sizeof(info), NULL);

	if (!NT_SUCCESS(status)) {
		DbgPrintEx(0, 0, "> ERROR 1");
		goto cleanup;
	}

	if (info.State != MEM_FREE || info.BaseAddress != (PVOID)start || info.RegionSize < (size_t)size) {
		status = STATUS_INVALID_ADDRESS;
		DbgPrintEx(0, 0, "> ERROR 2");
		goto cleanup;
	}

	DbgPrintEx(0, 0, "0x%p 0x%p 0x%p \n", MiAllocateVad, MiInsertVad, MiInsertVadCharges);
	PMMVAD vad = MiAllocateVad(start, end, TRUE);
	if (!vad) {
		status = STATUS_INSUFFICIENT_RESOURCES;
		goto cleanup;
	}

	static RTL_OSVERSIONINFOW version = { sizeof(RTL_OSVERSIONINFOW) };
	if (!version.dwBuildNumber) {
		RtlGetVersion(&version);
	}

	if (version.dwBuildNumber < 18362) {
		PMMVAD_FLAGS flags = (PMMVAD_FLAGS)& vad->u1.LongFlags;
		flags->Protection = MM_EXECUTE_READWRITE;
		flags->NoChange = 0;
	}
	else {
		PMMVAD_FLAGS_19H flags = (PMMVAD_FLAGS_19H)& vad->u1.LongFlags;
		flags->Protection = MM_EXECUTE_READWRITE;
		flags->NoChange = 0;
	}

	if (!NT_SUCCESS(status = MiInsertVadCharges(vad, process))) {
		ExFreePool(vad);
		goto cleanup;
	}

	// We should call MiLockVad but /shrug
	MiInsertVad(vad, process);
	module->SizeOfImage += size;

	//secure the extended region
	MmSecureVirtualMemory((PVOID)start, size, PAGE_READWRITE);

cleanup:
	KeDetachProcess();
	ObDereferenceObject(process);
	finish_req();
}

void job_handler() {
	DbgPrintEx(0, 0, "> job_handler\n");

	while (true) {
		read_um();

		if (shBuff.buff_0x0 == (uint64_t)DRIVER_CONTINUE) {			//working
			continue;
		}
		else if (shBuff.buff_0x0 == (uint64_t)DRIVER_GET_BASE) {
			handle_get_proc_base();
		}
		else if (shBuff.buff_0x0 == (uint64_t)DRIVER_COPYMEMROY) {
			handle_copy_memory();
		}
		else if (shBuff.buff_0x0 == (uint64_t)DRIVER_PROTECT) {
			handle_virtual_protect();
		}
		else if (shBuff.buff_0x0 == (uint64_t)DRIVER_ALLOC) {
			handle_virtual_alloc();
		}
		else if (shBuff.buff_0x0 == (uint64_t)DRIVER_STOP) {
			NTSTATUS status = PsTerminateSystemThread(0);
			
			break;
		}
		else if (shBuff.buff_0x0 == (uint64_t)DRIVER_GET_UM_MODULE) {
			handle_get_um_module();
		}
		else if (shBuff.buff_0x0 == (uint64_t)DRIVER_SECURE) {
			handle_secure_memory();
		}
		else if (shBuff.buff_0x0 == (uint64_t)DRIVER_GET_BASE_BY_ID) {
			handle_get_proc_base_by_id();
		}
		else if (shBuff.buff_0x0 == (uint64_t)DRIVER_WRITE_TO_READONLY) {
			handle_write_to_readonly();
		}
		else if (shBuff.buff_0x0 == (uint64_t)DRIVER_EXTEND_MODULE) {
			handle_extend_module();
		}
	}
}

void start_server() {
	PEPROCESS pProcess = (PEPROCESS)krnlutils::find_eprocess("Y6s1FAa9vi.exe");

	if (!pProcess)
		return;

	umProcessBase = krnlutils::get_procbase(pProcess);

	if (!umProcessBase)
		return;

	sharedBuffBase = umProcessBase + OFFSET_SHAREDBUFFER;

	job_handler();
}
#include "server.h"
#include "../krnlutils.h"
#include "shared_defs.h"
#include "../imports.h"
#include <intrin.h>

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

	DbgPrintEx(0, 0, "local. pid 0x%p\n", local.pid);

	if (!NT_SUCCESS(PsLookupProcessByProcessId(HANDLE(local.pid), &target)))
	{
		finish_req();
		return;
	}

	DbgPrintEx(0, 0, "> virtual protect: in->addr: 0x%p , &in->addr: 0x%p ,  &in->size: 0x%p  , in->protect: 0x%p\n", protect_base, &protect_base, &local.size, (ULONG)local.protect);

	KAPC_STATE apc;
	ULONG old_protection = NULL;
	KeStackAttachProcess(target, &apc);
	status = ZwProtectVirtualMemory(ZwCurrentProcess(), &protect_base, &local.size, (ULONG)local.protect, &old_protection);
	DbgPrintEx(0, 0, "> status: 0x%p", status);
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

	DbgPrintEx(0, 0, "> virtual alloc: in->addr: 0x%p ,  &in->size: 0x%p  , in->allocation_type: 0x%p  ,  in->protect 0x%p\n", (PVOID*)& alloc_base, (PSIZE_T)&in->size,
		(ULONG)in->allocation_type, (ULONG)in->protect);

	KAPC_STATE apc;
	KeStackAttachProcess(target, &apc);
	status = ZwAllocateVirtualMemory(ZwCurrentProcess(), &alloc_base, 0, &local.size,
		(ULONG)local.allocation_type, (ULONG)local.protect);

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

	DbgPrintEx(0, 0, "module_name: %ws \n", &module_name);

	uintptr_t moduleBase = krnlutils::get_um_module_base(pProcess, module_name);

	if (!moduleBase) {
		DbgPrintEx(0, 0, "> failed to get processModule : 0x%p\n ", moduleBase);
		finish_req();
		return;
	}
	else {
		DbgPrintEx(0, 0, "> got processModule : 0x%p\n ", moduleBase);
		RtlCopyMemory((uint64_t*)in->dst, &moduleBase, sizeof(uint64_t));
	}

	finish_req();
	ObDereferenceObject(pProcess);
}

void handle_secure_memory() {
	_k_secure_mem* in = (_k_secure_mem*)shBuff.buff_0x8;
	_k_secure_mem local = { in->addr, in->size, in->probemode };

	DbgPrintEx(0, 0, "MmSecureVirtualMemory params: 0x%p \t 0x%p \t 0x%p \t", local.addr, local.size, local.probemode);

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

	KAPC_STATE apc;
	KeStackAttachProcess(process_dst, &apc);

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

	KeUnstackDetachProcess(&apc);

	finish_req();

	ObDereferenceObject(process_src);
	ObDereferenceObject(process_dst);
}

void job_handler() {
	DbgPrintEx(0, 0, "> job_handler\n");

	while (true) {
		read_um();

		if (shBuff.buff_0x0 == (uint64_t)DRIVER_CONTINUE) {			//working
			continue;
		}
		else if (shBuff.buff_0x0 == (uint64_t)DRIVER_GET_BASE) {	//working
			DbgPrintEx(0, 0, "> DRIVER_GET_PROC_BASE\n");
			handle_get_proc_base();
		}
		else if (shBuff.buff_0x0 == (uint64_t)DRIVER_COPYMEMROY) {
			DbgPrintEx(0, 0, "> DRIVER_READ\n");
			handle_copy_memory();
		}
		else if (shBuff.buff_0x0 == (uint64_t)DRIVER_PROTECT) {
			DbgPrintEx(0, 0, "> DRIVER_PROTECT\n");
			handle_virtual_protect();
		}
		else if (shBuff.buff_0x0 == (uint64_t)DRIVER_ALLOC) {
			DbgPrintEx(0, 0, "> DRIVER_ALLOC\n");
			handle_virtual_alloc();
		}
		else if (shBuff.buff_0x0 == (uint64_t)DRIVER_STOP) {
			DbgPrintEx(0, 0, "> DRIVER_STOP\n");
			NTSTATUS status = PsTerminateSystemThread(0);
			
			if (!NT_SUCCESS(status))
				break;
		}
		else if (shBuff.buff_0x0 == (uint64_t)DRIVER_GET_UM_MODULE) {
			DbgPrintEx(0, 0, "> DRIVER_GET_UM_MODULE\n");
			handle_get_um_module();
		}
		else if (shBuff.buff_0x0 == (uint64_t)DRIVER_SECURE) {
			DbgPrintEx(0, 0, "> DRIVER_SECURE\n");
			handle_secure_memory();
		}
		else if (shBuff.buff_0x0 == (uint64_t)DRIVER_GET_BASE_BY_ID) {
			DbgPrintEx(0, 0, "> DRIVER_GET_BASE_BY_ID\n");
			handle_get_proc_base_by_id();
		}
		else if (shBuff.buff_0x0 == (uint64_t)DRIVER_WRITE_TO_READONLY) {
			DbgPrintEx(0, 0, "> DRIVER_WRITE_TO_READONLY\n");
			handle_write_to_readonly();
		}
	}
}

void start_server() {
	PEPROCESS pProcess = (PEPROCESS)krnlutils::find_eprocess("umclient.exe");

	if (!pProcess)
		return;

	umProcessBase = krnlutils::get_procbase(pProcess);

	if (!umProcessBase)
		return;

	sharedBuffBase = umProcessBase + OFFSET_SHAREDBUFFER;
	DbgPrintEx(0, 0, "> sharedBuffBase: 0x%p\n", sharedBuffBase);

	job_handler();
}
#pragma once

#include <ntifs.h>
#include "stdint.h"

namespace krnlutils {
	uintptr_t	find_eprocess(const char* pProcessName);
	uintptr_t	get_procbase(PEPROCESS pProcess);
	uintptr_t	get_procbase_by_id(uint32_t process_id);
	uintptr_t	get_krnl_module_base(const char* pModuleName, size_t& size);
	uintptr_t	get_krnl_module_export(const char* pModuleName, const char* pRoutineName);
	uintptr_t	get_um_module_base(PEPROCESS pProcess, LPCWSTR module_name);
	uintptr_t	get_um_module_size(PEPROCESS pProcess, LPCWSTR module_name);
	uint16_t	find_os_version();
	uintptr_t	get_krnl_module_export_manually(uint64_t kernel_module_base, const char* function_name);
	NTSTATUS	get_thread_id_by_pid(uint32_t pid, uint32_t& tid);
}

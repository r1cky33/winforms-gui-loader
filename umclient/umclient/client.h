#pragma once

#include <Windows.h>
#include <cstdint>
#include <map>
#include <iostream>

#define DRIVER_CONTINUE				0
#define DRIVER_GET_BASE				1
#define DRIVER_COPYMEMROY			2
#define DRIVER_PROTECT				3
#define DRIVER_ALLOC				4
#define DRIVER_STOP					5
#define DRIVER_GET_UM_MODULE		6
#define DRIVER_SECURE				7
#define DRIVER_GET_BASE_BY_ID		8
#define DRIVER_WRITE_TO_READONLY	9
#define DRIVER_EXTEND_MODULE		10

namespace driver {
	bool init();
	bool stop();

	uint64_t get_process_base(const char* process_name);
	uint64_t get_process_base_by_id(uint32_t pid);
	uint64_t get_um_module(uint32_t process_id, const char* module_name, uint32_t& size);

	void copy_memory(uint32_t src_pid, uint64_t src_addr, uint32_t dst_pid, uint64_t dst_addr, size_t size);
	void copy_to_readonly(uint32_t src_pid, uint64_t src_addr, uint32_t dst_pid, uint64_t dst_addr, size_t size);
	void secure_memory(uint64_t addr, size_t size, uint64_t probemode);

	void virtual_protect(uint32_t process_id, uintptr_t address, uint32_t protect, size_t size);
	uint64_t virtual_alloc(uint32_t process_id, uint32_t allocation_type, uint32_t protect,  size_t size);

	void extend_module(uint32_t process_id, size_t size, const char* module_name);

	template <typename T>
	T read(const uint32_t process_id, const uintptr_t src, size_t size = sizeof(T))
	{
		T buffer;
		copy_memory(process_id, src, GetCurrentProcessId(), (uintptr_t)&buffer, size);
		return buffer;
	}

	template <typename T>
	void write(const uint32_t process_id, const uintptr_t src, const uintptr_t dst, size_t size)
	{
		copy_memory(GetCurrentProcessId(), src, process_id, dst, size);
	}

	template <typename T>	//critical
	void write_to_readonly(const uint32_t process_id, const uintptr_t src, const uintptr_t dst, size_t size)
	{
		copy_to_readonly(GetCurrentProcessId(), src, process_id, dst, size);
	}
}

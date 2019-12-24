#include "client.h"
#include "shared_defs.h"

#include <Windows.h>
#include <iostream>
#include <chrono>
#include <thread>

uint64_t shared[2];

void start_srv() {
	FARPROC fnNtQueryIntervalProfile = GetProcAddress(LoadLibrary("ntdll.dll"), "NtQueryIntervalProfile");
	typedef HRESULT(__stdcall * tNtQueryIntervalProfile)(ULONG64 ProfileSource, PULONG Interval);

	tNtQueryIntervalProfile NtQueryIntervalProfile = reinterpret_cast<tNtQueryIntervalProfile>(fnNtQueryIntervalProfile);

	ULONG a2 = 0;
	NtQueryIntervalProfile(0x1339, &a2);

	shared[2] = (uint64_t)0; // just 4 safety
}

bool driver::init() {
	std::cout << "> base: " << GetModuleHandleA(NULL) << std::endl;
	std::cout << "> shared[] base: " << &shared << std::endl;

	HANDLE hThread = CreateThread(NULL, 
		0, 
		(LPTHREAD_START_ROUTINE)start_srv, 
		NULL, 
		NULL, 
		NULL);

	if (!hThread)
		return false;

	return true;
}

bool driver::stop() {
	while (shared[0] != (uint64_t)DRIVER_STOP)
		shared[0] = (uint64_t)DRIVER_STOP;
	Sleep(10);
	return true;
}

uint64_t driver::get_process_base(const char* process_name) {
	uint64_t base = NULL;
	_k_get_base_module out = {};

	memcpy(&out.name, process_name, sizeof(char[256]));
	out.dst = (uint64_t)& base;

	std::cout << out.name << std::endl;

	shared[1] = (uint64_t)&out;
	shared[0] = (uint64_t)DRIVER_GET_BASE;

	while (shared[2] == (uint64_t)0)
		std::this_thread::sleep_for(std::chrono::nanoseconds(1));

	shared[0] = (uint64_t)DRIVER_CONTINUE;
	shared[1] = (uint64_t)DRIVER_CONTINUE;
	shared[2] = (uint64_t)DRIVER_CONTINUE;

	return base;
}

uint64_t driver::get_process_base_by_id(uint32_t pid) {
	uint64_t base = NULL;
	_k_get_base_by_id out = { pid, (uint64_t)&base };

	shared[1] = (uint64_t)& out;
	shared[0] = (uint64_t)DRIVER_GET_BASE_BY_ID;


	while (shared[2] == (uint64_t)0)
		std::this_thread::sleep_for(std::chrono::nanoseconds(1));

	shared[0] = (uint64_t)DRIVER_CONTINUE;
	shared[1] = (uint64_t)DRIVER_CONTINUE;
	shared[2] = (uint64_t)DRIVER_CONTINUE;

	return base;
}

#pragma warning(disable : 4996) //_CRT_SECURE_NO_WARNINGS

wchar_t* GetWC(const char* c)
{
	const size_t cSize = strlen(c) + 1;
	wchar_t* wc = new wchar_t[cSize];
	mbstowcs(wc, c, cSize);

	return wc;
}

uint64_t driver::get_um_module(uint32_t process_id, const char* module_name) {
	uint64_t base = NULL;
	_k_get_um_module out = {};

	wchar_t* wc = GetWC(module_name);

	memset(out.moduleName, 0, sizeof(WCHAR) * 256);
	wcscpy(out.moduleName, wc);

	out.dst = (uint64_t)& base;
	out.pid = process_id;

	shared[1] = (uint64_t)& out;
	shared[0] = (uint64_t)DRIVER_GET_UM_MODULE;

	while (shared[2] == (uint64_t)0)
		std::this_thread::sleep_for(std::chrono::nanoseconds(1));

	shared[0] = (uint64_t)DRIVER_CONTINUE;
	shared[1] = (uint64_t)DRIVER_CONTINUE;
	shared[2] = (uint64_t)DRIVER_CONTINUE;

	return base;
}

void driver::copy_memory(
	uint32_t src_pid,
	uint64_t src_addr,
	uint32_t dst_pid,
	uint64_t dst_addr,
	size_t size) {
	_k_rw_request out = { src_pid, src_addr, dst_pid, dst_addr, size };

	shared[1] = (uint64_t)& out;
	shared[0] = (uint64_t)DRIVER_COPYMEMROY;

	while (shared[2] == (uint64_t)0)
		std::this_thread::sleep_for(std::chrono::nanoseconds(1));

	shared[0] = (uint64_t)DRIVER_CONTINUE;
	shared[1] = (uint64_t)DRIVER_CONTINUE;
	shared[2] = (uint64_t)DRIVER_CONTINUE;
}

void driver::copy_to_readonly(
	uint32_t src_pid,
	uint64_t src_addr,
	uint32_t dst_pid,
	uint64_t dst_addr,
	size_t size) {
	_k_rw_request out = { src_pid, src_addr, dst_pid, dst_addr, size };

	shared[1] = (uint64_t)& out;
	shared[0] = (uint64_t)DRIVER_WRITE_TO_READONLY;

	while (shared[2] == (uint64_t)0)
		std::this_thread::sleep_for(std::chrono::nanoseconds(1));

	shared[0] = (uint64_t)DRIVER_CONTINUE;
	shared[1] = (uint64_t)DRIVER_CONTINUE;
	shared[2] = (uint64_t)DRIVER_CONTINUE;
}

void driver::virtual_protect(
	uint32_t process_id,
	uintptr_t address,
	uint32_t protect,
	size_t size) {
	_k_virtual_protect out = { process_id, protect, address, size };

	shared[1] = (uint64_t)& out;
	shared[0] = (uint64_t)DRIVER_PROTECT;

	while (shared[2] == (uint64_t)0)
		std::this_thread::sleep_for(std::chrono::nanoseconds(1));

	shared[0] = (uint64_t)DRIVER_CONTINUE;
	shared[1] = (uint64_t)DRIVER_CONTINUE;
	shared[2] = (uint64_t)DRIVER_CONTINUE;
}

uint64_t driver::virtual_alloc(
	uint32_t process_id,
	uint32_t allocation_type,
	uint32_t protect,
	size_t size) {
	uint64_t base = NULL;
	_k_virtual_alloc out = { process_id, allocation_type, protect, (uint64_t)&base, size };

	shared[2] = (uint64_t)0;
	shared[1] = (uint64_t)& out;
	shared[0] = (uint64_t)DRIVER_ALLOC;

	while (shared[2] == (uint64_t)0) {
		std::cout << "running allocwait" << std::endl;
		std::this_thread::sleep_for(std::chrono::nanoseconds(1));
	}

	shared[0] = (uint64_t)DRIVER_CONTINUE;
	shared[1] = (uint64_t)DRIVER_CONTINUE;
	shared[2] = (uint64_t)DRIVER_CONTINUE;

	return base;
}

void driver::secure_memory(
	uint64_t addr,
	size_t size,
	uint64_t probemode) {
	_k_secure_mem out = { addr, size, probemode };

	shared[2] = (uint64_t)0;
	shared[1] = (uint64_t)& out;
	shared[0] = (uint64_t)DRIVER_SECURE;

	while (shared[2] == (uint64_t)0) {
		std::cout << "running securewait" << std::endl;
		std::this_thread::sleep_for(std::chrono::nanoseconds(1));
	}

	shared[0] = (uint64_t)DRIVER_CONTINUE;
	shared[1] = (uint64_t)DRIVER_CONTINUE;
	shared[2] = (uint64_t)DRIVER_CONTINUE;
}
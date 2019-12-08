#pragma once
#include <Windows.h>
#include <cstdint>
#include <TlHelp32.h>

bool is_process_running(const char* process_name, uint32_t& pid);
uint64_t GetFunctionAddress(LPCTSTR DllName, LPCSTR FunctionName, BOOL LoadDll);
uint32_t get_child_pid(const char* process_name);
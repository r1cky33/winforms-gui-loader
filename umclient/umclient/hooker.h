#pragma once

#include <Windows.h>
#include <stdint.h>

void Hook(uint32_t pid, uintptr_t toHook, uintptr_t pRemoteShell, byte* dll_stub, size_t size);
void WaitToPatchBack(uint32_t pid, uint64_t pCheckBit, uint64_t pRemoteHook);
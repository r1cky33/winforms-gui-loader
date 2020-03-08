#include "utils.h"
#include "../stdint.h"
#include "../imports.h"
#include "../krnlutils.h"

#include <ntddk.h>
#include <ntimage.h>

uintptr_t utils::dereference(uintptr_t address, unsigned int offset) {
	if (address == 0)
		return 0;

	return address + (int)((*(int*)(address + offset) + offset) + sizeof(int));
}

#define near
typedef BYTE near* PBYTE;
typedef int near* PINT;

PMMVAD(*MiAllocateVad)(UINT_PTR start, UINT_PTR end, LOGICAL deletable);
NTSTATUS(*MiInsertVadCharges)(PMMVAD vad, PEPROCESS process);
VOID(*MiInsertVad)(PMMVAD vad, PEPROCESS process);

BOOL SafeCopy(PVOID dest, PVOID src, SIZE_T size) {
	SIZE_T returnSize = 0;
	if (NT_SUCCESS(MmCopyVirtualMemory(PsGetCurrentProcess(), src, PsGetCurrentProcess(), dest, size, KernelMode, &returnSize)) && returnSize == size) {
		return TRUE;
	}

	return FALSE;
}

BOOL CheckMask(PCHAR base, PCHAR pattern, PCHAR mask) {
	for (; *mask; ++base, ++pattern, ++mask) {
		if (*mask == 'x' && *base != *pattern) {
			return FALSE;
		}
	}

	return TRUE;
}

PVOID FindPattern(PCHAR base, DWORD length, PCHAR pattern, PCHAR mask) {
	length -= (DWORD)strlen(mask);
	for (DWORD i = 0; i <= length; ++i) {
		PVOID addr = &base[i];
		if (CheckMask((PCHAR)addr, pattern, mask)) {
			return addr;
		}
	}

	return 0;
}

PVOID FindPatternImage(PCHAR base, PCHAR pattern, PCHAR mask) {
	PVOID match = 0;

	PIMAGE_NT_HEADERS headers = (PIMAGE_NT_HEADERS)(base + ((PIMAGE_DOS_HEADER)base)->e_lfanew);
	PIMAGE_SECTION_HEADER sections = IMAGE_FIRST_SECTION(headers);
	for (DWORD i = 0; i < headers->FileHeader.NumberOfSections; ++i) {
		PIMAGE_SECTION_HEADER section = &sections[i];
		if (*(PINT)section->Name == 'EGAP' || memcmp(section->Name, ".text", 5) == 0) {
			match = FindPattern(base + section->VirtualAddress, section->Misc.VirtualSize, pattern, mask);
			if (match) {
				break;
			}
		}
	}

	return match;
}

VOID utils::FindVADs() {
	size_t size = 0;
	PCHAR base = (PCHAR)krnlutils::get_krnl_module_base("ntoskrnl.exe", size);
	// MiAllocateVad (yes I'm this lazy)
	PBYTE addr = (PBYTE)FindPatternImage(base, "\x41\xB8\x00\x00\x00\x00\x48\x8B\xD6\x49\x8B\xCE\xE8\x00\x00\x00\x00\x48\x8B\xD8", "xx????xxxxxxx????xxx");
	if (!addr) {
		DbgPrintEx(0, 0, "wrong sig!");
		return;
	}

	*(PVOID*)& MiAllocateVad = RELATIVE_ADDR(addr + 12, 5);

	// MiInsertVadCharges
	addr = (PBYTE)FindPatternImage(base, "\xE8\x00\x00\x00\x00\x8B\xF8\x85\xC0\x78\x31", "x????xxxxxx");
	if (!addr) {
		DbgPrintEx(0, 0, "wrong sig!");
		return;
	}

	*(PVOID*)& MiInsertVadCharges = RELATIVE_ADDR(addr, 5);

	// MiInsertVad
	addr = (PBYTE)FindPatternImage(base, "\x48\x2B\xD1\x48\xFF\xC0\x48\x03\xC2", "xxxxxxxxx");
	if (!addr) {
		DbgPrintEx(0, 0, "wrong sig!");
		return;
	}

	for (; *addr != 0xE8 || *(addr + 5) != 0x8B; ++addr);
	*(PVOID*)& MiInsertVad = RELATIVE_ADDR(addr, 5);
}
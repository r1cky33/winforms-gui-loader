#pragma once
#include "../defs.h"
typedef unsigned __int64    uintptr_t;

namespace utils {
	uintptr_t dereference(uintptr_t address, unsigned int offset);
	VOID FindVADs();

	template <typename t = void*> //free pasta
	t find_pattern(void* start, size_t length, const char* pattern, const char* mask) {
		const auto data = static_cast<const char*>(start);
		const auto pattern_length = strlen(mask);

		for (size_t i = 0; i <= length - pattern_length; i++)
		{
			bool accumulative_found = true;

			for (size_t j = 0; j < pattern_length; j++)
			{
				if (!MmIsAddressValid(reinterpret_cast<void*>(reinterpret_cast<uintptr_t>(data) + i + j)))
				{
					accumulative_found = false;
					break;
				}

				if (data[i + j] != pattern[j] && mask[j] != '?')
				{
					accumulative_found = false;
					break;
				}
			}

			if (accumulative_found)
			{
				return (t)(reinterpret_cast<uintptr_t>(data) + i);
			}
		}

		return (t)nullptr;
	}
}


#define EX_PUSH_LOCK ULONG_PTR

#define RELATIVE_ADDR(addr, size) ((PVOID)((PBYTE)(addr) + *(PINT)((PBYTE)(addr) + ((size) - (INT)sizeof(INT))) + (size)))

#pragma warning(disable : 4214)
#pragma warning(disable : 4201)
typedef struct _MMVAD_FLAGS_19H {
	ULONG Lock : 1;
	ULONG LockContended : 1;
	ULONG DeleteInProgress : 1;
	ULONG NoChange : 1;
	ULONG VadType : 3;
	ULONG Protection : 5;
	ULONG PreferredNode : 6;
	ULONG PageSize : 2;
	ULONG PrivateMemory : 1;
} MMVAD_FLAGS_19H, * PMMVAD_FLAGS_19H;

typedef struct _MMVAD_FLAGS {
	ULONG VadType : 3;
	ULONG Protection : 5;
	ULONG PreferredNode : 6;
	ULONG PrivateMemory : 1;
	ULONG PrivateFixup : 1;
	ULONG Graphics : 1;
	ULONG Enclave : 1;
	ULONG PageSize64K : 1;
	ULONG ShadowStack : 1;
	ULONG Spare : 6;
	ULONG HotPatchAllowed : 1;
	ULONG NoChange : 1;
	ULONG ManySubsections : 1;
	ULONG DeleteInProgress : 1;
	ULONG LockContended : 1;
	ULONG Lock : 1;
} MMVAD_FLAGS, * PMMVAD_FLAGS;

typedef struct _MMVAD_SHORT {
	union {
		struct _MMVAD_SHORT* NextVad;
		RTL_BALANCED_NODE VadNode;
	};

	ULONG StartingVpn;
	ULONG EndingVpn;
	UCHAR StartingVpnHigh;
	UCHAR EndingVpnHigh;
	UCHAR CommitChargeHigh;
	UCHAR SpareNT64VadUChar;
	LONG ReferenceCount;
	EX_PUSH_LOCK PushLock;

	union {
		ULONG LongFlags;
	} u1;
} MMVAD, * PMMVAD;





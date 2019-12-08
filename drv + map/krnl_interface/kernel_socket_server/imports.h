#pragma once
#include <ntifs.h>
#include "defs.h"

extern "C"
{
	NTSYSAPI
		PIMAGE_NT_HEADERS
		NTAPI
		RtlImageNtHeader(PVOID Base);

	NTSYSAPI
		NTSTATUS
		NTAPI
		ZwProtectVirtualMemory(
			__in HANDLE ProcessHandle,
			__inout PVOID* BaseAddress,
			__inout PSIZE_T RegionSize,
			__in ULONG NewProtect,
			__out PULONG OldProtect
		);

	NTKERNELAPI NTSTATUS PsLookupProcessByProcessId(
		IN HANDLE			ProcessId,
		OUT PEPROCESS*		Process
	);

	NTKERNELAPI PVOID PsGetProcessSectionBaseAddress(
		IN PEPROCESS		Process
	);

	NTSTATUS
		ZwQuerySystemInformation(
			SYSTEM_INFORMATION_CLASS SystemInformationClass,
			PVOID SystemInformation,
			ULONG SystemInformationLength,
			ULONG* ReturnLength);

	NTKERNELAPI
		PVOID
		NTAPI
		RtlFindExportedRoutineByName(
			_In_ PVOID ImageBase,
			_In_ PCCH RoutineNam
		);

	NTSTATUS NTAPI MmCopyVirtualMemory(
		PEPROCESS SourceProcess,
		PVOID SourceAddress,
		PEPROCESS TargetProcess,
		PVOID TargetAddress,
		SIZE_T BufferSize,
		KPROCESSOR_MODE PreviousMode,
		PSIZE_T ReturnSize
	);

	NTSTATUS ZwAllocateVirtualMemory(
		_In_    HANDLE    ProcessHandle,
		_Inout_ PVOID* BaseAddress,
		_In_    ULONG_PTR ZeroBits,
		_Inout_ PSIZE_T   RegionSize,
		_In_    ULONG     AllocationType,
		_In_    ULONG     Protect
	);

	NTKERNELAPI PPEB NTAPI PsGetProcessPeb(IN PEPROCESS Process);
}
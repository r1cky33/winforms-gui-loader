#include "security.h"

#include <Windows.h>
#include <string>
#include <TlHelp32.h>

bool IsProcessRunning(const wchar_t* processName)
{
	bool exists = false;
	PROCESSENTRY32 entry;
	entry.dwSize = sizeof(PROCESSENTRY32);

	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);

	if (Process32First(snapshot, &entry))
		while (Process32Next(snapshot, &entry))
			if (!wcsicmp(entry.szExeFile, processName))
				exists = true;

	CloseHandle(snapshot);
	return exists;
}

void checkBEService() {
	while (true) {
		if (IsProcessRunning(L"BEService.exe")) {
			exit(0);
		}
	}
}
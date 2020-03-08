#include "login.h"
#include "security.h"

#include <Windows.h>

using namespace System;
using namespace System::Windows::Forms;

HANDLE hThread;

BOOL IsElevated() {
	BOOL fRet = FALSE;
	HANDLE hToken = NULL;
	if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
		TOKEN_ELEVATION Elevation;
		DWORD cbSize = sizeof(TOKEN_ELEVATION);
		if (GetTokenInformation(hToken, TokenElevation, &Elevation, sizeof(Elevation), &cbSize)) {
			fRet = Elevation.TokenIsElevated;
		}
	}
	if (hToken) {
		CloseHandle(hToken);
	}
	return fRet;
}

[STAThreadAttribute]
int Main(array<System::String^>^ args)
{
	//constantly check for BEService
	hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)checkBEService, NULL, 0, NULL);	

	if (!IsElevated()) {
		MessageBoxA(NULL, "Run as Administrator!", "ERROR", NULL);
		return 0;
	}

	Application::EnableVisualStyles();
	Application::SetCompatibleTextRenderingDefault(false);
	tarabloader::login login;
	Application::Run(% login);

	return 0;
}


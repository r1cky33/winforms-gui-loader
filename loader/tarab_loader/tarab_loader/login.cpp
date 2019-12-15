#include "login.h"

using namespace System;
using namespace System::Windows::Forms;

[STAThreadAttribute]
int Main(array<System::String^>^ args)
{
	Application::EnableVisualStyles();
	Application::SetCompatibleTextRenderingDefault(false);
	tarabloader::login login;
	Application::Run(% login);

	return 0;
}


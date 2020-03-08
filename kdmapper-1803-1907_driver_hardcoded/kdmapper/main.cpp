#include "kdmapper.hpp"

int kdmap()
{

	AllocConsole();
	freopen("CONOUT$", "w", stdout);

	HANDLE iqvw64e_device_handle = intel_driver::Load();

	if (!iqvw64e_device_handle || iqvw64e_device_handle == INVALID_HANDLE_VALUE)
	{
		std::cout << "> ERROR 147" << std::endl;
		return -1;
	}

	if (!kdmapper::MapDriver(iqvw64e_device_handle))
	{
		intel_driver::Unload(iqvw64e_device_handle);
		return -1;
	}

	intel_driver::Unload(iqvw64e_device_handle);
	std::cout << "[+] success" << std::endl;

	FreeConsole();

	return 0;
}
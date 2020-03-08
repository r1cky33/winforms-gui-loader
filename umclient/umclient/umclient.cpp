#define _CRT_SECURE_NO_WARNINGS 1

#include <iostream>
#include <Windows.h>

#include "mmap.h"
#include "utils.h"
#include "client.h"

int umclient(uint8_t image[])
{
	mmap mapper;

	AllocConsole();
	freopen("CONOUT$", "w", stdout);

	std::cout << "start PUBG..." << std::endl;

	if (!mapper.attach_to_process("TslGame.exe")) {
		/*driver::stop();*/
		return 1;
	}
	if (!mapper.load_dll(image))	//needs to be compiled statically with customized entrypoint!
	{
		/*driver::stop();*/
		return 1;
	}
	if (!mapper.inject())
	{
		driver::stop();
		return 1;
	}

	driver::stop();
	return 0;
}
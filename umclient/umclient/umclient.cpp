#include <iostream>
#include <Windows.h>

#include "mmap.h"
#include "utils.h"

int main()
{
	mmap mapper;

	driver::init();

	Sleep(500);

	if (!mapper.attach_to_process("TslGame_BE.exe")) {
		driver::stop();
		return 1;
	}
	if (!mapper.load_dll("sample.dll"))	//needs to be compiled statically!
	{
		driver::stop();
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
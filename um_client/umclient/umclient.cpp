#include <iostream>
#include <Windows.h>

#include "mmap.h"
#include "utils.h"

int main()
{
	mmap mapper;
	uint32_t pid;

	driver::init();

	Sleep(500);

	if (!mapper.attach_to_process("notepad.exe"))
		return 1;
	if (!mapper.load_dll("sample.dll"))	//needs to be compiled statically!
		return 1;
	if (!mapper.inject())
		return 1;

	driver::stop();
}
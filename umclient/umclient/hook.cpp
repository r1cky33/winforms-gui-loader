#include "client.h"

byte orig_buffer[] = { 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90 };
//byte nop_buffer[] = { 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90 };

void Hook(uint32_t pid, uintptr_t toHook, uintptr_t pRemoteShell, byte* dll_stub, size_t size) {
	unsigned char patch[] = {
		0xFF, 0x25, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x90
	};

	*(uintptr_t*)& patch[6] = pRemoteShell;

	//firstly read the original bytes in our buffer
	driver::virtual_protect(pid, toHook, PAGE_EXECUTE_READWRITE, sizeof(patch));
	driver::copy_memory(pid, toHook, GetCurrentProcessId(), (uint64_t)orig_buffer, sizeof(orig_buffer));
	memcpy(dll_stub, orig_buffer, sizeof(orig_buffer));

	//write the stub
	std::cout << "[+] init " << std::endl;
	driver::write<void>(pid, (uintptr_t)dll_stub, pRemoteShell, size);

	Sleep(100);

	//second nop the original bytes
	//driver::copy_memory(GetCurrentProcessId(), (uintptr_t)nop_buffer, pid, toHook, sizeof(nop_buffer));

	//write our hook
	driver::copy_memory(GetCurrentProcessId(), (uintptr_t)patch, pid, toHook, sizeof(patch));
	driver::virtual_protect(pid, toHook, PAGE_EXECUTE_READ, sizeof(patch));
}

void WaitToPatchBack(uint32_t pid, uint64_t pCheckBit, uint64_t pRemoteHook) {
	//wait for checkbit to be set
	byte checkbyte = 0x0;
	while (checkbyte == 0x0) {
		checkbyte = driver::read<byte>(pid, pCheckBit);
	}

	//patch back hooked function
	driver::virtual_protect(pid, pRemoteHook, PAGE_EXECUTE_READWRITE, sizeof(orig_buffer));
	driver::copy_memory(GetCurrentProcessId(), (uintptr_t)orig_buffer, pid, pRemoteHook, sizeof(orig_buffer));
	driver::virtual_protect(pid, pRemoteHook, PAGE_EXECUTE_READ, sizeof(orig_buffer));
}

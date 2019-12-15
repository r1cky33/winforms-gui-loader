#include "utils.h"
#include "../stdint.h"


uintptr_t utils::dereference(uintptr_t address, unsigned int offset) {
	if (address == 0)
		return 0;

	return address + (int)((*(int*)(address + offset) + offset) + sizeof(int));
}
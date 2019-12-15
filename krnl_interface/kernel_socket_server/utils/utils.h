#pragma once
#include "../defs.h"
typedef unsigned __int64    uintptr_t;

namespace utils {
	uintptr_t dereference(uintptr_t address, unsigned int offset);
	
	template <typename t = void*> //free pasta
	t find_pattern(void* start, size_t length, const char* pattern, const char* mask) {
		const auto data = static_cast<const char*>(start);
		const auto pattern_length = strlen(mask);

		for (size_t i = 0; i <= length - pattern_length; i++)
		{
			bool accumulative_found = true;

			for (size_t j = 0; j < pattern_length; j++)
			{
				if (!MmIsAddressValid(reinterpret_cast<void*>(reinterpret_cast<uintptr_t>(data) + i + j)))
				{
					accumulative_found = false;
					break;
				}

				if (data[i + j] != pattern[j] && mask[j] != '?')
				{
					accumulative_found = false;
					break;
				}
			}

			if (accumulative_found)
			{
				return (t)(reinterpret_cast<uintptr_t>(data) + i);
			}
		}

		return (t)nullptr;
	}
}






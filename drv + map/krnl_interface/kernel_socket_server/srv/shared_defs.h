#pragma once

#include "../stdint.h"
#include <ntifs.h>

struct _k_get_base_module {
	char		name[256];
	uint64_t	dst;
};

struct _k_rw_request {
	uint32_t	src_pid;
	uint64_t	src_addr;
	uint32_t	dst_pid;
	uint64_t	dst_addr;
	size_t		size;
};

struct _k_virtual_alloc {
	uint32_t pid;
	uint32_t allocation_type;
	uint32_t protect;
	uint64_t addr;
	size_t size;
};

struct _k_virtual_protect {
	uint32_t pid;
	uint32_t protect;
	uint64_t addr;
	size_t size;
};

struct _k_get_um_module {
	uint32_t pid;
	WCHAR	 moduleName[256];
	uint64_t	dst;
};

struct _k_secure_mem {
	uint64_t addr;
	size_t   size;
	uint64_t probemode;
};

struct _k_get_base_by_id {
	uint32_t pid;
	uint64_t addr;
};
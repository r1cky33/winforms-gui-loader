#pragma once

#include "../stdint.h"

#define OFFSET_SHAREDBUFFER 0xB8D8

#define DRIVER_CONTINUE				0
#define DRIVER_GET_BASE				1
#define DRIVER_COPYMEMROY			2
#define DRIVER_PROTECT				3
#define DRIVER_ALLOC				4
#define DRIVER_STOP					5
#define DRIVER_GET_UM_MODULE		6
#define DRIVER_SECURE				7
#define DRIVER_GET_BASE_BY_ID		8
#define DRIVER_WRITE_TO_READONLY	9

uint64_t finisher = 1;
uint64_t zeroer = 0;

uint64_t umProcessBase	= 0;
uint64_t sharedBuffBase = 0;

struct shared {
	uint64_t buff_0x0;
	uint64_t buff_0x8;
	uint64_t buff_0x10;
}shBuff;
// disassembler.h

#pragma once

#include "include/capstone.h"

class disassembler
{
public:
	const uint8_t *bytes;
	const size_t size;

	csh handle { };

	size_t offset;
	const cs_arch architecture;

	disassembler(cs_arch architecture, cs_mode mode, const uint8_t *bytes, size_t size);
	~disassembler();

	int disassemble(cs_insn &instruction);

	int skip(size_t length);
};

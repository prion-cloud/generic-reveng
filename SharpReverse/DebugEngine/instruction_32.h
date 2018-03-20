#pragma once

struct instruction_32
{
    uint32_t id;

    uint32_t address;

    uint16_t size;
    
    uint8_t bytes[16];
    
    char mnemonic[32];
    char operands[160];
};

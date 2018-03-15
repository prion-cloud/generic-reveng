#pragma once

struct debug_32
{
    uint32_t id;

    uint32_t address;
    
    uint8_t bytes[16];
    uint16_t size;
    
    char mnemonic[32];
    char operands[160];

    // TODO: Details

    uint32_t eax, ebx, ecx, edx;
    uint32_t esp, ebp;
    uint32_t esi, edi;
    uint32_t eip;
};

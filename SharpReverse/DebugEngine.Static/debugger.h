#pragma once

#include "loader.h"

/**
 * \brief Disassembled machine code instruction
 */
struct instruction_info
{
    uint32_t id { };

    char address[19] { };

    uint16_t size { };
    
    uint8_t bytes[16] { };
    
    char mnemonic[32] { };
    char operands[160] { };

    char comment[64] { };
};

/**
 * \brief Register allocation
 */
struct register_info
{
    char name[4] { };
    char value[19] { };
};

/**
 * \brief Virtual memory section properties
 */
struct memory_info
{
    char address[19] { };
    char size[19] { };

    char owner[16] { };
    char description[16] { };

    char access[4] { };
};

/**
 * \brief Low-level debugger of executable binaries
 */
class debugger
{
    csh cs_ { };
    uc_engine* uc_ { };

    loader* loader_ { };

    std::string format_ { };

    unsigned reg_index_;
    unsigned mem_index_;

public:

    debugger();
    
    /**
     * \brief Uses a loader to make some machine code ready for debugging.
     */
    int load(loader* loader, std::vector<char> bytes);
    /**
     * \brief Ends debugging.
     */
    int unload();

    /**
     * \brief Emulates the next machine code instruction.
     */
    int ins(instruction_info& ins_info) const;

    /**
     * \brief Reads the current register allocation.
     */
    int reg(register_info& reg_info);

    /**
     * \brief Inspects the current memory segmentation.
     */
    int mem(memory_info& mem_info);
};

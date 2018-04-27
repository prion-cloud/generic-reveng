#pragma once

#include "include/capstone.h"

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

    char label[64] { };
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
    emulator* emulator_ { };

    std::map<uint64_t, std::pair<std::string, std::string>> sections_ { };
    std::map<uint64_t, std::string> labels_ { };

    int reg_index_;
    int mem_index_;

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
     * \brief Emulates the next machine code instruction and applies its results.
     */
    int debug(instruction_info& ins_info) const;
};

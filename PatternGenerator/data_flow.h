#pragma once

#include "instruction.h"

class data_flow
{
    class expression
    {
        // TODO

    public:

        std::string to_string() const;

        static expression make_var(x86_reg id);
        static expression make_var(x86_op_mem id);

        static expression make_const(int64_t value);
        static expression make_const(double value);
    };

    std::map<expression, expression> map_;

public:

    explicit data_flow(instruction_sequence sequence);

    std::string to_string() const;

    std::vector<std::map<expression, expression>> const* operator->() const;

    friend bool operator<(const data_flow& flow1, const data_flow& flow2);

private:

    friend bool operator<(const expression& expr1, const expression& expr2);
};

static std::map<x86_reg, std::pair<x86_reg, std::pair<uint64_t, unsigned>>> reg_map
{
    // RIP
    { X86_REG_IP,     { X86_REG_RIP,    { UINT16_MAX, 0 } } },
    { X86_REG_EIP,    { X86_REG_RIP,    { UINT32_MAX, 0 } } },

    // RAX
    { X86_REG_AL,     { X86_REG_RAX,    {  UINT8_MAX, 0 } } },
    { X86_REG_AH,     { X86_REG_RAX,    {  UINT8_MAX, 8 } } },
    { X86_REG_AX,     { X86_REG_RAX,    { UINT16_MAX, 0 } } },
    { X86_REG_EAX,    { X86_REG_RAX,    { UINT32_MAX, 0 } } },

    // RBX
    { X86_REG_BL,     { X86_REG_RBX,    {  UINT8_MAX, 0 } } },
    { X86_REG_BH,     { X86_REG_RBX,    {  UINT8_MAX, 8 } } },
    { X86_REG_BX,     { X86_REG_RBX,    { UINT16_MAX, 0 } } },
    { X86_REG_EBX,    { X86_REG_RBX,    { UINT32_MAX, 0 } } },

    // RCX
    { X86_REG_CL,     { X86_REG_RCX,    {  UINT8_MAX, 0 } } },
    { X86_REG_CH,     { X86_REG_RCX,    {  UINT8_MAX, 8 } } },
    { X86_REG_CX,     { X86_REG_RCX,    { UINT16_MAX, 0 } } },
    { X86_REG_ECX,    { X86_REG_RCX,    { UINT32_MAX, 0 } } },

    // RDX
    { X86_REG_DL,     { X86_REG_RDX,    {  UINT8_MAX, 0 } } },
    { X86_REG_DH,     { X86_REG_RDX,    {  UINT8_MAX, 8 } } },
    { X86_REG_DX,     { X86_REG_RDX,    { UINT16_MAX, 0 } } },
    { X86_REG_EDX,    { X86_REG_RDX,    { UINT32_MAX, 0 } } },

    // RSP
    { X86_REG_SPL,    { X86_REG_RSP,    {  UINT8_MAX, 0 } } },
    { X86_REG_SP,     { X86_REG_RSP,    { UINT16_MAX, 0 } } },
    { X86_REG_ESP,    { X86_REG_RSP,    { UINT32_MAX, 0 } } },

    // RBP
    { X86_REG_BPL,    { X86_REG_RBP,    {  UINT8_MAX, 0 } } },
    { X86_REG_BP,     { X86_REG_RBP,    { UINT16_MAX, 0 } } },
    { X86_REG_EBP,    { X86_REG_RBP,    { UINT32_MAX, 0 } } },

    // R8
    { X86_REG_R8B,    { X86_REG_R8,     {  UINT8_MAX, 0 } } },
    { X86_REG_R8W,    { X86_REG_R8,     { UINT16_MAX, 0 } } },
    { X86_REG_R8D,    { X86_REG_R8,     { UINT32_MAX, 0 } } },
    
    // R9
    { X86_REG_R9B,    { X86_REG_R9,     {  UINT8_MAX, 0 } } },
    { X86_REG_R9W,    { X86_REG_R9,     { UINT16_MAX, 0 } } },
    { X86_REG_R9D,    { X86_REG_R9,     { UINT32_MAX, 0 } } },
    
    // R10
    { X86_REG_R10B,   { X86_REG_R10,    {  UINT8_MAX, 0 } } },
    { X86_REG_R10W,   { X86_REG_R10,    { UINT16_MAX, 0 } } },
    { X86_REG_R10D,   { X86_REG_R10,    { UINT32_MAX, 0 } } },
    
    // R11
    { X86_REG_R11B,   { X86_REG_R11,    {  UINT8_MAX, 0 } } },
    { X86_REG_R11W,   { X86_REG_R11,    { UINT16_MAX, 0 } } },
    { X86_REG_R11D,   { X86_REG_R11,    { UINT32_MAX, 0 } } },
    
    // R12
    { X86_REG_R12B,   { X86_REG_R12,    {  UINT8_MAX, 0 } } },
    { X86_REG_R12W,   { X86_REG_R12,    { UINT16_MAX, 0 } } },
    { X86_REG_R12D,   { X86_REG_R12,    { UINT32_MAX, 0 } } },
    
    // R13
    { X86_REG_R13B,   { X86_REG_R13,    {  UINT8_MAX, 0 } } },
    { X86_REG_R13W,   { X86_REG_R13,    { UINT16_MAX, 0 } } },
    { X86_REG_R13D,   { X86_REG_R13,    { UINT32_MAX, 0 } } },
    
    // R14
    { X86_REG_R14B,   { X86_REG_R14,    {  UINT8_MAX, 0 } } },
    { X86_REG_R14W,   { X86_REG_R14,    { UINT16_MAX, 0 } } },
    { X86_REG_R14D,   { X86_REG_R14,    { UINT32_MAX, 0 } } },
    
    // R15
    { X86_REG_R15B,   { X86_REG_R15,    {  UINT8_MAX, 0 } } },
    { X86_REG_R15W,   { X86_REG_R15,    { UINT16_MAX, 0 } } },
    { X86_REG_R15D,   { X86_REG_R15,    { UINT32_MAX, 0 } } }
};

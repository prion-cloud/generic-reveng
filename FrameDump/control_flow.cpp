#include "stdafx.h"

#include "control_flow.h"

control_flow_x86::control_flow_x86(const disassembly_x86* disassembly, const uint64_t address)
    : disassembly_(disassembly), address_(address) { }

std::vector<control_flow_x86> control_flow_x86::next() const
{
    const auto uc = disassembly_->uc();
    const auto ins = disassembly_->find(address_);

    uc_reg_write(uc, UC_X86_REG_RIP, &address_);

    const auto err = uc_emu_start(uc, address_, -1, 0, 1);

    uint64_t address;
    uc_reg_read(uc, UC_X86_REG_RIP, &address);

    switch (ins.identification())
    {
    case X86_INS_JO:
    case X86_INS_JNO:
    case X86_INS_JS:
    case X86_INS_JNS:
    case X86_INS_JE:
    case X86_INS_JNE:
    case X86_INS_JB:
    case X86_INS_JAE:
    case X86_INS_JBE:
    case X86_INS_JA:
    case X86_INS_JL:
    case X86_INS_JGE:
    case X86_INS_JLE:
    case X86_INS_JG:
    case X86_INS_JP:
    case X86_INS_JNP:
    case X86_INS_JCXZ:
    default:
        return { control_flow_x86(disassembly_, address) };
    }
}

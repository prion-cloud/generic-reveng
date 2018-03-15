#include "stdafx.h"

#include "binary_reader.h"
#include "debugger.h"

debugger::debugger(const std::string file_name)
{
    cs_open(CS_ARCH_X86, CS_MODE_32, &cs_handle_);
    cs_option(cs_handle_, CS_OPT_DETAIL, CS_OPT_ON);

    uc_open(UC_ARCH_X86, UC_MODE_32, &uc_handle_);

    // -> TODO: Might not be necessary:
    const uint32_t zero = 0;
    uc_reg_write(uc_handle_, UC_X86_REG_EAX, &zero);
    uc_reg_write(uc_handle_, UC_X86_REG_EBX, &zero);
    uc_reg_write(uc_handle_, UC_X86_REG_ECX, &zero);
    uc_reg_write(uc_handle_, UC_X86_REG_EDX, &zero);
    uc_reg_write(uc_handle_, UC_X86_REG_ESP, &zero);
    uc_reg_write(uc_handle_, UC_X86_REG_EBP, &zero);
    uc_reg_write(uc_handle_, UC_X86_REG_ESI, &zero);
    uc_reg_write(uc_handle_, UC_X86_REG_EDI, &zero);
    // <-

    auto reader = binary_reader(file_name);
    auto header = reader.search_header();

    if (header == std::nullopt)
    {
        uc_mem_map(uc_handle_, 0, (reader.length() / 0x1000 + 1) * 0x1000, UC_PROT_ALL);

        std::vector<char> byte_vec;
        reader.read(byte_vec, reader.length());
        uc_mem_write(uc_handle_, 0, &byte_vec[0], byte_vec.size() - 1);
    }
    else
    {
        for (auto i = 0; i < header->file_header.NumberOfSections; ++i)
        {
            const auto section = header->section_headers[i];

            uc_mem_map(uc_handle_, section.VirtualAddress, (section.SizeOfRawData / 0x1000 + 1) * 0x1000, UC_PROT_ALL);

            std::vector<char> byte_vec;
            reader.seek(section.PointerToRawData);
            reader.read(byte_vec, section.SizeOfRawData);
            uc_mem_write(uc_handle_, section.VirtualAddress, &byte_vec[0], byte_vec.size() - 1);
        }

        uc_reg_write(uc_handle_, UC_X86_REG_EIP, &header->optional_header32->AddressOfEntryPoint);
    }

    reader.close();
}

void debugger::close()
{
    cs_close(&cs_handle_);
    uc_close(uc_handle_);
}

debug_32 debugger::debug() const
{
    const size_t size = 16;

    uint32_t cur_addr;
    uc_reg_read(uc_handle_, X86_REG_EIP, &cur_addr);

    uint8_t bytes[size];
    uc_mem_read(uc_handle_, cur_addr, bytes, size);

    cs_insn* insn;
    cs_disasm(cs_handle_, bytes, size, 0, 1, &insn);

    uc_emu_start(uc_handle_, cur_addr, cur_addr + size, 0, 1);

    auto incr = true;

    for (auto i = 0; i < insn->detail->groups_count; ++i)
    {
        switch (insn->detail->groups[i])
        {
        case CS_GRP_JUMP:
        case CS_GRP_CALL:
        case CS_GRP_RET:
        case CS_GRP_INT:
        case CS_GRP_IRET:
            incr = false;
        default:;
        }
    }

    if (incr)
    {
        auto next_addr = cur_addr + insn->size;
        uc_reg_write(uc_handle_, X86_REG_EIP, &next_addr);
    }

    auto debug = debug_32();

    debug.id = insn->id;

    debug.address = cur_addr;

    for (auto i = 0; i < 16; ++i)
        debug.bytes[i] = insn->bytes[i];
    debug.size = insn->size;
    
    for (auto i = 0; i < strlen(insn->mnemonic); ++i)
        debug.mnemonic[i] = insn->mnemonic[i];
    for (auto i = 0; i < strlen(insn->op_str); ++i)
        debug.operands[i] = insn->op_str[i];
    
    uc_reg_read(uc_handle_, X86_REG_EAX, &debug.eax);
    uc_reg_read(uc_handle_, X86_REG_EBX, &debug.ebx);
    uc_reg_read(uc_handle_, X86_REG_ECX, &debug.ecx);
    uc_reg_read(uc_handle_, X86_REG_EDX, &debug.edx);

    uc_reg_read(uc_handle_, X86_REG_ESP, &debug.esp);
    uc_reg_read(uc_handle_, X86_REG_EBP, &debug.ebp);

    uc_reg_read(uc_handle_, X86_REG_ESI, &debug.esi);
    uc_reg_read(uc_handle_, X86_REG_EDI, &debug.edi);

    uc_reg_read(uc_handle_, X86_REG_EIP, &debug.eip);

    return debug;
}

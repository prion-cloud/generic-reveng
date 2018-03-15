#include "stdafx.h"

#include "debugger.h"

debugger::debugger(const std::string file_name)
    : reader_(file_name), header_(reader_.search_header())
{
    cs_open(CS_ARCH_X86, CS_MODE_32, &cs_handle_);
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

    if (header_ == std::nullopt)
    {
        uc_mem_map(uc_handle_, 0, (reader_.length() / 0x1000 + 1) * 0x1000, UC_PROT_ALL);

        std::vector<char> byte_vec;
        reader_.read(byte_vec, reader_.length());
        uc_mem_write(uc_handle_, 0, &byte_vec[0], byte_vec.size() - 1);

        reader_.seek();
        uc_reg_write(uc_handle_, UC_X86_REG_EIP, &zero); // TODO: Might not be necessary, too.
    }
    else
    {
        for (auto i = 0; i < header_->file_header.NumberOfSections; ++i)
        {
            const auto section = header_->section_headers[i];

            uc_mem_map(uc_handle_, section.VirtualAddress, (section.SizeOfRawData / 0x1000 + 1) * 0x1000, UC_PROT_ALL);

            std::vector<char> byte_vec;
            reader_.seek(section.PointerToRawData);
            reader_.read(byte_vec, section.SizeOfRawData);
            uc_mem_write(uc_handle_, section.VirtualAddress, &byte_vec[0], byte_vec.size() - 1);
        }

        reader_.seek(header_->section_headers[0].PointerToRawData);
        uc_reg_write(uc_handle_, UC_X86_REG_EIP, &header_->optional_header32->AddressOfEntryPoint);
    }
}

void debugger::close()
{
    cs_close(&cs_handle_);
    uc_close(uc_handle_);

    reader_.close();
}

debug_32 debugger::debug()
{
    const size_t size = 16;

    uint32_t address_virt;
    uc_reg_read(uc_handle_, X86_REG_EIP, &address_virt);

    std::array<uint8_t, size> bytes;
    const auto res = reader_.read(bytes);

    cs_insn* insn;
    cs_disasm(cs_handle_, bytes._Unchecked_begin(), size, 0, 1, &insn);

    uc_emu_start(uc_handle_, address_virt, address_virt + size, 0, 1);

    reader_.seek(insn->size - static_cast<long>(res + size), SEEK_CUR);

    auto debug = debug_32();

    debug.id = insn->id;

    debug.address = address_virt;

    for (auto i = 0; i < 16; i++)
        debug.bytes[i] = insn->bytes[i];
    debug.size = insn->size;
    
    for (auto i = 0; i < strlen(insn->mnemonic); i++)
        debug.mnemonic[i] = insn->mnemonic[i];
    for (auto i = 0; i < strlen(insn->op_str); i++)
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

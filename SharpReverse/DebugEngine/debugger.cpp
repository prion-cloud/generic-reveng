#include "stdafx.h"

#include "debugger.h"

debugger::debugger(const std::string file_name)
{
    cs_open(CS_ARCH_X86, CS_MODE_32, &cs_handle_);
    cs_option(cs_handle_, CS_OPT_DETAIL, CS_OPT_ON);

    uc_open(UC_ARCH_X86, UC_MODE_32, &uc_handle_); // TODO: Determine arch and mode

    auto reader = binary_reader(file_name);
    auto header = reader.search_header();

    if (header == std::nullopt)
    {
        initialize_section(reader, 0x1000, 0x0, reader.length(), 0x0);
        initialize_registers(0x0);
    }
    else
    {
        const auto image_base = header->optional_header32->ImageBase;
        const auto section_alignment = header->optional_header32->SectionAlignment;

        auto section_headers = header->section_headers;

        initialize_section(reader, section_alignment, 0x0, 0x1000 /*TODO: Change*/, 0x0);

        for (size_t i = 0; i < section_headers.size(); ++i)
        {
            initialize_section(
                reader,
                section_alignment,
                section_headers[i].PointerToRawData,
                section_headers[i].SizeOfRawData,
                image_base + section_headers[i].VirtualAddress);
        }

        initialize_registers(image_base + header->optional_header32->AddressOfEntryPoint);
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

    cs_insn* instruction;
    cs_disasm(cs_handle_, bytes, size, cur_addr, 1, &instruction);

    uc_emu_start(uc_handle_, cur_addr, -1, 0, 1);

    auto incr = true;

    for (auto i = 0; i < instruction->detail->groups_count; ++i)
    {
        switch (instruction->detail->groups[i])
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
        auto next_addr = cur_addr + instruction->size;
        uc_reg_write(uc_handle_, X86_REG_EIP, &next_addr);
    }

    return create_result(instruction);
}

void debugger::initialize_section(
    binary_reader reader,
    const size_t alignment,
    const size_t raw_address,
    const size_t raw_size,
    const size_t virtual_address) const
{
    auto virtual_size = alignment * (raw_size / alignment);
    if (raw_size % alignment > 0)
        virtual_size += alignment;

    uc_mem_map(uc_handle_, virtual_address, virtual_size, UC_PROT_ALL);

    std::vector<char> byte_vec;
    reader.seek(raw_address);
    reader.read(byte_vec, raw_size);
    uc_mem_write(uc_handle_, virtual_address, &byte_vec[0], byte_vec.size() - 1);
}
void debugger::initialize_registers(const size_t virtual_address_entry_point) const
{
    uc_reg_write(uc_handle_, X86_REG_EIP, &virtual_address_entry_point);
}

debug_32 debugger::create_result(cs_insn* instruction) const
{
    auto debug = debug_32();

    debug.id = instruction->id;

    debug.address = static_cast<uint32_t>(instruction->address);

    debug.size = instruction->size;

    memcpy(debug.bytes, instruction->bytes, instruction->size);

    memcpy(debug.mnemonic, instruction->mnemonic, strlen(instruction->mnemonic));
    memcpy(debug.operands, instruction->op_str, strlen(instruction->op_str));

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

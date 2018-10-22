#include "stdafx.h"

#include "disassembly.h"

disassembly::pe_header::pe_header(const std::vector<uint8_t>& code)
{
    dos_header = *reinterpret_cast<IMAGE_DOS_HEADER const*>(&code.at(0));

    const auto fh_pos = dos_header.e_lfanew + sizeof(DWORD);
    const auto oh_pos = fh_pos + sizeof(IMAGE_FILE_HEADER);

    file_header = *reinterpret_cast<IMAGE_FILE_HEADER const*>(&code.at(fh_pos));
    optional_header = *reinterpret_cast<IMAGE_OPTIONAL_HEADER64 const*>(&code.at(oh_pos));

    auto sh_pos = oh_pos + sizeof(IMAGE_OPTIONAL_HEADER64);
    for (auto i = 0; i < file_header.NumberOfSections; ++i, sh_pos += sizeof(IMAGE_SECTION_HEADER))
        section_headers.push_back(*reinterpret_cast<IMAGE_SECTION_HEADER const*>(&code.at(sh_pos)));
}

disassembly::disassembly(const std::vector<uint8_t>& code)
    : header_(code)
{
    cs_open(CS_ARCH_X86, CS_MODE_64, &cs_);
    uc_open(UC_ARCH_X86, UC_MODE_64, &uc_);

    cs_option(cs_, CS_OPT_DETAIL, CS_OPT_ON);
    cs_option(cs_, CS_OPT_SKIPDATA, CS_OPT_ON);

    mem_map(header_.optional_header.ImageBase, std::vector<uint8_t>(code.begin(), code.begin() + PAGE_SIZE));
    for (const auto section_header : header_.section_headers)
    {
        const auto first = code.begin() + section_header.PointerToRawData;
        mem_map(header_.optional_header.ImageBase + section_header.VirtualAddress, std::vector<uint8_t>(first, first + section_header.SizeOfRawData));
    }

    mem_map(STACK_TOP, header_.optional_header.SizeOfStackCommit);
}
disassembly::~disassembly()
{
    cs_close(&cs_);
    uc_close(uc_);
}

//uint64_t disassembly::emulate(const uint64_t address) const
//{
//    uc_emu_start(uc_, address, -1, 0, 1);
//
//    uint64_t next_address;
//    uc_reg_read(uc_, UC_X86_REG_RIP, &next_address);
//
//    return next_address;
//}

//void const* disassembly::get_context() const
//{
//    std::copy()
//}
//void disassembly::set_context(void* context)
//{
//    uc_ = static_cast<uc_engine*>(context);
//}

instruction disassembly::operator[](const uint64_t address) const
{
    const size_t buffer_size = 0x10;

    uint8_t buffer[buffer_size];
    uc_mem_read(uc_, address, buffer, buffer_size);

    cs_insn* cs_instructions;
    cs_disasm(cs_, buffer, buffer_size, address, 1, &cs_instructions);

    const instruction instruction(cs_instructions[0]);

    cs_free(cs_instructions, 1);

    return instruction;
}

void disassembly::mem_map(const uint64_t address, const size_t size) const
{
    if (size == 0)
        return;

    auto virt_size = PAGE_SIZE * (size / PAGE_SIZE);
    if (size % PAGE_SIZE > 0)
        virt_size += PAGE_SIZE;

    uc_mem_map(uc_, address, virt_size, UC_PROT_READ);
}
void disassembly::mem_map(const uint64_t address, const std::vector<uint8_t>& buffer) const
{
    if (buffer.empty())
        return;

    mem_map(address, buffer.size());

    uc_mem_write(uc_, address, &buffer.at(0), buffer.size());
}

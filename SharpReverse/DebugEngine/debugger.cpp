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
        initialize_registers(0xffffffff, 0x0);
    }
    else
    {
        const auto image_base = header->optional_header.ImageBase;
        const auto section_alignment = header->optional_header.SectionAlignment;

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

        const auto stack_size = header->optional_header.SizeOfStackCommit;
        const auto stack_offset = 0xffffffff - stack_size + 1; // Pointer is end of address space; TODO: Change?

        const auto stack_pointer = stack_offset + stack_size - 1;

        initialize_section(
            section_alignment,
            stack_size,
            stack_offset);

        initialize_import_table(
            image_base,
            header->optional_header.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

        initialize_registers(
            stack_pointer,
            image_base + header->optional_header.AddressOfEntryPoint);
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
    initialize_section(alignment, raw_size, virtual_address);

    std::vector<char> byte_vec;
    reader.seek(raw_address);
    reader.read(byte_vec, raw_size);
    uc_mem_write(uc_handle_, virtual_address, &byte_vec[0], byte_vec.size() - 1);
}
void debugger::initialize_section(
    const size_t alignment,
    const size_t raw_size,
    const size_t virtual_address) const
{
    auto virtual_size = alignment * (raw_size / alignment);
    if (raw_size % alignment > 0)
        virtual_size += alignment;

    uc_mem_map(uc_handle_, virtual_address, virtual_size, UC_PROT_ALL);
}
void debugger::initialize_import_table(
    const size_t image_base,
    const size_t import_table_address) const
{
    std::vector<IMAGE_IMPORT_DESCRIPTOR> descriptors;

    for (auto i = 0;; ++i)
    {
        IMAGE_IMPORT_DESCRIPTOR descriptor;

        uc_mem_read(
            uc_handle_,
            image_base + import_table_address + i * sizeof(IMAGE_IMPORT_DESCRIPTOR),
            &descriptor,
            sizeof(IMAGE_IMPORT_DESCRIPTOR));

        if (descriptor.OriginalFirstThunk == 0x0)
            break;

        descriptors.push_back(descriptor);
    }

    if (descriptors.size() == 0)
        return;

    for (auto i = descriptors[0].OriginalFirstThunk; i < descriptors[0].Name; i += sizeof(uint32_t))
    {
        DWORD module_addr = -1;

        for (auto j = 0; j < descriptors.size(); ++j)
        {
            if (i >= descriptors[j].OriginalFirstThunk)
                module_addr = descriptors[j].Name;
        }

        uint32_t proc_loc;
        uc_mem_read(uc_handle_, image_base + i, &proc_loc, sizeof(uint32_t));

        if (proc_loc == 0)
            continue;

        std::vector<char> module_chars;
        for (auto j = 0;; ++j)
        {
            char c;
            uc_mem_read(uc_handle_, image_base + module_addr + j, &c, 1);
            module_chars.push_back(c);

            if (c == '\0')
                break;
        }
        std::string module_name(module_chars.begin(), module_chars.end());

        auto brk = false;
        std::vector<char> proc_chars;
        for (auto j = 0;; ++j)
        {
            char c;
            uc_mem_read(uc_handle_, image_base + proc_loc + j, &c, 1);

            if (c != '\0')
                brk = true;
            else if (!brk)
                continue;

            proc_chars.push_back(c);

            if (c == '\0' && brk)
                break;
        }
        std::string proc_name(proc_chars.begin(), proc_chars.end());

        const auto addr = GetProcAddress(GetModuleHandleA(module_name.c_str()), proc_name.c_str());
        auto a = uc_mem_write(uc_handle_, image_base + i, &addr, sizeof(uint32_t));
        auto b = a;
    }
}
void debugger::initialize_registers(
    const uint32_t stack_pointer,
    const uint32_t entry_point) const
{
    uc_reg_write(uc_handle_, X86_REG_ESP, &stack_pointer);
    uc_reg_write(uc_handle_, X86_REG_EBP, &stack_pointer);

    uc_reg_write(uc_handle_, X86_REG_EIP, &entry_point);
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

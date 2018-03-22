#include "stdafx.h"

#include "debugger.h"

#include "uc_extensions.h"

debugger::debugger(
    const std::string file_name)
{
    cs_open(CS_ARCH_X86, CS_MODE_32, &cs_);
    cs_option(cs_, CS_OPT_DETAIL, CS_OPT_ON);

    uc_open(UC_ARCH_X86, UC_MODE_32, &uc_); // TODO: Determine arch and mode

    uint32_t entry_point;
    uint32_t stack_pointer;
    uint32_t stack_size;

    auto reader = binary_reader(file_name);
    auto header = reader.inspect_header();

    if (header == std::nullopt)
    {
        entry_point = 0x0;
        stack_pointer = 0xffffffff;
        stack_size = 0x1000;

        uc_initialize_section(uc_, reader.read_vector<char>(reader.length(), entry_point), entry_point);
    }
    else
    {
        const auto image_base = header->optional_header.ImageBase;

        entry_point = image_base + header->optional_header.AddressOfEntryPoint;
        stack_pointer = 0xffffffff; // End of address space; TODO: Change?
        stack_size = header->optional_header.SizeOfStackCommit;

        for (auto s_h : header->section_headers)
            uc_initialize_section(uc_, reader.read_vector<char>(s_h.SizeOfRawData, s_h.PointerToRawData), image_base + s_h.VirtualAddress);

        initialize_import_table(image_base, header->optional_header.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
    }

    reader.close();

    uc_initialize_section(uc_, std::vector<char>(stack_size), stack_pointer - stack_size + 1);
    initialize_registers(stack_pointer, entry_point);
}

void debugger::close()
{
    cs_close(&cs_);
    uc_close(uc_);
}

instruction_32 debugger::debug_32() const
{
    const size_t size = 16;

    uint32_t cur_addr;
    uc_reg_read(uc_, X86_REG_EIP, &cur_addr);

    uint8_t bytes[size];
    uc_mem_read(uc_, cur_addr, bytes, size);

    cs_insn* instruction;
    cs_disasm(cs_, bytes, size, cur_addr, 1, &instruction);

    uc_emu_start(uc_, cur_addr, -1, 0, 1);

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
        uc_reg_write(uc_, X86_REG_EIP, &next_addr);
    }

    auto result = instruction_32();

    result.id = instruction->id;

    result.address = static_cast<uint32_t>(instruction->address);

    result.size = instruction->size;

    memcpy(result.bytes, instruction->bytes, instruction->size);

    memcpy(result.mnemonic, instruction->mnemonic, strlen(instruction->mnemonic));
    memcpy(result.operands, instruction->op_str, strlen(instruction->op_str));

    return result;
}

register_state_32 debugger::get_registers_32() const
{
    auto result = register_state_32();

    uc_reg_read(uc_, X86_REG_EAX, &result.eax);
    uc_reg_read(uc_, X86_REG_EBX, &result.ebx);
    uc_reg_read(uc_, X86_REG_ECX, &result.ecx);
    uc_reg_read(uc_, X86_REG_EDX, &result.edx);

    uc_reg_read(uc_, X86_REG_ESP, &result.esp);
    uc_reg_read(uc_, X86_REG_EBP, &result.ebp);

    uc_reg_read(uc_, X86_REG_ESI, &result.esi);
    uc_reg_read(uc_, X86_REG_EDI, &result.edi);

    uc_reg_read(uc_, X86_REG_EIP, &result.eip);

    return result;
}

void debugger::initialize_import_table(
    const size_t image_base,
    const size_t import_table_address) const
{
    for (auto i = 0;; ++i)
    {
        IMAGE_IMPORT_DESCRIPTOR descriptor;
        uc_mem_read(uc_, image_base + import_table_address, i, descriptor);

        if (descriptor.Name == 0x0)
            break;

        std::string module_name;
        uc_mem_read_string(uc_, image_base + descriptor.Name, module_name);

        load_dll(module_name);

        for (auto j = 0;; ++j)
        {
            uint32_t proc_name_address;
            uc_mem_read(uc_, image_base + descriptor.FirstThunk, j, proc_name_address);

            if (proc_name_address == 0x0)
                break;

            std::string proc_name;
            uc_mem_read_string(uc_, image_base + proc_name_address, proc_name);

            const auto proc_address = GetProcAddress(GetModuleHandleA(module_name.c_str()), proc_name.c_str()); // TODO: GetModuleHandle/GetProcAddress?
            uc_mem_write(uc_, image_base + descriptor.FirstThunk, j, proc_address);
        }
    }
}
void debugger::initialize_registers(
    const uint32_t stack_pointer,
    const uint32_t entry_point) const
{
    uc_reg_write(uc_, X86_REG_ESP, &stack_pointer);
    uc_reg_write(uc_, X86_REG_EBP, &stack_pointer);

    uc_reg_write(uc_, X86_REG_EIP, &entry_point);
}

void debugger::load_dll(
    const std::string name) const
{
    auto reader = binary_reader("C:\\Windows\\System32\\" + name); // TODO: Replace with %windir%, etc.

    auto header = reader.inspect_header();

    const auto reloc = header->optional_header.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
    const auto dll_base = reinterpret_cast<uint32_t>(GetModuleHandleA(name.c_str())); // TODO: GetModuleHandle?

    for (auto s_h : header->section_headers)
        uc_initialize_section(uc_, reader.read_vector<char>(s_h.SizeOfRawData, s_h.PointerToRawData), dll_base + s_h.VirtualAddress);

    auto offset = 0;
    while (true)
    {
        IMAGE_BASE_RELOCATION br;
        uc_mem_read(uc_, dll_base + reloc + offset, br);

        if (br.VirtualAddress == 0x0)
            break;

        const int count = (br.SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
        for (auto j = 0; j < count; ++j)
        {
            WORD w;
            uc_mem_read(uc_, dll_base + reloc + offset + sizeof(IMAGE_BASE_RELOCATION), j, w);

            const auto type = (w & 0xf000) >> 12;
            w &= 0xfff;

            if (type == IMAGE_REL_BASED_HIGHLOW)
            {
                const auto address = dll_base + br.VirtualAddress + w;
                const auto delta = dll_base - header->optional_header.ImageBase;

                uint32_t value;
                uc_mem_read(uc_, address, value);

                uc_mem_write(uc_, address, value + delta);
            }
        }

        offset += br.SizeOfBlock;
    }
}

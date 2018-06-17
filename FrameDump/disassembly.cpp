#include "stdafx.h"

#include "disassembly.h"
#include "serialization.h"

disassembly_part_x86::disassembly_part_x86(const std::vector<instruction_x86> instructions, const std::vector<uint8_t> code)
    : instructions_(instructions), code_(code) { }

uint64_t disassembly_part_x86::base() const
{
    return instructions_.at(0).address();
}
size_t disassembly_part_x86::size() const
{
    return instructions_.size();
}
const void* disassembly_part_x86::nipple() const
{
    return &code_.at(0);
}

bool disassembly_part_x86::find(const uint64_t address, instruction_x86& instruction) const
{
    size_t l = 0;
    auto r = instructions_.size() - 1;

    while (true)
    {
        if (l > r)
            break;

        const auto m = (l + r) / 2;
        const auto ins = instructions_.at(m);

        if (ins.address() < address)
        {
            l = m + 1;
            continue;
        }

        if (ins.address() > address)
        {
            r = m - 1;
            continue;
        }

        instruction = ins;
        return true;
    }

    return false;
}

void disassembly_part_x86::save(const std::string file_name) const
{
    std::ofstream stream(file_name, std::ios::binary);
    stream <<= instructions_;
    stream <<= code_;
}

std::set<uint64_t> disassembly_part_x86::crawl_sequences(const int min, const unsigned find, const std::set<unsigned> add) const
{
    std::set<uint64_t> result;

    for (auto i = 0; i < instructions_.size(); ++i)
    {
        const auto ins = instructions_.at(i);

        if (ins.identification() != find)
            continue;

        auto j = 0;

        do
        {
            ++i;
            ++j;

            if (i >= instructions_.size())
                break;
        }
        while (instructions_.at(i).identification() == find || add.find(instructions_.at(i).identification()) != add.end());

        if (j >= min)
            result.insert(ins.address());
    }

    return result;
}

disassembly_part_x86 disassembly_part_x86::create_complete(const uint64_t base_address, const std::vector<uint8_t> code)
{
    csh handle;
    cs_open(CS_ARCH_X86, CS_MODE_64, &handle);
    cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
    cs_option(handle, CS_OPT_SKIPDATA, CS_OPT_ON);

    cs_insn* cs_instructions;
    const auto count = cs_disasm(handle, &code.at(0), code.size(), base_address, 0, &cs_instructions);

    cs_close(&handle);

    disassembly_part_x86 disassembly(std::vector<instruction_x86>(cs_instructions, cs_instructions + count), code);

    cs_free(cs_instructions, count);

    return disassembly;
}

disassembly_part_x86 disassembly_part_x86::load(const std::string file_name)
{
    std::vector<instruction_x86> instructions;
    std::vector<uint8_t> bytes;

    std::ifstream stream(file_name, std::ios::binary);
    stream >>= instructions;
    stream >>= bytes;

    return disassembly_part_x86(instructions, bytes);
}

disassembly_x86::disassembly_x86()
{
    uc_open(UC_ARCH_X86, UC_MODE_64, &uc_);

    const uint64_t stack_bottom = 0xffffffff;
    const uint64_t stack_size = PAGE_SIZE;

    uc_mem_map(uc_, stack_bottom - stack_size + 1, stack_size, UC_PROT_ALL);

    const auto stack_pointer = stack_bottom - stack_size / 2;
    uc_reg_write(uc_, UC_X86_REG_RSP, &stack_pointer);
    uc_reg_write(uc_, UC_X86_REG_RBP, &stack_pointer);
}
disassembly_x86::~disassembly_x86()
{
    uc_close(uc_);
}

uc_engine* disassembly_x86::uc() const
{
    return uc_;
}

void disassembly_x86::add(const disassembly_part_x86 part)
{
    parts_.push_back(part);

    auto size = PAGE_SIZE * (part.size() / PAGE_SIZE);
    if (part.size() % PAGE_SIZE > 0)
        size += PAGE_SIZE;

    uc_mem_map(uc_, part.base(), size, UC_PROT_ALL);
    uc_mem_write(uc_, part.base(), part.nipple(), part.size());
}

instruction_x86 disassembly_x86::find(const uint64_t address) const
{
    instruction_x86 instruction;
    for (const auto part : parts_)
    {
        if (part.find(address, instruction))
            return instruction;
    }

    return { };
}

std::set<uint64_t> disassembly_x86::crawl_sequences(const int min, const unsigned find, const std::set<unsigned> add) const
{
    std::set<uint64_t> result;

    for (const auto part : parts_)
    {
        for (const auto sub : part.crawl_sequences(min, find, add))
            result.insert(sub);
    }

    return result;
}

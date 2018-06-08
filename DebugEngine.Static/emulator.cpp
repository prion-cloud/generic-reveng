#include "stdafx.h"

#include "emulator.h"

bool operator<(const uc_mem_region a, const uc_mem_region b)
{
    return a.end <= b.begin;
}

emulator::emulator(const uint16_t machine)
{
    auto mode = static_cast<uc_mode>(0);

    switch (machine)
    {
#ifdef _WIN64
    case IMAGE_FILE_MACHINE_AMD64:

        mode = UC_MODE_64;

        max_scale_ = UINT64_MAX;

        reg_sp_id_ = UC_X86_REG_RSP;
        reg_bp_id_ = UC_X86_REG_RBP;

        reg_ip_id_ = UC_X86_REG_RIP;

        break;
#else
    case IMAGE_FILE_MACHINE_I386:

        mode = UC_MODE_32;

        max_scale_ = UINT32_MAX;

        reg_sp_id_ = UC_X86_REG_ESP;
        reg_bp_id_ = UC_X86_REG_EBP;

        reg_ip_id_ = UC_X86_REG_EIP;

        break;
#endif
    default:
        THROW("Invalid machine specification.");
    }

    FATAL_IF(uc_open(UC_ARCH_X86, mode, &uc_));
}
emulator::~emulator()
{
    uc_close(uc_);
}

// Memory

void emulator::mem_map(const uint64_t address, const std::vector<uint8_t> buffer)
{
    if (buffer.size() == 0)
        return;

    auto virt_size = PAGE_SIZE * (buffer.size() / PAGE_SIZE);
    if (buffer.size() % PAGE_SIZE > 0)
        virt_size += PAGE_SIZE;

    const uint32_t perms = UC_PROT_ALL;

    FATAL_IF(uc_mem_map(uc_, address, virt_size, perms));

    uc_mem_region region;
    region.begin = address;
    region.end = address + virt_size;
    region.perms = perms;

    mem_regions_.insert(region);

    FATAL_IF(uc_mem_write(uc_, address, &buffer.at(0), buffer.size()));
}

bool emulator::mem_is_mapped(const uint64_t address) const
{
    uc_mem_region cmp_region;

    cmp_region.begin = address;
    cmp_region.end = address;

    return mem_regions_.lower_bound(cmp_region) != mem_regions_.upper_bound(cmp_region);
}

void emulator::mem_read(const uint64_t address, std::vector<uint8_t>& buffer) const
{
    FATAL_IF(uc_mem_read(uc_, address, &buffer.at(0), buffer.size()));
}

std::string emulator::mem_read_string(const uint64_t address) const
{
    std::vector<char> chars;
    for (auto j = 0;; ++j)
    {
        auto c = mem_read<char>(address, j);

        if (c == '\0')
            break;

        chars.push_back(c);
    }

    return std::string(chars.begin(), chars.end());
}

// Registers

uint64_t emulator::address() const
{
    return reg_read<uint64_t>(reg_ip_id_);
}
void emulator::jump_to(const uint64_t address) const
{
    reg_write(reg_ip_id_, address);
}

void emulator::resize_stack(const uint64_t pointer) const
{
    reg_write(reg_sp_id_, pointer);
    reg_write(reg_bp_id_, pointer);
}

// Emulation

int emulator::emulate_any() const
{
    return uc_emu_start(uc_, reg_read<uint64_t>(reg_ip_id_), -1, 0, 0);
}
int emulator::emulate_once() const
{
    return uc_emu_start(uc_, reg_read<uint64_t>(reg_ip_id_), -1, 0, 1);
}

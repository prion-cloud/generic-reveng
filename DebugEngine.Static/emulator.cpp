#include "stdafx.h"

#include "emulator.h"

emulator::emulator(const uint16_t machine)
{
    uc_arch arch;
    uc_mode mode;

    switch (machine)
    {
#ifdef _WIN64
    case IMAGE_FILE_MACHINE_AMD64:
        
        arch = UC_ARCH_X86;
        mode = UC_MODE_64;

        scale_ = UINT64_MAX;

        reg_sp_id_ = UC_X86_REG_RSP;
        reg_bp_id_ = UC_X86_REG_RBP;

        reg_ip_id_ = UC_X86_REG_RIP;

        break;
#else
    case IMAGE_FILE_MACHINE_I386:

        arch = UC_ARCH_X86;
        mode = UC_MODE_32;

        scale_ = UINT32_MAX;

        reg_sp_id_ = UC_X86_REG_ESP;
        reg_bp_id_ = UC_X86_REG_EBP;

        reg_ip_id_ = UC_X86_REG_EIP;

        break;
#endif
    default:
        THROW;
    }

    E_FAT(uc_open(arch, mode, &uc_));
}
emulator::~emulator()
{
    uc_close(uc_);
}

// Memory

void emulator::mem_map(const uint64_t address, void* buffer, const size_t size) const
{
    if (size == 0x0)
        return;

    auto virt_size = PAGE_SIZE * (size / PAGE_SIZE);
    if (size % PAGE_SIZE > 0)
        virt_size += PAGE_SIZE;

    E_FAT(uc_mem_map(uc_, address, virt_size, UC_PROT_ALL));
    
    if (buffer == nullptr)
        return;

    E_FAT(uc_mem_write(uc_, address, buffer, size));
}

void emulator::mem_read(const uint64_t address, void* buffer, const size_t size) const
{
    E_FAT(uc_mem_read(uc_, address, buffer, size));
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

void emulator::init_regs(const uint64_t stack_pointer, const uint64_t instruction_pointer) const
{
    reg_write(reg_sp_id_, stack_pointer);
    reg_write(reg_bp_id_, stack_pointer);

    jump(instruction_pointer);
}

uint64_t emulator::address() const
{
    return reg_read<uint64_t>(reg_ip_id_);
}
void emulator::jump(const uint64_t address) const
{
    reg_write(reg_ip_id_, address);
}

// Emulation

int emulator::run() const
{
    return R_FAILURE; // TODO
}

int emulator::step_into() const
{
    E_ERR(uc_emu_start(uc_, reg_read<uint64_t>(reg_ip_id_), -1, 0, 1));
    return R_SUCCESS;
}
int emulator::step_over() const
{
    return R_FAILURE; // TODO
}

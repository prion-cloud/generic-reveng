#include "stdafx.h"
#include "macro.h"

#include "emulator.h"

emulator::emulator(const WORD machine)
{
    uc_arch arch;
    uc_mode mode;

    switch (machine)
    {
#ifdef _WIN32
    case IMAGE_FILE_MACHINE_I386:

        arch = UC_ARCH_X86;
        mode = UC_MODE_32;

        scale_ = UINT32_MAX;

        registers_ =
        {
            { reg_ax, UC_X86_REG_EAX },
            { reg_bx, UC_X86_REG_EBX },
            { reg_cx, UC_X86_REG_ECX },
            { reg_dx, UC_X86_REG_EDX },
            { reg_sp, UC_X86_REG_ESP },
            { reg_bp, UC_X86_REG_EBP },
            { reg_si, UC_X86_REG_ESI },
            { reg_di, UC_X86_REG_EDI },
            { reg_ip, UC_X86_REG_EIP }
        };

        break;
#endif
#ifdef _WIN64
    case IMAGE_FILE_MACHINE_AMD64:
        
        arch = UC_ARCH_X86;
        mode = UC_MODE_64;

        scale_ = UINT64_MAX;
        
        registers_ =
        {
            { reg_ax, UC_X86_REG_RAX },
            { reg_bx, UC_X86_REG_RBX },
            { reg_cx, UC_X86_REG_RCX },
            { reg_dx, UC_X86_REG_RDX },
            { reg_sp, UC_X86_REG_RSP },
            { reg_bp, UC_X86_REG_RBP },
            { reg_si, UC_X86_REG_RSI },
            { reg_di, UC_X86_REG_RDI },
            { reg_ip, UC_X86_REG_RIP }
        };

        break;
#endif
    default:
        THROW_E;
    }

    uc_open(arch, mode, &uc_);

    auto a = uc_;
}
emulator::~emulator()
{
    uc_close(uc_);
}

void emulator::mem_map(const uint64_t address, void* buffer, const size_t size) const
{
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

void emulator::jump(const uint64_t address) const
{
    reg_write(reg_ip, address);
}

void emulator::run() const
{
    THROW_E; // TODO
}

void emulator::step_into() const
{
    uc_emu_start(uc_, reg_read<uint64_t>(reg_ip), -1, 0, 1);
}
void emulator::step_over() const
{
    THROW_E; // TODO
}

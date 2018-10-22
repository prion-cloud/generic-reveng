#include "../include/follower/loader.h"

loader::loader(uc_arch const architecture, uc_mode const mode)
    : machine_(std::make_pair(architecture, mode))
{
    switch (architecture)
    {
    case UC_ARCH_X86:
        switch (mode)
        {
        case UC_MODE_32:
            instruction_pointer_register_id_ = UC_X86_REG_EIP;
            return;
        case UC_MODE_64:
            instruction_pointer_register_id_ = UC_X86_REG_RIP;
            return;
        default:
            break;
        }
        break;

    // TODO

    default:
        break;
    }

    throw std::invalid_argument("Unsupported machine specification");
}

std::shared_ptr<uc_engine> loader::create_uc() const
{
    uc_engine* uc;
    uc_open(machine_.first, machine_.second, &uc);

    return std::shared_ptr<uc_engine>(uc, uc_close);
}

#include "../include/follower/loader.h"

loader_pe::loader_pe(uc_arch const architecture, const uc_mode mode)
    : loader(architecture, mode) { }

std::shared_ptr<uc_engine> loader_pe::operator()(std::istream& stream) const
{
    uc_engine* uc;
    uc_open(UC_ARCH_X86, UC_MODE_64, &uc);

    // TODO

    return std::shared_ptr<uc_engine>(uc, uc_close);
}

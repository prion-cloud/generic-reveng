#include "stdafx.h"

#include "cfg.h"
#include "deobfuscator.h"

deobfuscator_x86::deobfuscator_x86(loader& loader, std::vector<uint8_t> code)
    : debugger_(std::make_shared<debugger>(loader, code)) { }

void deobfuscator_x86::deobfuscate(const uint64_t address) const
{
    const auto context = debugger_->get_context();

    const auto cfg = cfg_x86(debugger_, address);
    cfg.draw();

    std::cout << std::endl;

    debugger_->set_context(context);
}

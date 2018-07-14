#pragma once

class deobfuscator_x86
{
    std::shared_ptr<debugger> debugger_;

public:

    explicit deobfuscator_x86(loader& loader, std::vector<uint8_t> code);

    void deobfuscate(uint64_t address) const;
};

#pragma once

class data_monitor
{
    std::map<x86_reg, std::string> map_;

public:

    data_monitor() = default;

    void apply(const instruction_x86& instruction);

private:

    std::string safe_at(x86_reg reg) const;

    std::map<x86_reg, std::string> inspect_changes(const instruction_x86& instruction) const;
};

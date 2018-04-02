#pragma once

class loader
{
public:

    virtual ~loader() = default;

    virtual int load(std::vector<char> bytes, csh& cs, uc_engine*& uc, uint64_t& scale, std::vector<int>& regs, int& ip_index) const = 0;
};

#pragma once

#include <istream>
#include <memory>
#include <unordered_map>
#include <utility>

#include "../../submodules/unicorn/include/unicorn/unicorn.h"

class loader
{
protected:

    std::pair<uc_arch, uc_mode> machine_;

    int instruction_pointer_register_id_;

public:

    virtual ~loader() = default;

    virtual std::shared_ptr<uc_engine> operator()(std::istream& is) const = 0;

protected:

    loader(uc_arch architecture, uc_mode mode);

    std::shared_ptr<uc_engine> create_uc() const;
};

class loader_pe : loader
{
public:

    loader_pe(uc_arch architecture, uc_mode mode);

    std::shared_ptr<uc_engine> operator()(std::istream& is) const override;
};

class loader_elf : loader
{
public:

    // TODO
};

#pragma once

#include <istream>
#include <memory>

#include "../../submodules/unicorn/include/unicorn/unicorn.h"

class loader
{
protected:

    uc_arch architecture_;
    uc_mode mode_;

    loader(uc_arch architecture, uc_mode mode);

public:

    virtual ~loader() = default;

    virtual std::shared_ptr<uc_engine> operator()(std::istream& stream) const = 0;
};

class loader_pe : loader
{
public:

    loader_pe(uc_arch architecture, uc_mode mode);

    std::shared_ptr<uc_engine> operator()(std::istream& stream) const override;
};

class loader_elf : loader
{
public:

    // TODO
};

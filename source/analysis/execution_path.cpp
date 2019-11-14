#include <generic-reveng/analysis/execution_path.hpp>

namespace grev
{
    bool execution_path::update(std::uint64_t const address, machine_impact impact)
    {
        if (!address_registry_.insert(address).second)
            return false;

        push_back(address);

        impact_ = std::move(impact);

        return true;
    }

    machine_impact const& execution_path::impact() const
    {
        return impact_;
    }
}

static_assert(std::is_destructible_v<grev::execution_path>);

static_assert(std::is_copy_constructible_v<grev::execution_path>);
static_assert(std::is_copy_assignable_v<grev::execution_path>);

static_assert(std::is_move_constructible_v<grev::execution_path>);
static_assert(std::is_move_assignable_v<grev::execution_path>);

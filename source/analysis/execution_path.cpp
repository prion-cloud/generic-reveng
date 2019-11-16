#include <generic-reveng/analysis/execution_path.hpp>

namespace grev
{
    bool execution_path::update(std::uint64_t const address, machine_state state)
    {
        if (!address_registry_.insert(address).second)
            return false;

        push_back(address);

        state_ = std::move(state);

        return true;
    }

    machine_state const& execution_path::state() const
    {
        return state_;
    }
}

static_assert(std::is_destructible_v<grev::execution_path>);

static_assert(std::is_copy_constructible_v<grev::execution_path>);
static_assert(std::is_copy_assignable_v<grev::execution_path>);

static_assert(std::is_move_constructible_v<grev::execution_path>);
static_assert(std::is_move_assignable_v<grev::execution_path>);

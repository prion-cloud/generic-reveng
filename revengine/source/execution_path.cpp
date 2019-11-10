#include <revengine/execution_path.hpp>

namespace rev
{
    void execution_path::step(std::uint64_t const address)
    {
        push_back(address);
    }

    machine_impact& execution_path::impact()
    {
        return impact_;
    }
}

static_assert(std::is_destructible_v<rev::execution_path>);

static_assert(std::is_copy_constructible_v<rev::execution_path>);
static_assert(std::is_copy_assignable_v<rev::execution_path>);

static_assert(std::is_move_constructible_v<rev::execution_path>);
static_assert(std::is_move_assignable_v<rev::execution_path>);

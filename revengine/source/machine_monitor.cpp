#include <revengine/machine_monitor.hpp>

namespace rev
{
    std::vector<execution_path> const& machine_monitor::paths() const
    {
        return paths_;
    }
}

static_assert(std::is_destructible_v<rev::machine_monitor>);

static_assert(std::is_copy_constructible_v<rev::machine_monitor>);
static_assert(std::is_copy_assignable_v<rev::machine_monitor>);

static_assert(std::is_move_constructible_v<rev::machine_monitor>);
static_assert(std::is_move_assignable_v<rev::machine_monitor>);

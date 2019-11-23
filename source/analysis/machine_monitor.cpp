#include <generic-reveng/analysis/machine_monitor.hpp>

namespace grev
{
    // >>-----
    std::vector<std::vector<std::uint32_t>> machine_monitor::path_addresses() const
    {
        std::vector<std::vector<std::uint32_t>> path_addresses;

        for (auto const& path : paths_)
            path_addresses.push_back(path.addresses());

        return path_addresses;
    }
    // -----<<
}

static_assert(std::is_destructible_v<grev::machine_monitor>);

static_assert(std::is_copy_constructible_v<grev::machine_monitor>);
static_assert(std::is_nothrow_move_constructible_v<grev::machine_monitor>);

static_assert(std::is_copy_assignable_v<grev::machine_monitor>);
static_assert(std::is_nothrow_move_assignable_v<grev::machine_monitor>);
